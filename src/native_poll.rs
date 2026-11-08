//! Metadata-only polling for registered Codex thread turn-completion observers.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const INTERVAL_MS: i64 = 5_000;
const CLAIM_MS: i64 = 180_000;
const PAGE_SIZE: i64 = 100;
const MAX_PAGES: usize = 10;
const CONDITION_BATCH_LIMIT: i64 = 128;
type Rpc<'a> = dyn FnMut(&str, Value) -> Result<Value> + 'a;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
struct Turn {
    id: String,
    status: String,
}

#[derive(Clone, Debug)]
struct ConditionMember {
    group_id: String,
    kind: String,
    repo: String,
    resource: String,
    event: String,
    outcome: String,
    armed: bool,
    buffer_overflow: bool,
    buffer_overflow_count: i64,
    baseline_cursor: Option<String>,
    observer_exists: bool,
    baseline_turn_id: Option<String>,
    baseline_status: Option<String>,
    baseline_order_uncertain: bool,
}

impl ConditionMember {
    fn selector(&self) -> crate::conditions::Selector {
        crate::conditions::Selector {
            kind: self.kind.clone(),
            repo: self.repo.clone(),
            resource: self.resource.clone(),
            event: self.event.clone(),
            outcome: (!self.outcome.is_empty()).then(|| self.outcome.clone()),
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS native_observers (
        subscription_id TEXT PRIMARY KEY,
        resource TEXT NOT NULL,
        thread TEXT NOT NULL,
        baseline_turn_id TEXT,
        baseline_status TEXT,
        next_poll_ms INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('unknown','baseline','observed','error')),
        reason TEXT,
        updated_ms INTEGER NOT NULL
    ); CREATE INDEX IF NOT EXISTS native_observers_due ON native_observers(next_poll_ms);
    CREATE TABLE IF NOT EXISTS native_condition_observers (
        group_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        repo TEXT NOT NULL,
        resource TEXT NOT NULL,
        event TEXT NOT NULL,
        outcome TEXT NOT NULL,
        baseline_turn_id TEXT,
        baseline_status TEXT,
        baseline_order_uncertain INTEGER NOT NULL DEFAULT 0
            CHECK(baseline_order_uncertain IN (0,1)),
        next_poll_ms INTEGER NOT NULL,
        PRIMARY KEY(group_id,kind,repo,resource,event,outcome)
    );
    CREATE INDEX IF NOT EXISTS native_condition_observers_due
        ON native_condition_observers(next_poll_ms);",
    )?;
    Ok(())
}

fn registration(db: &Connection, id: &str) -> Result<(String, String, String)> {
    let (kind, event, resource, thread): (String, String, String, String) = db
        .query_row(
            "SELECT kind,event,resource,thread FROM subscriptions WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .context("Native poll subscription not found")?;
    ensure!(
        (kind == "thread" && event == "turn_completed")
            || (kind == "subagent" && event == "completed"),
        "Native poll requires a thread or native subagent completion"
    );
    let resource = Uuid::parse_str(&resource)
        .context("Thread source must be a UUID")?
        .to_string();
    let thread = Uuid::parse_str(&thread)
        .context("Destination thread must be a UUID")?
        .to_string();
    Ok((kind, resource, thread))
}

fn source_parent(call: &mut Rpc, kind: &str, source: &str) -> Result<Option<String>> {
    if kind != "subagent" {
        return Ok(None);
    }
    let response = call(
        "thread/read",
        json!({"threadId":source,"includeTurns":false}),
    )?;
    ensure!(
        response["thread"]["id"] == source,
        "Subagent thread identity mismatch"
    );
    let parent = response
        .pointer("/thread/source/subAgent/thread_spawn/parent_thread_id")
        .and_then(Value::as_str)
        .context("Source is not an attributable native subagent thread")?;
    let parent = Uuid::parse_str(parent)?.to_string();
    ensure!(parent != source, "Subagent cannot be its own parent");
    Ok(Some(parent))
}

fn turns_page(
    call: &mut Rpc,
    thread: &str,
    cursor: Option<&str>,
) -> Result<(Vec<Turn>, Option<String>)> {
    let mut params =
        json!({"threadId":thread,"limit":PAGE_SIZE,"sortDirection":"desc","itemsView":"notLoaded"});
    if let Some(cursor) = cursor {
        params["cursor"] = json!(cursor);
    }
    let response = call("thread/turns/list", params)?;
    let data = response["data"]
        .as_array()
        .context("thread/turns/list response has no data page")?;
    ensure!(
        data.len() <= PAGE_SIZE as usize,
        "thread/turns/list exceeded requested page size"
    );
    let mut turns = Vec::with_capacity(data.len());
    for value in data {
        let id = value["id"].as_str().context("Turn has no id")?;
        ensure!(
            !id.is_empty() && id.len() <= 255 && id.bytes().all(|byte| byte.is_ascii_graphic()),
            "Invalid turn identifier"
        );
        let status = value["status"].as_str().context("Turn has no status")?;
        ensure!(
            matches!(
                status,
                "inProgress" | "completed" | "interrupted" | "failed"
            ),
            "Unsupported turn status"
        );
        turns.push(Turn {
            id: id.to_owned(),
            status: status.to_owned(),
        });
    }
    ensure!(
        response["nextCursor"].is_null() || response["nextCursor"].is_string(),
        "Invalid turn cursor"
    );
    Ok((turns, response["nextCursor"].as_str().map(str::to_owned)))
}

fn first_turn(call: &mut Rpc, thread: &str) -> Result<Option<Turn>> {
    Ok(turns_page(call, thread, None)?.0.into_iter().next())
}

fn recorded_interruption(sessions: &Path, path: &Path, thread: &str, turn: &str) -> Result<bool> {
    const TAIL_BYTES: u64 = 1024 * 1024;
    let root = fs::canonicalize(sessions)?;
    let canonical = fs::canonicalize(path)?;
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Rollout symlink"
    );
    let relative = canonical
        .strip_prefix(&root)
        .context("Rollout is outside Codex sessions")?;
    let name = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .context("Rollout has no file name")?;
    let stamp = name
        .strip_prefix("rollout-")
        .and_then(|s| s.strip_suffix(&format!("-{thread}.jsonl")))
        .context("Rollout identity mismatch")?;
    ensure!(
        stamp.len() == 19
            && stamp.bytes().enumerate().all(|(i, c)| match i {
                4 | 7 | 13 | 16 => c == b'-',
                10 => c == b'T',
                _ => c.is_ascii_digit(),
            }),
        "Invalid rollout timestamp"
    );
    let open_child = |parent: &File, name: &std::ffi::OsStr, flags: i32| -> Result<File> {
        let name = CString::new(name.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | flags,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for component in root.strip_prefix("/")?.components() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("Invalid sessions directory")
        };
        directory = open_child(&directory, name, libc::O_DIRECTORY)?;
    }
    for component in relative
        .parent()
        .context("Rollout has no parent")?
        .components()
    {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("Invalid rollout directory")
        };
        directory = open_child(&directory, name, libc::O_DIRECTORY)?;
    }
    let mut file = open_child(
        &directory,
        relative.file_name().context("Rollout has no name")?,
        libc::O_NONBLOCK,
    )?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } && metadata.nlink() == 1,
        "Unsafe rollout file"
    );
    let mut header = Vec::new();
    (&mut file).take(64 * 1024).read_to_end(&mut header)?;
    let header_end = header
        .iter()
        .position(|b| *b == b'\n')
        .context("Incomplete rollout header")?;
    let header: Value = serde_json::from_slice(&header[..header_end])?;
    ensure!(
        header["type"] == "session_meta" && header["payload"]["id"] == thread,
        "Rollout header identity mismatch"
    );
    let offset = metadata.len().saturating_sub(TAIL_BYTES);
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(TAIL_BYTES).read_to_end(&mut bytes)?;
    let start = if offset == 0 {
        0
    } else {
        bytes
            .iter()
            .position(|b| *b == b'\n')
            .map_or(bytes.len(), |n| n + 1)
    };
    Ok(bytes[start..]
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| line.last() == Some(&b'\n'))
        .any(|line| {
            serde_json::from_slice::<Value>(line).is_ok_and(|v| {
                v["type"] == "event_msg"
                    && v["payload"]["type"] == "turn_aborted"
                    && v["payload"]["turn_id"] == turn
                    && v["payload"]["reason"] == "interrupted"
            })
        }))
}

fn observation_reason(call: &mut Rpc, thread: &str, turn: Option<&Turn>) -> Option<&'static str> {
    let turn = turn.filter(|turn| turn.status == "interrupted")?;
    let evidence = (|| -> Result<bool> {
        let metadata = call(
            "thread/read",
            json!({"threadId":thread,"includeTurns":false}),
        )?;
        ensure!(
            metadata["thread"]["id"] == thread,
            "Rollout thread mismatch"
        );
        let path = metadata["thread"]["path"]
            .as_str()
            .context("Rollout path unavailable")?;
        let home = std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".codex")))
            .context("Codex home unavailable")?;
        recorded_interruption(&home.join("sessions"), Path::new(path), thread, &turn.id)
    })();
    Some(match evidence {
        Ok(true) => "turn_aborted_recorded",
        Ok(false) => "interrupted_unconfirmed",
        Err(_) => "interruption_evidence_unavailable",
    })
}

fn record_unknown(
    db: &Connection,
    id: &str,
    resource: &str,
    thread: &str,
    now: i64,
) -> Result<bool> {
    Ok(db.execute("INSERT INTO native_observers(subscription_id,resource,thread,next_poll_ms,state,reason,updated_ms) VALUES(?1,?2,?3,?4,'unknown','baseline_unavailable',?5) ON CONFLICT(subscription_id) DO NOTHING", params![id,resource,thread,now+CLAIM_MS,now])? > 0)
}

fn condition_members_due(db: &Connection, now: i64) -> Result<(Vec<ConditionMember>, bool)> {
    let mut statement = db.prepare(
        "SELECT m.group_id,m.kind,m.repo,m.resource,m.event,m.outcome,m.armed,
                m.buffer_overflow,m.buffer_overflow_count,m.baseline_cursor,
                o.group_id IS NOT NULL,o.baseline_turn_id,o.baseline_status,
                COALESCE(o.baseline_order_uncertain,0)
         FROM condition_members m
         JOIN condition_groups g ON g.id=m.group_id
         LEFT JOIN native_condition_observers o
           ON o.group_id=m.group_id AND o.kind=m.kind AND o.repo=m.repo
          AND o.resource=m.resource AND o.event=m.event AND o.outcome=m.outcome
         WHERE m.polling=1 AND m.matched=0
           AND g.state='pending'
           AND ((m.kind='thread' AND m.event='turn_completed')
                OR (m.kind='subagent' AND m.event='completed'))
           AND (o.group_id IS NULL OR o.next_poll_ms<=?1)
         ORDER BY m.group_id,m.kind,m.repo,m.resource,m.event,m.outcome
         LIMIT ?2",
    )?;
    let rows = statement.query_map(params![now, CONDITION_BATCH_LIMIT + 1], |row| {
        Ok(ConditionMember {
            group_id: row.get(0)?,
            kind: row.get(1)?,
            repo: row.get(2)?,
            resource: row.get(3)?,
            event: row.get(4)?,
            outcome: row.get(5)?,
            armed: row.get::<_, i64>(6)? != 0,
            buffer_overflow: row.get::<_, i64>(7)? != 0,
            buffer_overflow_count: row.get(8)?,
            baseline_cursor: row.get(9)?,
            observer_exists: row.get::<_, bool>(10)?,
            baseline_turn_id: row.get(11)?,
            baseline_status: row.get(12)?,
            baseline_order_uncertain: row.get::<_, i64>(13)? != 0,
        })
    })?;
    let mut rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let has_more = rows.len() as i64 > CONDITION_BATCH_LIMIT;
    if has_more {
        rows.pop();
    }
    Ok((rows, has_more))
}

fn claim_condition_member(db: &Connection, member: &ConditionMember, now: i64) -> Result<bool> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let initial_turn = if member.armed && !member.observer_exists {
        member.baseline_cursor.as_deref()
    } else {
        None
    };
    let initial_status = initial_turn.map(|_| "completed");
    let changed = tx.execute(
        "INSERT INTO native_condition_observers
         (group_id,kind,repo,resource,event,outcome,baseline_turn_id,baseline_status,next_poll_ms)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(group_id,kind,repo,resource,event,outcome) DO UPDATE
            SET next_poll_ms=excluded.next_poll_ms
          WHERE native_condition_observers.next_poll_ms<=?10",
        params![
            member.group_id,
            member.kind,
            member.repo,
            member.resource,
            member.event,
            member.outcome,
            initial_turn,
            initial_status,
            now + CLAIM_MS,
            now
        ],
    )?;
    tx.commit()?;
    Ok(changed == 1)
}

fn condition_member_retry(db: &Connection, member: &ConditionMember, now: i64) -> Result<()> {
    db.execute(
        "UPDATE native_condition_observers SET next_poll_ms=?1
         WHERE group_id=?2 AND kind=?3 AND repo=?4 AND resource=?5 AND event=?6 AND outcome=?7",
        params![
            now + INTERVAL_MS,
            member.group_id,
            member.kind,
            member.repo,
            member.resource,
            member.event,
            member.outcome
        ],
    )?;
    Ok(())
}

fn condition_member_observed(
    db: &Connection,
    member: &ConditionMember,
    latest: Option<&Turn>,
    now: i64,
) -> Result<()> {
    db.execute(
        "UPDATE native_condition_observers
         SET baseline_turn_id=?1,
             baseline_status=CASE
                 WHEN baseline_turn_id=?1 AND baseline_status='completed' THEN 'completed'
                 ELSE ?2
             END,
             next_poll_ms=?3
         WHERE group_id=?4 AND kind=?5 AND repo=?6 AND resource=?7 AND event=?8 AND outcome=?9",
        params![
            latest.map(|turn| turn.id.as_str()),
            latest.map(|turn| turn.status.as_str()),
            now + INTERVAL_MS,
            member.group_id,
            member.kind,
            member.repo,
            member.resource,
            member.event,
            member.outcome
        ],
    )?;
    Ok(())
}

/// Read a bounded native history slice, oldest-first, ending at the captured
/// baseline when one exists. A missing baseline cursor is never silently
/// treated as a complete history if the page cap is reached.
fn turns_since_baseline(
    call: &mut Rpc,
    resource: &str,
    baseline_turn_id: Option<&str>,
) -> Result<(Option<Turn>, Vec<Turn>, bool)> {
    let (mut page, mut cursor) = turns_page(call, resource, None)?;
    let latest = page.first().cloned();
    let mut descending = Vec::new();
    let mut found = baseline_turn_id.is_none();
    let mut exhausted = cursor.is_none();
    for page_no in 0..MAX_PAGES {
        if baseline_turn_id.is_some_and(|baseline| page.iter().any(|turn| turn.id == baseline)) {
            found = true;
        }
        descending.append(&mut page);
        if (baseline_turn_id.is_some() && found) || exhausted {
            break;
        }
        let Some(next_cursor) = cursor.take() else {
            exhausted = true;
            break;
        };
        if page_no + 1 == MAX_PAGES {
            break;
        }
        (page, cursor) = turns_page(call, resource, Some(&next_cursor))?;
        exhausted = cursor.is_none();
    }
    if !found {
        anyhow::bail!("Native condition baseline cursor was not found within the page limit");
    }
    let baseline_missing_beyond_cap = baseline_turn_id.is_none() && !exhausted;
    if let Some(baseline) = baseline_turn_id {
        let index = descending
            .iter()
            .position(|turn| turn.id == baseline)
            .context("Native condition baseline cursor was not found")?;
        descending.truncate(index + 1);
    }
    descending.reverse();
    Ok((latest, descending, baseline_missing_beyond_cap))
}

fn native_condition_source(kind: &str, resource: &str, parent: Option<&str>, turn: &Turn) -> Value {
    if kind == "subagent" {
        json!({"session_id":parent,"agent_id":resource,"turnId":turn.id,"status":turn.status})
    } else {
        json!({"session_id":resource,"turnId":turn.id,"status":turn.status})
    }
}

fn tick_condition_members(db: &Connection, call: &mut Rpc) -> Result<Value> {
    crate::conditions::initialize(db)?;
    initialize(db)?;
    let now = now_ms();
    let (due, has_more) = condition_members_due(db, now)?;
    let mut report = json!({
        "due": due.len(),
        "armed": 0,
        "armed_with_order_uncertainty": 0,
        "baseline_order_uncertain_members": due.iter().filter(|member| member.baseline_order_uncertain).count(),
        "observed": 0,
        "ready_groups": 0,
        "payload_collisions": 0,
        "buffer_overflow_members": due.iter().filter(|member| member.buffer_overflow).count(),
        "buffer_overflow_events": due.iter().map(|member| member.buffer_overflow_count).sum::<i64>(),
        "errors": 0,
        "has_more": has_more,
        "batch_limit": CONDITION_BATCH_LIMIT
    });

    for member in due {
        if !claim_condition_member(db, &member, now_ms())? {
            continue;
        }
        let valid_resource =
            Uuid::parse_str(&member.resource).is_ok_and(|uuid| uuid.to_string() == member.resource);
        if !valid_resource {
            condition_member_retry(db, &member, now_ms())?;
            report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
            continue;
        }

        if !member.armed {
            let baseline = source_parent(call, &member.kind, &member.resource)
                .and_then(|_| first_turn(call, &member.resource));
            let baseline = match baseline {
                Ok(baseline) => baseline,
                Err(_) => {
                    condition_member_retry(db, &member, now_ms())?;
                    report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                    continue;
                }
            };
            if let Some(turn) = baseline.as_ref().filter(|turn| turn.status == "completed") {
                let ambiguous: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM condition_pending_events WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6 AND event_cursor=?7)",
                    params![member.group_id,member.kind,member.repo,member.resource,member.event,member.outcome,turn.id], |row| row.get(0),
                )?;
                if ambiguous {
                    db.execute("UPDATE native_condition_observers SET baseline_turn_id=?1,baseline_status='completed',baseline_order_uncertain=1,next_poll_ms=?2 WHERE group_id=?3 AND kind=?4 AND repo=?5 AND resource=?6 AND event=?7 AND outcome=?8", params![turn.id,now_ms()+INTERVAL_MS,member.group_id,member.kind,member.repo,member.resource,member.event,member.outcome])?;
                    report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                    continue;
                }
            }
            // Anchor the first observation at the latest turn so older history
            // cannot be replayed; an active baseline can still complete later.
            let baseline_cursor = baseline.as_ref().map(|turn| turn.id.as_str());
            let order_uncertain = baseline
                .as_ref()
                .is_some_and(|turn| turn.status == "completed");
            let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
            let armed = crate::conditions::arm_native_member_in(
                &tx,
                &member.group_id,
                &member.selector(),
                baseline_cursor,
            );
            match armed {
                Ok(true) => {
                    tx.execute(
                        "UPDATE native_condition_observers
                         SET baseline_turn_id=?1,baseline_status=?2,
                             baseline_order_uncertain=?3,next_poll_ms=?4
                         WHERE group_id=?5 AND kind=?6 AND repo=?7 AND resource=?8 AND event=?9 AND outcome=?10",
                        params![
                            baseline.as_ref().map(|turn| turn.id.as_str()),
                            baseline.as_ref().map(|turn| turn.status.as_str()),
                            i64::from(order_uncertain),
                            now_ms() + INTERVAL_MS,
                            member.group_id,
                            member.kind,
                            member.repo,
                            member.resource,
                            member.event,
                            member.outcome
                        ],
                    )?;
                    tx.commit()?;
                    let key = if order_uncertain {
                        "armed_with_order_uncertainty"
                    } else {
                        "armed"
                    };
                    report[key] = json!(report[key].as_u64().unwrap_or(0) + 1);
                }
                Ok(false) => {
                    tx.commit()?;
                    condition_member_retry(db, &member, now_ms())?;
                }
                Err(error) => {
                    drop(tx);
                    condition_member_retry(db, &member, now_ms())?;
                    return Err(error);
                }
            }
            continue;
        }

        let baseline_turn_id = if member.observer_exists {
            member.baseline_turn_id.clone()
        } else {
            member.baseline_cursor.clone()
        };
        let baseline_status = if member.observer_exists {
            member.baseline_status.clone()
        } else if baseline_turn_id.is_some() {
            Some("completed".to_owned())
        } else {
            None
        };
        let observed = (|| -> Result<_> {
            let parent = source_parent(call, &member.kind, &member.resource)?;
            let (latest, chronological, incomplete) =
                turns_since_baseline(call, &member.resource, baseline_turn_id.as_deref())?;
            let mut previous_id = baseline_turn_id.clone();
            let mut previous_status = baseline_status.clone();
            let mut completed = Vec::new();
            for turn in chronological {
                let same = previous_id.as_deref() == Some(turn.id.as_str());
                if turn.status == "completed"
                    && (!same || previous_status.as_deref() != Some("completed"))
                {
                    completed.push(turn.clone());
                }
                previous_id = Some(turn.id);
                previous_status = Some(turn.status);
            }
            Ok((parent, latest, completed, incomplete))
        })();
        let (parent, latest, completed, incomplete) = match observed {
            Ok(observed) => observed,
            Err(_) => {
                condition_member_retry(db, &member, now_ms())?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                continue;
            }
        };

        let mut collision_without_match = false;
        for turn in &completed {
            let source =
                native_condition_source(&member.kind, &member.resource, parent.as_deref(), turn);
            let outcome = if member.kind == "subagent" {
                "completed"
            } else {
                "turn_completed"
            };
            let selector = crate::conditions::Selector {
                kind: member.kind.clone(),
                repo: member.repo.clone(),
                resource: member.resource.clone(),
                event: outcome.into(),
                outcome: Some(outcome.into()),
            };
            let Some(source_event_key) = crate::subscriptions::source_event_identity(
                &member.kind,
                &member.repo,
                &member.resource,
                outcome,
                outcome,
                &source,
            )?
            else {
                condition_member_retry(db, &member, now_ms())?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                continue;
            };
            let record = crate::conditions::record_native_poll_event(
                db,
                &member.group_id,
                &crate::conditions::PublishedEvent {
                    selector,
                    source_event_key,
                    cursor: Some(turn.id.clone()),
                    ci: None,
                    source,
                },
            )?;
            report["observed"] = json!(report["observed"].as_u64().unwrap_or(0) + 1);
            report["ready_groups"] =
                json!(report["ready_groups"].as_u64().unwrap_or(0) + record.ready_groups as u64);
            if record.payload_collision {
                report["payload_collisions"] =
                    json!(report["payload_collisions"].as_u64().unwrap_or(0) + 1);
                collision_without_match |= record.new_members == 0;
            }
            if record.buffer_overflow {
                report["buffer_overflow_members"] =
                    json!(report["buffer_overflow_members"].as_u64().unwrap_or(0) + 1);
                report["buffer_overflow_events"] =
                    json!(report["buffer_overflow_events"].as_i64().unwrap_or(0) + 1);
            }
        }

        if collision_without_match {
            let matched: i64 = db.query_row(
                "SELECT matched FROM condition_members
                 WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6",
                params![member.group_id,member.kind,member.repo,member.resource,member.event,member.outcome],
                |row| row.get(0),
            )?;
            if matched == 0 {
                // Keep the saved baseline so an identity collision cannot
                // silently skip this turn; a later valid turn in this batch
                // may still have matched the member.
                condition_member_retry(db, &member, now_ms())?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                continue;
            }
        }

        if incomplete && completed.is_empty() {
            condition_member_retry(db, &member, now_ms())?;
            report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
        } else {
            condition_member_observed(db, &member, latest.as_ref(), now_ms())?;
        }
    }
    Ok(report)
}

/// Arm after inserting the subscription. RPC errors are retained as `unknown` state for retry.
pub fn arm(db: &Connection, id: &str, codex: &Path) -> Result<()> {
    arm_with(db, id, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

fn arm_with(db: &Connection, id: &str, call: &mut Rpc) -> Result<()> {
    initialize(db)?;
    let (kind, resource, thread) = registration(db, id)?;
    let now = now_ms();
    if !record_unknown(db, id, &resource, &thread, now)? {
        return Ok(());
    }
    match source_parent(call, &kind, &resource).and_then(|_| first_turn(call, &resource)) {
        Ok(turn) => {
            let reason = observation_reason(call, &resource, turn.as_ref());
            db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='baseline',reason=?5,updated_ms=?3 WHERE subscription_id=?4 AND state='unknown' AND reason='baseline_unavailable'", params![turn.as_ref().map(|t|t.id.as_str()),turn.as_ref().map(|t|t.status.as_str()),now+INTERVAL_MS,id,reason])?;
            crate::observability::emit(
                "native_poll.arm",
                "ok",
                reason.unwrap_or("baseline"),
                None,
                Duration::ZERO,
                1,
            );
        }
        Err(_) => {
            db.execute("UPDATE native_observers SET next_poll_ms=?1,state='unknown',reason='rpc_error',updated_ms=?1 WHERE subscription_id=?2 AND state='unknown' AND reason='baseline_unavailable'", params![now+INTERVAL_MS,id])?;
            crate::observability::emit(
                "native_poll.arm",
                "error",
                "rpc_error",
                None,
                Duration::ZERO,
                1,
            );
        }
    }
    Ok(())
}

/// Poll due observers. Uses only metadata; never starts/resumes turns or reads items.
pub fn tick(db: &Connection, codex: &Path) -> Result<Value> {
    tick_with(db, &mut |method, params| {
        crate::goals::rpc(codex, method, params)
    })
}

fn tick_with(db: &Connection, call: &mut Rpc) -> Result<Value> {
    initialize(db)?;
    let now = now_ms();
    let due = {
        let mut statement = db.prepare("SELECT s.id,s.resource,s.thread,o.baseline_turn_id,o.baseline_status,o.state,s.kind FROM subscriptions s LEFT JOIN native_observers o ON o.subscription_id=s.id WHERE ((s.kind='thread' AND s.event='turn_completed') OR (s.kind='subagent' AND s.event='completed')) AND s.state='waiting' AND (o.subscription_id IS NULL OR o.next_poll_ms<=?1) ORDER BY s.id")?;
        statement
            .query_map([now], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut report = json!({"due":due.len(),"baselined":0,"published":0,"unchanged":0,"errors":0});
    for (id, resource, thread, base_id, base_status, state, kind) in due {
        let valid = Uuid::parse_str(&resource).is_ok_and(|u| u.to_string() == resource)
            && Uuid::parse_str(&thread).is_ok_and(|u| u.to_string() == thread);
        if !valid {
            let stamp = now_ms();
            db.execute("INSERT INTO native_observers(subscription_id,resource,thread,next_poll_ms,state,reason,updated_ms) VALUES(?1,?2,?3,?4,'error','invalid_thread_uuid',?4) ON CONFLICT(subscription_id) DO UPDATE SET next_poll_ms=excluded.next_poll_ms,state='error',reason=excluded.reason,updated_ms=excluded.updated_ms",params![id,resource,thread,stamp+INTERVAL_MS])?;
            report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "error",
                "invalid_thread_uuid",
                None,
                Duration::ZERO,
                1,
            );
            continue;
        }
        let stamp = now_ms();
        let inserted = record_unknown(db, &id, &resource, &thread, stamp)?;
        if !inserted && db.execute("UPDATE native_observers SET next_poll_ms=?1 WHERE subscription_id=?2 AND next_poll_ms<=?3",params![stamp+CLAIM_MS,id,now])? == 0 { continue; }
        let first: Result<_> = (|| {
            Ok((
                source_parent(call, &kind, &resource)?,
                turns_page(call, &resource, None)?,
            ))
        })();
        let (parent, (latest_page, next)) = match first {
            Ok(page) => page,
            Err(_) => {
                db.execute("UPDATE native_observers SET next_poll_ms=?1,state=CASE WHEN state='unknown' THEN 'unknown' ELSE 'error' END,reason='rpc_error',updated_ms=?1 WHERE subscription_id=?2",params![stamp+INTERVAL_MS,id])?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                crate::observability::emit(
                    "native_poll.tick",
                    "error",
                    "rpc_error",
                    None,
                    Duration::ZERO,
                    1,
                );
                continue;
            }
        };
        let latest = latest_page.first().cloned();
        if state.as_deref() == Some("unknown") || (state.is_none() && base_id.is_none()) {
            let observed = latest.as_ref();
            let reason = observation_reason(call, &resource, observed);
            db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='baseline',reason=?5,updated_ms=?3 WHERE subscription_id=?4",params![observed.map(|t|t.id.as_str()),observed.map(|t|t.status.as_str()),stamp+INTERVAL_MS,id,reason])?;
            report["baselined"] = json!(report["baselined"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                reason.unwrap_or("baseline"),
                None,
                Duration::ZERO,
                1,
            );
            continue;
        }
        let chronological = if base_id.is_none() {
            latest_page.into_iter().rev().collect::<Vec<_>>()
        } else {
            let mut page = latest_page;
            let mut cursor = next;
            let mut found = false;
            let mut descending = Vec::new();
            for page_no in 0..MAX_PAGES {
                for turn in &page {
                    if turn.id == base_id.as_deref().unwrap_or_default() {
                        found = true;
                        break;
                    }
                }
                descending.extend(page);
                if found {
                    break;
                }
                let Some(next_cursor) = cursor else { break };
                if page_no + 1 == MAX_PAGES {
                    break;
                }
                match turns_page(call, &resource, Some(&next_cursor)) {
                    Ok((next_page, next_cursor)) => {
                        page = next_page;
                        cursor = next_cursor;
                    }
                    Err(_) => {
                        found = false;
                        break;
                    }
                }
            }
            if !found {
                db.execute("UPDATE native_observers SET next_poll_ms=?1,state='error',reason='baseline_cursor_not_found',updated_ms=?1 WHERE subscription_id=?2",params![stamp+INTERVAL_MS,id])?;
                report["errors"] = json!(report["errors"].as_u64().unwrap_or(0) + 1);
                crate::observability::emit(
                    "native_poll.tick",
                    "error",
                    "baseline_cursor_not_found",
                    None,
                    Duration::ZERO,
                    1,
                );
                continue;
            }
            if let Some(base) = descending
                .iter()
                .position(|turn| Some(turn.id.as_str()) == base_id.as_deref())
            {
                descending.truncate(base + 1);
            }
            descending.into_iter().rev().collect()
        };
        let previous_id = base_id.clone();
        let mut previous_status = base_status.clone();
        let mut event_turn = None;
        for turn in chronological {
            let same = previous_id.as_deref() == Some(turn.id.as_str());
            // Another controller can reconstruct an unloaded live turn as interrupted.
            if turn.status == "completed"
                && (!same || previous_status.as_deref() != Some("completed"))
            {
                event_turn = Some(turn.clone());
                break;
            }
            previous_status = Some(turn.status);
        }
        let reason = observation_reason(call, &resource, latest.as_ref());
        if let Some(turn) = event_turn {
            let source = if kind == "subagent" {
                json!({"session_id":parent.context("Native subagent parent missing")?,"agent_id":resource,"turnId":turn.id,"status":turn.status})
            } else {
                json!({"session_id":resource,"turnId":turn.id,"status":turn.status})
            };
            let count = crate::subscriptions::publish_observation(
                db,
                &id,
                if kind == "subagent" {
                    "completed"
                } else {
                    "turn_completed"
                },
                &source,
            )?;
            report["published"] = json!(report["published"].as_u64().unwrap_or(0) + count as u64);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                "published",
                None,
                Duration::ZERO,
                count as u64,
            );
        } else {
            report["unchanged"] = json!(report["unchanged"].as_u64().unwrap_or(0) + 1);
            crate::observability::emit(
                "native_poll.tick",
                "ok",
                reason.unwrap_or("unchanged"),
                None,
                Duration::ZERO,
                1,
            );
        }
        let last_status = if latest.as_ref().map(|t| t.id.as_str()) == base_id.as_deref()
            && base_status.as_deref() == Some("completed")
        {
            Some("completed")
        } else {
            latest.as_ref().map(|t| t.status.as_str())
        };
        let reason = if last_status == Some("completed") {
            None
        } else {
            reason
        };
        db.execute("UPDATE native_observers SET baseline_turn_id=?1,baseline_status=?2,next_poll_ms=?3,state='observed',reason=?5,updated_ms=?3 WHERE subscription_id=?4",params![latest.as_ref().map(|t|t.id.as_str()),last_status,stamp+INTERVAL_MS,id,reason])?;
    }
    report["conditions"] = tick_condition_members(db, call)?;
    Ok(report)
}

/// Resolve the ordering of a buffered native event after inspecting its evidence.
pub fn resolve_condition_order(
    db: &Connection,
    group_id: &str,
    resource: &str,
    accept: bool,
) -> Result<bool> {
    let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
    let mut statement = tx.prepare("SELECT kind,repo,event,outcome,baseline_turn_id,baseline_status FROM native_condition_observers WHERE group_id=?1 AND resource=?2 AND baseline_order_uncertain=1")?;
    let rows = statement
        .query_map(params![group_id, resource], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    anyhow::ensure!(
        rows.len() == 1,
        "Expected exactly one ambiguous native observer"
    );
    let (kind, repo, event, outcome, turn, baseline_status) = &rows[0];
    let selector = crate::conditions::Selector {
        kind: kind.clone(),
        repo: repo.clone(),
        resource: resource.to_owned(),
        event: event.clone(),
        outcome: (!outcome.is_empty()).then(|| outcome.clone()),
    };
    let accepted_event = if accept {
        anyhow::ensure!(
            baseline_status.as_deref() == Some("completed"),
            "Accepting a native event requires an observed completed turn"
        );
        let pending: Option<(String, String)> = tx
            .query_row(
                "SELECT source_event_key,source_json FROM condition_pending_events
             WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5
               AND outcome=?6 AND event_cursor=?7 LIMIT 1",
                params![group_id, kind, repo, resource, event, outcome, turn],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (source_event_key, source): (String, Value) = match pending {
            Some((key, source)) => (key, serde_json::from_str(&source)?),
            None => {
                anyhow::ensure!(
                    kind == "thread" && baseline_status.as_deref() == Some("completed"),
                    "Accepting a native baseline requires explicit completion evidence"
                );
                let turn = Turn {
                    id: turn.clone(),
                    status: "completed".into(),
                };
                let source = native_condition_source(kind, resource, None, &turn);
                let observed_outcome = if kind == "subagent" {
                    "completed"
                } else {
                    "turn_completed"
                };
                let key = crate::subscriptions::source_event_identity(
                    kind,
                    repo,
                    resource,
                    event,
                    observed_outcome,
                    &source,
                )?
                .context("Accepted native baseline has no stable event identity")?;
                (key, source)
            }
        };
        Some(crate::conditions::PublishedEvent {
            selector: selector.clone(),
            source_event_key,
            cursor: Some(turn.clone()),
            ci: None,
            source,
        })
    } else {
        None
    };
    let changed = crate::conditions::arm_native_member_in(&tx, group_id, &selector, Some(turn))?;
    if let Some(event) = accepted_event {
        let recorded = crate::conditions::record_native_accepted_event_in(&tx, group_id, &event)?;
        anyhow::ensure!(
            !recorded.payload_collision,
            "Accepted native event has conflicting payload"
        );
    }
    tx.execute("UPDATE native_condition_observers SET baseline_order_uncertain=0,next_poll_ms=?1 WHERE group_id=?2 AND resource=?3 AND kind=?4 AND repo=?5 AND event=?6 AND outcome=?7",params![now_ms()+INTERVAL_MS,group_id,resource,kind,repo,event,outcome])?;
    tx.commit()?;
    Ok(changed)
}

/// Read observer state only; never contacts the app-server or returns turn contents.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let mut statement=db.prepare("SELECT subscription_id,resource,thread,baseline_turn_id,baseline_status,state,reason,next_poll_ms,updated_ms FROM native_observers ORDER BY subscription_id")?;
    let mut rows=statement.query_map([],|r|Ok(json!({"subscription_id":r.get::<_,String>(0)?,"resource":r.get::<_,String>(1)?,"thread":r.get::<_,String>(2)?,"baseline_turn_id":r.get::<_,Option<String>>(3)?,"baseline_status":r.get::<_,Option<String>>(4)?,"state":r.get::<_,String>(5)?,"reason":r.get::<_,Option<String>>(6)?,"next_poll_ms":r.get::<_,i64>(7)?,"updated_ms":r.get::<_,i64>(8)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut statement = db.prepare(
        "SELECT group_id,kind,resource,event,baseline_status,baseline_order_uncertain,next_poll_ms
         FROM native_condition_observers ORDER BY group_id,kind,resource,event",
    )?;
    rows.extend(
        statement
            .query_map([], |row| {
                Ok(json!({
                    "observer_kind":"condition_member",
                    "group_id":row.get::<_,String>(0)?,
                    "kind":row.get::<_,String>(1)?,
                    "resource":row.get::<_,String>(2)?,
                    "event":row.get::<_,String>(3)?,
                    "baseline_status":row.get::<_,Option<String>>(4)?,
                    "baseline_order_uncertain":row.get::<_,i64>(5)? != 0,
                    "next_poll_ms":row.get::<_,i64>(6)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    );
    Ok(json!(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
    const TARGET: &str = "22222222-2222-4222-8222-222222222222";
    #[test]
    #[ignore = "requires an isolated real-Codex interruption proof in WAKE_PROOF_ROOT"]
    fn recorded_interruption_reads_real_codex_fixture() {
        let root = PathBuf::from(std::env::var_os("WAKE_PROOF_ROOT").expect("WAKE_PROOF_ROOT"));
        let receipt: Value =
            serde_json::from_slice(&fs::read(root.join("result.json")).unwrap()).unwrap();
        assert_eq!(receipt["persisted_abort"]["before"], 0);
        assert_eq!(receipt["persisted_abort"]["after"], 1);
        assert!(
            recorded_interruption(
                &root.join("codex/sessions"),
                Path::new(receipt["rollout_path"].as_str().unwrap()),
                receipt["started_thread"].as_str().unwrap(),
                receipt["started_turn"].as_str().unwrap(),
            )
            .unwrap()
        );
    }
    #[test]
    fn persisted_interruption_requires_a_complete_matching_record() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let path = sessions.join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl"));
        fs::write(&path, format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{SOURCE}\"}}}}\n{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"t1\"}}}}\n")).unwrap();
        assert!(!recorded_interruption(&sessions, &path, SOURCE, "t1").unwrap());
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, "{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"turn_aborted\",\"turn_id\":\"t1\",\"reason\":\"interrupted\"}}}}").unwrap();
        assert!(!recorded_interruption(&sessions, &path, SOURCE, "t1").unwrap());
        writeln!(file).unwrap();
        assert!(!recorded_interruption(&sessions, &path, SOURCE, "another-turn").unwrap());
        assert!(recorded_interruption(&sessions, &path, SOURCE, "t1").unwrap());
    }

    #[test]
    fn persisted_interruption_rejects_foreign_paths_and_links() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let foreign = dir
            .path()
            .join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl"));
        fs::write(&foreign, b"{}\n").unwrap();
        assert!(recorded_interruption(&sessions, &foreign, SOURCE, "t1").is_err());
        let foreign_directory = sessions.join("foreign");
        symlink(dir.path(), &foreign_directory).unwrap();
        assert!(
            recorded_interruption(
                &sessions,
                &foreign_directory.join(foreign.file_name().unwrap()),
                SOURCE,
                "t1"
            )
            .is_err()
        );
        let inside = sessions.join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl"));
        fs::write(&inside, b"{}\n").unwrap();
        assert!(recorded_interruption(&sessions, &inside, SOURCE, "t1").is_err());
        let alias = sessions.join(format!("alias-{SOURCE}.jsonl"));
        symlink(&inside, &alias).unwrap();
        assert!(recorded_interruption(&sessions, &alias, SOURCE, "t1").is_err());
        fs::remove_file(&alias).unwrap();
        fs::hard_link(&inside, &alias).unwrap();
        assert!(recorded_interruption(&sessions, &inside, SOURCE, "t1").is_err());
        fs::remove_file(&inside).unwrap();
        fs::remove_file(&alias).unwrap();
        let fifo = CString::new(inside.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(recorded_interruption(&sessions, &inside, SOURCE, "t1").is_err());
    }
    #[test]
    fn persisted_interruption_search_is_bounded_to_complete_tail_records() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        let path = sessions.join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl"));
        let mut file = fs::File::create(&path).unwrap();
        writeln!(
            file,
            "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{SOURCE}\"}}}}"
        )
        .unwrap();
        file.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        file.write_all(b"\n{\"type\":\"event_msg\",\"payload\":{\"type\":\"turn_aborted\",\"turn_id\":\"t1\",\"reason\":\"interrupted\"}}\n").unwrap();
        assert!(recorded_interruption(&sessions, &path, SOURCE, "t1").unwrap());
        file.write_all(&vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(!recorded_interruption(&sessions, &path, SOURCE, "t1").unwrap());
    }
    #[test]
    fn interruption_reason_uses_the_verified_thread_rollout() {
        if let Some(root) = std::env::var_os("WAKE_TEST_ROLLOUT_HOME") {
            let path = PathBuf::from(root)
                .join("sessions")
                .join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl"));
            let mut rpc = |method: &str, params: Value| -> Result<Value> {
                assert_eq!(params["threadId"], SOURCE);
                match method {
                    "thread/read" => Ok(json!({"thread":{"id":SOURCE,"path":path}})),
                    "thread/turns/list" => {
                        Ok(json!({"data":[turn("t1", "interrupted")],"nextCursor":null}))
                    }
                    _ => unreachable!(),
                }
            };
            assert_eq!(
                observation_reason(&mut rpc, SOURCE, Some(&turn("t1", "interrupted"))),
                Some("turn_aborted_recorded")
            );
            assert_eq!(
                observation_reason(&mut rpc, SOURCE, Some(&turn("t2", "interrupted"))),
                Some("interrupted_unconfirmed")
            );
            let db = db();
            let id = sub(&db);
            arm_with(&db, &id, &mut rpc).unwrap();
            assert_eq!(status(&db).unwrap()[0]["reason"], "turn_aborted_recorded");
            assert_eq!(
                crate::subscriptions::status(&db).unwrap()[0]["state"],
                "waiting"
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sessions = dir.path().join("sessions");
        fs::create_dir(&sessions).unwrap();
        fs::write(sessions.join(format!("rollout-2026-11-07T15-38-19-{SOURCE}.jsonl")), format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{SOURCE}\"}}}}\n{{\"type\":\"event_msg\",\"payload\":{{\"type\":\"turn_aborted\",\"turn_id\":\"t1\",\"reason\":\"interrupted\"}}}}\n")).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_poll::tests::interruption_reason_uses_the_verified_thread_rollout",
            ])
            .env("WAKE_TEST_ROLLOUT_HOME", dir.path())
            .env("CODEX_HOME", dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    #[test]
    fn slow_arming_cannot_overwrite_a_newer_poll_baseline() {
        let db = db();
        let id = sub(&db);
        arm_with(&db,&id,&mut |_,_| {
            db.execute("UPDATE native_observers SET baseline_turn_id='newer',baseline_status='completed',state='observed',reason=NULL",[])?;
            Ok(json!({"data":[{"id":"older","status":"inProgress"}],"nextCursor":null}))
        }).unwrap();
        let cursor: String = db
            .query_row(
                "SELECT baseline_turn_id FROM native_observers WHERE subscription_id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cursor, "newer");
    }
    #[test]
    fn subagent_poll_requires_verified_native_parent_and_child_identity() {
        let db = db();
        let id = crate::subscriptions::subscribe(&db, "subagent", "", SOURCE, "completed", TARGET)
            .unwrap();
        db.execute(
            "UPDATE subscriptions SET message_template='{{source.agent_id}}' WHERE id=?1",
            [&id],
        )
        .unwrap();
        let state = std::cell::Cell::new("inProgress");
        let mut rpc = |method: &str, params: Value| -> Result<Value> {
            assert_eq!(params["threadId"], SOURCE);
            Ok(if method == "thread/read" {
                assert_eq!(params["includeTurns"], false);
                json!({"thread":{"id":SOURCE,"source":{"subAgent":{"thread_spawn":{"parent_thread_id":TARGET,"depth":1}}}}})
            } else {
                assert_eq!(method, "thread/turns/list");
                json!({"data":[{"id":"child-turn","status":state.get()}],"nextCursor":null})
            })
        };
        arm_with(&db, &id, &mut rpc).unwrap();
        state.set("completed");
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        let source: Value = serde_json::from_str(&source).unwrap();
        assert_eq!(source["agent_id"], SOURCE);
        assert_eq!(source["session_id"], TARGET);
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 0);
    }

    #[test]
    fn ordinary_thread_cannot_impersonate_a_subagent() {
        let db = db();
        let id = crate::subscriptions::subscribe(&db, "subagent", "", SOURCE, "completed", TARGET)
            .unwrap();
        let mut rpc = |method: &str, _| -> Result<Value> {
            assert_eq!(method, "thread/read");
            Ok(json!({"thread":{"id":SOURCE,"source":"cli"}}))
        };
        arm_with(&db, &id, &mut rpc).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["errors"], 1);
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }
    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        db
    }
    fn sub(db: &Connection) -> String {
        let id =
            crate::subscriptions::subscribe(db, "thread", "", SOURCE, "turn_completed", TARGET)
                .unwrap();
        db.execute(
            "UPDATE subscriptions SET message_template='{{source.turnId}}' WHERE id=?1",
            [&id],
        )
        .unwrap();
        id
    }
    fn page(expected_thread: &str, turns: Vec<Turn>) -> impl FnMut(&str, Value) -> Result<Value> {
        let expected_thread = expected_thread.to_owned();
        move |method, params| {
            assert_eq!(params["threadId"], expected_thread);
            if method == "thread/read" {
                return Ok(json!({"thread":{"id":expected_thread,"path":null}}));
            }
            assert_eq!(method, "thread/turns/list");
            assert_eq!(params["itemsView"], "notLoaded");
            Ok(json!({"data":turns.clone(),"nextCursor":null}))
        }
    }
    fn three_pages() -> impl FnMut(&str, Value) -> Result<Value> {
        let mut page_no = 0;
        move |method, params| {
            assert_eq!(method, "thread/turns/list");
            assert_eq!(params["threadId"], SOURCE);
            assert_eq!(params["itemsView"], "notLoaded");
            let (data, cursor) = match page_no {
                0 => {
                    assert!(params["cursor"].is_null());
                    (
                        vec![turn("t3", "completed"), turn("t2", "completed")],
                        Some("c1"),
                    )
                }
                1 => {
                    assert_eq!(params["cursor"], "c1");
                    (
                        vec![turn("t1", "completed"), turn("base", "failed")],
                        Some("c2"),
                    )
                }
                2 => {
                    assert_eq!(params["cursor"], "c2");
                    (vec![turn("baseline", "inProgress")], None)
                }
                _ => panic!("unexpected turns page"),
            };
            page_no += 1;
            Ok(json!({"data":data,"nextCursor":cursor}))
        }
    }
    fn turn(id: &str, status: &str) -> Turn {
        Turn {
            id: id.into(),
            status: status.into(),
        }
    }

    #[test]
    fn active_baseline_completion_publishes_once_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("poll.sqlite");
        let id = {
            let db = Connection::open(&path).unwrap();
            crate::subscriptions::initialize(&db).unwrap();
            let id = sub(&db);
            arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
            id
        };
        let db = Connection::open(&path).unwrap();
        initialize(&db).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        let mut rpc = page(SOURCE, vec![turn("t1", "completed")]);
        assert_eq!(tick_with(&db, &mut rpc).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&source).unwrap(),
            json!({"session_id":SOURCE,"turnId":"t1","status":"completed"})
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "ready"
        );
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["due"],
            0
        );
    }

    #[test]
    fn independent_baselines_do_not_publish_to_later_registration() {
        let db = db();
        let early = sub(&db);
        arm_with(
            &db,
            &early,
            &mut page(SOURCE, vec![turn("t1", "inProgress")]),
        )
        .unwrap();
        let late = crate::subscriptions::subscribe(
            &db,
            "thread",
            "later-registration",
            SOURCE,
            "turn_completed",
            "33333333-3333-4333-8333-333333333333",
        )
        .unwrap();
        arm_with(&db, &late, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        let result = tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap();
        assert_eq!(result["published"], 1);
        for (id, expected) in [(&early, "ready"), (&late, "waiting")] {
            let state: String = db
                .query_row("SELECT state FROM subscriptions WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(state, expected);
        }
    }

    #[test]
    fn historical_completed_turn_is_only_a_baseline() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap();
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }

    #[test]
    fn completed_baseline_does_not_replay_after_reconstructed_interruption() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap();
        for observed in ["interrupted", "completed"] {
            db.execute("UPDATE native_observers SET next_poll_ms=0", [])
                .unwrap();
            assert_eq!(
                tick_with(&db, &mut page(SOURCE, vec![turn("old", observed)])).unwrap()["published"],
                0
            );
            assert_eq!(
                crate::subscriptions::status(&db).unwrap()[0]["state"],
                "waiting"
            );
            assert_eq!(status(&db).unwrap()[0]["baseline_status"], "completed");
        }
    }

    #[test]
    fn unarmed_first_poll_baselines_historical_completion() {
        let db = db();
        sub(&db);
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap()["baselined"],
            1
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "old");
    }

    #[test]
    fn three_pages_use_source_uuid_and_find_new_turns_without_timestamp_fields() {
        let db = db();
        let id = sub(&db);
        arm_with(
            &db,
            &id,
            &mut page(SOURCE, vec![turn("baseline", "inProgress")]),
        )
        .unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(tick_with(&db, &mut three_pages()).unwrap()["published"], 1);
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&source).unwrap(),
            json!({"session_id":SOURCE,"turnId":"t1","status":"completed"})
        );
    }

    #[test]
    fn arm_does_not_reset_existing_baseline_or_call_rpc_again() {
        let db = db();
        let id = sub(&db);
        arm_with(
            &db,
            &id,
            &mut page(SOURCE, vec![turn("active", "inProgress")]),
        )
        .unwrap();
        arm_with(&db, &id, &mut |_, _| {
            panic!("existing observer must not be re-armed")
        })
        .unwrap();
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "active");
    }

    fn register_native_condition(db: &Connection) -> String {
        crate::conditions::register_group(
            db,
            crate::conditions::Mode::Or,
            &[crate::conditions::Selector {
                kind: "thread".into(),
                repo: String::new(),
                resource: SOURCE.into(),
                event: "turn_completed".into(),
                outcome: Some("turn_completed".into()),
            }],
            TARGET,
            None,
            None,
        )
        .unwrap()
    }

    fn hook_event(turn_id: &str) -> crate::conditions::PublishedEvent {
        let source = json!({
            "hook_event_name":"Stop",
            "session_id":SOURCE,
            "turn_id":turn_id,
            "turnId":turn_id,
            "status":"completed"
        });
        let source_event_key = crate::subscriptions::source_event_identity(
            "thread",
            "",
            SOURCE,
            "turn_completed",
            "turn_completed",
            &source,
        )
        .unwrap()
        .unwrap();
        crate::conditions::PublishedEvent {
            selector: crate::conditions::Selector {
                kind: "thread".into(),
                repo: String::new(),
                resource: SOURCE.into(),
                event: "turn_completed".into(),
                outcome: Some("turn_completed".into()),
            },
            source_event_key,
            cursor: Some(turn_id.into()),
            ci: None,
            source,
        }
    }

    #[test]
    fn ambiguous_hook_and_baseline_are_not_dispatched() {
        let db = db();
        let group = register_native_condition(&db);
        let hook = hook_event("turn-new");
        let hook_key = hook.source_event_key.clone();
        let mut rpc = |method: &str, params: Value| -> Result<Value> {
            assert_eq!(method, "thread/turns/list");
            assert_eq!(params["threadId"], SOURCE);
            crate::conditions::record_published_event(&db, &hook)?;
            Ok(json!({
                "data":[{"id":"turn-new","status":"completed"}],
                "nextCursor":null
            }))
        };

        let report = tick_with(&db, &mut rpc).unwrap();
        assert_eq!(report["conditions"]["armed"], 0);
        assert_eq!(report["conditions"]["errors"], 1);
        assert_eq!(
            crate::conditions::matched_group_count_for_event(&db, &hook_key).unwrap(),
            0
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        assert_eq!(
            db.query_row(
                "SELECT baseline_order_uncertain FROM native_condition_observers WHERE group_id=?1",
                [&group],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(resolve_condition_order(&db, &group, SOURCE, true).unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
        assert_eq!(
            db.query_row(
                "SELECT baseline_order_uncertain FROM native_condition_observers WHERE group_id=?1",
                [&group],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn active_first_baseline_does_not_replay_older_completions() {
        let db = db();
        let group = register_native_condition(&db);
        let turns = vec![turn("active", "inProgress"), turn("old", "completed")];
        let first = tick_with(&db, &mut page(SOURCE, turns.clone())).unwrap();
        assert_eq!(first["conditions"]["armed"], 1);
        let baseline: (String, String) = db
            .query_row(
                "SELECT baseline_turn_id,baseline_status FROM native_condition_observers WHERE group_id=?1",
                [&group],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(baseline, ("active".into(), "inProgress".into()));

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        let next = tick_with(&db, &mut page(SOURCE, turns)).unwrap();
        assert_eq!(next["conditions"]["observed"], 0);
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn completed_condition_baseline_stays_completed_after_interruption() {
        let db = db();
        let group = register_native_condition(&db);
        tick_with(&db, &mut page(SOURCE, vec![turn("old", "completed")])).unwrap();
        resolve_condition_order(&db, &group, SOURCE, false).unwrap();

        for status in ["interrupted", "completed"] {
            db.execute(
                "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
                [&group],
            )
            .unwrap();
            let report = tick_with(&db, &mut page(SOURCE, vec![turn("old", status)])).unwrap();
            assert_eq!(report["conditions"]["observed"], 0);
            let baseline_status: String = db
                .query_row(
                    "SELECT baseline_status FROM native_condition_observers WHERE group_id=?1",
                    [&group],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(baseline_status, "completed");
        }
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn accepting_completed_baseline_matches_only_that_explicit_turn() {
        let db = db();
        let group = register_native_condition(&db);
        let turns = vec![turn("new", "completed"), turn("old", "completed")];
        tick_with(&db, &mut page(SOURCE, turns.clone())).unwrap();
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());

        resolve_condition_order(&db, &group, SOURCE, true).unwrap();
        let matched_cursor: String = db
            .query_row(
                "SELECT last_cursor FROM condition_members WHERE group_id=?1",
                [&group],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(matched_cursor, "new");

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        let report = tick_with(&db, &mut page(SOURCE, turns)).unwrap();
        assert_eq!(report["conditions"]["observed"], 0);
        let old_receipts: i64 = db
            .query_row(
                "SELECT count(*) FROM condition_publications WHERE event_cursor='old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_receipts, 0);
        let ready = crate::conditions::claim_ready(&db).unwrap().unwrap();
        assert_eq!(ready.group_id, group);
    }

    #[test]
    fn real_stop_then_poller_same_turn_has_no_collision_and_uses_poll_payload() {
        const BASELINE: &str = "baseline-turn";
        const TURN: &str = "completed-turn";

        let db = db();
        let group = register_native_condition(&db);
        tick_with(&db, &mut page(SOURCE, vec![turn(BASELINE, "inProgress")])).unwrap();

        // Match the real Stop path: publish the raw hook payload first, then
        // main adds turnId before recording the condition event.
        let raw_stop = json!({
            "hook_event_name":"Stop",
            "session_id":SOURCE,
            "turn_id":TURN,
            "cwd":"/home/codex"
        });
        let raw_event_key = crate::subscriptions::source_event_identity(
            "thread",
            "",
            SOURCE,
            "turn_completed",
            "turn_completed",
            &raw_stop,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            crate::subscriptions::publish_with_source(
                &db,
                "thread",
                "",
                SOURCE,
                "turn_completed",
                &raw_stop,
            )
            .unwrap(),
            0
        );
        let condition_receipts: i64 = db
            .query_row(
                "SELECT count(*) FROM condition_publications WHERE source_event_key=?1",
                [&raw_event_key],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(condition_receipts, 0);

        let mut hook_source = raw_stop;
        hook_source["turnId"] = json!(TURN);
        let source_event_key = crate::subscriptions::source_event_identity(
            "thread",
            "",
            SOURCE,
            "turn_completed",
            "turn_completed",
            &hook_source,
        )
        .unwrap()
        .unwrap();
        assert_eq!(source_event_key, raw_event_key);
        let hook_publication = crate::conditions::PublishedEvent {
            selector: crate::conditions::Selector {
                kind: "thread".into(),
                repo: String::new(),
                resource: SOURCE.into(),
                event: "turn_completed".into(),
                outcome: Some("turn_completed".into()),
            },
            source_event_key: source_event_key.clone(),
            cursor: Some(TURN.into()),
            ci: None,
            source: hook_source,
        };
        let hook_record =
            crate::conditions::record_published_event(&db, &hook_publication).unwrap();
        assert!(!hook_record.payload_collision);
        assert_eq!(hook_record.ready_groups, 0);
        assert_eq!(
            crate::conditions::matched_group_count_for_event(&db, &source_event_key).unwrap(),
            0
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        let report = tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![turn(TURN, "completed"), turn(BASELINE, "inProgress")],
            ),
        )
        .unwrap();
        assert_eq!(report["conditions"]["observed"], 1);
        assert_eq!(report["conditions"]["payload_collisions"], 0);
        assert_eq!(report["conditions"]["ready_groups"], 1);
        assert_eq!(
            crate::conditions::publication_collision_count(&db, &source_event_key).unwrap(),
            0
        );
        let digests: (String, Option<String>) = db
            .query_row(
                "SELECT source_digest,native_poll_digest FROM condition_publications
                 WHERE source_event_key=?1",
                [&source_event_key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(digests.1.is_some());
        assert_ne!(digests.0, digests.1.unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
        let source_json: String = db
            .query_row(
                "SELECT source_json FROM condition_members WHERE group_id=?1",
                [&group],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&source_json).unwrap(),
            native_condition_source("thread", SOURCE, None, &turn(TURN, "completed"))
        );
    }

    #[test]
    fn historical_ambiguous_hook_can_be_excluded_without_delivery() {
        let db = db();
        let group = register_native_condition(&db);
        let hook = hook_event("old-turn");
        let mut rpc = |_: &str, _: Value| -> Result<Value> {
            crate::conditions::record_published_event(&db, &hook)?;
            Ok(json!({"data":[{"id":"old-turn","status":"completed"}],"nextCursor":null}))
        };
        tick_with(&db, &mut rpc).unwrap();
        assert!(resolve_condition_order(&db, &group, SOURCE, false).unwrap());
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn publication_before_group_registration_is_not_replayed_by_baseline_polling() {
        let db = db();
        let old = hook_event("turn-old");
        let old_key = old.source_event_key.clone();
        crate::conditions::record_published_event(&db, &old).unwrap();
        let group = register_native_condition(&db);
        // A delivery retry after registration reuses the receipt and is not
        // buffered for the newly registered member.
        crate::conditions::record_published_event(&db, &old).unwrap();

        let baseline =
            tick_with(&db, &mut page(SOURCE, vec![turn("turn-old", "completed")])).unwrap();
        assert_eq!(baseline["conditions"]["armed_with_order_uncertainty"], 1);
        db.execute("UPDATE native_condition_observers SET next_poll_ms=0", [])
            .unwrap();
        let next = tick_with(&db, &mut page(SOURCE, vec![turn("turn-old", "completed")])).unwrap();
        assert_eq!(next["conditions"]["observed"], 0);
        assert_eq!(
            crate::conditions::matched_group_count_for_event(&db, &old_key).unwrap(),
            0
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let state: String = db
            .query_row(
                "SELECT state FROM condition_groups WHERE id=?1",
                [&group],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "pending");
    }

    #[test]
    fn member_order_rejects_t1_and_t2_but_keeps_t3_after_peer_receipt() {
        let db = db();
        let earlier = register_native_condition(&db);
        tick_with(&db, &mut page(SOURCE, vec![turn("T1", "inProgress")])).unwrap();

        let later = register_native_condition(&db);
        tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![turn("T2", "completed"), turn("T1", "completed")],
            ),
        )
        .unwrap();

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&earlier],
        )
        .unwrap();
        let earlier_report = tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![
                    turn("T3", "completed"),
                    turn("T2", "completed"),
                    turn("T1", "completed"),
                ],
            ),
        )
        .unwrap();
        assert_eq!(earlier_report["conditions"]["observed"], 3);
        let baselines: (Option<String>, Option<String>) = db
            .query_row(
                "SELECT m.baseline_cursor,o.baseline_turn_id
                 FROM condition_members m JOIN native_condition_observers o USING(group_id)
                 WHERE m.group_id=?1",
                [&later],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(baselines, (Some("T2".into()), Some("T2".into())));
        assert_eq!(
            crate::conditions::delivery_status(&db, &later)
                .unwrap()
                .state,
            "pending"
        );
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            earlier
        );

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&later],
        )
        .unwrap();
        let later_report = tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![
                    turn("T3", "completed"),
                    turn("T2", "completed"),
                    turn("T1", "completed"),
                ],
            ),
        )
        .unwrap();
        assert_eq!(later_report["conditions"]["observed"], 1);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            later
        );
    }

    #[test]
    fn delayed_stop_for_pre_baseline_turn_cannot_match_but_next_turn_survives_peer_receipt() {
        // These UUIDs deliberately sort opposite to the source chronology:
        // T1 > T2 > T3 lexically, while the poller reports T1, T2, then T3.
        const T1: &str = "f0000000-0000-4000-8000-000000000001";
        const T2: &str = "10000000-0000-4000-8000-000000000002";
        const T3: &str = "08000000-0000-4000-8000-000000000003";

        let db = db();
        let later = register_native_condition(&db);
        let peer = register_native_condition(&db);
        tick_with(
            &db,
            &mut page(SOURCE, vec![turn(T2, "completed"), turn(T1, "completed")]),
        )
        .unwrap();
        for group in [&later, &peer] {
            let baseline: String = db
                .query_row(
                    "SELECT baseline_turn_id FROM native_condition_observers WHERE group_id=?1",
                    [group],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(baseline, T2);
        }

        // The Stop hook is delayed until after T2 was captured. Its global
        // publication receipt is not evidence that T1 follows this baseline.
        let delayed_stop = hook_event(T1);
        assert_eq!(
            crate::subscriptions::publish_with_source(
                &db,
                "thread",
                "",
                SOURCE,
                "turn_completed",
                &delayed_stop.source,
            )
            .unwrap(),
            0
        );
        crate::conditions::record_published_event(&db, &delayed_stop).unwrap();
        assert_eq!(
            crate::conditions::matched_group_count_for_event(&db, &delayed_stop.source_event_key)
                .unwrap(),
            0
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());

        // A different observer records T3 first. The later group's own poller
        // must accept it by list order even though its UUID sorts before T2.
        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&peer],
        )
        .unwrap();
        let peer_report = tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![
                    turn(T3, "completed"),
                    turn(T2, "completed"),
                    turn(T1, "completed"),
                ],
            ),
        )
        .unwrap();
        assert_eq!(peer_report["conditions"]["observed"], 1);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            peer
        );

        db.execute(
            "UPDATE native_condition_observers SET next_poll_ms=0 WHERE group_id=?1",
            [&later],
        )
        .unwrap();
        let later_report = tick_with(
            &db,
            &mut page(
                SOURCE,
                vec![
                    turn(T3, "completed"),
                    turn(T2, "completed"),
                    turn(T1, "completed"),
                ],
            ),
        )
        .unwrap();
        assert_eq!(later_report["conditions"]["observed"], 1);
        assert_eq!(
            crate::conditions::matched_group_count_for_event(&db, &delayed_stop.source_event_key)
                .unwrap(),
            0
        );
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            later
        );
    }

    #[test]
    fn stop_and_native_completion_claim_once_in_either_order() {
        for hook_first in [true, false] {
            let db = db();
            let id = sub(&db);
            db.execute(
                "UPDATE subscriptions SET message_template=NULL WHERE id=?1",
                [&id],
            )
            .unwrap();
            arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
            db.execute(
                "UPDATE native_observers SET next_poll_ms=0 WHERE subscription_id=?1",
                [&id],
            )
            .unwrap();
            let hook = || {
                crate::subscriptions::publish_with_source(
                    &db,
                    "thread",
                    "",
                    SOURCE,
                    "turn_completed",
                    &json!({"session_id":SOURCE,"turn_id":"t1"}),
                )
                .unwrap()
            };
            let poll = || {
                tick_with(&db,&mut page(SOURCE,vec![turn("t1","completed")])).unwrap()["published"].as_u64().unwrap() as usize
            };
            let (first, second) = if hook_first {
                (hook(), poll())
            } else {
                (poll(), hook())
            };
            assert_eq!((first, second), (1, 0));
            let rows = crate::subscriptions::status(&db).unwrap();
            assert_eq!(rows.as_array().unwrap().len(), 1);
            assert_eq!(rows[0]["state"], "ready");
        }
    }

    #[test]
    fn stop_and_native_completion_race_claim_one_subscription() {
        use std::sync::{Arc, Barrier};
        let temp = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("state.sqlite3");
        let db = crate::bridge::connect(&path).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        let id = sub(&db);
        db.execute(
            "UPDATE subscriptions SET message_template=NULL WHERE id=?1",
            [&id],
        )
        .unwrap();
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute(
            "UPDATE native_observers SET next_poll_ms=0 WHERE subscription_id=?1",
            [&id],
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let hook_path = path.clone();
        let hook_barrier = barrier.clone();
        let hook = std::thread::spawn(move || {
            let db = crate::bridge::connect(&hook_path).unwrap();
            hook_barrier.wait();
            crate::subscriptions::publish_with_source(
                &db,
                "thread",
                "",
                SOURCE,
                "turn_completed",
                &json!({"session_id":SOURCE,"turn_id":"t1"}),
            )
            .unwrap()
        });
        let poll_path = path.clone();
        let poll = std::thread::spawn(move || {
            let db = crate::bridge::connect(&poll_path).unwrap();
            barrier.wait();
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"]
                .as_u64()
                .unwrap() as usize
        });
        assert_eq!(hook.join().unwrap() + poll.join().unwrap(), 1);
        let row = crate::subscriptions::status(&db).unwrap();
        assert_eq!(row.as_array().unwrap().len(), 1);
        assert_eq!(row[0]["state"], "ready");
    }

    #[test]
    fn unloaded_interrupted_baseline_can_later_complete() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "interrupted")])).unwrap();
        assert_eq!(
            status(&db).unwrap()[0]["reason"],
            "interruption_evidence_unavailable"
        );
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "interrupted")])).unwrap()["published"],
            0
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
        assert_eq!(
            status(&db).unwrap()[0]["reason"],
            "interruption_evidence_unavailable"
        );
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"],
            1
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "ready"
        );
        assert!(status(&db).unwrap()[0]["reason"].is_null());
    }

    #[test]
    fn interrupted_poll_remains_uncertain_and_can_recover() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "interrupted")])).unwrap()["published"],
            0
        );
        assert_eq!(
            status(&db).unwrap()[0]["reason"],
            "interruption_evidence_unavailable"
        );
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"],
            1
        );
        assert!(status(&db).unwrap()[0]["reason"].is_null());
    }

    #[test]
    fn failed_turn_does_not_publish() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        tick_with(&db, &mut page(SOURCE, vec![turn("t1", "failed")])).unwrap();
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }

    #[test]
    fn rpc_error_preserves_active_cursor_for_later_completion() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut page(SOURCE, vec![turn("t1", "inProgress")])).unwrap();
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut |_, _| anyhow::bail!("offline")).unwrap()["errors"],
            1
        );
        assert_eq!(status(&db).unwrap()[0]["baseline_turn_id"], "t1");
        assert_eq!(status(&db).unwrap()[0]["state"], "error");
        db.execute("UPDATE native_observers SET next_poll_ms=0", [])
            .unwrap();
        assert_eq!(
            tick_with(&db, &mut page(SOURCE, vec![turn("t1", "completed")])).unwrap()["published"],
            1
        );
    }

    #[test]
    fn rpc_failure_keeps_waiting_subscription_observable_unknown() {
        let db = db();
        let id = sub(&db);
        arm_with(&db, &id, &mut |_, _| anyhow::bail!("offline")).unwrap();
        assert_eq!(status(&db).unwrap()[0]["state"], "unknown");
        assert_eq!(status(&db).unwrap()[0]["reason"], "rpc_error");
        assert_eq!(
            crate::subscriptions::status(&db).unwrap()[0]["state"],
            "waiting"
        );
    }
}
