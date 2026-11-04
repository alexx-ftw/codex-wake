//! Bounded GitHub REST polling for explicitly registered waits and listeners.
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PAGE_LIMIT: usize = 10;
const MAX_OUTPUT: usize = 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);
const INTERVAL_MS: i64 = 60_000;
const MAX_BACKOFF_MS: i64 = 3_600_000;

pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS github_poll_state (
        endpoint TEXT NOT NULL, page INTEGER NOT NULL, etag TEXT, body TEXT,
        cursor TEXT, has_next INTEGER NOT NULL DEFAULT 0,
        next_poll_ms INTEGER NOT NULL DEFAULT 0, backoff_ms INTEGER NOT NULL DEFAULT 60000,
        last_success_ms INTEGER, error_category TEXT, calls INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(endpoint,page));",
    )?;
    Ok(())
}

/// Poll only resources with waiting registrations. `gh` is the configured executable path.
pub fn tick(db: &Connection, gh: &Path) -> Result<Value> {
    tick_with(db, now_ms(), |route, etag| github_fetch(gh, route, etag))
}

fn tick_with<F>(db: &Connection, now: i64, mut fetch: F) -> Result<Value>
where
    F: FnMut(&str, Option<&str>) -> std::result::Result<HttpResponse, Failure>,
{
    initialize(db)?;
    let targets = targets(db)?;
    let mut report = Report::default();
    db.execute("UPDATE github_poll_state SET error_category=NULL WHERE endpoint='__global__' AND next_poll_ms<=?1",[now])?;

    for wait in &targets.waits {
        let route = format!(
            "/repos/{}/actions/runs/{}/attempts/{}",
            wait.repo, wait.run, wait.attempt
        );
        let outcome = poll_endpoint(db, &route, 0, now, &mut fetch, |db, _, items, _| {
            let Some(run) = items.first() else {
                return Err(Failure::new("invalid_response"));
            };
            if run["status"] == "completed" {
                if !(run["id"].as_i64() == Some(wait.run)
                    && run["run_attempt"].as_i64() == Some(wait.attempt)
                    && run["head_sha"].as_str() == Some(wait.sha.as_str()))
                {
                    return Err(Failure::new("identity_mismatch"));
                }
                let event = json!({"action":"completed","workflow_run":run,
                    "repository":{"full_name":wait.repo}});
                return Ok((None, u64::from(bridge_accept(db, &event)? == "recorded")));
            }
            Ok((None, 0))
        })?;
        report.record(outcome);
    }

    let mut validated_prs = BTreeSet::new();
    for resource in &targets.pull_requests {
        let number: i64 = resource.resource.parse().unwrap_or(0);
        let route = format!("/repos/{}/pulls/{}", resource.repo, resource.resource);
        let validated = &mut validated_prs;
        let outcome = poll_endpoint(db, &route, 0, now, &mut fetch, |db, cursor, items, _| {
            let pr = items
                .first()
                .ok_or_else(|| Failure::new("invalid_response"))?;
            if !valid_pr(pr, number) {
                return Err(Failure::new("invalid_response"));
            }
            validated.insert(resource.clone());
            let head = pr
                .pointer("/head/sha")
                .and_then(Value::as_str)
                .ok_or_else(|| Failure::new("invalid_response"))?;
            let base = pr
                .pointer("/base/ref")
                .and_then(Value::as_str)
                .ok_or_else(|| Failure::new("invalid_response"))?;
            let old: Value = cursor
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or(Value::Null);
            let full = |action: &str, changes: Value| {
                json!({"action":action,"number":number,
                "pull_request":pr,"repository":{"full_name":resource.repo},"changes":changes})
            };
            let mut accepted = 0u64;
            if pr["state"] == "closed" {
                if pr["merged"].as_bool().is_none() {
                    return Err(Failure::new("invalid_response"));
                }
                let event_time = if pr["merged"] == true {
                    pr["merged_at"].as_str()
                } else {
                    pr["closed_at"].as_str()
                };
                let event_time = event_time.ok_or_else(|| Failure::new("invalid_response"))?;
                let mut closed_pr = pr.clone();
                closed_pr["updated_at"] = json!(event_time);
                let event = json!({"action":"closed","number":number,"pull_request":closed_pr,
                    "repository":{"full_name":resource.repo}});
                accepted += scoped_subscription_accept(
                    db,
                    "pull_request",
                    &event,
                    &resource.repo,
                    &resource.resource,
                    None,
                )? as u64;
            } else if !old.is_null() {
                let changed_at = pr["updated_at"].as_str();
                if old["head"].as_str().is_some_and(|v| v != head) {
                    accepted += scoped_subscription_accept(
                        db,
                        "pull_request",
                        &full("synchronize", Value::Null),
                        &resource.repo,
                        &resource.resource,
                        changed_at,
                    )? as u64;
                }
                if old["base"].as_str().is_some_and(|v| v != base) {
                    accepted += scoped_subscription_accept(
                        db,
                        "pull_request",
                        &full("edited", json!({"base":{"ref":old["base"]}})),
                        &resource.repo,
                        &resource.resource,
                        changed_at,
                    )? as u64;
                }
            }
            Ok((
                Some(json!({"head":head,"base":base,"updated_at":pr["updated_at"]}).to_string()),
                accepted,
            ))
        })?;
        if outcome.error.is_none() && outcome.skipped && cached_pr_is_valid(db, &route, number)? {
            validated_prs.insert(resource.clone());
        }
        report.record(outcome);
    }

    for resource in &targets.reviews {
        let number = &resource.resource;
        let route = format!("/repos/{}/pulls/{number}/reviews", resource.repo);
        let repo = resource.repo.clone();
        let outcome = poll_endpoint(
            db,
            &route,
            PAGE_LIMIT,
            now,
            &mut fetch,
            move |db, cursor, items, _| {
                let previous: BTreeMap<String, String> = decode_cursor(cursor)?;
                let mut seen = previous;
                let mut matched = 0u64;
                for review in &items {
                    let id = positive_id(&review["id"])
                        .ok_or_else(|| Failure::new("invalid_response"))?;
                    let Some(submitted) = review["submitted_at"].as_str() else {
                        continue;
                    };
                    let state = review["state"]
                        .as_str()
                        .ok_or_else(|| Failure::new("invalid_response"))?;
                    let version = format!("{submitted}|{state}");
                    if seen.get(&id) == Some(&version) {
                        continue;
                    }
                    seen.insert(id, version);
                    let normalized = match state {
                        "APPROVED" => "approved",
                        "CHANGES_REQUESTED" => "changes_requested",
                        "COMMENTED" => "commented",
                        _ => state,
                    };
                    let mut review = review.clone();
                    review["state"] = json!(normalized);
                    let event = json!({"action":"submitted","pull_request":{"number":number.parse::<i64>().unwrap_or(0)},
                    "review":review,"repository":{"full_name":repo}});
                    // REST uses uppercase states; the acceptor consumes webhook enums.
                    matched += scoped_subscription_accept(
                        db,
                        "pull_request_review",
                        &event,
                        &repo,
                        number,
                        Some(submitted),
                    )? as u64;
                }
                Ok((
                    Some(
                        serde_json::to_string(&seen)
                            .map_err(|_| Failure::new("invalid_response"))?,
                    ),
                    matched,
                ))
            },
        )?;
        report.record(outcome);
    }

    for resource in &targets.deployments {
        let route = format!(
            "/repos/{}/deployments/{}/statuses",
            resource.repo, resource.resource
        );
        let outcome = poll_endpoint(db, &route, 100, now, &mut fetch, |db, _, items, _| {
            let mut accepted = 0;
            if let Some(status) = items
                .iter()
                .max_by_key(|item| item["created_at"].as_str().unwrap_or(""))
                && matches!(
                    status["state"].as_str(),
                    Some("success" | "failure" | "error")
                )
            {
                let event = json!({"deployment":{"id":resource.resource.parse::<i64>().unwrap_or(0)},
                    "deployment_status":status,"repository":{"full_name":resource.repo}});
                accepted += subscriptions_accept(db, "deployment_status", &event)? as u64;
            }
            Ok((None, accepted))
        })?;
        report.record(outcome);
    }

    for resource in &targets.refs {
        let branch = escape_ref(&resource.resource);
        let route = format!("/repos/{}/git/ref/heads/{branch}", resource.repo);
        let repo = resource.repo.clone();
        let name = resource.resource.clone();
        let outcome = poll_endpoint(
            db,
            &route,
            0,
            now,
            &mut fetch,
            move |db, cursor, items, _| {
                let ref_item = items
                    .first()
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                let sha = ref_item
                    .pointer("/object/sha")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                if !valid_sha(sha)
                    || ref_item["ref"].as_str() != Some(format!("refs/heads/{name}").as_str())
                {
                    return Err(Failure::new("identity_mismatch"));
                }
                if cursor.is_some_and(|old| old != sha) {
                    let event = json!({"ref":format!("refs/heads/{name}"),"deleted":false,
                    "after":sha,"repository":{"full_name":repo}});
                    let matched =
                        scoped_subscription_accept(db, "push", &event, &repo, &name, None)? as u64;
                    return Ok((Some(sha.to_owned()), matched));
                }
                Ok((Some(sha.to_owned()), 0))
            },
        )?;
        report.record(outcome);
    }

    for resource in &targets.rule_prs {
        if !validated_prs.contains(resource) {
            report.skipped += 2;
            continue;
        }
        for (endpoint, header) in [
            ("issue", "issue_comment"),
            ("review", "pull_request_review_comment"),
        ] {
            let route = if endpoint == "issue" {
                format!(
                    "/repos/{}/issues/{}/comments",
                    resource.repo, resource.resource
                )
            } else {
                format!(
                    "/repos/{}/pulls/{}/comments",
                    resource.repo, resource.resource
                )
            };
            let repo = resource.repo.clone();
            let pr = resource.resource.clone();
            let outcome = poll_endpoint(
                db,
                &route,
                PAGE_LIMIT,
                now,
                &mut fetch,
                move |db, cursor, items, _| {
                    let previous: BTreeMap<String, String> = decode_cursor(cursor)?;
                    let mut seen = previous;
                    let mut matched = 0u64;
                    for comment in &items {
                        let id = positive_id(&comment["id"])
                            .ok_or_else(|| Failure::new("invalid_response"))?;
                        let created = comment["created_at"]
                            .as_str()
                            .ok_or_else(|| Failure::new("invalid_response"))?;
                        let updated = comment["updated_at"].as_str().unwrap_or(created);
                        let action = if let Some(old) = seen.get(&id) {
                            (old != updated).then_some("edited")
                        } else {
                            Some("created")
                        };
                        seen.insert(id, updated.to_owned());
                        if let Some(action) = action {
                            matched +=
                                accept_comment(db, header, &repo, &pr, comment, action)? as u64;
                            if action == "created" && timestamp_gt(db, updated, created)? {
                                matched +=
                                    accept_comment(db, header, &repo, &pr, comment, "edited")?
                                        as u64;
                            }
                        }
                    }
                    Ok((
                        Some(
                            serde_json::to_string(&seen)
                                .map_err(|_| Failure::new("invalid_response"))?,
                        ),
                        matched,
                    ))
                },
            )?;
            report.record(outcome);
        }
    }
    crate::observability::emit(
        "poll.tick",
        if report.errors.is_empty() {
            "ok"
        } else {
            "partial"
        },
        "",
        None,
        Duration::ZERO,
        report.calls,
    );
    Ok(report.json(
        targets.waits.len(),
        targets.pull_requests.len()
            + targets.reviews.len()
            + targets.deployments.len()
            + targets.refs.len()
            + targets.rule_prs.len(),
    ))
}

/// SQL-only aggregate status. Cached response bodies and ETags are never returned.
pub fn status(db: &Connection) -> Result<Value> {
    initialize(db)?;
    let count = |table: &str, query: &str| -> Result<i64> {
        if db
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |_| Ok(()),
            )
            .optional()?
            .is_none()
        {
            return Ok(0);
        }
        Ok(db.query_row(query, [], |row| row.get(0))?)
    };
    let waits = count("waits", "SELECT count(*) FROM waits WHERE state='waiting'")?;
    let subscriptions = count(
        "subscriptions",
        "SELECT count(*) FROM subscriptions WHERE state='waiting' AND kind IN ('pull_request','review','deployment','git_ref')",
    )?;
    let rules = count("rules", "SELECT count(*) FROM rules WHERE enabled=1")?;
    let (last_success, next_poll, calls): (Option<i64>, Option<i64>, i64) = db.query_row(
        "SELECT max(last_success_ms),min(next_poll_ms),coalesce(sum(calls),0) FROM github_poll_state", [],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let mut statement = db.prepare("SELECT error_category,count(*) FROM github_poll_state WHERE error_category IS NOT NULL GROUP BY error_category")?;
    let errors = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    let pages: i64 = db.query_row(
        "SELECT count(*) FROM github_poll_state WHERE body IS NOT NULL",
        [],
        |r| r.get(0),
    )?;
    Ok(
        json!({"active":{"waits":waits,"subscriptions":subscriptions,"rules":rules},
        "last_success_ms":last_success,"errors":errors,"next_poll_ms":next_poll,
        "calls":calls,"cached_pages":pages}),
    )
}

#[derive(Clone, Debug)]
struct Failure {
    category: &'static str,
    retry_at: Option<i64>,
}
impl Failure {
    fn new(category: &'static str) -> Self {
        Self {
            category,
            retry_at: None,
        }
    }
}
#[derive(Default)]
struct Report {
    calls: u64,
    accepted: u64,
    errors: BTreeMap<String, u64>,
    skipped: u64,
    pages: u64,
}
struct EndpointOutcome {
    error: Option<&'static str>,
    calls: u64,
    pages: u64,
    accepted: u64,
    skipped: bool,
}
impl Report {
    fn record(&mut self, outcome: EndpointOutcome) {
        self.calls += outcome.calls;
        self.pages += outcome.pages;
        self.accepted += outcome.accepted;
        self.skipped += u64::from(outcome.skipped);
        if let Some(e) = outcome.error {
            *self.errors.entry(e.into()).or_default() += 1;
        }
    }
    fn json(&self, waits: usize, resources: usize) -> Value {
        json!({"calls":self.calls,"accepted":self.accepted,
        "errors":self.errors,"skipped":self.skipped,"pages":self.pages,"active_waits":waits,"active_resources":resources})
    }
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Resource {
    repo: String,
    resource: String,
}
struct Wait {
    repo: String,
    run: i64,
    attempt: i64,
    sha: String,
}
#[derive(Default)]
struct Targets {
    waits: Vec<Wait>,
    pull_requests: BTreeSet<Resource>,
    reviews: BTreeSet<Resource>,
    deployments: BTreeSet<Resource>,
    refs: BTreeSet<Resource>,
    rule_prs: BTreeSet<Resource>,
}

fn targets(db: &Connection) -> Result<Targets> {
    let mut out = Targets::default();
    {
        let mut s =
            db.prepare("SELECT repo,run_id,attempt,sha FROM waits WHERE state='waiting'")?;
        for row in s.query_map([], |r| {
            Ok(Wait {
                repo: r.get(0)?,
                run: r.get(1)?,
                attempt: r.get(2)?,
                sha: r.get(3)?,
            })
        })? {
            let w = row?;
            if valid_repo(&w.repo) && w.run > 0 && w.attempt > 0 && valid_sha(&w.sha) {
                out.waits.push(w);
            }
        }
    }
    {
        let mut s=db.prepare("SELECT kind,repo,resource FROM subscriptions WHERE state='waiting' AND kind IN ('pull_request','review','deployment','git_ref')")?;
        for row in s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (kind, repo, resource) = row?;
            if !valid_repo(&repo) {
                continue;
            }
            let r = Resource { repo, resource };
            match kind.as_str() {
                "pull_request" => {
                    if positive_text(&r.resource) {
                        out.pull_requests.insert(r);
                    }
                }
                "review" => {
                    if positive_text(&r.resource) {
                        out.reviews.insert(r);
                    }
                }
                "deployment" => {
                    if positive_text(&r.resource) {
                        out.deployments.insert(r);
                    }
                }
                "git_ref" if valid_branch(&r.resource) => {
                    out.refs.insert(r);
                }
                _ => {}
            }
        }
    }
    {
        let mut s = db.prepare("SELECT input FROM rules WHERE enabled=1")?;
        for raw in s.query_map([], |r| r.get::<_, String>(0))? {
            if let Ok(value) = serde_json::from_str::<Value>(&raw?) {
                let repo = value["repo"].as_str().unwrap_or_default();
                let pr = value["pr"].as_i64().unwrap_or(0);
                if valid_repo(repo) && pr > 0 {
                    let target = Resource {
                        repo: repo.to_owned(),
                        resource: pr.to_string(),
                    };
                    out.pull_requests.insert(target.clone());
                    out.rule_prs.insert(target);
                }
            }
        }
    }
    Ok(out)
}

fn poll_endpoint<F, H>(
    db: &Connection,
    route: &str,
    page_size: usize,
    now: i64,
    fetch: &mut F,
    process: H,
) -> Result<EndpointOutcome>
where
    F: FnMut(&str, Option<&str>) -> std::result::Result<HttpResponse, Failure>,
    H: FnOnce(
        &Connection,
        Option<&str>,
        Vec<Value>,
        i64,
    ) -> std::result::Result<(Option<String>, u64), Failure>,
{
    initialize(db)?;
    let first = if page_size == 0 { 0 } else { 1 };
    if state(db, "__global__", 0)?.is_some_and(|s| s.next_poll > now) {
        return Ok(EndpointOutcome {
            error: None,
            calls: 0,
            pages: 0,
            accepted: 0,
            skipped: true,
        });
    }
    let root = state(db, route, first)?;
    if root.as_ref().is_some_and(|s| s.next_poll > now) {
        return Ok(EndpointOutcome {
            error: None,
            calls: 0,
            pages: 0,
            accepted: 0,
            skipped: true,
        });
    }
    let cursor = root.as_ref().and_then(|s| s.cursor.as_deref());
    let mut page = first;
    let mut page_updates = Vec::new();
    let mut all = Vec::new();
    let mut requests = 0u64;
    loop {
        let cache_page = if page_size == 0 { 0 } else { page };
        let cached = state(db, route, cache_page)?;
        let url = if page_size == 0 {
            route.to_owned()
        } else {
            format!("{route}?per_page={page_size}&page={page}")
        };
        requests += 1;
        let response = match fetch(&url, cached.as_ref().and_then(|s| s.etag.as_deref())) {
            Ok(r) => r,
            Err(e) => {
                record_failure(db, route, first, now, &e, requests)?;
                return Ok(EndpointOutcome {
                    error: Some(e.category),
                    calls: requests,
                    pages: page_updates.len() as u64,
                    accepted: 0,
                    skipped: false,
                });
            }
        };
        if response.status != 200 && response.status != 304 {
            let e = response.failure();
            record_failure(db, route, first, now, &e, requests)?;
            return Ok(EndpointOutcome {
                error: Some(e.category),
                calls: requests,
                pages: page_updates.len() as u64,
                accepted: 0,
                skipped: false,
            });
        }
        let (body, etag, has_next) = if response.status == 304 {
            let Some(old) = cached.as_ref().and_then(|s| s.body.clone()) else {
                let e = Failure::new("cache_miss");
                record_failure(db, route, first, now, &e, requests)?;
                return Ok(EndpointOutcome {
                    error: Some(e.category),
                    calls: requests,
                    pages: page_updates.len() as u64,
                    accepted: 0,
                    skipped: false,
                });
            };
            (
                old,
                response
                    .etag()
                    .or_else(|| cached.as_ref().and_then(|s| s.etag.clone())),
                cached.as_ref().is_some_and(|s| s.has_next),
            )
        } else {
            if response.body.len() >= MAX_OUTPUT {
                let e = Failure::new("output_limit");
                record_failure(db, route, first, now, &e, requests)?;
                return Ok(EndpointOutcome {
                    error: Some(e.category),
                    calls: requests,
                    pages: page_updates.len() as u64,
                    accepted: 0,
                    skipped: false,
                });
            }
            let body = match String::from_utf8(response.body.clone()) {
                Ok(body) => body,
                Err(_) => {
                    let e = Failure::new("invalid_response");
                    record_failure(db, route, first, now, &e, requests)?;
                    return Ok(EndpointOutcome {
                        error: Some(e.category),
                        calls: requests,
                        pages: page_updates.len() as u64,
                        accepted: 0,
                        skipped: false,
                    });
                }
            };
            let next = page_size > 0 && response.has_next();
            (body, response.etag(), next)
        };
        let data: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => {
                let e = Failure::new("invalid_response");
                record_failure(db, route, first, now, &e, requests)?;
                return Ok(EndpointOutcome {
                    error: Some(e.category),
                    calls: requests,
                    pages: page_updates.len() as u64,
                    accepted: 0,
                    skipped: false,
                });
            }
        };
        if page_size == 0 {
            all.push(data);
        } else if let Some(items) = data.as_array() {
            all.extend(items.iter().cloned());
        } else {
            let e = Failure::new("invalid_response");
            record_failure(db, route, first, now, &e, requests)?;
            return Ok(EndpointOutcome {
                error: Some(e.category),
                calls: requests,
                pages: page_updates.len() as u64,
                accepted: 0,
                skipped: false,
            });
        }
        page_updates.push(PageUpdate {
            page: cache_page,
            body,
            etag,
            has_next,
        });
        if !has_next {
            break;
        }
        page += 1;
        if page > 10_000 {
            let e = Failure::new("pagination_limit");
            record_failure(db, route, first, now, &e, requests)?;
            return Ok(EndpointOutcome {
                error: Some(e.category),
                calls: requests,
                pages: page_updates.len() as u64,
                accepted: 0,
                skipped: false,
            });
        }
    }
    let (cursor, accepted) = match process(db, cursor, all, now) {
        Ok(v) => v,
        Err(e) => {
            record_failure(db, route, first, now, &e, requests)?;
            return Ok(EndpointOutcome {
                error: Some(e.category),
                calls: requests,
                pages: page_updates.len() as u64,
                accepted: 0,
                skipped: false,
            });
        }
    };
    save_success(db, route, first, page_updates, cursor, now, requests)?;
    crate::observability::emit("poll.endpoint", "ok", "", None, Duration::ZERO, accepted);
    Ok(EndpointOutcome {
        error: None,
        calls: requests,
        pages: requests,
        accepted,
        skipped: false,
    })
}

struct State {
    etag: Option<String>,
    body: Option<String>,
    cursor: Option<String>,
    has_next: bool,
    next_poll: i64,
    backoff: i64,
}
struct PageUpdate {
    page: usize,
    body: String,
    etag: Option<String>,
    has_next: bool,
}
fn state(db: &Connection, endpoint: &str, page: usize) -> Result<Option<State>> {
    Ok(db.query_row("SELECT etag,body,cursor,has_next,next_poll_ms,backoff_ms FROM github_poll_state WHERE endpoint=?1 AND page=?2",params![endpoint,page as i64],|r|Ok(State{etag:r.get(0)?,body:r.get(1)?,cursor:r.get(2)?,has_next:r.get::<_,i64>(3)?!=0,next_poll:r.get(4)?,backoff:r.get(5)?})).optional()?)
}
fn save_success(
    db: &Connection,
    route: &str,
    first: usize,
    pages: Vec<PageUpdate>,
    cursor: Option<String>,
    now: i64,
    calls: u64,
) -> Result<()> {
    db.execute_batch("BEGIN IMMEDIATE")?;
    let res = (|| -> Result<()> {
        for p in &pages {
            db.execute("INSERT INTO github_poll_state(endpoint,page,etag,body,cursor,has_next,next_poll_ms,backoff_ms,last_success_ms,error_category,calls) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,?10) ON CONFLICT(endpoint,page) DO UPDATE SET etag=excluded.etag,body=excluded.body,cursor=CASE WHEN page=?11 THEN excluded.cursor ELSE github_poll_state.cursor END,has_next=excluded.has_next,next_poll_ms=excluded.next_poll_ms,backoff_ms=excluded.backoff_ms,last_success_ms=excluded.last_success_ms,error_category=NULL,calls=github_poll_state.calls+excluded.calls",params![route,p.page as i64,p.etag,p.body,if p.page==first{cursor.clone()}else{None},i64::from(p.has_next),now+INTERVAL_MS,INTERVAL_MS,now,if p.page==first{calls as i64}else{0},first as i64])?;
        }
        db.execute(
            "DELETE FROM github_poll_state WHERE endpoint=?1 AND page>?2",
            params![route, pages.last().map_or(first as i64, |p| p.page as i64)],
        )?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            db.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}
fn record_failure(
    db: &Connection,
    route: &str,
    page: usize,
    now: i64,
    e: &Failure,
    calls: u64,
) -> Result<()> {
    let old = state(db, route, page)?.map_or(INTERVAL_MS, |s| s.backoff.max(INTERVAL_MS));
    let delay = if e.category == "rate_limited" {
        e.retry_at
            .map_or(INTERVAL_MS, |at| (at - now).max(INTERVAL_MS))
    } else {
        old.min(MAX_BACKOFF_MS)
    };
    let next_backoff = (old.saturating_mul(2)).min(MAX_BACKOFF_MS);
    let next = now.saturating_add(delay);
    db.execute("INSERT INTO github_poll_state(endpoint,page,next_poll_ms,backoff_ms,error_category,calls) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(endpoint,page) DO UPDATE SET next_poll_ms=excluded.next_poll_ms,backoff_ms=excluded.backoff_ms,error_category=excluded.error_category,calls=github_poll_state.calls+excluded.calls",params![route,page as i64,next,next_backoff,e.category,calls as i64])?;
    if e.category == "rate_limited" {
        db.execute("INSERT INTO github_poll_state(endpoint,page,next_poll_ms,backoff_ms,error_category,calls) VALUES('__global__',0,?1,?2,'rate_limited',0) ON CONFLICT(endpoint,page) DO UPDATE SET next_poll_ms=max(github_poll_state.next_poll_ms,excluded.next_poll_ms),error_category='rate_limited'",params![next,next_backoff])?;
    }
    crate::observability::emit(
        "poll.endpoint",
        "error",
        e.category,
        None,
        Duration::ZERO,
        calls,
    );
    Ok(())
}

#[derive(Clone)]
struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
impl HttpResponse {
    fn etag(&self) -> Option<String> {
        self.headers.get("etag").filter(|s| safe_header(s)).cloned()
    }
    fn has_next(&self) -> bool {
        self.headers.get("link").is_some_and(|h| {
            h.split(',')
                .any(|part| part.to_ascii_lowercase().contains("rel=\"next\""))
        })
    }
    fn failure(&self) -> Failure {
        let status = self.status;
        let remaining = self
            .headers
            .get("x-ratelimit-remaining")
            .is_some_and(|s| s == "0");
        let retry_after = self
            .headers
            .get("retry-after")
            .and_then(|s| s.parse::<i64>().ok());
        let category = if status == 401 {
            "authentication"
        } else if status == 403 && !remaining && retry_after.is_none() {
            "forbidden"
        } else if status == 403 || status == 429 {
            "rate_limited"
        } else if status == 404 {
            "not_found"
        } else if status >= 500 {
            "server_error"
        } else {
            "http_error"
        };
        let retry = retry_after
            .map(|s| now_ms().saturating_add(s.saturating_mul(1000)))
            .or_else(|| {
                self.headers
                    .get("x-ratelimit-reset")
                    .and_then(|s| s.parse::<i64>().ok())
                    .map(|s| s.saturating_mul(1000))
            });
        Failure {
            category,
            retry_at: retry,
        }
    }
}
fn github_fetch(
    gh: &Path,
    route: &str,
    etag: Option<&str>,
) -> std::result::Result<HttpResponse, Failure> {
    let started = Instant::now();
    let mut cmd = Command::new(gh);
    cmd.args([
        "api",
        "--include",
        "--header",
        "Accept: application/vnd.github+json",
        "--header",
        "X-GitHub-Api-Version: 2022-11-28",
    ]);
    if let Some(etag) = etag {
        if !safe_header(etag) {
            return Err(Failure::new("invalid_cache"));
        }
        cmd.arg("--header").arg(format!("If-None-Match: {etag}"));
    }
    cmd.arg(route);
    let output = crate::manager::run(&mut cmd, TIMEOUT).map_err(|e| {
        if e.to_string().contains("timed out") {
            Failure::new("timeout")
        } else {
            Failure::new("command_error")
        }
    })?;
    let parsed = parse_http(&output.stdout)?;
    if !output.status.success() && parsed.status == 200 {
        return Err(Failure::new("command_error"));
    }
    crate::observability::emit(
        "poll.github",
        if parsed.status < 400 { "ok" } else { "error" },
        if parsed.status < 400 {
            ""
        } else {
            parsed.failure().category
        },
        None,
        started.elapsed(),
        1,
    );
    Ok(parsed)
}
fn parse_http(raw: &[u8]) -> std::result::Result<HttpResponse, Failure> {
    if raw.len() >= MAX_OUTPUT {
        return Err(Failure::new("output_limit"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| Failure::new("invalid_response"))?;
    let mut rest = text;
    loop {
        let (sep, n) = if let Some(i) = rest.find("\r\n\r\n") {
            (i, 4)
        } else if let Some(i) = rest.find("\n\n") {
            (i, 2)
        } else {
            return Err(Failure::new("invalid_response"));
        };
        let head = &rest[..sep];
        let mut lines = head.lines();
        let status_line = lines
            .next()
            .ok_or_else(|| Failure::new("invalid_response"))?;
        if !status_line.starts_with("HTTP/") {
            return Err(Failure::new("invalid_response"));
        }
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Failure::new("invalid_response"))?;
        let mut headers = BTreeMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
            }
        }
        let after = &rest[sep + n..];
        if after.starts_with("HTTP/") {
            rest = after;
            continue;
        }
        return Ok(HttpResponse {
            status,
            headers,
            body: after.as_bytes().to_vec(),
        });
    }
}

fn scoped_subscription_accept(
    db: &Connection,
    header: &str,
    payload: &Value,
    repo: &str,
    resource: &str,
    event_time: Option<&str>,
) -> std::result::Result<usize, Failure> {
    let kind = match header {
        "pull_request" => "pull_request",
        "pull_request_review" => "review",
        "deployment_status" => "deployment",
        "push" => "git_ref",
        _ => return Err(Failure::new("invalid_response")),
    };
    let candidate = Connection::open_in_memory().map_err(|_| Failure::new("database"))?;
    crate::subscriptions::initialize(&candidate).map_err(|_| Failure::new("database"))?;
    // GitHub dates have second precision; include ties rather than permanently dropping them.
    let mut s=db.prepare("SELECT id,kind,repo,resource,event,thread,state,outcome,reason,updated,message_template,source_json,execution_json FROM subscriptions WHERE state='waiting' AND kind=?1 AND repo=?2 AND resource=?3 AND (?4 IS NULL OR datetime(updated)<=datetime(?4))").map_err(|_|Failure::new("database"))?;
    let rows = s
        .query_map(params![kind, repo, resource, event_time], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, String>(9)?,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, Option<String>>(11)?,
                r.get::<_, Option<String>>(12)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?;
    for row in rows {
        candidate.execute("INSERT INTO subscriptions(id,kind,repo,resource,event,thread,state,outcome,reason,updated,message_template,source_json,execution_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![row.0,row.1,row.2,row.3,row.4,row.5,row.6,row.7,row.8,row.9,row.10,row.11,row.12]).map_err(|_|Failure::new("database"))?;
    }
    crate::subscriptions::accept(&candidate, header, payload)
        .map_err(|_| Failure::new("accept"))?;
    let ready = {
        let mut s = candidate
            .prepare("SELECT id,outcome,reason,source_json FROM subscriptions WHERE state='ready'")
            .map_err(|_| Failure::new("database"))?;
        s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?
    };
    let tx = db
        .unchecked_transaction()
        .map_err(|_| Failure::new("database"))?;
    let mut count = 0;
    for (id, outcome, reason, source) in ready {
        count+=tx.execute("UPDATE subscriptions SET state='ready',outcome=?1,reason=?2,source_json=CASE WHEN message_template IS NOT NULL THEN ?3 ELSE source_json END,updated=CURRENT_TIMESTAMP WHERE id=?4 AND state='waiting'",params![outcome,reason,source,id]).map_err(|_|Failure::new("database"))?;
    }
    tx.commit().map_err(|_| Failure::new("database"))?;
    Ok(count)
}
fn rules_accept_scoped(
    db: &Connection,
    header: &str,
    payload: &Value,
    repo: &str,
    pr: i64,
    created: &str,
) -> std::result::Result<usize, Failure> {
    crate::rules::initialize(db).map_err(|_| Failure::new("database"))?;
    let candidate = Connection::open_in_memory().map_err(|_| Failure::new("database"))?;
    crate::rules::initialize(&candidate).map_err(|_| Failure::new("database"))?;
    let mut s = db
        .prepare(
            "SELECT id,input,updated FROM rules WHERE enabled=1 AND datetime(updated)<=datetime(?1)",
        )
        .map_err(|_| Failure::new("database"))?;
    let rows = s
        .query_map([created], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?;
    for (id, input, updated) in rows {
        let value: Value = serde_json::from_str(&input).map_err(|_| Failure::new("database"))?;
        if value["repo"].as_str() != Some(repo) || value["pr"].as_i64() != Some(pr) {
            continue;
        }
        candidate
            .execute(
                "INSERT INTO rules(id,input,enabled,updated) VALUES(?1,?2,1,?3)",
                params![id, input, updated],
            )
            .map_err(|_| Failure::new("database"))?;
    }
    crate::rules::accept(&candidate, header, payload).map_err(|_| Failure::new("accept"))?;
    let pending = {
        let mut s = candidate
            .prepare("SELECT rule_id,event_header,comment_id,source FROM rule_deliveries")
            .map_err(|_| Failure::new("database"))?;
        s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?
    };
    let tx = db
        .unchecked_transaction()
        .map_err(|_| Failure::new("database"))?;
    let mut count = 0;
    for (id, event, comment, source) in pending {
        count+=tx.execute("INSERT OR IGNORE INTO rule_deliveries(rule_id,event_header,comment_id,source) VALUES(?1,?2,?3,?4)",params![id,event,comment,source]).map_err(|_|Failure::new("database"))?;
    }
    tx.commit().map_err(|_| Failure::new("database"))?;
    Ok(count)
}
fn accept_comment(
    db: &Connection,
    header: &str,
    repo: &str,
    pr: &str,
    comment: &Value,
    action: &str,
) -> std::result::Result<usize, Failure> {
    let created = comment["created_at"]
        .as_str()
        .ok_or_else(|| Failure::new("invalid_response"))?;
    let updated = comment["updated_at"].as_str().unwrap_or(created);
    let number = pr
        .parse::<i64>()
        .map_err(|_| Failure::new("invalid_response"))?;
    let event = if header == "issue_comment" {
        json!({"action":action,"repository":{"full_name":repo},"issue":{"number":number,"pull_request":{"url":format!("https://api.github.com/repos/{repo}/pulls/{number}")}},"comment":comment})
    } else {
        json!({"action":action,"repository":{"full_name":repo},"pull_request":{"number":number},"comment":comment})
    };
    let registered_after = if action == "edited" { updated } else { created };
    rules_accept_scoped(db, header, &event, repo, number, registered_after)
}
fn timestamp_gt(db: &Connection, later: &str, earlier: &str) -> std::result::Result<bool, Failure> {
    db.query_row(
        "SELECT datetime(?1)>datetime(?2)",
        params![later, earlier],
        |r| r.get(0),
    )
    .map_err(|_| Failure::new("database"))
}
fn valid_pr(pr: &Value, number: i64) -> bool {
    pr["number"].as_i64() == Some(number)
        && matches!(pr["state"].as_str(), Some("open" | "closed"))
        && pr
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .is_some_and(valid_sha)
        && pr
            .pointer("/base/ref")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        && (pr["state"] != "closed" || pr["merged"].as_bool().is_some())
}
fn cached_pr_is_valid(db: &Connection, route: &str, number: i64) -> Result<bool> {
    Ok(state(db, route, 0)?
        .and_then(|s| s.body)
        .and_then(|body| serde_json::from_str::<Value>(&body).ok())
        .is_some_and(|pr| valid_pr(&pr, number)))
}
fn bridge_accept(db: &Connection, payload: &Value) -> std::result::Result<&'static str, Failure> {
    crate::bridge::accept(db, payload).map_err(|_| Failure::new("accept"))
}
fn subscriptions_accept(
    db: &Connection,
    header: &str,
    payload: &Value,
) -> std::result::Result<usize, Failure> {
    crate::subscriptions::accept(db, header, payload).map_err(|_| Failure::new("accept"))
}
fn decode_cursor(cursor: Option<&str>) -> std::result::Result<BTreeMap<String, String>, Failure> {
    cursor
        .map(|s| serde_json::from_str(s).map_err(|_| Failure::new("invalid_cache")))
        .unwrap_or_else(|| Ok(BTreeMap::new()))
}
fn positive_id(v: &Value) -> Option<String> {
    v.as_u64().filter(|n| *n > 0).map(|n| n.to_string())
}
fn positive_text(v: &str) -> bool {
    v.parse::<u64>().is_ok_and(|n| n > 0)
}
fn valid_repo(repo: &str) -> bool {
    let p: Vec<_> = repo.split('/').collect();
    p.len() == 2
        && p.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_branch(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with('/')
        && !s.starts_with('.')
        && !s.ends_with('/')
        && !s.ends_with('.')
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("@{")
        && !s
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b"~^:?*[\\".contains(&b))
}
fn escape_ref(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b == b'/' || b.is_ascii_alphanumeric() || b"_.-".contains(&b) {
            out.push(b as char)
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
fn safe_header(s: &str) -> bool {
    s.len() <= 1024 && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    type Fetch<'a> =
        dyn FnMut(&str, Option<&str>) -> std::result::Result<HttpResponse, Failure> + 'a;

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE waits(repo TEXT,run_id INTEGER,attempt INTEGER,sha TEXT,state TEXT)",
        )
        .unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        initialize(&db).unwrap();
        db
    }
    fn response(body: Value, next: bool) -> HttpResponse {
        let mut headers = BTreeMap::from([("etag".into(), "\"version1\"".into())]);
        if next {
            headers.insert("link".into(), "<ignored>; rel=\"next\"".into());
        }
        HttpResponse {
            status: 200,
            headers,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    fn subscribe(db: &Connection, kind: &str, resource: &str, event: &str) -> String {
        let id = crate::subscriptions::subscribe(
            db,
            kind,
            "owner/repo",
            resource,
            event,
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        db.execute(
            "UPDATE subscriptions SET updated='2026-01-01 00:00:00' WHERE id=?1",
            [&id],
        )
        .unwrap();
        id
    }
    fn registration_state(db: &Connection, id: &str) -> String {
        db.query_row("SELECT state FROM subscriptions WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .unwrap()
    }

    #[test]
    fn no_listeners_make_no_network_requests() {
        let report = tick_with(&db(), 1, |_, _| panic!("unexpected request")).unwrap();
        assert_eq!(report["calls"], 0);
    }

    #[test]
    fn pagination_failure_keeps_cursor_and_cached_pages_then_304_reuses_them() {
        let db = db();
        let run = |now, fetch: &mut Fetch<'_>| {
            poll_endpoint(
                &db,
                "/list",
                10,
                now,
                &mut |r, e| fetch(r, e),
                |_, old, items, _| {
                    assert!(old.is_none() || old == Some("checkpoint"));
                    assert_eq!(items, vec![json!(1), json!(2)]);
                    Ok((Some("checkpoint".into()), 0))
                },
            )
            .unwrap()
        };
        assert_eq!(
            run(1, &mut |route, _| Ok(response(
                if route.ends_with("page=1") {
                    json!([1])
                } else {
                    json!([2])
                },
                route.ends_with("page=1")
            )))
            .calls,
            2
        );
        let failure = run(INTERVAL_MS + 1, &mut |route, etag| {
            assert_eq!(etag, Some("\"version1\""));
            if route.ends_with("page=1") {
                Ok(response(json!([99]), true))
            } else {
                Err(Failure::new("server_error"))
            }
        });
        assert_eq!(failure.error, Some("server_error"));
        let saved = state(&db, "/list", 1).unwrap().unwrap();
        assert_eq!(saved.body.as_deref(), Some("[1]"));
        assert_eq!(saved.cursor.as_deref(), Some("checkpoint"));
        let cached = run(INTERVAL_MS * 3 + 1, &mut |_, etag| {
            assert_eq!(etag, Some("\"version1\""));
            Ok(HttpResponse {
                status: 304,
                headers: BTreeMap::new(),
                body: vec![],
            })
        });
        assert_eq!(cached.calls, 2);
        assert_eq!(cached.error, None);
    }

    #[test]
    fn server_rate_limit_stops_other_endpoints_and_preserves_long_reset() {
        let db = db();
        let now = now_ms();
        let retry = now + MAX_BACKOFF_MS * 2;
        let failed = poll_endpoint(
            &db,
            "/limited",
            0,
            now,
            &mut |_, _| {
                Ok(HttpResponse {
                    status: 403,
                    headers: BTreeMap::from([
                        ("x-ratelimit-remaining".into(), "0".into()),
                        ("x-ratelimit-reset".into(), (retry / 1000).to_string()),
                    ]),
                    body: vec![],
                })
            },
            |_, _, _, _| panic!("rate-limited body must not be accepted"),
        )
        .unwrap();
        assert_eq!(failed.error, Some("rate_limited"));
        let blocked = poll_endpoint(
            &db,
            "/other",
            0,
            now + MAX_BACKOFF_MS,
            &mut |_, _| panic!("global backoff ignored"),
            |_, _, _, _| panic!(),
        )
        .unwrap();
        assert!(blocked.skipped);
        assert!(state(&db, "__global__", 0).unwrap().unwrap().next_poll >= retry - 1000);
    }

    #[test]
    fn review_pending_then_submitted_uses_rest_state_and_source_pr_number() {
        let db = db();
        let id = subscribe(&db, "review", "7", "approved");
        let pending = tick_with(&db, 1, |route, _| {
            assert_eq!(
                route,
                "/repos/owner/repo/pulls/7/reviews?per_page=10&page=1"
            );
            Ok(response(
                json!([{"id":3,"state":"PENDING","submitted_at":null}]),
                false,
            ))
        })
        .unwrap();
        assert_eq!(pending["accepted"], 0);
        let accepted = tick_with(&db, INTERVAL_MS + 1, |_, _| {
            Ok(response(
                json!([{"id":3,"state":"APPROVED","submitted_at":"2026-01-02T00:00:00Z"}]),
                false,
            ))
        })
        .unwrap();
        assert_eq!(accepted["accepted"], 1);
        assert_eq!(registration_state(&db, &id), "ready");
        tick_with(&db, INTERVAL_MS * 2 + 1, |_, _| {
            panic!("completed one-shot subscription polled again")
        })
        .unwrap();
    }

    #[test]
    fn same_second_event_ties_are_included_for_subscriptions_and_rules() {
        let db = db();
        let id = subscribe(&db, "review", "7", "approved");
        let report = tick_with(&db, 1, |_, _| {
            Ok(response(
                json!([{"id":3,"state":"APPROVED","submitted_at":"2026-01-01T00:00:00Z"}]),
                false,
            ))
        })
        .unwrap();
        assert_eq!(report["accepted"], 1);
        assert_eq!(registration_state(&db, &id), "ready");
        rule(&db);
        let comment = json!({"id":4,"body":"wake","user":{"login":"trusted","type":"User"},"created_at":"2026-01-01T00:00:00Z"});
        assert_eq!(
            accept_comment(&db, "issue_comment", "owner/repo", "7", &comment, "created").unwrap(),
            1
        );
        assert_eq!(
            accept_comment(&db, "issue_comment", "owner/repo", "7", &comment, "created").unwrap(),
            0
        );
    }

    #[test]
    fn historical_review_does_not_wake_late_registration() {
        let db = db();
        let id = subscribe(&db, "review", "7", "submitted");
        let report = tick_with(&db, 1, |_, _| {
            Ok(response(
                json!([{"id":3,"state":"COMMENTED","submitted_at":"2025-12-31T00:00:00Z"}]),
                false,
            ))
        })
        .unwrap();
        assert_eq!(report["accepted"], 0);
        assert_eq!(registration_state(&db, &id), "waiting");
    }

    #[test]
    fn git_ref_baseline_does_not_wake_until_sha_changes() {
        let db = db();
        let id = subscribe(&db, "git_ref", "topic/test", "updated");
        for (now, sha, expected) in [
            (1, "a".repeat(40), "waiting"),
            (INTERVAL_MS + 1, "b".repeat(40), "ready"),
        ] {
            tick_with(&db, now, |route, _| {
                assert_eq!(route, "/repos/owner/repo/git/ref/heads/topic/test");
                Ok(response(
                    json!({"ref":"refs/heads/topic/test","object":{"sha":sha}}),
                    false,
                ))
            })
            .unwrap();
            assert_eq!(registration_state(&db, &id), expected);
        }
    }

    #[test]
    fn pr_head_and_base_changes_share_one_snapshot_without_historical_wake() {
        let db = db();
        let head = subscribe(&db, "pull_request", "7", "synchronize");
        let base = subscribe(&db, "pull_request", "7", "base_changed");
        for (now, sha, branch, expected) in [
            (1, "a".repeat(40), "main", "waiting"),
            (INTERVAL_MS + 1, "b".repeat(40), "develop", "ready"),
        ] {
            let mut calls = 0;
            tick_with(&db,now,|route,_| {
                calls+=1;
                assert_eq!(route,"/repos/owner/repo/pulls/7");
                Ok(response(json!({"number":7,"state":"open","head":{"sha":sha},"base":{"ref":branch},"updated_at":"2026-01-02T00:00:00Z"}),false))
            }).unwrap();
            assert_eq!(calls, 1);
            assert_eq!(registration_state(&db, &head), expected);
            assert_eq!(registration_state(&db, &base), expected);
        }
    }

    fn rule(db: &Connection) {
        crate::rules::configure(db,serde_json::from_value(json!({"repo":"owner/repo","pr":7,"author":"trusted","contains":"wake","prompt":"Continue","target_thread":"11111111-1111-4111-8111-111111111111"})).unwrap()).unwrap();
        db.execute("UPDATE rules SET updated='2026-01-01 00:00:00'", [])
            .unwrap();
    }

    #[test]
    fn comments_require_real_pr_and_only_new_or_newly_edited_versions_match() {
        let db = db();
        rule(&db);
        let missing = tick_with(&db, 1, |route, _| {
            assert_eq!(route, "/repos/owner/repo/pulls/7");
            Ok(HttpResponse {
                status: 404,
                headers: BTreeMap::new(),
                body: vec![],
            })
        })
        .unwrap();
        assert_eq!(missing["accepted"], 0);
        let count = || {
            db.query_row("SELECT count(*) FROM rule_deliveries", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
        };
        assert_eq!(count(), 0);
        for (now, expected) in [(INTERVAL_MS + 1, 2), (INTERVAL_MS * 2 + 1, 2)] {
            tick_with(&db,now,|route,_| {
                let body=if route.ends_with("/pulls/7") {
                    json!({"number":7,"state":"open","head":{"sha":"a".repeat(40)},"base":{"ref":"main"},"updated_at":"2026-01-02T00:00:00Z"})
                } else if route.contains("/issues/7/comments?") {
                    json!([
                        {"id":1,"body":"wake","user":{"login":"trusted","type":"User"},"created_at":"2025-12-01T00:00:00Z","updated_at":"2025-12-01T00:00:00Z"},
                        {"id":2,"body":"wake","user":{"login":"trusted","type":"User"},"created_at":"2026-01-02T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"},
                        {"id":3,"body":"wake","user":{"login":"trusted","type":"User"},"created_at":"2025-12-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}
                    ])
                } else { assert!(route.contains("/pulls/7/comments?")); json!([]) };
                Ok(response(body,false))
            }).unwrap();
            assert_eq!(count(), expected);
        }
    }

    #[test]
    fn http_parser_preserves_etag_and_refuses_incomplete_or_oversized_output() {
        let parsed = parse_http(b"HTTP/2 304 Not Modified\r\nETag: \"abc\"\r\n\r\n").unwrap();
        assert_eq!(parsed.status, 304);
        assert_eq!(parsed.etag().as_deref(), Some("\"abc\""));
        assert_eq!(
            parse_http(b"HTTP/2 200").err().unwrap().category,
            "invalid_response"
        );
        assert_eq!(
            parse_http(&vec![b'x'; MAX_OUTPUT]).err().unwrap().category,
            "output_limit"
        );
    }
}
