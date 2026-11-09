//! Bounded GitHub REST polling for explicitly registered waits and listeners.
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "pr_notifications.rs"]
pub(crate) mod pr_notifications;

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
        PRIMARY KEY(endpoint,page));
        CREATE TABLE IF NOT EXISTS github_poll_generation (
            endpoint TEXT PRIMARY KEY, generation INTEGER NOT NULL);",
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
    pr_notifications::initialize(db)?;
    let targets = targets(db)?;
    let mut report = Report::default();
    db.execute("UPDATE github_poll_state SET error_category=NULL WHERE endpoint='__global__' AND next_poll_ms<=?1",[now])?;

    for (key, run_target) in &targets.runs {
        let (repo, run_id, attempt) = key;
        let route = format!("/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}");
        let outcome = poll_endpoint(db, &route, 0, now, &mut fetch, |db, _, items, _| {
            let Some(run) = items.first() else {
                return Err(Failure::new("invalid_response"));
            };
            if run["id"].as_i64() != Some(*run_id) || run["run_attempt"].as_i64() != Some(*attempt)
            {
                return Err(Failure::new("identity_mismatch"));
            }
            let sha = run["head_sha"]
                .as_str()
                .filter(|sha| valid_sha(sha))
                .ok_or_else(|| Failure::new("identity_mismatch"))?;
            let mut accepted = 0;
            if !run_target.wait_shas.is_empty() && run["status"] == "completed" {
                if !run_target.wait_shas.contains(sha) {
                    return Err(Failure::new("identity_mismatch"));
                }
                let event = json!({"action":"completed","workflow_run":run,
                    "repository":{"full_name":repo}});
                accepted += u64::from(bridge_accept(db, &event)? == "recorded");
            }
            let created = run["created_at"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| Failure::new("invalid_response"))?;
            let mut observations = Vec::new();
            if run["status"] == "completed" {
                let conclusion = run["conclusion"]
                    .as_str()
                    .filter(|value| {
                        matches!(
                            *value,
                            "success"
                                | "failure"
                                | "neutral"
                                | "cancelled"
                                | "skipped"
                                | "timed_out"
                                | "action_required"
                                | "stale"
                                | "startup_failure"
                        )
                    })
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                let completed = run["completed_at"]
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .or_else(|| run["updated_at"].as_str().filter(|value| !value.is_empty()))
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                let event = json!({"action":"completed","workflow_run":run,
                    "repository":{"full_name":repo}});
                let current_members = crate::conditions::pending_polling_members(db, None)
                    .map_err(|_| Failure::new("database"))?;
                for member in current_members.iter().filter(|member| {
                    member.selector.kind == "job"
                        && member.ci.as_ref().is_some_and(|ci| {
                            ci.repo == *repo && ci.run_id == *run_id && ci.attempt == *attempt
                        })
                }) {
                    if member.ci.as_ref().is_some_and(|ci| ci.sha == sha)
                        && (member.selector.event == "completed"
                            || member.selector.event == conclusion)
                        && member
                            .selector
                            .outcome
                            .as_deref()
                            .is_none_or(|v| v == conclusion)
                    {
                        observations.push(ConditionObservation {
                            resource: member.selector.resource.clone(),
                            event: member.selector.event.clone(),
                            outcome: Some(conclusion.to_owned()),
                            key: crate::subscriptions::source_event_identity(
                                "job",
                                repo,
                                &member.selector.resource,
                                &member.selector.event,
                                conclusion,
                                &event,
                            )
                            .map_err(|_| Failure::new("database"))?
                            .ok_or_else(|| Failure::new("identity_mismatch"))?,
                            cursor: completed.to_owned(),
                            ci: member.ci.clone(),
                            order_ambiguous: false,
                            source: event.clone(),
                        });
                    }
                }
            }
            let baseline = Some(created.to_owned());
            let condition_count = observe_conditions(
                db,
                "job",
                repo,
                &run_id.to_string(),
                &observations,
                baseline.as_deref(),
                Some((sha, *attempt)),
            )?;
            accepted += condition_count as u64;
            Ok((None, accepted))
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
            let observed_state = pr["state"]
                .as_str()
                .ok_or_else(|| Failure::new("invalid_response"))?;
            codex_wake::pr_ci::observe_pull_request_state_in(
                db,
                &resource.repo,
                &resource.resource,
                observed_state,
                now,
            )
            .map_err(|_| Failure::new("database"))?;
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
            // Older PR cursors omit state; recover it from the cached response.
            let prior_state = match old["state"].as_str() {
                Some(state @ ("open" | "closed")) => Some(state.to_owned()),
                _ if old.is_null() => None,
                _ => state(db, &route, 0)
                    .map_err(|_| Failure::new("database"))?
                    .and_then(|cached| cached.body)
                    .and_then(|body| serde_json::from_str::<Value>(&body).ok())
                    .filter(|cached| valid_pr(cached, number))
                    .and_then(|cached| cached["state"].as_str().map(str::to_owned)),
            };
            let full = |action: &str, changes: Value| {
                json!({"action":action,"number":number,
                "pull_request":pr,"repository":{"full_name":resource.repo},"changes":changes})
            };
            let mut accepted = 0u64;
            let prior_sequence = old["poll_seq"].as_i64();
            let baseline = cursor_number(prior_sequence.unwrap_or(now));
            let event_cursor = prior_sequence.map(|last| cursor_number(last.saturating_add(1)));
            let mut condition_observations = Vec::new();
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
                let event_name = if pr["merged"] == true {
                    "merged"
                } else {
                    "closed"
                };
                let event_key = stable_source_key(
                    "pull_request",
                    &resource.repo,
                    &resource.resource,
                    event_name,
                    "",
                    &[event_time],
                );
                let ambiguous_baseline = !old.is_null() && prior_state.is_none();
                let ambiguous_event_cursor = ambiguous_baseline
                    .then(|| event_cursor.clone().unwrap_or_else(|| cursor_number(now)));
                let observation_cursor = if ambiguous_baseline {
                    ambiguous_event_cursor.as_ref()
                } else if prior_state.as_deref() == Some("open") {
                    event_cursor.as_ref()
                } else {
                    None
                };
                if let Some(cursor) = observation_cursor {
                    condition_observations.push(ConditionObservation {
                        resource: resource.resource.clone(),
                        event: event_name.to_owned(),
                        outcome: None,
                        key: stable_source_key(
                            "pull_request",
                            &resource.repo,
                            &resource.resource,
                            event_name,
                            "",
                            &[event_time],
                        ),
                        cursor: cursor.clone(),
                        ci: None,
                        order_ambiguous: ambiguous_baseline,
                        source: event.clone(),
                    });
                }
                accepted += scoped_subscription_accept(
                    db,
                    "pull_request",
                    &event,
                    &resource.repo,
                    &resource.resource,
                    None,
                )? as u64;
                pr_notifications::record_event(
                    db,
                    "pull_request",
                    &resource.repo,
                    &resource.resource,
                    event_name,
                    event_time,
                    &event_key,
                    &event,
                )
                .map_err(|_| Failure::new("database"))?;
            } else if !old.is_null() {
                let changed_at = pr["updated_at"].as_str();
                if prior_state.as_deref() == Some("closed") {
                    let event_at = changed_at.ok_or_else(|| Failure::new("invalid_response"))?;
                    let event = full("reopened", Value::Null);
                    let event_key = stable_source_key(
                        "pull_request",
                        &resource.repo,
                        &resource.resource,
                        "reopened",
                        "",
                        &[event_at],
                    );
                    let tx = rusqlite::Transaction::new_unchecked(
                        db,
                        rusqlite::TransactionBehavior::Immediate,
                    )
                    .map_err(|_| Failure::new("database"))?;
                    let notifications = pr_notifications::record_event_in(
                        &tx,
                        "pull_request",
                        &resource.repo,
                        &resource.resource,
                        "reopened",
                        event_at,
                        &event_key,
                        &event,
                    )
                    .map_err(|_| Failure::new("database"))?;
                    for notification in notifications {
                        codex_wake::pr_ci::consume_reopened_notification_in(
                            &tx,
                            &notification.id,
                            now,
                        )
                        .map_err(|_| Failure::new("database"))?;
                    }
                    tx.commit().map_err(|_| Failure::new("database"))?;
                }
                if old["head"].as_str().is_some_and(|v| v != head) {
                    let event_key = stable_source_key(
                        "pull_request",
                        &resource.repo,
                        &resource.resource,
                        "synchronize",
                        "",
                        &[changed_at.unwrap_or_default(), head],
                    );
                    if let Some(cursor) = event_cursor.as_ref() {
                        condition_observations.push(ConditionObservation {
                            resource: resource.resource.clone(),
                            event: "synchronize".into(),
                            outcome: None,
                            key: event_key.clone(),
                            cursor: cursor.clone(),
                            ci: None,
                            order_ambiguous: false,
                            source: full("synchronize", Value::Null),
                        });
                    }
                    accepted += scoped_subscription_accept(
                        db,
                        "pull_request",
                        &full("synchronize", Value::Null),
                        &resource.repo,
                        &resource.resource,
                        changed_at,
                    )? as u64;
                    if let Some(event_at) = changed_at {
                        pr_notifications::record_event(
                            db,
                            "pull_request",
                            &resource.repo,
                            &resource.resource,
                            "synchronize",
                            event_at,
                            &event_key,
                            &full("synchronize", Value::Null),
                        )
                        .map_err(|_| Failure::new("database"))?;
                    }
                }
                if old["base"].as_str().is_some_and(|v| v != base) {
                    let event_key = stable_source_key(
                        "pull_request",
                        &resource.repo,
                        &resource.resource,
                        "base_changed",
                        "",
                        &[changed_at.unwrap_or_default(), base],
                    );
                    if let Some(cursor) = event_cursor.as_ref() {
                        condition_observations.push(ConditionObservation {
                            resource: resource.resource.clone(),
                            event: "base_changed".into(),
                            outcome: None,
                            key: event_key.clone(),
                            cursor: cursor.clone(),
                            ci: None,
                            order_ambiguous: false,
                            source: full("edited", json!({"base":{"ref":old["base"]}})),
                        });
                    }
                    accepted += scoped_subscription_accept(
                        db,
                        "pull_request",
                        &full("edited", json!({"base":{"ref":old["base"]}})),
                        &resource.repo,
                        &resource.resource,
                        changed_at,
                    )? as u64;
                    if let Some(event_at) = changed_at {
                        pr_notifications::record_event(
                            db,
                            "pull_request",
                            &resource.repo,
                            &resource.resource,
                            "base_changed",
                            event_at,
                            &event_key,
                            &full("edited", json!({"base":{"ref":old["base"]}})),
                        )
                        .map_err(|_| Failure::new("database"))?;
                    }
                }
            }
            accepted += observe_conditions(
                db,
                "pull_request",
                &resource.repo,
                &resource.resource,
                &condition_observations,
                Some(&baseline),
                None,
            )? as u64;
            Ok((
                Some(
                    json!({"head":head,"base":base,"state":pr["state"],"updated_at":pr["updated_at"],
                    "poll_seq":now})
                    .to_string(),
                ),
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
                let baseline = review_baseline(&previous);
                let mut seen = previous;
                let mut matched = 0u64;
                let mut observations = Vec::new();
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
                    seen.insert(id.clone(), version);
                    let normalized = match state {
                        "APPROVED" => "approved",
                        "CHANGES_REQUESTED" => "changes_requested",
                        "COMMENTED" => "commented",
                        _ => state,
                    };
                    let condition_events = if normalized == "commented" {
                        vec!["submitted"]
                    } else {
                        vec!["submitted", normalized]
                    };
                    let mut review = review.clone();
                    review["state"] = json!(normalized);
                    let event = json!({"action":"submitted","pull_request":{"number":number.parse::<i64>().unwrap_or(0)},
                    "review":review,"repository":{"full_name":repo}});
                    for condition_event in condition_events {
                        observations.push(ConditionObservation {
                            resource: number.clone(),
                            event: condition_event.to_owned(),
                            outcome: Some(normalized.to_owned()),
                            key: stable_source_key(
                                "review",
                                &repo,
                                number,
                                condition_event,
                                normalized,
                                &[&id, submitted],
                            ),
                            cursor: review_cursor(submitted, &id),
                            ci: None,
                            order_ambiguous: false,
                            source: event.clone(),
                        });
                    }
                    // REST uses uppercase states; the acceptor consumes webhook enums.
                    matched += scoped_subscription_accept(
                        db,
                        "pull_request_review",
                        &event,
                        &repo,
                        number,
                        Some(submitted),
                    )? as u64;
                    let notification_event = match normalized {
                        "approved" | "changes_requested" => normalized,
                        _ => "submitted",
                    };
                    let event_key = stable_source_key(
                        "review",
                        &repo,
                        number,
                        notification_event,
                        normalized,
                        &[&id, submitted],
                    );
                    pr_notifications::record_event(
                        db,
                        "review",
                        &repo,
                        number,
                        notification_event,
                        submitted,
                        &event_key,
                        &event,
                    )
                    .map_err(|_| Failure::new("database"))?;
                }
                matched += observe_conditions(
                    db,
                    "review",
                    &repo,
                    number,
                    &observations,
                    Some(
                        baseline
                            .as_deref()
                            .or_else(|| observations.iter().map(|o| o.cursor.as_str()).max())
                            .unwrap_or("0"),
                    ),
                    None,
                )? as u64;
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
        let outcome = poll_endpoint(db, &route, 100, now, &mut fetch, |db, cursor, items, _| {
            let mut accepted = 0;
            let current_cursor = deployment_baseline(&items);
            let baseline = cursor
                .map(str::to_owned)
                .or_else(|| current_cursor.clone())
                .unwrap_or_else(|| "0".into());
            let mut observations = Vec::new();
            for status in &items {
                let Some(event_name) = status["state"]
                    .as_str()
                    .filter(|s| matches!(*s, "success" | "failure" | "error"))
                else {
                    continue;
                };
                let Some(id) = positive_id(&status["id"]) else {
                    return Err(Failure::new("invalid_response"));
                };
                let Some(created) = status["created_at"].as_str() else {
                    return Err(Failure::new("invalid_response"));
                };
                let event = json!({"deployment":{"id":resource.resource.parse::<i64>().unwrap_or(0)},
                    "deployment_status":status,"repository":{"full_name":resource.repo}});
                observations.push(ConditionObservation {
                    resource: resource.resource.clone(),
                    event: event_name.to_owned(),
                    outcome: Some(event_name.to_owned()),
                    key: stable_source_key(
                        "deployment",
                        &resource.repo,
                        &resource.resource,
                        event_name,
                        event_name,
                        &[&id, created],
                    ),
                    cursor: deployment_cursor(created, &id),
                    ci: None,
                    order_ambiguous: false,
                    source: event,
                });
            }
            accepted += observe_conditions(
                db,
                "deployment",
                &resource.repo,
                &resource.resource,
                &observations,
                Some(&baseline),
                None,
            )? as u64;
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
            Ok((current_cursor.or(Some(baseline)), accepted))
        })?;
        report.record(outcome);
    }

    for resource in &targets.refs {
        let branch = escape_ref(&resource.resource);
        let route = format!("/repos/{}/git/ref/heads/{branch}", resource.repo);
        let state_route = route.clone();
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
                let prior_poll =
                    state(db, &state_route, 0).map_err(|_| Failure::new("database"))?;
                let baseline = prior_poll
                    .as_ref()
                    .and_then(|state| state.last_success)
                    .map(cursor_number)
                    .or_else(|| Some(cursor_number(now)));
                if cursor.is_some_and(|old| old != sha) {
                    let event = json!({"ref":format!("refs/heads/{name}"),"deleted":false,
                    "after":sha,"repository":{"full_name":repo}});
                    let matched =
                        scoped_subscription_accept(db, "push", &event, &repo, &name, None)? as u64;
                    let old_success = prior_poll
                        .as_ref()
                        .and_then(|state| state.last_success)
                        .unwrap_or(now);
                    let event_cursor = cursor_number(old_success.saturating_add(1));
                    let observation = ConditionObservation {
                        resource: name.clone(),
                        event: "updated".into(),
                        outcome: None,
                        key: stable_source_key(
                            "git_ref",
                            &repo,
                            &name,
                            "updated",
                            "",
                            &[sha, event_cursor.as_str()],
                        ),
                        cursor: event_cursor,
                        ci: None,
                        order_ambiguous: false,
                        source: event.clone(),
                    };
                    let conditions = observe_conditions(
                        db,
                        "git_ref",
                        &repo,
                        &name,
                        &[observation],
                        baseline.as_deref(),
                        None,
                    )? as u64;
                    return Ok((Some(sha.to_owned()), matched + conditions));
                }
                let conditions = observe_conditions(
                    db,
                    "git_ref",
                    &repo,
                    &name,
                    &[],
                    baseline.as_deref(),
                    None,
                )? as u64;
                Ok((Some(sha.to_owned()), conditions))
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
            + targets.rule_prs.len()
            + targets
                .runs
                .values()
                .filter(|target| target.condition_member)
                .count(),
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
    let automatic_notifications_pending = count(
        "automatic_pr_notifications",
        "SELECT count(*) FROM automatic_pr_notifications WHERE state='pending'",
    )?;
    let automatic_notifications_attention = count(
        "automatic_pr_notifications",
        "SELECT count(*) FROM automatic_pr_notifications WHERE state IN ('sending','needs_attention')",
    )?;
    let pr_ci_trackers = count(
        "pr_ci_trackers",
        "SELECT count(*) FROM pr_ci_trackers WHERE active=1",
    )?;
    let pr_ci_pending = count(
        "pr_ci_deliveries",
        "SELECT count(*) FROM pr_ci_deliveries WHERE state='pending'",
    )?;
    let pr_ci_attention = count(
        "pr_ci_deliveries",
        "SELECT count(*) FROM pr_ci_deliveries WHERE state IN ('claimed','needs_attention')",
    )?;
    let pr_ci_errors = count(
        "pr_ci_trackers",
        "SELECT count(*) FROM pr_ci_trackers WHERE active=1 AND error IS NOT NULL",
    )?;
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
        "automatic_pr_notifications":{"pending":automatic_notifications_pending,"needs_attention":automatic_notifications_attention},
        "automatic_pr_ci":{"active":pr_ci_trackers,"pending":pr_ci_pending,"needs_attention":pr_ci_attention,"errors":pr_ci_errors},
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
struct RunTarget {
    wait_shas: BTreeSet<String>,
    condition_member: bool,
}
#[derive(Default)]
struct Targets {
    waits: Vec<Wait>,
    runs: BTreeMap<(String, i64, i64), RunTarget>,
    condition_members: Vec<crate::conditions::PollingMemberStatus>,
    pull_requests: BTreeSet<Resource>,
    reviews: BTreeSet<Resource>,
    deployments: BTreeSet<Resource>,
    refs: BTreeSet<Resource>,
    rule_prs: BTreeSet<Resource>,
}

fn targets(db: &Connection) -> Result<Targets> {
    crate::conditions::initialize(db)?;
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
                out.runs
                    .entry((w.repo.clone(), w.run, w.attempt))
                    .or_default()
                    .wait_shas
                    .insert(w.sha.clone());
                out.waits.push(w);
            }
        }
    }
    out.condition_members = crate::conditions::pending_polling_members(db, None)?;
    for member in &out.condition_members {
        let selector = &member.selector;
        if !valid_repo(&selector.repo) {
            continue;
        }
        let resource = Resource {
            repo: selector.repo.clone(),
            resource: selector.resource.clone(),
        };
        match selector.kind.as_str() {
            "pull_request" if positive_text(&resource.resource) => {
                out.pull_requests.insert(resource);
            }
            "review" if positive_text(&resource.resource) => {
                out.reviews.insert(resource);
            }
            "deployment" if positive_text(&resource.resource) => {
                out.deployments.insert(resource);
            }
            "git_ref" => {
                let branch = selector
                    .resource
                    .strip_prefix("refs/heads/")
                    .unwrap_or(&selector.resource);
                if valid_branch(branch) {
                    out.refs.insert(Resource {
                        repo: selector.repo.clone(),
                        resource: branch.to_owned(),
                    });
                }
            }
            "job" => {
                if let Some(ci) = &member.ci
                    && ci.repo == selector.repo
                    && ci.run_id > 0
                    && ci.attempt > 0
                    && valid_sha(&ci.sha)
                {
                    out.runs
                        .entry((ci.repo.clone(), ci.run_id, ci.attempt))
                        .or_default()
                        .condition_member = true;
                }
            }
            _ => {}
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
    {
        let mut s = db.prepare("SELECT kind,repo,pr FROM automatic_pr_notification_listeners")?;
        for row in s.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })? {
            let (kind, repo, pr) = row?;
            if !valid_repo(&repo) || !positive_text(&pr) {
                continue;
            }
            let target = Resource { repo, resource: pr };
            match kind.as_str() {
                "pull_request" => {
                    out.pull_requests.insert(target);
                }
                "review" => {
                    out.reviews.insert(target);
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

struct ConditionObservation {
    resource: String,
    event: String,
    outcome: Option<String>,
    key: String,
    cursor: String,
    ci: Option<crate::conditions::CiRunIdentity>,
    order_ambiguous: bool,
    source: Value,
}

fn observe_conditions(
    db: &Connection,
    kind: &str,
    repo: &str,
    resource: &str,
    observations: &[ConditionObservation],
    baseline: Option<&str>,
    ci: Option<(&str, i64)>,
) -> std::result::Result<usize, Failure> {
    db.execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| Failure::new("database"))?;
    let result = (|| {
        let pending = crate::conditions::pending_polling_members(db, None)
            .map_err(|_| Failure::new("database"))?;
        let mut count = 0;
        for member in pending.into_iter().filter(|member| {
            member.group_state == "pending"
                && member.selector.kind == kind
                && member.selector.repo == repo
                && (kind != "job"
                    || ci.is_some_and(|(sha, attempt)| {
                        member.ci.as_ref().is_some_and(|identity| {
                            identity.sha == sha && identity.attempt == attempt
                        })
                    }))
                && (if kind == "job" {
                    member
                        .ci
                        .as_ref()
                        .is_some_and(|ci| ci.repo == repo && ci.run_id.to_string() == resource)
                } else if kind == "git_ref" {
                    member
                        .selector
                        .resource
                        .strip_prefix("refs/heads/")
                        .unwrap_or(&member.selector.resource)
                        == resource
                } else {
                    member.selector.resource == resource
                })
        }) {
            if kind == "pull_request" {
                let uncertain: bool = db
                    .query_row(
                        "SELECT order_uncertain FROM condition_members
                         WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3
                           AND event=?4 AND outcome=?5",
                        rusqlite::params![
                            member.group_id,
                            repo,
                            member.selector.resource,
                            member.selector.event,
                            member.selector.outcome.as_deref().unwrap_or("")
                        ],
                        |row| row.get(0),
                    )
                    .map_err(|_| Failure::new("database"))?;
                let observation =
                    observations.iter().find(|observation| {
                        observation.event == member.selector.event
                            && observation.resource == member.selector.resource
                            && member.selector.outcome.as_deref().is_none_or(|expected| {
                                observation.outcome.as_deref() == Some(expected)
                            })
                    });
                let order_unknown = if let Some(observation) = observation {
                    if observation.order_ambiguous {
                        true
                    } else if member.armed {
                        false
                    } else {
                        let event_time = observation
                            .source
                            .pointer("/pull_request/updated_at")
                            .and_then(Value::as_str)
                            .ok_or_else(|| Failure::new("invalid_response"))?;
                        let registered: String = db
                            .query_row(
                                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ',created) FROM condition_groups WHERE id=?1",
                                [&member.group_id],
                                |row| row.get(0),
                            )
                            .map_err(|_| Failure::new("database"))?;
                        event_time <= registered.as_str()
                    }
                } else {
                    false
                };
                if let Some(observation) = observation.filter(|_| order_unknown && !uncertain) {
                    // Persist the member ambiguity and its buffered event atomically.
                    let event_time = observation
                        .source
                        .pointer("/pull_request/updated_at")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Failure::new("invalid_response"))?;
                    let marked = db
                        .execute(
                            "UPDATE condition_members
                             SET armed=0,order_uncertain=1,ambiguous_cursor=?1,last_cursor=?2
                             WHERE group_id=?3 AND kind='pull_request' AND repo=?4 AND resource=?5
                               AND event=?6 AND outcome=?7 AND polling=1 AND matched=0
                               AND EXISTS(SELECT 1 FROM condition_groups g
                                          WHERE g.id=condition_members.group_id AND g.state='pending')",
                            rusqlite::params![
                                event_time,
                                observation.cursor,
                                member.group_id,
                                repo,
                                member.selector.resource,
                                member.selector.event,
                                member.selector.outcome.as_deref().unwrap_or("")
                            ],
                        )
                        .map_err(|_| Failure::new("database"))?;
                    if marked == 0 {
                        continue;
                    }
                    // This observation has unknown ordering; do not publish it globally,
                    // where it could satisfy an armed or explicit member immediately.
                    let source = serde_json::to_string(&observation.source)
                        .map_err(|_| Failure::new("invalid_response"))?;
                    if source.len() > MAX_OUTPUT {
                        return Err(Failure::new("invalid_response"));
                    }
                    let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
                    let candidate_key = stable_source_key(
                        "pull_request",
                        repo,
                        &member.selector.resource,
                        &observation.event,
                        "",
                        &[event_time, &observation.cursor],
                    );
                    db.execute(
                        "INSERT OR IGNORE INTO condition_pending_events
                         (group_id,kind,repo,resource,event,outcome,source_event_key,event_cursor,source_digest,source_json)
                         SELECT group_id,kind,repo,resource,event,outcome,?1,?2,?3,?4
                         FROM condition_members m WHERE group_id=?5 AND kind='pull_request'
                           AND repo=?6 AND resource=?7 AND event=?8 AND outcome=?9",
                        rusqlite::params![candidate_key, observation.cursor, digest, source,
                            member.group_id, repo, member.selector.resource, member.selector.event,
                            member.selector.outcome.as_deref().unwrap_or("")],
                    )
                    .map_err(|_| Failure::new("database"))?;
                    continue;
                }
                if uncertain {
                    // A later, observed open-to-closed transition is known to be
                    // newer than the ambiguous first observation.
                    if let Some(observation) = observations.iter().find(|observation| {
                        !observation.order_ambiguous
                            && observation.event == member.selector.event
                            && observation.resource == member.selector.resource
                            && member.selector.outcome.as_deref().is_none_or(|expected| {
                                observation.outcome.as_deref() == Some(expected)
                            })
                    }) {
                        let source = serde_json::to_string(&observation.source)
                            .map_err(|_| Failure::new("invalid_response"))?;
                        if source.len() > MAX_OUTPUT {
                            return Err(Failure::new("invalid_response"));
                        }
                        let digest = format!("{:x}", Sha256::digest(source.as_bytes()));
                        db.execute(
                            "DELETE FROM condition_pending_events WHERE group_id=?1 AND kind='pull_request'
                             AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5",
                            rusqlite::params![member.group_id, repo, member.selector.resource,
                                member.selector.event, member.selector.outcome.as_deref().unwrap_or("")],
                        ).map_err(|_| Failure::new("database"))?;
                        db.execute(
                            "INSERT INTO condition_pending_events
                             (group_id,kind,repo,resource,event,outcome,source_event_key,event_cursor,source_digest,source_json)
                             VALUES(?1,'pull_request',?2,?3,?4,?5,?6,?7,?8,?9)",
                            rusqlite::params![member.group_id, repo, member.selector.resource,
                                member.selector.event, member.selector.outcome.as_deref().unwrap_or(""),
                                observation.key, observation.cursor, digest, source],
                        ).map_err(|_| Failure::new("database"))?;
                        db.execute(
                            "UPDATE condition_members SET buffer_overflow=0,buffer_overflow_count=0
                             WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5",
                            rusqlite::params![member.group_id, repo, member.selector.resource,
                                member.selector.event, member.selector.outcome.as_deref().unwrap_or("")],
                        ).map_err(|_| Failure::new("database"))?;
                        let registration = crate::conditions::MemberRegistration::polling(
                            member.selector.clone(),
                            None,
                        );
                        crate::conditions::arm_observed_member_in(
                            db,
                            &member.group_id,
                            &registration,
                            Some("0"),
                        )
                        .map_err(|_| Failure::new("database"))?;
                        db.execute(
                            "UPDATE condition_members SET order_uncertain=0,ambiguous_cursor=NULL
                             WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5",
                            rusqlite::params![member.group_id, repo, member.selector.resource,
                                member.selector.event, member.selector.outcome.as_deref().unwrap_or("")],
                        ).map_err(|_| Failure::new("database"))?;
                        let event = crate::conditions::PublishedEvent {
                            selector: member.selector.clone(),
                            source_event_key: observation.key.clone(),
                            cursor: Some(observation.cursor.clone()),
                            ci: None,
                            source: observation.source.clone(),
                        };
                        let recorded = crate::conditions::record_published_event_in(db, &event)
                            .map_err(|_| Failure::new("database"))?;
                        if recorded.payload_collision {
                            return Err(Failure::new("identity_mismatch"));
                        }
                        count += recorded.ready_groups;
                    }
                    continue;
                }
            }
            if kind == "job" && !member.armed {
                let ci = member
                    .ci
                    .as_ref()
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                let uncertain: bool = db.query_row("SELECT order_uncertain FROM condition_members WHERE group_id=?1 AND kind=?2 AND repo=?3 AND resource=?4 AND event=?5 AND outcome=?6 AND ci_run_id=?7 AND ci_attempt=?8 AND ci_sha=?9",rusqlite::params![member.group_id,kind,repo,member.selector.resource,member.selector.event,member.selector.outcome.as_deref().unwrap_or(""),ci.run_id,ci.attempt,ci.sha],|row|row.get(0)).map_err(|_| Failure::new("database"))?;
                if uncertain {
                    continue;
                }
            }
            let member_registration = crate::conditions::MemberRegistration::polling(
                member.selector.clone(),
                member.ci.clone(),
            );
            let member_baseline = if member.armed {
                member.baseline_cursor.as_deref()
            } else if kind == "job" {
                Some("0")
            } else {
                baseline
            };
            let Some(member_baseline) = member_baseline else {
                return Err(Failure::new("invalid_baseline"));
            };
            // A completed first observation has no trustworthy ordering against registration.
            if kind == "job"
                && !member.armed
                && let Some(observation) = observations.iter().find(|event| {
                    event.event == member.selector.event
                        && event.resource == member.selector.resource
                        && event.ci == member.ci
                        && member
                            .selector
                            .outcome
                            .as_deref()
                            .is_none_or(|expected| event.outcome.as_deref() == Some(expected))
                })
            {
                let event = crate::conditions::PublishedEvent {
                    selector: crate::conditions::Selector {
                        kind: kind.into(),
                        repo: repo.into(),
                        resource: member.selector.resource.clone(),
                        event: observation.event.clone(),
                        outcome: observation.outcome.clone(),
                    },
                    source_event_key: observation.key.clone(),
                    cursor: Some(observation.cursor.clone()),
                    ci: observation.ci.clone(),
                    source: observation.source.clone(),
                };
                crate::conditions::record_published_event_in(db, &event)
                    .map_err(|_| Failure::new("database"))?;
                let ci = member
                    .ci
                    .as_ref()
                    .ok_or_else(|| Failure::new("invalid_response"))?;
                db.execute("UPDATE condition_members SET order_uncertain=1,ambiguous_cursor=?1 WHERE group_id=?2 AND kind=?3 AND repo=?4 AND resource=?5 AND event=?6 AND outcome=?7 AND ci_run_id=?8 AND ci_attempt=?9 AND ci_sha=?10",rusqlite::params![observation.cursor,member.group_id,kind,repo,member.selector.resource,member.selector.event,member.selector.outcome.as_deref().unwrap_or(""),ci.run_id,ci.attempt,ci.sha]).map_err(|_| Failure::new("database"))?;
                continue;
            }
            for observation in observations.iter().filter(|observation| {
                observation.event == member.selector.event
                    && (kind != "job" || observation.resource == member.selector.resource)
                    && member
                        .selector
                        .outcome
                        .as_deref()
                        .is_none_or(|expected| observation.outcome.as_deref() == Some(expected))
                    && (kind != "job" || observation.ci == member.ci)
                    && observation.cursor.as_str() > member_baseline
                    && member
                        .last_cursor
                        .as_deref()
                        .is_none_or(|last| observation.cursor.as_str() > last)
            }) {
                let published = crate::conditions::PublishedEvent {
                    selector: crate::conditions::Selector {
                        kind: kind.to_owned(),
                        repo: repo.to_owned(),
                        resource: member.selector.resource.clone(),
                        event: observation.event.clone(),
                        outcome: observation.outcome.clone(),
                    },
                    source_event_key: if kind == "git_ref" {
                        stable_source_key(
                            kind,
                            repo,
                            &member.selector.resource,
                            &observation.event,
                            observation.outcome.as_deref().unwrap_or(""),
                            &[&observation.key],
                        )
                    } else {
                        observation.key.clone()
                    },
                    cursor: Some(observation.cursor.clone()),
                    ci: observation.ci.clone(),
                    source: observation.source.clone(),
                };
                let recorded = crate::conditions::record_published_event_in(db, &published)
                    .map_err(|_| Failure::new("database"))?;
                if recorded.payload_collision {
                    return Err(Failure::new("identity_mismatch"));
                }
                count += recorded.ready_groups;
            }
            if !member.armed {
                crate::conditions::arm_observed_member_in(
                    db,
                    &member.group_id,
                    &member_registration,
                    Some(member_baseline),
                )
                .map_err(|_| Failure::new("database"))?;
            }
        }
        Ok(count)
    })();
    match result {
        Ok(count) => match db.execute_batch("COMMIT") {
            Ok(()) => Ok(count),
            Err(_) => {
                let _ = db.execute_batch("ROLLBACK");
                Err(Failure::new("database"))
            }
        },
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

pub fn resolve_pr_condition_order(
    db: &Connection,
    group_id: &str,
    resource: &str,
    event: &str,
    accept: bool,
) -> Result<bool> {
    anyhow::ensure!(matches!(event, "closed" | "merged"), "Unsupported PR event");
    let (repo, resource) = match resource.split_once('#') {
        Some((repo, number)) => {
            anyhow::ensure!(
                valid_repo(repo) && positive_text(number),
                "Invalid PR resource"
            );
            (Some(repo), number)
        }
        None => (None, resource),
    };
    let tx = rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let candidates: Vec<_> = crate::conditions::pending_polling_members(&tx, Some(group_id))?
        .into_iter()
        .filter(|member| {
            member.selector.kind == "pull_request"
                && member.selector.resource == resource
                && member.selector.event == event
                && repo.is_none_or(|repo| member.selector.repo == repo)
                && !member.armed
        })
        .collect();
    anyhow::ensure!(
        candidates.len() == 1,
        "Expected exactly one pending PR member; use owner/repo#number when needed"
    );
    let member = &candidates[0];
    let (cursor, event_time): (String, String) = tx.query_row(
        "SELECT last_cursor,ambiguous_cursor FROM condition_members
         WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4
           AND outcome=?5 AND order_uncertain=1",
        rusqlite::params![
            group_id,
            member.selector.repo,
            resource,
            event,
            member.selector.outcome.as_deref().unwrap_or("")
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let key = stable_source_key(
        "pull_request",
        &member.selector.repo,
        resource,
        event,
        "",
        &[&event_time, &cursor],
    );
    let retained: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM condition_pending_events
         WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4
           AND outcome=?5 AND source_event_key=?6 AND event_cursor=?7)",
        rusqlite::params![
            group_id,
            member.selector.repo,
            resource,
            event,
            member.selector.outcome.as_deref().unwrap_or(""),
            key,
            cursor
        ],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        retained,
        "Ambiguous PR event was not retained in the member buffer"
    );
    tx.execute(
        "DELETE FROM condition_pending_events WHERE group_id=?1 AND kind='pull_request'
         AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5
         AND (CASE WHEN ?6 THEN source_event_key<>?7 ELSE source_event_key=?7 END)",
        rusqlite::params![
            group_id,
            member.selector.repo,
            resource,
            event,
            member.selector.outcome.as_deref().unwrap_or(""),
            accept,
            key
        ],
    )?;
    if accept {
        tx.execute(
            "UPDATE condition_members SET buffer_overflow=0,buffer_overflow_count=0
             WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5",
            rusqlite::params![group_id, member.selector.repo, resource, event,
                member.selector.outcome.as_deref().unwrap_or("")],
        )?;
    }
    let registration =
        crate::conditions::MemberRegistration::polling(member.selector.clone(), None);
    let changed = crate::conditions::arm_observed_member_in(
        &tx,
        group_id,
        &registration,
        Some(if accept { "0" } else { &cursor }),
    )?;
    tx.execute(
        "UPDATE condition_members SET order_uncertain=0,ambiguous_cursor=NULL
         WHERE group_id=?1 AND kind='pull_request' AND repo=?2 AND resource=?3 AND event=?4
           AND outcome=?5 AND order_uncertain=1",
        rusqlite::params![
            group_id,
            member.selector.repo,
            resource,
            member.selector.event,
            member.selector.outcome.as_deref().unwrap_or("")
        ],
    )?;
    tx.commit()?;
    Ok(changed)
}

pub fn resolve_ci_condition_order(
    db: &Connection,
    group_id: &str,
    resource: &str,
    ci: Option<(String, i64, i64, String)>,
    event: Option<&str>,
    outcome: Option<&str>,
    accept: bool,
) -> Result<bool> {
    let tx = rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
    let members: Vec<_> = crate::conditions::pending_polling_members(&tx, Some(group_id))?
        .into_iter()
        .filter(|m| {
            m.selector.kind == "job"
                && m.selector.resource == resource
                && !m.armed
                && ci.as_ref().is_none_or(|(ci_repo, run_id, attempt, sha)| {
                    m.ci.as_ref().is_some_and(|identity| {
                        identity.repo == *ci_repo
                            && identity.run_id == *run_id
                            && identity.attempt == *attempt
                            && identity.sha == *sha
                    })
                })
                && event.is_none_or(|event| m.selector.event == event)
                && outcome.is_none_or(|outcome| m.selector.outcome.as_deref() == Some(outcome))
        })
        .collect();
    anyhow::ensure!(
        members.len() == 1,
        "Expected exactly one pending CI member; provide ci, member_event, and member_outcome when needed"
    );
    let member = &members[0];
    let ci = member
        .ci
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing CI identity"))?;
    let cursor: String = tx.query_row("SELECT ambiguous_cursor FROM condition_members WHERE group_id=?1 AND kind='job' AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5 AND ci_run_id=?6 AND ci_attempt=?7 AND ci_sha=?8 AND order_uncertain=1",rusqlite::params![group_id,member.selector.repo,resource,member.selector.event,member.selector.outcome.as_deref().unwrap_or(""),ci.run_id,ci.attempt,ci.sha],|row|row.get(0))?;
    let registration =
        crate::conditions::MemberRegistration::polling(member.selector.clone(), member.ci.clone());
    let changed = crate::conditions::arm_observed_member_in(
        &tx,
        group_id,
        &registration,
        Some(if accept { "0" } else { &cursor }),
    )?;
    tx.execute("UPDATE condition_members SET order_uncertain=0,ambiguous_cursor=NULL WHERE group_id=?1 AND kind='job' AND repo=?2 AND resource=?3 AND event=?4 AND outcome=?5 AND ci_run_id=?6 AND ci_attempt=?7 AND ci_sha=?8",rusqlite::params![group_id,member.selector.repo,resource,member.selector.event,member.selector.outcome.as_deref().unwrap_or(""),ci.run_id,ci.attempt,ci.sha])?;
    tx.commit()?;
    Ok(changed)
}

fn stable_source_key(
    kind: &str,
    repo: &str,
    resource: &str,
    event: &str,
    outcome: &str,
    identity: &[&str],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"codex-wake/github-poll-event/v1\0");
    for field in [kind, repo, resource, event, outcome]
        .into_iter()
        .chain(identity.iter().copied())
    {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("github-poll-v1:{:x}", hash.finalize())
}

fn cursor_number(value: i64) -> String {
    format!("{:020}", value.max(0))
}

fn review_cursor(submitted: &str, id: &str) -> String {
    format!("{submitted}|{id:0>20}")
}

fn review_baseline(previous: &BTreeMap<String, String>) -> Option<String> {
    previous
        .iter()
        .filter_map(|(id, version)| {
            let submitted = version.split('|').next()?;
            (!submitted.is_empty()).then(|| review_cursor(submitted, id))
        })
        .max()
}

fn deployment_cursor(created: &str, id: &str) -> String {
    format!("{created}|{id:0>20}")
}

fn deployment_baseline(items: &[Value]) -> Option<String> {
    items
        .iter()
        .filter_map(|item| {
            let created = item["created_at"].as_str()?;
            let id = positive_id(&item["id"])?;
            Some(deployment_cursor(created, &id))
        })
        .max()
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
    let generation = poll_generation(db, route)?;
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
                record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
            record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
                record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
                record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
                    record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
                record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
            record_fetch_failure(db, route, first, now, &e, requests, generation)?;
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
            record_fetch_failure(db, route, first, now, &e, requests, generation)?;
            return Ok(EndpointOutcome {
                error: Some(e.category),
                calls: requests,
                pages: page_updates.len() as u64,
                accepted: 0,
                skipped: false,
            });
        }
    }
    // Serialize acceptance and discard a response fetched before another commit.
    let _guard = PollCommitGuard::acquire(db)?;
    if poll_generation(db, route)? != generation {
        return Ok(EndpointOutcome {
            error: None,
            calls: requests,
            pages: requests,
            accepted: 0,
            skipped: true,
        });
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
    last_success: Option<i64>,
}

fn poll_generation(db: &Connection, route: &str) -> Result<i64> {
    Ok(db
        .query_row(
            "SELECT generation FROM github_poll_generation WHERE endpoint=?1",
            [route],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

// Lock the containing directory instead of a sidecar: unlinking a sidecar can
// otherwise split waiters across two inodes during cleanup.
struct PollCommitGuard {
    _local: std::sync::MutexGuard<'static, ()>,
    _file: Option<std::fs::File>,
}
impl PollCommitGuard {
    fn acquire(db: &Connection) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        static LOCAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let local = LOCAL
            .lock()
            .map_err(|_| anyhow::anyhow!("poll commit lock poisoned"))?;
        let file = if let Some(path) = db.path().filter(|p| !p.is_empty()) {
            let canonical = std::fs::canonicalize(path)?;
            let database = std::fs::metadata(&canonical)?;
            anyhow::ensure!(
                database.is_file() && database.nlink() == 1,
                "polling database must have one link"
            );
            let file = lock_database_parent(&canonical, false)?;
            let after = std::fs::metadata(&canonical)?;
            anyhow::ensure!(
                after.dev() == database.dev()
                    && after.ino() == database.ino()
                    && after.nlink() == 1,
                "polling database changed during lock acquisition"
            );
            Some(file)
        } else {
            None
        };
        Ok(Self {
            _local: local,
            _file: file,
        })
    }
}

pub(crate) fn lock_database_parent(path: &Path, nonblocking: bool) -> Result<std::fs::File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database has no parent"))?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(parent)?;
    let mode = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), mode) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}
struct PageUpdate {
    page: usize,
    body: String,
    etag: Option<String>,
    has_next: bool,
}
fn state(db: &Connection, endpoint: &str, page: usize) -> Result<Option<State>> {
    Ok(db.query_row("SELECT etag,body,cursor,has_next,next_poll_ms,backoff_ms,last_success_ms FROM github_poll_state WHERE endpoint=?1 AND page=?2",params![endpoint,page as i64],|r|Ok(State{etag:r.get(0)?,body:r.get(1)?,cursor:r.get(2)?,has_next:r.get::<_,i64>(3)?!=0,next_poll:r.get(4)?,backoff:r.get(5)?,last_success:r.get(6)?})).optional()?)
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
        db.execute("INSERT INTO github_poll_generation(endpoint,generation) VALUES(?1,1) ON CONFLICT(endpoint) DO UPDATE SET generation=generation+1", [route])?;
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
fn record_fetch_failure(
    db: &Connection,
    route: &str,
    page: usize,
    now: i64,
    e: &Failure,
    calls: u64,
    generation: i64,
) -> Result<()> {
    let _guard = PollCommitGuard::acquire(db)?;
    if poll_generation(db, route)? == generation {
        record_failure(db, route, page, now, e, calls)?;
    }
    Ok(())
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
    crate::subscriptions::initialize(db).map_err(|_| Failure::new("database"))?;
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
    let mut s=db.prepare("SELECT id,kind,repo,resource,event,thread,state,outcome,reason,updated,message_template,source_json,execution_json,required_source FROM subscriptions WHERE state='waiting' AND kind=?1 AND repo=?2 AND resource=?3 AND (?4 IS NULL OR datetime(updated)<=datetime(?4))").map_err(|_|Failure::new("database"))?;
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
                r.get::<_, Option<String>>(13)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?;
    for row in rows {
        candidate.execute("INSERT INTO subscriptions(id,kind,repo,resource,event,thread,state,outcome,reason,updated,message_template,source_json,execution_json,required_source) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![row.0,row.1,row.2,row.3,row.4,row.5,row.6,row.7,row.8,row.9,row.10,row.11,row.12,row.13]).map_err(|_|Failure::new("database"))?;
    }
    crate::subscriptions::accept(&candidate, header, payload)
        .map_err(|_| Failure::new("accept"))?;
    let ready = {
        let mut s = candidate
            .prepare("SELECT id,outcome,reason,source_json,source_event_key FROM subscriptions WHERE state='ready'")
            .map_err(|_| Failure::new("database"))?;
        s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|_| Failure::new("database"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| Failure::new("database"))?
    };
    db.execute_batch("BEGIN IMMEDIATE")
        .map_err(|_| Failure::new("database"))?;
    let result: std::result::Result<usize, Failure> = (|| {
        // BEGIN IMMEDIATE acquires the writer lock before sampling the clock.
        let now = now_ms();
        crate::subscriptions::expire_due_in_transaction(db, now)
            .map_err(|_| Failure::new("database"))?;
        let mut count = 0;
        for (id, outcome, reason, source, source_event_key) in ready {
            count += db.execute(
                "UPDATE subscriptions SET state='ready',outcome=?1,reason=?2,source_event_key=?5,
                    source_json=CASE WHEN message_template IS NOT NULL OR required_source IS NOT NULL
                        THEN ?3 ELSE source_json END,updated=CURRENT_TIMESTAMP
                 WHERE id=?4 AND state='waiting' AND (expires_at_ms IS NULL OR expires_at_ms>?6)",
                params![outcome, reason, source, id, source_event_key, now],
            ).map_err(|_| Failure::new("database"))?;
        }
        Ok(count)
    })();
    match result {
        Ok(count) => match db.execute_batch("COMMIT") {
            Ok(()) => Ok(count),
            Err(_) => {
                let _ = db.execute_batch("ROLLBACK");
                Err(Failure::new("database"))
            }
        },
        Err(error) => {
            let _ = db.execute_batch("ROLLBACK");
            Err(error)
        }
    }
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
            .prepare("SELECT rule_id,event_header,comment_id,source,source_event_key,event_identity_verified FROM rule_deliveries")
            .map_err(|_| Failure::new("database"))?;
        s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, bool>(5)?,
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
    for (id, event, comment, source, source_event_key, identity_verified) in pending {
        count+=tx.execute("INSERT OR IGNORE INTO rule_deliveries(rule_id,event_header,comment_id,source,source_event_key,event_identity_verified) VALUES(?1,?2,?3,?4,?5,?6)",params![id,event,comment,source,source_event_key,identity_verified]).map_err(|_|Failure::new("database"))?;
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
    use std::sync::atomic::{AtomicBool, Ordering};

    static POLLING_WRITER_LOCK_BUSY: AtomicBool = AtomicBool::new(false);

    fn mark_polling_writer_lock_busy(_: i32) -> bool {
        POLLING_WRITER_LOCK_BUSY.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(2));
        true
    }

    type Fetch<'a> =
        dyn FnMut(&str, Option<&str>) -> std::result::Result<HttpResponse, Failure> + 'a;

    #[test]
    fn failed_poll_save_does_not_replay_an_uncertain_wait_delivery() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/state.sqlite3");
        let mut db = crate::bridge::connect(&path).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let sha = "a".repeat(40);
        crate::bridge::register(
            &db,
            "owner/repo",
            123,
            1,
            "11111111-1111-4111-8111-111111111111",
            &sha,
        )
        .unwrap();
        db.execute_batch("CREATE TRIGGER fail_poll_save BEFORE INSERT ON github_poll_generation BEGIN SELECT RAISE(FAIL,'injected'); END").unwrap();
        let payload = json!({"action":"completed","repository":{"full_name":"owner/repo"},"workflow_run":{"id":123,"run_attempt":1,"head_sha":sha,"status":"completed","conclusion":"success"}});
        let run = || response(payload["workflow_run"].clone(), false);
        let mut fetch = |_: &str, _: Option<&str>| Ok(run());
        let process = |db: &Connection, _: Option<&str>, _: Vec<Value>, _: i64| {
            Ok((None, u64::from(bridge_accept(db, &payload)? == "recorded")))
        };
        assert!(poll_endpoint(&db, "test-run", 0, 1, &mut fetch, process).is_err());
        let calls = dir.path().join("calls");
        let codex = dir.path().join("fake-codex");
        std::fs::write(
            &codex,
            format!("#!/bin/sh\necho attempt >> '{}'\nexit 1\n", calls.display()),
        )
        .unwrap();
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            crate::bridge::dispatch(&mut db, &codex, Duration::from_secs(2)).unwrap(),
            1
        );
        let state: String = db
            .query_row("SELECT state FROM waits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "needs_attention");
        db.execute_batch("DROP TRIGGER fail_poll_save").unwrap();
        let outcome = poll_endpoint(&db, "test-run", 0, 1, &mut fetch, process).unwrap();
        // bridge::accept reports "recorded" for both a new record and a duplicate.
        assert_eq!(outcome.accepted, 1);
        assert_eq!(
            crate::bridge::dispatch(&mut db, &codex, Duration::from_secs(2)).unwrap(),
            0
        );
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 1);
        let state: String = db
            .query_row("SELECT state FROM waits", [], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "needs_attention");
    }

    #[test]
    fn failed_poll_save_does_not_replay_an_uncertain_subscription() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mut db = crate::bridge::connect(&dir.path().join("state/state.sqlite3")).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let id = subscribe(&db, "git_ref", "topic/test", "updated");
        let value = |sha: &str| {
            response(
                json!({"ref":"refs/heads/topic/test","object":{"sha":sha.repeat(40)}}),
                false,
            )
        };
        tick_with(&db, 1, |_, _| Ok(value("a"))).unwrap();
        db.execute_batch("CREATE TRIGGER fail_poll_save BEFORE UPDATE ON github_poll_generation BEGIN SELECT RAISE(FAIL,'injected'); END").unwrap();
        assert!(tick_with(&db, INTERVAL_MS + 1, |_, _| Ok(value("b"))).is_err());
        let calls = dir.path().join("calls");
        let codex = dir.path().join("fake-codex");
        std::fs::write(
            &codex,
            format!("#!/bin/sh\necho attempt >> '{}'\nexit 1\n", calls.display()),
        )
        .unwrap();
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            crate::subscriptions::dispatch(&mut db, &codex, Duration::from_secs(2)).unwrap(),
            1
        );
        assert_eq!(registration_state(&db, &id), "needs_attention");
        db.execute_batch("DROP TRIGGER fail_poll_save").unwrap();
        let event = json!({"ref":"refs/heads/topic/test","deleted":false,"after":"b".repeat(40),"repository":{"full_name":"owner/repo"}});
        assert_eq!(
            scoped_subscription_accept(&db, "push", &event, "owner/repo", "topic/test", None)
                .unwrap(),
            0
        );
        assert_eq!(
            crate::subscriptions::dispatch(&mut db, &codex, Duration::from_secs(2)).unwrap(),
            0
        );
        assert_eq!(std::fs::read_to_string(calls).unwrap().lines().count(), 1);
        assert_eq!(registration_state(&db, &id), "needs_attention");
    }

    #[test]
    fn polling_rejects_hard_linked_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let db = Connection::open(&path).unwrap();
        std::fs::hard_link(&path, dir.path().join("alias.sqlite")).unwrap();
        assert!(PollCommitGuard::acquire(&db).is_err());
    }

    #[test]
    fn stale_response_from_another_process_does_not_regress_cursor() {
        use std::{process::Command, thread};
        fn wait_for(path: &Path) {
            let end = Instant::now() + Duration::from_secs(10);
            while !path.exists() {
                assert!(
                    Instant::now() < end,
                    "timed out waiting for {}",
                    path.display()
                );
                thread::sleep(Duration::from_millis(5));
            }
        }
        let value = |sha: &str| {
            response(
                json!({"ref":"refs/heads/topic/test","object":{"sha":sha.repeat(40)}}),
                false,
            )
        };
        if let Some(dir) = std::env::var_os("WAKE_STALE_POLL_TEST_DIR") {
            let dir = std::path::PathBuf::from(dir);
            let db = Connection::open(dir.join("state.sqlite")).unwrap();
            db.busy_timeout(Duration::from_secs(5)).unwrap();
            let result = tick_with(&db, INTERVAL_MS + 1, |_, _| {
                std::fs::write(dir.join("started"), b"").unwrap();
                wait_for(&dir.join("release"));
                Ok(value("b"))
            })
            .unwrap();
            assert_eq!(result["accepted"], 0);
            assert_eq!(result["skipped"], 1);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = Connection::open(dir.path().join("state.sqlite")).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db.execute_batch(
            "CREATE TABLE waits(repo TEXT,run_id INTEGER,attempt INTEGER,sha TEXT,state TEXT)",
        )
        .unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let id = subscribe(&db, "git_ref", "topic/test", "updated");
        tick_with(&db, 1, |_, _| Ok(value("a"))).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "polling::tests::stale_response_from_another_process_does_not_regress_cursor",
                "--nocapture",
            ])
            .env("WAKE_STALE_POLL_TEST_DIR", dir.path())
            .spawn()
            .unwrap();
        wait_for(&dir.path().join("started"));
        tick_with(&db, INTERVAL_MS + 1, |_, _| Ok(value("c"))).unwrap();
        std::fs::write(dir.path().join("release"), b"").unwrap();
        assert!(child.wait().unwrap().success());
        let route = "/repos/owner/repo/git/ref/heads/topic/test";
        assert_eq!(
            state(&db, route, 0).unwrap().unwrap().cursor.as_deref(),
            Some("c".repeat(40).as_str())
        );
        assert_eq!(registration_state(&db, &id), "ready");
    }

    #[test]
    fn condition_ci_poll_deduplicates_wait_request_and_checks_exact_run_identity() {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let db = crate::bridge::connect(&dir.path().join("state.sqlite")).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        let sha = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0";
        let thread = "11111111-1111-4111-8111-111111111111";
        crate::bridge::register(&db, "owner/repo", 42, 3, thread, sha).unwrap();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let ci = crate::conditions::CiRunIdentity {
            repo: "owner/repo".into(),
            run_id: 42,
            attempt: 3,
            sha: sha.into(),
        };
        let member = crate::conditions::MemberRegistration::polling(selector, Some(ci));
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            thread,
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_groups SET created='2026-11-08 09:00:00' WHERE id=?1",
            [&group],
        )
        .unwrap();
        let body = json!({
            "id":42,"run_attempt":3,"head_sha":sha,"status":"completed",
            "conclusion":"success","created_at":"2026-11-08T10:00:00Z",
            "completed_at":"2026-11-08T10:01:00Z"
        });
        let mut calls = 0;
        let mut running = body.clone();
        running["status"] = json!("in_progress");
        tick_with(&db, 1, |route, _| {
            calls += 1;
            assert_eq!(route, "/repos/owner/repo/actions/runs/42/attempts/3");
            Ok(response(running.clone(), false))
        })
        .unwrap();
        let result = tick_with(&db, INTERVAL_MS + 1, |route, _| {
            calls += 1;
            assert_eq!(route, "/repos/owner/repo/actions/runs/42/attempts/3");
            Ok(response(body.clone(), false))
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(result["active_waits"], 1);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
        let wait_state: String = db
            .query_row(
                "SELECT state FROM waits WHERE repo='owner/repo' AND run_id=42 AND attempt=3",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wait_state, "ready");
    }

    #[test]
    fn condition_ci_events_are_scoped_to_their_job_resource() {
        let db = db();
        let sha = "a".repeat(40);
        let ci = crate::conditions::CiRunIdentity {
            repo: "owner/repo".into(),
            run_id: 42,
            attempt: 1,
            sha: sha.clone(),
        };
        let register = |resource: &str, thread: &str| {
            let member = crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "job".into(),
                    repo: "owner/repo".into(),
                    resource: resource.into(),
                    event: "completed".into(),
                    outcome: Some("success".into()),
                },
                Some(ci.clone()),
            );
            crate::conditions::register_group_with_members(
                &db,
                crate::conditions::Mode::Or,
                &[member],
                thread,
                None,
                None,
            )
            .unwrap()
        };
        let build = register("build", "11111111-1111-4111-8111-111111111111");
        let deploy = register("deploy", "22222222-2222-4222-8222-222222222222");
        let poll = |now, run: Value| {
            tick_with(&db, now, |route, _| {
                assert_eq!(route, "/repos/owner/repo/actions/runs/42/attempts/1");
                Ok(response(run.clone(), false))
            })
            .unwrap()
        };
        let mut run = json!({
            "id":42,"run_attempt":1,"head_sha":sha,"status":"in_progress",
            "created_at":"2026-11-08T10:00:00Z","completed_at":null
        });
        let baseline = poll(1, run.clone());
        assert_eq!(baseline["errors"], json!({}), "{baseline}");
        run["status"] = json!("completed");
        run["conclusion"] = json!("success");
        run["completed_at"] = json!("2026-11-08T10:01:00Z");
        let completed = poll(INTERVAL_MS + 1, run);
        assert_eq!(completed["errors"], json!({}), "{completed}");
        let ready = [
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(ready, BTreeSet::from([build, deploy]));
    }

    #[test]
    fn ci_completion_after_running_baseline_ignores_clock_skew() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let ci = crate::conditions::CiRunIdentity {
            repo: "owner/repo".into(),
            run_id: 42,
            attempt: 1,
            sha: "a".repeat(40),
        };
        let member = crate::conditions::MemberRegistration::polling(selector, Some(ci.clone()));
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_groups SET created='2035-01-01 00:00:00' WHERE id=?1",
            [&group],
        )
        .unwrap();
        observe_conditions(
            &db,
            "job",
            "owner/repo",
            "42",
            &[],
            Some("2026-01-01T00:00:00Z"),
            Some((ci.sha.as_str(), ci.attempt)),
        )
        .unwrap();
        let event = ConditionObservation {
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
            key: "ci-skew".into(),
            cursor: "2026-01-01T01:00:00Z".into(),
            ci: Some(ci.clone()),
            order_ambiguous: false,
            source: json!({}),
        };
        observe_conditions(
            &db,
            "job",
            "owner/repo",
            "42",
            &[event],
            Some("2026-01-01T00:00:00Z"),
            Some((ci.sha.as_str(), ci.attempt)),
        )
        .unwrap();
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
    }

    #[test]
    fn github_run_42418119129_is_not_replayed_after_registration() {
        let db = db();
        let sha = "c1".repeat(20);
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "ci-run".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let member = crate::conditions::MemberRegistration::polling(
            selector,
            Some(crate::conditions::CiRunIdentity {
                repo: "owner/repo".into(),
                run_id: 42_418_119_129,
                attempt: 1,
                sha: sha.clone(),
            }),
        );
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_groups SET created='2026-11-08 00:00:00' WHERE id=?1",
            [&group],
        )
        .unwrap();
        let run = json!({
            "id":42418119129_i64,
            "run_attempt":1,
            "head_sha":sha,
            "status":"completed",
            "conclusion":"success",
            "created_at":"2026-11-07T21:00:00Z",
            "completed_at":null,
            "updated_at":"2026-11-07T21:56:59Z"
        });
        tick_with(&db, 1, |route, _| {
            assert_eq!(
                route,
                "/repos/owner/repo/actions/runs/42418119129/attempts/1"
            );
            Ok(response(run.clone(), false))
        })
        .unwrap();
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        assert!(!crate::conditions::pending_polling_members(&db, Some(&group)).unwrap()[0].armed);
        assert!(
            resolve_ci_condition_order(&db, &group, "ci-run", None, None, None, false).unwrap()
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn ci_completion_at_registration_second_is_not_replayed() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let ci = crate::conditions::CiRunIdentity {
            repo: "owner/repo".into(),
            run_id: 42,
            attempt: 1,
            sha: "a".repeat(40),
        };
        let member = crate::conditions::MemberRegistration::polling(selector, Some(ci.clone()));
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            std::slice::from_ref(&member),
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let at: String = db
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ',created) FROM condition_groups WHERE id=?1",
                [&group],
                |row| row.get(0),
            )
            .unwrap();
        let historical_group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "22222222-2222-4222-8222-222222222222",
            None,
            None,
        )
        .unwrap();
        db.execute("UPDATE condition_groups SET created=(SELECT created FROM condition_groups WHERE id=?1) WHERE id=?2",rusqlite::params![group,historical_group]).unwrap();
        let observation = ConditionObservation {
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
            key: "ci-event".into(),
            cursor: at.clone(),
            ci: Some(ci),
            order_ambiguous: false,
            source: json!({}),
        };
        let sha = "a".repeat(40);
        assert!(
            observe_conditions(
                &db,
                "job",
                "owner/repo",
                "42",
                &[observation],
                Some("2020-01-01T00:00:00Z"),
                Some((sha.as_str(), 1))
            )
            .is_ok()
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        assert!(!crate::conditions::pending_polling_members(&db, Some(&group)).unwrap()[0].armed);
        assert_eq!(
            db.query_row(
                "SELECT order_uncertain FROM condition_members WHERE group_id=?1",
                [&group],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(resolve_ci_condition_order(&db, &group, "build", None, None, None, true).unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
        assert!(
            resolve_ci_condition_order(&db, &historical_group, "build", None, None, None, false)
                .unwrap()
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn ci_order_resolution_selects_the_exact_shared_resource_member() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let member = |run_id| {
            crate::conditions::MemberRegistration::polling(
                selector.clone(),
                Some(crate::conditions::CiRunIdentity {
                    repo: "owner/repo".into(),
                    run_id,
                    attempt: 1,
                    sha: "a".repeat(40),
                }),
            )
        };
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member(41), member(42)],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        db.execute(
            "UPDATE condition_members SET order_uncertain=1,ambiguous_cursor='2026-11-08T10:00:00Z' WHERE group_id=?1",
            [&group],
        )
        .unwrap();
        assert!(resolve_ci_condition_order(&db, &group, "build", None, None, None, false).is_err());
        assert!(
            resolve_ci_condition_order(
                &db,
                &group,
                "build",
                Some(("owner/repo".into(), 42, 1, "a".repeat(40))),
                Some("completed"),
                Some("success"),
                false,
            )
            .unwrap()
        );
        let states: Vec<(i64, i64)> = db
            .prepare("SELECT ci_run_id,order_uncertain FROM condition_members WHERE group_id=?1 ORDER BY ci_run_id")
            .unwrap()
            .query_map([&group], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(states, vec![(41, 1), (42, 0)]);
    }

    #[test]
    fn ci_poll_does_not_arm_a_different_attempt_of_the_same_run() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let member = |attempt| {
            crate::conditions::MemberRegistration::polling(
                selector.clone(),
                Some(crate::conditions::CiRunIdentity {
                    repo: "owner/repo".into(),
                    run_id: 42,
                    attempt,
                    sha: "a".repeat(40),
                }),
            )
        };
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::And,
            &[member(1), member(2)],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let sha = "a".repeat(40);
        observe_conditions(
            &db,
            "job",
            "owner/repo",
            "42",
            &[],
            Some("2026-01-01T00:00:00Z"),
            Some((sha.as_str(), 1)),
        )
        .unwrap();
        let members = crate::conditions::pending_polling_members(&db, Some(&group)).unwrap();
        assert!(members.iter().any(|member| {
            member.ci.as_ref().is_some_and(|ci| ci.attempt == 1) && member.armed
        }));
        assert!(members.iter().any(|member| {
            member.ci.as_ref().is_some_and(|ci| ci.attempt == 2) && !member.armed
        }));
    }

    #[test]
    fn condition_poll_arms_a_baseline_then_observes_a_new_pr_change() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "pull_request".into(),
            repo: "owner/repo".into(),
            resource: "7".into(),
            event: "synchronize".into(),
            outcome: None,
        };
        let member = crate::conditions::MemberRegistration::polling(selector, None);
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let pull = |head: &str, updated_at: &str| {
            json!({"number":7,"state":"open","merged":false,"updated_at":updated_at,
                "head":{"sha":head.repeat(40)},"base":{"ref":"main"}})
        };
        tick_with(&db, 1, |_, _| {
            Ok(response(pull("a", "2026-11-08T10:00:00Z"), false))
        })
        .unwrap();
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        tick_with(&db, INTERVAL_MS + 1, |_, _| {
            Ok(response(pull("b", "2026-11-08T10:01:00Z"), false))
        })
        .unwrap();
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
    }

    #[test]
    fn closed_pr_condition_ignores_old_closure_and_accepts_a_new_transition() {
        let db = db();
        let member = crate::conditions::MemberRegistration::polling(
            crate::conditions::Selector {
                kind: "pull_request".into(),
                repo: "owner/repo".into(),
                resource: "7".into(),
                event: "closed".into(),
                outcome: None,
            },
            None,
        );
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let pull = |state: &str, closed_at: Option<&str>, updated_at: &str| {
            json!({
                "number":7,"state":state,"merged":false,"closed_at":closed_at,
                "merged_at":null,"updated_at":updated_at,
                "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
            })
        };
        for (now, state, closed_at, updated_at, should_be_ready) in [
            (
                1,
                "closed",
                Some("2026-11-07T10:00:00Z"),
                "2026-11-07T10:00:00Z",
                false,
            ),
            (
                INTERVAL_MS + 1,
                "closed",
                Some("2026-11-07T10:00:00Z"),
                "2026-11-07T10:00:00Z",
                false,
            ),
            (
                INTERVAL_MS * 2 + 1,
                "open",
                None,
                "2026-11-08T10:01:00Z",
                false,
            ),
            (
                INTERVAL_MS * 3 + 1,
                "closed",
                Some("2026-11-08T10:02:00Z"),
                "2026-11-08T10:02:00Z",
                true,
            ),
        ] {
            let report = tick_with(&db, now, |route, _| {
                assert_eq!(route, "/repos/owner/repo/pulls/7");
                Ok(response(pull(state, closed_at, updated_at), false))
            })
            .unwrap();
            assert_eq!(report["errors"], json!({}), "{report}");
            let ready = crate::conditions::claim_ready(&db).unwrap();
            if should_be_ready {
                assert_eq!(ready.unwrap().group_id, group);
            } else {
                assert!(ready.is_none());
            }
        }
    }

    #[test]
    fn reopened_notification_and_open_poll_reconcile_ci_trackers() {
        let mut db = db();
        let thread = "11111111-1111-4111-8111-111111111111";
        let unregistered_thread = "22222222-2222-4222-8222-222222222222";
        codex_wake::pr_ci::register(&mut db, "owner/repo", "7", thread).unwrap();
        codex_wake::pr_ci::register(&mut db, "owner/repo", "7", unregistered_thread).unwrap();
        codex_wake::pr_ci::unregister(&db, "owner/repo", "7", unregistered_thread).unwrap();
        let closed = json!({
            "number":7,"state":"closed","merged":false,"merged_at":null,
            "closed_at":"2098-12-31T23:59:00Z","updated_at":"2098-12-31T23:59:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        seed_legacy_pr_cursor(&db, Some(&closed));
        crate::polling::pr_notifications::register(&db, "pull_request", "owner/repo", "7", thread)
            .unwrap();
        let reopened = json!({
            "number":7,"state":"open","merged":false,"merged_at":null,
            "closed_at":null,"updated_at":"2099-01-01T00:00:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        let route = "/repos/owner/repo/pulls/7";
        let report = tick_with(&db, INTERVAL_MS + 1, |requested, _| {
            assert_eq!(requested, route);
            Ok(response(reopened.clone(), false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");

        let closed_poll = json!({
            "number":7,"state":"closed","merged":false,"merged_at":null,
            "closed_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-01T00:00:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        let report = tick_with(&db, INTERVAL_MS * 2 + 1, |requested, _| {
            assert_eq!(requested, route);
            Ok(response(closed_poll.clone(), false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");
        let active_after_close: i64 = db
            .query_row(
                "SELECT active FROM pr_ci_trackers WHERE thread=?1",
                [thread],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_after_close, 0, "closed poll must pause the tracker");

        // Model a cursor that retained `open` while the closed-state reconciliation committed.
        let mut cursor: Value = db
            .query_row(
                "SELECT cursor FROM github_poll_state WHERE endpoint=?1 AND page=0",
                [route],
                |row| {
                    let value: String = row.get(0)?;
                    Ok(serde_json::from_str(&value).unwrap())
                },
            )
            .unwrap();
        cursor["state"] = json!("open");
        db.execute(
            "UPDATE github_poll_state SET cursor=?1 WHERE endpoint=?2 AND page=0",
            rusqlite::params![cursor.to_string(), route],
        )
        .unwrap();
        let report = tick_with(&db, INTERVAL_MS * 3 + 1, |requested, _| {
            assert_eq!(requested, route);
            Ok(response(reopened.clone(), false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");

        let notices = crate::polling::pr_notifications::pending(&db).unwrap();
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].kind, "pull_request");
        assert_eq!(notices[0].event, "reopened");
        assert_eq!(notices[0].source["action"], "reopened");
        let tracker_states: Vec<(String, bool)> = {
            let mut statement = db
                .prepare("SELECT thread,active FROM pr_ci_trackers ORDER BY thread")
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(
            tracker_states,
            vec![(thread.into(), true), (unregistered_thread.into(), false)]
        );
    }

    #[test]
    fn legacy_pr_cursor_recovers_state_from_its_cached_response() {
        let db = db();
        let old = json!({
            "number":7,"state":"open","merged":false,"merged_at":null,"closed_at":null,
            "updated_at":"2026-11-08T10:00:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        seed_legacy_pr_cursor(&db, Some(&old));
        let group = register_closed_pr_group(&db);
        db.execute(
            "UPDATE condition_groups SET created='2026-11-08 10:01:00' WHERE id=?1",
            [&group],
        )
        .unwrap();
        let closed = json!({
            "number":7,"state":"closed","merged":false,"merged_at":null,
            "closed_at":"2026-11-08T10:02:00Z","updated_at":"2026-11-08T10:02:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        let report = tick_with(&db, INTERVAL_MS + 1, |route, _| {
            assert_eq!(route, "/repos/owner/repo/pulls/7");
            Ok(response(closed.clone(), false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
        let saved = state(&db, "/repos/owner/repo/pulls/7", 0).unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(saved.cursor.as_deref().unwrap()).unwrap()["state"],
            "closed"
        );
    }

    #[test]
    fn pr_transition_before_registration_stays_ambiguous_after_cached_poll() {
        let db = db();
        let old = json!({
            "number":7,"state":"open","merged":false,"merged_at":null,"closed_at":null,
            "updated_at":"2026-11-08T10:00:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        seed_legacy_pr_cursor(&db, Some(&old));
        let group = register_closed_pr_group(&db);
        db.execute(
            "UPDATE condition_groups SET created='2026-11-08 10:03:00' WHERE id=?1",
            [&group],
        )
        .unwrap();
        let closed = json!({
            "number":7,"state":"closed","merged":false,"merged_at":null,
            "closed_at":"2026-11-08T10:02:00Z","updated_at":"2026-11-08T10:02:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        let report = tick_with(&db, INTERVAL_MS + 1, |route, _| {
            assert_eq!(route, "/repos/owner/repo/pulls/7");
            Ok(response(closed.clone(), false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        assert!(
            db.query_row(
                "SELECT order_uncertain FROM condition_members WHERE group_id=?1",
                [&group],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
        );
        assert!(resolve_pr_condition_order(&db, &group, "7", "closed", true).unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            group
        );
    }

    #[test]
    fn legacy_pr_cursor_without_cached_state_keeps_groups_ambiguous_and_continues_polling() {
        let db = db();
        seed_legacy_pr_cursor(&db, None);
        let subscription = subscribe(&db, "pull_request", "7", "closed");
        rule(&db);
        let buffered_group = register_closed_pr_group(&db);
        let buffered_event = crate::conditions::PublishedEvent {
            selector: crate::conditions::Selector {
                kind: "pull_request".into(),
                repo: "owner/repo".into(),
                resource: "7".into(),
                event: "closed".into(),
                outcome: None,
            },
            source_event_key: "earlier-buffered-event".into(),
            cursor: Some(cursor_number(INTERVAL_MS - 1)),
            ci: None,
            source: json!({"earlier":true}),
        };
        crate::conditions::record_published_event_in(&db, &buffered_event).unwrap();
        let affected_group = register_closed_pr_group(&db);
        let second_affected_group = register_closed_pr_group(&db);
        let armed_group = register_closed_pr_group(&db);
        let unresolved_group = register_closed_pr_group(&db);
        let armed_selector = crate::conditions::Selector {
            kind: "pull_request".into(),
            repo: "owner/repo".into(),
            resource: "7".into(),
            event: "closed".into(),
            outcome: None,
        };
        let armed_member =
            crate::conditions::MemberRegistration::polling(armed_selector.clone(), None);
        assert!(
            crate::conditions::arm_observed_member(
                &db,
                &armed_group,
                &armed_member,
                Some(&cursor_number(INTERVAL_MS)),
            )
            .unwrap()
        );
        let explicit_group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[crate::conditions::MemberRegistration::explicit(
                armed_selector,
            )],
            "33333333-3333-4333-8333-333333333333",
            None,
            None,
        )
        .unwrap();
        let unrelated_group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "pull_request".into(),
                    repo: "owner/repo".into(),
                    resource: "7".into(),
                    event: "merged".into(),
                    outcome: None,
                },
                None,
            )],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let closed = json!({
            "number":7,"state":"closed","merged":false,"merged_at":null,
            "closed_at":"2026-11-08T10:02:00Z","updated_at":"2026-11-08T10:02:00Z",
            "head":{"sha":"a".repeat(40)},"base":{"ref":"main"}
        });
        let comment = json!({
            "id":9,"body":"wake","user":{"login":"trusted","type":"User"},
            "created_at":"2026-11-08T10:02:00Z","updated_at":"2026-11-08T10:02:00Z"
        });
        let mut routes = BTreeSet::new();
        let report = tick_with(&db, INTERVAL_MS + 1, |route, _| {
            routes.insert(route.to_owned());
            let body = if route == "/repos/owner/repo/pulls/7" {
                closed.clone()
            } else if route.starts_with("/repos/owner/repo/issues/7/comments") {
                json!([comment.clone()])
            } else {
                assert_eq!(
                    route,
                    "/repos/owner/repo/pulls/7/comments?per_page=10&page=1"
                );
                json!([])
            };
            Ok(response(body, false))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");
        assert_eq!(registration_state(&db, &subscription), "ready");
        assert_eq!(
            db.query_row("SELECT count(*) FROM rule_deliveries", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
        assert!(
            routes
                .iter()
                .any(|route| { route.starts_with("/repos/owner/repo/issues/7/comments") })
        );
        assert!(
            routes
                .iter()
                .any(|route| { route == "/repos/owner/repo/pulls/7/comments?per_page=10&page=1" })
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let saved = state(&db, "/repos/owner/repo/pulls/7", 0).unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(saved.cursor.as_deref().unwrap()).unwrap()["state"],
            "closed"
        );
        assert!(saved.body.is_some());
        let uncertainty = |group_id: &str| {
            db.query_row(
                "SELECT order_uncertain,ambiguous_cursor FROM condition_members WHERE group_id=?1",
                [group_id],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .unwrap()
        };
        assert_eq!(
            uncertainty(&affected_group),
            (true, Some("2026-11-08T10:02:00Z".into()))
        );
        assert_eq!(
            uncertainty(&second_affected_group),
            (true, Some("2026-11-08T10:02:00Z".into()))
        );
        assert_eq!(
            uncertainty(&armed_group),
            (true, Some("2026-11-08T10:02:00Z".into()))
        );
        assert!(uncertainty(&unresolved_group).0);
        assert!(uncertainty(&buffered_group).0);
        assert_eq!(uncertainty(&explicit_group), (false, None));
        for group in [
            &affected_group,
            &second_affected_group,
            &armed_group,
            &unresolved_group,
        ] {
            let cursor: Option<String> = db
                .query_row(
                    "SELECT last_cursor FROM condition_members WHERE group_id=?1",
                    [group],
                    |row| row.get(0),
                )
                .unwrap();
            let expected_cursor = cursor_number(INTERVAL_MS + 1);
            assert_eq!(cursor.as_deref(), Some(expected_cursor.as_str()));
        }
        assert_eq!(uncertainty(&unrelated_group), (false, None));
        let error: Option<String> = db
            .query_row(
                "SELECT error_category FROM github_poll_state WHERE endpoint='/repos/owner/repo/pulls/7' AND page=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(error, None);
        let repeated = tick_with(&db, INTERVAL_MS * 2 + 1, |route, _| {
            let body = if route == "/repos/owner/repo/pulls/7" {
                closed.clone()
            } else if route.starts_with("/repos/owner/repo/issues/7/comments") {
                json!([comment.clone()])
            } else {
                assert_eq!(
                    route,
                    "/repos/owner/repo/pulls/7/comments?per_page=10&page=1"
                );
                json!([])
            };
            Ok(response(body, false))
        })
        .unwrap();
        assert_eq!(repeated["errors"], json!({}), "{repeated}");
        assert_eq!(registration_state(&db, &subscription), "ready");
        assert_eq!(
            db.query_row("SELECT count(*) FROM rule_deliveries", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
        assert!(uncertainty(&affected_group).0);
        assert_eq!(
            crate::conditions::pending_polling_members(&db, Some(&affected_group))
                .unwrap()
                .len(),
            1
        );
        assert!(
            !crate::conditions::pending_polling_members(&db, Some(&affected_group)).unwrap()[0]
                .armed
        );
        assert!(
            !crate::conditions::pending_polling_members(&db, Some(&second_affected_group)).unwrap()
                [0]
            .armed
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM condition_pending_events WHERE group_id IN (?1,?2,?3,?4,?5)",
                rusqlite::params![
                    affected_group,
                    second_affected_group,
                    armed_group,
                    unresolved_group,
                    buffered_group
                ],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            6
        );
        assert!(resolve_pr_condition_order(&db, &affected_group, "7", "closed", true).unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            affected_group
        );
        assert_eq!(uncertainty(&affected_group), (false, None));
        assert!(resolve_pr_condition_order(&db, &buffered_group, "7", "closed", true).unwrap());
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            buffered_group
        );
        let matched_source: String = db
            .query_row(
                "SELECT source_json FROM condition_members WHERE group_id=?1",
                [&buffered_group],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&matched_source).unwrap()["pull_request"]["number"],
            7
        );
        assert!(uncertainty(&second_affected_group).0);
        assert!(
            resolve_pr_condition_order(&db, &second_affected_group, "7", "closed", false).unwrap()
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        assert_eq!(uncertainty(&second_affected_group), (false, None));
        let excluded =
            crate::conditions::pending_polling_members(&db, Some(&second_affected_group)).unwrap();
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].armed);
        assert!(resolve_pr_condition_order(&db, &armed_group, "7", "closed", false).unwrap());
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let mut reopened = closed.clone();
        reopened["state"] = json!("open");
        reopened["closed_at"] = Value::Null;
        let mut closed_again = closed.clone();
        closed_again["closed_at"] = json!("2026-11-08T10:05:00Z");
        closed_again["updated_at"] = json!("2026-11-08T10:05:00Z");
        for (now, pr) in [
            (INTERVAL_MS * 3 + 1, reopened),
            (INTERVAL_MS * 4 + 1, closed_again),
        ] {
            let report = tick_with(&db, now, |route, _| {
                let body = if route == "/repos/owner/repo/pulls/7" {
                    pr.clone()
                } else if route.starts_with("/repos/owner/repo/issues/7/comments") {
                    json!([comment.clone()])
                } else {
                    assert_eq!(
                        route,
                        "/repos/owner/repo/pulls/7/comments?per_page=10&page=1"
                    );
                    json!([])
                };
                Ok(response(body, false))
            })
            .unwrap();
            assert_eq!(report["errors"], json!({}), "{report}");
        }
        let ready = (0..4)
            .map(|_| {
                crate::conditions::claim_ready(&db)
                    .unwrap()
                    .unwrap()
                    .group_id
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(uncertainty(&unresolved_group), (false, None));
        assert_eq!(
            ready,
            BTreeSet::from([
                second_affected_group,
                armed_group,
                explicit_group,
                unresolved_group
            ])
        );
    }

    #[test]
    fn ambiguous_pr_members_with_same_number_are_resolved_by_repo() {
        let db = db();
        let members = ["owner/repo-a", "owner/repo-b"].map(|repo| {
            crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "pull_request".into(),
                    repo: repo.into(),
                    resource: "7".into(),
                    event: "closed".into(),
                    outcome: None,
                },
                None,
            )
        });
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::And,
            &members,
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let observation = ConditionObservation {
            resource: "7".into(),
            event: "closed".into(),
            outcome: None,
            key: "unused-for-ambiguous-pr".into(),
            cursor: cursor_number(INTERVAL_MS + 1),
            ci: None,
            order_ambiguous: true,
            source: json!({"pull_request":{"updated_at":"2026-11-08T10:02:00Z"}}),
        };
        for repo in ["owner/repo-a", "owner/repo-b"] {
            observe_conditions(
                &db,
                "pull_request",
                repo,
                "7",
                std::slice::from_ref(&observation),
                Some("0"),
                None,
            )
            .unwrap();
        }
        assert!(resolve_pr_condition_order(&db, &group, "7", "closed", false).is_err());
        assert!(
            resolve_pr_condition_order(&db, &group, "owner/repo-a#7", "closed", false).unwrap()
        );
        assert!(resolve_pr_condition_order(&db, &group, "owner/repo-b#7", "closed", true).unwrap());
        let rows = {
            let mut statement = db.prepare("SELECT repo,armed,matched,order_uncertain FROM condition_members WHERE group_id=?1 ORDER BY repo").unwrap();
            statement
                .query_map([&group], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, bool>(3)?,
                    ))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert_eq!(
            rows,
            vec![
                ("owner/repo-a".into(), true, false, false),
                ("owner/repo-b".into(), true, true, false)
            ]
        );
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
    }

    #[test]
    fn condition_ci_poll_does_not_accept_a_different_sha() {
        let db = db();
        let selector = crate::conditions::Selector {
            kind: "job".into(),
            repo: "owner/repo".into(),
            resource: "build".into(),
            event: "completed".into(),
            outcome: Some("success".into()),
        };
        let member = crate::conditions::MemberRegistration::polling(
            selector,
            Some(crate::conditions::CiRunIdentity {
                repo: "owner/repo".into(),
                run_id: 42,
                attempt: 3,
                sha: "a".repeat(40),
            }),
        );
        let group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap();
        let wrong_attempt = json!({
            "id":42,"run_attempt":2,"head_sha":"a".repeat(40),"status":"completed",
            "conclusion":"success","created_at":"2026-11-08T10:00:00Z",
            "completed_at":"2026-11-08T10:01:00Z"
        });
        let result = tick_with(&db, 1, |_, _| Ok(response(wrong_attempt.clone(), false))).unwrap();
        assert_eq!(result["errors"]["identity_mismatch"], 1);
        let wrong_sha = json!({
            "id":42,"run_attempt":3,"head_sha":"b".repeat(40),"status":"completed",
            "conclusion":"success","created_at":"2026-11-08T10:00:00Z",
            "completed_at":"2026-11-08T10:01:00Z"
        });
        tick_with(&db, INTERVAL_MS + 1, |_, _| {
            Ok(response(wrong_sha.clone(), false))
        })
        .unwrap();
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let pending = crate::conditions::pending_polling_members(&db, Some(&group)).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].armed);
    }

    #[test]
    fn condition_review_and_deployment_polls_ignore_baselines_then_accept_new_events() {
        let db = db();
        let make_member = |kind: &str, resource: &str, event: &str| {
            crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: kind.into(),
                    repo: "owner/repo".into(),
                    resource: resource.into(),
                    event: event.into(),
                    outcome: Some(event.into()),
                },
                None,
            )
        };
        let review_member = make_member("review", "17", "approved");
        let deployment_member = make_member("deployment", "9", "success");
        let thread = "11111111-1111-4111-8111-111111111111";
        let review_group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[review_member],
            thread,
            None,
            None,
        )
        .unwrap();
        let deployment_group = crate::conditions::register_group_with_members(
            &db,
            crate::conditions::Mode::Or,
            &[deployment_member],
            thread,
            None,
            None,
        )
        .unwrap();
        let old_review = json!({"id":7,"submitted_at":"2026-11-08T10:00:00Z","state":"APPROVED"});
        let new_review = json!({"id":8,"submitted_at":"2026-11-08T10:01:00Z","state":"APPROVED"});
        let old_deployment = json!({"id":90,"created_at":"2026-11-08T10:00:00Z","state":"success"});
        let new_deployment = json!({"id":91,"created_at":"2026-11-08T10:01:00Z","state":"success"});
        let fetch = |include_new: bool| {
            let old_review = old_review.clone();
            let new_review = new_review.clone();
            let old_deployment = old_deployment.clone();
            let new_deployment = new_deployment.clone();
            move |route: &str, _: Option<&str>| {
                let body = if route
                    .split('?')
                    .next()
                    .unwrap_or(route)
                    .ends_with("/reviews")
                {
                    if include_new {
                        json!([old_review.clone(), new_review.clone()])
                    } else {
                        json!([old_review.clone()])
                    }
                } else if include_new {
                    json!([old_deployment.clone(), new_deployment.clone()])
                } else {
                    json!([old_deployment.clone()])
                };
                Ok(response(body, false))
            }
        };
        let first_report = tick_with(&db, 1, fetch(false)).unwrap();
        assert_eq!(first_report["errors"], json!({}), "{first_report}");
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let second_report = tick_with(&db, INTERVAL_MS + 1, fetch(true)).unwrap();
        assert_eq!(second_report["errors"], json!({}), "{second_report}");
        let ready = [
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(ready, BTreeSet::from([review_group, deployment_group]));
    }

    #[test]
    fn submitted_review_conditions_match_all_submitted_states_and_specific_states() {
        let db = db();
        let register = |event: &str, outcome: Option<&str>, thread: &str| {
            let member = crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "review".into(),
                    repo: "owner/repo".into(),
                    resource: "17".into(),
                    event: event.into(),
                    outcome: outcome.map(str::to_owned),
                },
                None,
            );
            crate::conditions::register_group_with_members(
                &db,
                crate::conditions::Mode::Or,
                &[member],
                thread,
                None,
                None,
            )
            .unwrap()
        };
        let submitted = register("submitted", None, "11111111-1111-4111-8111-111111111111");
        let approved = register(
            "approved",
            Some("approved"),
            "22222222-2222-4222-8222-222222222222",
        );
        let changes_requested = register(
            "changes_requested",
            Some("changes_requested"),
            "33333333-3333-4333-8333-333333333333",
        );
        let old = json!({"id":7,"submitted_at":"2026-11-08T10:00:00Z","state":"COMMENTED"});
        let first = tick_with(&db, 1, |route, _| {
            assert_eq!(
                route,
                "/repos/owner/repo/pulls/17/reviews?per_page=10&page=1"
            );
            Ok(response(json!([old.clone()]), false))
        })
        .unwrap();
        assert_eq!(first["errors"], json!({}), "{first}");
        assert!(crate::conditions::claim_ready(&db).unwrap().is_none());
        let report = tick_with(&db, INTERVAL_MS + 1, |route, _| {
            assert_eq!(
                route,
                "/repos/owner/repo/pulls/17/reviews?per_page=10&page=1"
            );
            Ok(response(
                json!([
                    old.clone(),
                    {"id":8,"submitted_at":"2026-11-08T10:01:00Z","state":"APPROVED"},
                    {"id":9,"submitted_at":"2026-11-08T10:02:00Z","state":"CHANGES_REQUESTED"}
                ]),
                false,
            ))
        })
        .unwrap();
        assert_eq!(report["errors"], json!({}), "{report}");
        let ready = (0..3)
            .map(|_| {
                crate::conditions::claim_ready(&db)
                    .unwrap()
                    .unwrap()
                    .group_id
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            ready,
            BTreeSet::from([submitted, approved, changes_requested])
        );
    }

    fn db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE waits(repo TEXT,run_id INTEGER,attempt INTEGER,sha TEXT,state TEXT)",
        )
        .unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        initialize(&db).unwrap();
        db
    }
    fn seed_legacy_pr_cursor(db: &Connection, body: Option<&Value>) -> String {
        let cursor = json!({
            "head":"a".repeat(40),"base":"main",
            "updated_at":"2026-11-08T10:00:00Z","poll_seq":INTERVAL_MS
        })
        .to_string();
        db.execute(
            "INSERT INTO github_poll_state(endpoint,page,body,cursor,next_poll_ms,backoff_ms,last_success_ms,calls) VALUES('/repos/owner/repo/pulls/7',0,?1,?2,0,60000,?3,1)",
            rusqlite::params![body.map(|value| value.to_string()), cursor.as_str(), INTERVAL_MS],
        )
        .unwrap();
        cursor
    }
    fn register_closed_pr_group(db: &Connection) -> String {
        let member = crate::conditions::MemberRegistration::polling(
            crate::conditions::Selector {
                kind: "pull_request".into(),
                repo: "owner/repo".into(),
                resource: "7".into(),
                event: "closed".into(),
                outcome: None,
            },
            None,
        );
        crate::conditions::register_group_with_members(
            db,
            crate::conditions::Mode::Or,
            &[member],
            "11111111-1111-4111-8111-111111111111",
            None,
            None,
        )
        .unwrap()
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
    fn scoped_polling_copies_the_stable_event_key_from_its_candidate_database() {
        let db = db();
        let id = subscribe(&db, "review", "42", "approved");
        let source = json!({
            "action":"submitted",
            "repository":{"full_name":"owner/repo"},
            "pull_request":{"number":42},
            "review":{"id":77,"state":"approved"}
        });
        assert_eq!(
            scoped_subscription_accept(
                &db,
                "pull_request_review",
                &source,
                "owner/repo",
                "42",
                None,
            )
            .unwrap(),
            1
        );
        assert_eq!(registration_state(&db, &id), "ready");
        let stored: String = db
            .query_row(
                "SELECT source_event_key FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            Some(stored),
            crate::delivery_evidence::subscription_event_identity(
                "review",
                "owner/repo",
                "42",
                "approved",
                "approved",
                &source,
            )
            .unwrap()
        );
    }

    #[test]
    fn scoped_polling_does_not_accept_a_subscription_after_its_deadline() {
        let db = db();
        let id = crate::subscriptions::subscribe_with_delivery(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "merged",
            "11111111-1111-4111-8111-111111111111",
            crate::subscriptions::DeliveryConfig {
                expires_at_ms: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        let payload = json!({"action":"closed","number":7,"pull_request":{"merged":true},"repository":{"full_name":"owner/repo"}});

        assert_eq!(
            scoped_subscription_accept(&db, "pull_request", &payload, "owner/repo", "7", None)
                .unwrap(),
            0
        );
        let status = crate::subscriptions::status_for_id(&db, &id).unwrap();
        assert_eq!(status["state"], "needs_attention");
        assert_eq!(status["reason"], "subscription_expired");
        assert_eq!(status["expiration_notice_state"], "ready");
    }

    #[test]
    fn scoped_polling_waiting_for_writer_lock_uses_the_post_lock_clock() {
        use std::sync::mpsc;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("poll-expiry-lock.sqlite");
        let setup = Connection::open(&path).unwrap();
        crate::subscriptions::initialize(&setup).unwrap();
        let id = crate::subscriptions::subscribe(
            &setup,
            "pull_request",
            "owner/repo",
            "7",
            "merged",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        let deadline = now_ms() + 500;
        setup
            .execute(
                "UPDATE subscriptions SET expires_at_ms=?2 WHERE id=?1",
                params![id, deadline],
            )
            .unwrap();
        drop(setup);

        let holder = Connection::open(&path).unwrap();
        holder.busy_timeout(Duration::from_secs(5)).unwrap();
        holder.execute_batch("BEGIN IMMEDIATE").unwrap();
        POLLING_WRITER_LOCK_BUSY.store(false, Ordering::SeqCst);
        let (started_tx, started_rx) = mpsc::channel();
        let worker = {
            let path = path.clone();
            std::thread::spawn(move || {
                let db = Connection::open(path).unwrap();
                db.busy_handler(Some(mark_polling_writer_lock_busy))
                    .unwrap();
                started_tx.send(()).unwrap();
                let payload = json!({"action":"closed","number":7,"pull_request":{"merged":true},"repository":{"full_name":"owner/repo"}});
                scoped_subscription_accept(&db, "pull_request", &payload, "owner/repo", "7", None)
                    .unwrap()
            })
        };
        started_rx.recv().unwrap();
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while !POLLING_WRITER_LOCK_BUSY.load(Ordering::SeqCst) && Instant::now() < wait_deadline {
            std::thread::yield_now();
        }
        assert!(
            POLLING_WRITER_LOCK_BUSY.load(Ordering::SeqCst),
            "polling worker never entered SQLite's busy handler"
        );
        while now_ms() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        holder.execute_batch("COMMIT").unwrap();

        assert_eq!(worker.join().unwrap(), 0);
        let db = Connection::open(&path).unwrap();
        let status = crate::subscriptions::status_for_id(&db, &id).unwrap();
        assert_eq!(status["state"], "needs_attention");
        assert_eq!(status["reason"], "subscription_expired");
        assert_eq!(status["expiration_notice_state"], "ready");
    }

    #[test]
    fn scoped_polling_rolls_back_when_commit_fails() {
        let db = db();
        let id = subscribe(&db, "pull_request", "7", "merged");
        db.execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
             CREATE TABLE commit_child(parent_id INTEGER REFERENCES commit_parent(id)
                DEFERRABLE INITIALLY DEFERRED);
             CREATE TRIGGER force_commit_failure AFTER UPDATE OF state ON subscriptions
                WHEN NEW.resource='7' BEGIN
                    INSERT INTO commit_child(parent_id) VALUES(999);
                END;",
        )
        .unwrap();
        let payload = json!({"action":"closed","number":7,"pull_request":{"merged":true},"repository":{"full_name":"owner/repo"}});

        assert!(
            scoped_subscription_accept(&db, "pull_request", &payload, "owner/repo", "7", None)
                .is_err()
        );
        assert!(db.is_autocommit());
        assert_eq!(registration_state(&db, &id), "waiting");
        let child_rows: i64 = db
            .query_row("SELECT count(*) FROM commit_child", [], |row| row.get(0))
            .unwrap();
        assert_eq!(child_rows, 0);
    }

    #[test]
    fn scoped_comment_polling_copies_event_identity_to_rule_delivery() {
        let db = db();
        let rule: crate::rules::RuleInput = serde_json::from_value(json!({
            "repo":"owner/repo",
            "pr":42,
            "author":"alice",
            "author_type":"User",
            "contains":"ship it",
            "prompt":"Review the existing task",
            "target_thread":"11111111-1111-4111-8111-111111111111"
        }))
        .unwrap();
        let rule_id = crate::rules::configure(&db, rule).unwrap();
        db.execute(
            "UPDATE rules SET updated='2025-01-01 00:00:00' WHERE id=?1",
            [&rule_id],
        )
        .unwrap();
        let source = json!({
            "action":"created",
            "repository":{"full_name":"owner/repo"},
            "issue":{"number":42,"pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/42"}},
            "comment":{"id":77,"user":{"login":"alice","type":"User"},"body":"please ship it"}
        });
        assert_eq!(
            rules_accept_scoped(
                &db,
                "issue_comment",
                &source,
                "owner/repo",
                42,
                "2026-01-02T00:00:00Z",
            )
            .unwrap(),
            1
        );
        let stored: (String, bool) = db
            .query_row(
                "SELECT source_event_key,event_identity_verified FROM rule_deliveries WHERE rule_id=?1",
                [&rule_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            Some(stored.0),
            crate::delivery_evidence::github_comment_event_identity("issue_comment", &source)
                .unwrap()
        );
        assert!(stored.1);
    }

    #[test]
    fn no_listeners_make_no_network_requests() {
        let report = tick_with(&db(), 1, |_, _| panic!("unexpected request")).unwrap();
        assert_eq!(report["calls"], 0);
    }

    #[test]
    fn github_scoped_accept_preserves_source_and_required_fields() {
        let db = db();
        let paths = vec!["pull_request.html_url".to_string()];
        let id = crate::subscriptions::subscribe_with_delivery(
            &db,
            "pull_request",
            "owner/repo",
            "7",
            "merged",
            "11111111-1111-4111-8111-111111111111",
            crate::subscriptions::DeliveryConfig {
                required_source: Some(&paths),
                ..Default::default()
            },
        )
        .unwrap();
        let payload = json!({"action":"closed","number":7,"pull_request":{"merged":true},"repository":{"full_name":"owner/repo"}});
        assert_eq!(
            scoped_subscription_accept(&db, "pull_request", &payload, "owner/repo", "7", None)
                .unwrap(),
            1
        );
        assert_eq!(
            scoped_subscription_accept(&db, "pull_request", &payload, "owner/repo", "7", None)
                .unwrap(),
            0
        );
        let row = crate::subscriptions::status(&db).unwrap();
        assert_eq!(row[0]["id"], id);
        assert_eq!(row[0]["missing_source"], json!(["pull_request.html_url"]));
        let source: String = db
            .query_row(
                "SELECT source_json FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&source).unwrap(), payload);
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
        let event_key: Option<String> = db
            .query_row(
                "SELECT source_event_key FROM subscriptions WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_key, None);
    }

    #[test]
    fn git_ref_update_key_distinguishes_a_return_to_an_old_sha() {
        let db = db();
        let register = |thread: &str| {
            let member = crate::conditions::MemberRegistration::polling(
                crate::conditions::Selector {
                    kind: "git_ref".into(),
                    repo: "owner/repo".into(),
                    resource: "topic/test".into(),
                    event: "updated".into(),
                    outcome: None,
                },
                None,
            );
            crate::conditions::register_group_with_members(
                &db,
                crate::conditions::Mode::Or,
                &[member],
                thread,
                None,
                None,
            )
            .unwrap()
        };
        let poll = |now, sha: &str| {
            let report = tick_with(&db, now, |route, _| {
                assert_eq!(route, "/repos/owner/repo/git/ref/heads/topic/test");
                Ok(response(
                    json!({"ref":"refs/heads/topic/test","object":{"sha":sha}}),
                    false,
                ))
            })
            .unwrap();
            assert_eq!(report["errors"], json!({}), "{report}");
        };
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let first = register("11111111-1111-4111-8111-111111111111");
        poll(1, &a);
        poll(INTERVAL_MS + 1, &b);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            first
        );
        let second = register("22222222-2222-4222-8222-222222222222");
        poll(INTERVAL_MS * 2 + 1, &a);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            second
        );
        let third = register("33333333-3333-4333-8333-333333333333");
        poll(INTERVAL_MS * 3 + 1, &b);
        assert_eq!(
            crate::conditions::claim_ready(&db)
                .unwrap()
                .unwrap()
                .group_id,
            third
        );
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
        for id in [&head, &base] {
            let event_key: Option<String> = db
                .query_row(
                    "SELECT source_event_key FROM subscriptions WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(event_key, None);
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
