use serde_json::{Value, json};

pub fn actionable(waits: &Value, subscriptions: &Value, rules: &Value) -> Value {
    let mut items = Vec::new();
    for (source, rows) in [
        ("wait", waits),
        ("subscription", subscriptions),
        ("rule", &rules["deliveries"]),
    ] {
        for row in rows.as_array().into_iter().flatten() {
            let state = row["state"].as_str().unwrap_or("");
            let dependency = source == "subscription"
                && row["kind"] == "dependency"
                && row["event"] == "recovered";
            let goal_delivery =
                source == "subscription" && state == "sending" && row["resume_goal"] == true;
            if state != "needs_attention" && !dependency && !goal_delivery {
                continue;
            }
            let next_action = match state {
                "needs_attention" if source == "rule" => {
                    "Inspect the reason and any created chat before deciding how to proceed; creation or delivery may be uncertain, so do not blindly retry."
                }
                "needs_attention" => {
                    "Inspect the reason and destination chat before deciding how to proceed; delivery may be uncertain, so do not blindly retry."
                }
                "waiting" => {
                    "No recovery event has matched this subscription. Check the provider or publisher and keep waiting for verified recovery."
                }
                "ready" => {
                    "A recovery event matched this subscription and delivery is pending. Check receiver health and use recover_ready if appropriate."
                }
                "sending" if goal_delivery => {
                    "Goal delivery is in progress or its outcome is unknown. Inspect the sender, goal stage and destination; the input may already be accepted, so do not resend it."
                }
                "sending" => {
                    "Delivery is in progress. Inspect its eventual status before taking further action."
                }
                "queued" => {
                    "Input was accepted, but execution is not verified. Inspect the destination chat and verify the task continues."
                }
                _ => "Inspect the destination chat and delivery status.",
            };
            let thread = row[if source == "rule" {
                "thread_id"
            } else {
                "thread"
            }]
            .as_str();
            items.push(json!({"source":source,"evidence":row,"thread_link":thread.map(|id| format!("codex://threads/{id}")),"next_action":next_action}));
        }
    }
    items.sort_by_key(|item| item["evidence"]["state"] != "needs_attention");
    json!(items)
}

pub fn circular_notices(circular: &Value) -> Vec<Value> {
    circular["notices"].as_array().into_iter().flatten().filter(|notice| notice["diagnostic"] == "sending_outcome_unknown").map(|notice| {
        let thread = notice["thread"].as_str();
        json!({"source":"circular_notice","evidence":notice,"thread_link":thread.map(|id| format!("codex://threads/{id}")),"next_action":"The delivery outcome is unknown and it may still be in progress. Inspect the destination and sender before deciding what to do; do not blindly retry."})
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlights_attention_and_dependency_progress_without_claiming_execution() {
        let waits = json!([{"state":"needs_attention","reason":"timeout_delivery_unknown","run_id":12,"attempt":2,"thread":"t"}]);
        let subscriptions = json!([
            {"kind":"dependency","event":"recovered","state":"queued","resource":"db","thread":"t","outcome":"recovered"},
            {"kind":"dependency","event":"recovered","state":"waiting","resource":"cache"},
            {"kind":"dependency","event":"recovered","state":"ready","resource":"api"},
            {"kind":"chat","event":"completed","state":"needs_attention","reason":"template_error"},
            {"kind":"chat","event":"completed","state":"queued"}
        ]);
        let rules = json!({"deliveries":[{"state":"needs_attention","thread_id":null,"reason":"creation_unknown"}]});
        let result = actionable(&waits, &subscriptions, &rules);
        let items = result.as_array().unwrap();
        assert_eq!(items.len(), 6);
        assert_eq!(items[0]["evidence"]["reason"], "timeout_delivery_unknown");
        assert_eq!(items[0]["thread_link"], "codex://threads/t");
        assert_eq!(items[1]["source"], "subscription");
        assert_eq!(items[2]["source"], "rule");
        assert!(items[2]["thread_link"].is_null());
        assert!(
            items[2]["next_action"]
                .as_str()
                .unwrap()
                .contains("created chat")
        );
        assert!(
            items[0]["next_action"]
                .as_str()
                .unwrap()
                .contains("do not blindly retry")
        );
        assert!(
            items[3]["next_action"]
                .as_str()
                .unwrap()
                .contains("execution is not verified")
        );
        assert!(
            items[4]["next_action"]
                .as_str()
                .unwrap()
                .contains("No recovery event has matched")
        );
        assert!(
            items[5]["next_action"]
                .as_str()
                .unwrap()
                .contains("recover_ready")
        );
    }

    #[test]
    fn in_progress_delivery_is_not_described_as_complete_or_retried() {
        let subscriptions = json!([
            {"kind":"dependency","event":"recovered","state":"sending","resource":"db","thread":"t"}
        ]);
        let result = actionable(&json!([]), &subscriptions, &json!({"deliveries":[]}));
        assert_eq!(result.as_array().unwrap().len(), 1);
        assert_eq!(result[0]["evidence"]["state"], "sending");
        assert!(
            result[0]["next_action"]
                .as_str()
                .unwrap()
                .contains("in progress")
        );
        assert!(
            !result[0]["next_action"]
                .as_str()
                .unwrap()
                .contains("recover_ready")
        );
    }

    #[test]
    fn in_progress_goal_delivery_warns_against_replaying_input() {
        let subscriptions = json!([
            {"kind":"artifact","event":"available","state":"sending","resume_goal":true,"goal_stage":"activating","thread":"t"}
        ]);
        let result = actionable(&json!([]), &subscriptions, &json!({"deliveries":[]}));
        let items = result.as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            items[0]["next_action"]
                .as_str()
                .unwrap()
                .contains("do not resend")
        );
        assert_eq!(items[0]["thread_link"], "codex://threads/t");
    }
}
