---
name: publish-result
description: Publish a verified job, chat, artifact, dependency or resource result to Wake subscribers.
---

Verify the producer's result, then call Wake's `publish_result` with the exact kind, namespace, resource and outcome. If this result is linked to a validation commitment with an explicit structured scope, include the corresponding `scope`; Wake warns when it differs from that linked pending commitment but does not verify the declared scope.
For a job with a known execution and attempt, provide both `execution_id` and `attempt`, and include the publisher and evidence in `source`. Do not infer an identity that is unknown.
If the response reports a conflict, use `get_result_conflicts` with the same identity and follow its `next` cursor to inspect all evidence. Do not choose a result automatically; earlier delivery may already have occurred.
Use the supported event vocabulary in the tool schema. Silence or an idle chat does not prove task success.
Report matching subscriptions and delivery results separately; an unmatched event does not create a subscription.
