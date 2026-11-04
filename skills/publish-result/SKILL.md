---
name: publish-result
description: Publish a verified job, chat, artifact, dependency or resource result to Wake subscribers.
---

Verify the producer's result, then call Wake's `publish_result` with the exact kind, namespace, resource and outcome.
Use the supported event vocabulary in the tool schema. Silence or an idle chat does not prove task success.
Report matching subscriptions and delivery results separately; an unmatched event does not create a subscription.
