---
name: register-condition-group
description: Subscribe a chat to a combination of Wake events or a chain of dependent work.
---

Call Wake's `register_condition_group` with the destination chat, `and` or `or`, and the exact event members. For an Actions run, provide its run ID, attempt and SHA in `ci`. GitHub and native members are observed in the background; inspect `get_coordination` for their armed state.
To follow an earlier group, set `dependency.group_id` and choose `success_only` or `any_terminal` for that link. Queue acceptance is not work completion. Publish the actual chat result with `source.group_id` and `source.turn_id` to release the next link.
For explicit publications, include a stable `source.event_id` so Wake can identify redeliveries. Use `message_template` with `source.0.source` and other indexed source fields as needed.
If `get_coordination` reports an ambiguous event order, inspect the evidence and call `resolve_condition_order` with the verified decision. Use `source: "native"`, `"ci"`, or `"pull_request"`; for a pull request also supply its `event` (`"closed"` or `"merged"`).
