---
name: edit-goal
description: Edit an existing Codex chat goal through Wake.
---

Read the target with Wake's `get_goal`, then call `edit_goal` with the requested changes. Preserve fields the user did not ask to change.
An optional input template is queued separately from the goal mutation. Report those results separately; an active goal may continue before that input arrives.

For an explicitly configured cooperative receiver, create and retain a stable `request_id` before the first call. `pending` acknowledges storage only; it does not confirm the goal mutation or input. `needs_attention` means the outcome is uncertain and must not be replayed automatically. If the server generates an ID and the response is lost, a retry cannot be identified safely.
