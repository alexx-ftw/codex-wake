---
name: resume-goal
description: Resume an existing Codex chat goal through Wake, optionally supplying input.
---

Read the target with Wake's `get_goal`, then call `resume_goal` for the requested saved goal. Include the requested input template and execution preset when provided.
Report activation separately from optional input delivery. Codex controls continuation; activation is not proof of a completed turn.

For an explicitly configured cooperative receiver, create and retain a stable `request_id` before the first call. `pending` acknowledges storage only; it does not confirm the goal mutation or input. `needs_attention` means the outcome is uncertain and must not be replayed automatically. If the server generates an ID and the response is lost, a retry cannot be identified safely.
