---
name: resume-goal
description: Resume an existing Codex chat goal through Wake, optionally supplying input.
---

Read the target with Wake's `get_goal`, then call `resume_goal` for the requested saved goal. Include the requested input template and execution preset when provided.
Report activation separately from optional input delivery. Codex controls continuation; activation is not proof of a completed turn.
