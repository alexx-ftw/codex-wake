---
name: edit-goal
description: Edit an existing Codex chat goal through Wake.
---

Read the target with Wake's `get_goal`, then call `edit_goal` with the requested changes. Preserve fields the user did not ask to change.
An optional input template is queued separately from the goal mutation. Report those results separately; an active goal may continue before that input arrives.
