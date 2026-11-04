---
name: create-goal
description: Create a Wake goal for a specified Codex chat, with optional input and execution settings.
---

Call Wake's `create_goal` with the destination chat and requested objective. Set a token budget only when explicitly requested.
An existing goal causes a conflict; use `get_goal` to inspect it rather than replacing it implicitly. Optional input and execution settings follow the tool schema.
Report the saved goal and any separate input delivery result; Codex may begin continuing the goal automatically.
