---
name: configure-rule
description: Configure a Wake PR-comment rule that queues input or creates a Codex chat.
---

Call Wake's `configure_rule` for the specified repository and PR. Match the requested author, account type or literal text using `all` or `any` as requested.
Provide the trusted task in `prompt`; use source placeholders for comment data. Select an existing destination chat or the requested project/cwd for a new chat. Set a goal and execution preset only when requested.
Report the saved rule ID. Creating a rule does not prove a future delivery occurred.
