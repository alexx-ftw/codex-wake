---
name: list-obligations
description: List a Codex chat's pending publication obligations.
---

Call Wake's `list_obligations` with the chat UUID and follow `next_cursor` using `after` until it is null.
