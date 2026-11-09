---
name: list-obligations
description: List a Codex chat's pending publication obligations.
---

Call Wake's `list_obligations` with the chat UUID and follow `next_cursor` using `after` until it is null.
After reviewing every page, if obligations remain pending, call `acknowledge_obligation_review` with the chat UUID, all reviewed obligation IDs and the `review_digest` shared by every page. If the digest changes, list every page again. This records the review without resolving any obligation.
