---
name: queue-thread
description: Queue or resume a Codex chat with a Wake input template.
---

Call Wake's `queue_thread` with the destination UUID and `message_template`. Pass placeholder values in `source`.
Use `resume: false` to queue only and `resume: true` to wake it. Requested execution presets require an idle resumable chat.
Report queue acceptance separately from execution; do not resend an ambiguous delivery automatically.
