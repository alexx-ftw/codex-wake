---
name: queue-thread
description: Queue or resume a Codex chat with a Wake input template.
---

Call Wake's `queue_thread` with the destination UUID and `message_template`. Pass placeholder values in `source`.
Default `resume` and `steer` to `false`. `resume: true` wakes the target; `steer: true` instead holds the rendered input until that target's own `PostToolUse` or `Stop` hook runs. The JSON-encoded rendered string, including quotes and escapes, is limited to 2048 UTF-8 bytes. Steer does not wake an idle target and cannot be combined with `resume: true` or `execution`.
Steer is claimed atomically once. A `claimed` result means hook output was prepared, not that the model consumed it. Never replay automatically after a crash or rejected hook output. `stop_hook_active: true` skips only the steer claim/continuation; the `Stop` lifecycle event is still published. Parent-thread inputs are not delivered by child hooks.
Report queue acceptance separately from execution; do not resend an ambiguous delivery automatically.
