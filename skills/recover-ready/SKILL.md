---
name: recover-ready
description: Dispatch Wake events already stored as ready without replaying uncertain deliveries.
---

Inspect Wake's `get_status`, then call `recover_ready` to dispatch stored ready events.
The tool does not retry `sending` or `needs_attention` records. Investigate those against actual target history before considering any resend; do not reset delivery states.
Report attempted delivery and remaining problems, without equating queue acceptance with execution.
