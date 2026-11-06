---
name: status
description: Inspect Wake service health, subscriptions and delivery problems.
---

Call Wake's `get_status`. Summarize source health, pending work and delivery failures relevant to the request.
Review `actionable` for deliveries needing attention and dependency recovery progress. Report the evidence and next action for relevant entries.
`queued` confirms accepted input, not agent execution or task completion. Use the returned diagnostics to distinguish source errors from delivery errors.
