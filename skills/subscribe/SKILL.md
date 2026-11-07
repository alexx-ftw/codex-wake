---
name: subscribe
description: Subscribe a Codex chat to a Wake event from GitHub, a local source or another chat.
---

Call Wake's `subscribe` with the destination chat UUID and exact source, resource and event. Other subscriptions remain independent; each registration is one-shot.
Use `expires_in_secs` or `expires_at_ms` to notify the destination if the subscription expires before its event arrives.
For local polling, supply the matching `observation` for a file, HTTP endpoint, flock or systemd invocation; systemd accepts `scope: "user"` (the default, including saved JSON without `scope`) or `scope: "system"`. Native turn completion does not establish overall task completion.
Use `message_template` for the requested continuation, with `{{source.path}}`, `{{event.resource}}` or `{{target.thread}}` placeholders. Execution presets belong in `execution` when requested.
Set `resume_goal` to activate an existing goal after the event input is accepted into its queue.
Use `required_source` for dotted paths relative to the original source (for example `details.url`) when the continuation needs those fields. Missing or null fields are reported to the destination and in status; the event remains recorded. Decide how to obtain missing information without inventing it.
