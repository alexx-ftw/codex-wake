---
name: subscribe
description: Subscribe a Codex chat to a Wake event from GitHub, a local source or another chat.
---

Call Wake's `subscribe` with the destination chat UUID and exact source, resource and event. Other subscriptions remain independent; each registration is one-shot.
For local polling, supply the matching `observation` for a file, HTTP endpoint, flock or systemd invocation. Native turn completion does not establish overall task completion.
Use `message_template` for the requested continuation, with `{{source.path}}`, `{{event.resource}}` or `{{target.thread}}` placeholders. Execution presets belong in `execution` when requested.
