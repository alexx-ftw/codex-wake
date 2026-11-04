---
name: register-wait
description: Wake a Codex chat when an exact GitHub Actions run attempt finishes.
---

Resolve the repository, run ID, attempt and full head SHA from GitHub, then call Wake's `register_wait` with the destination chat UUID.
Keep that exact identity; a rerun or another SHA is a different subscription. Include the requested continuation template and execution preset when provided.
