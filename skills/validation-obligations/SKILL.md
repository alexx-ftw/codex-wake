---
name: validation-obligations
description: Record and resolve validation checks the agent has committed to perform.
---

When you commit to a specific validation check that remains to be done, call Wake's `register_validation` with the responsible chat ID and the check's description. Do not register hypothetical checks as commitments. Wake reminds only checks explicitly registered; it does not infer commitments from prose.

Use `list_obligations` to inspect pending checks. After performing a check, call `resolve_validation` with its obligation ID and evidence of what was actually checked and observed. A pending or blocked check stays open; report its state without inventing evidence.
