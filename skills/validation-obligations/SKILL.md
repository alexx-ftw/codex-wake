---
name: validation-obligations
description: Record and resolve validation checks the agent has committed to perform.
---

When you commit to a specific validation check that remains to be done, call Wake's `register_validation` with the responsible chat ID and the check's description. Do not register hypothetical checks as commitments. Wake reminds only checks explicitly registered; it does not infer commitments from prose. If a published result must be compared with the commitment's scope, also provide `link` with the exact publication `kind`, `repo` and `resource`, plus a structured `scope` such as `{"environment":"production"}`. Supply both fields together.

Use `list_obligations` to inspect pending checks. After performing a check, call `resolve_validation` with its obligation ID and evidence of what was actually checked and observed. A pending or blocked check stays open; report its state without inventing evidence. `publish_result` may include the matching structured scope; Wake warns when it differs from a linked pending commitment. That warning compares declared fields only: it does not verify either claim or resolve the validation.
