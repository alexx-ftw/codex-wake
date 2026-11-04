# Validation

Local qualification on 2026-11-04 with the installed Codex Desktop runtime:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- Binary unit tests: 83 passed, including cleanup ownership, nested links,
  external database identity, process identity, and host-config isolation.
- Native-test reply matcher self-check: passed; a marker in the user prompt alone is rejected.
- Real HTTP tests: 2 passed with verified adnanh/webhook 2.8.3 and fake Codex.
  They cover authentication, duplicate delivery, deferred PR-comment rules and artifact events.
- Real lifecycle test: passed. Concurrent MCP processes used one enabled user
  service; closing all test clients preserved its PID.
  This also passed after explicitly removing the unit: two concurrent MCP
  startups recreated it and shared one receiver, which remained active after
  both clients closed. TCP inspection confirmed one listener on 127.0.0.1:9000.
  The MCP handshake assertion confirms no usage instructions are injected;
  native plugin inspection reports no onboarding skill or bundled skills.
- Automatic uninstall qualification: passed twice in an isolated native Codex
  installation, with the receiver active and with it deliberately stopped.
  Two MCP sessions were left open and a subscription was stored. Native
  `codex plugin remove` automatically triggered user-manager cleanup in both
  cases. Both MCP processes exited; state/database, secrets, runtime, build/package
  cache, all three unit files and enablement links were removed. TCP port 9000
  was closed. Owned hook records and the generated marketplace registration were
  removed while an unrelated host-config sentinel remained unchanged.
  Disabling alone preserved the receiver and stored subscription in both runs.
  No model turns were started. The existing user's subscriptions were outside
  the isolated state roots and were preserved.
- Opt-in native qualification: passed. A signed loopback PR-comment event
  created a projectless chat and one requested model turn. The assistant returned
  the exact expected reply; persisted settings were `gpt-6.1-sol` / `low`.
  Goal creation applied and read back the preset before mutation; goal
  create/edit/read succeeded. Codex automatically started one further
  continuation. Both turns completed; the fixture goal was completed and only
  the fixture rule/deliveries were removed. Private reports remain ignored.

Earlier qualification failures exposed an overly broad reply matcher, a wrong
metadata-only goal assumption, and an attempt to resume a new chat before its
first rollout existed. These were corrected before the successful run.

The native API does not atomically combine a goal mutation with message input.
The preset is prepared first; an optional message is queued separately. A native
goal continuation can begin before that message arrives. Queue acceptance alone
does not prove execution or the model that processed a particular turn.

The local plugin is installed and enabled from a clean source archive. Its
installed launcher exposes 13 MCP tools and reuses the existing service. The
archive contains no VCS metadata, private test reports or chat transcript.
The installed Codex 0.166.0 runtime detected MCP configuration but ignored hooks
from the portable root manifest, including its compatibility overlay. Using the
Codex manifest alone made all three hooks discoverable; `hooks/list` confirms
SessionStart, Stop and SubagentStop are enabled but `untrusted` pending host review.

The shared receiver and its persistent native controller report ready. Public
HTTPS ingress is not configured or qualified. Real GitHub-to-Desktop delivery,
automatic host hook execution, and ChatGPT Desktop compatibility are not claimed.
The hooks require host trust review. Remote repository recreation/publication
was unblocked after the old repository was removed. The repository was recreated
empty for publication of this Rust revision. Local history was recreated from a
Rust-only root; remote CI is qualified separately after publication.
