# Validation

Local qualification on 2026-11-04 with the installed Codex Desktop runtime:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- Binary unit tests: 70 passed.
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
- Administrative lifecycle qualification: passed against the real installation.
  Persistently disabling the plugin and then uninstalling it preserved the
  receiver PID and signed HTTP health. Uninstall removed the plugin cache.
  Explicit `remove-service` removed the unit, stopped the receiver and its
  supervised processes, and closed TCP port 9000. Database rows and webhook
  secret were unchanged throughout; SQLite integrity remained `ok`.
  `ensure` recreated the enabled service and ready native controller.
  Reinstalling the plugin and starting its installed launcher reused that new
  service without another restart. Final state: plugin installed/enabled,
  receiver active, persisted data retained. No model turns were started.
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
remains pending GitHub's interactive access verification; remote CI has not run
for this Rust revision. Local history was recreated from a Rust-only root.
