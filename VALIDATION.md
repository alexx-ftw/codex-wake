# Validation

Local qualification on 2026-11-04 with the installed Codex Desktop runtime:

- `cargo fmt --check`: passed.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- Binary unit tests: 86 passed, including hook result summaries, duplicate
  quieting, payload privacy, cleanup ownership, nested links,
  external database identity, process identity, and host-config isolation.
- Native-test reply matcher self-check: passed; a marker in the user prompt alone is rejected.
- Hook CLI tests: 2 passed. Stop/SubagentStop emit one valid JSON object;
  failures retain a failing exit code and emit a supported warning shape.
  The installed SessionStart command was invoked against the real service:
  it recreated the removed receiver and returned a `systemMessage` confirming
  receiver/controller availability. No context or continuation fields were emitted.
  Useful output uses Codex's documented common hook output contract; automatic
  host invocation requires the user's hook trust review.
- After that review, automatic runtime qualification passed. `hooks/list`
  confirmed all three enabled hooks were `trusted`. A normal Desktop test turn
  spawned one Luna/low subagent; its completion and the parent turn's completion
  triggered their subscribed Sol/low recipient turns, which returned the exact
  expected delivery markers. A second probe used temporary native threads and
  captured real `hook/completed` notifications for SessionStart, Stop and
  SubagentStop: all were `completed`, and useful results were classified as
  `warning` entries. The two completion hooks each reported one newly matched
  subscription, one queue acceptance, zero pending and zero requiring attention.
  The probe verified two further recipient replies, five warning entries and
  zero plugin model-context entries. Hooks were never invoked manually in either
  automatic test. Fixture subscriptions were removed and reused test chats were
  archived after the test; the source chat was subsequently reopened for inspection.
  This verifies native execution and event-stream output, not visual rendering.
  Read-only inspection of the installed Desktop bundle confirms the presentation
  path: `hook/completed` updates the turn's `hookRuns`; completed runs retain
  `warning` entries in `hookStats`; the response action labelled `Hook stats`
  opens the run-history dialog, which renders their text under `Message` and
  displays the run status separately. Informational messages do not indicate a
  failed run. These are code-level findings, not a visual qualification of the
  live dialog. Desktop capture worked, but pointer automation did not reliably
  operate the interface; no claim of successful visual verification is made.
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
SessionStart, Stop and SubagentStop are enabled and `trusted` after host review.

The shared receiver and its persistent native controller report ready. Public
HTTPS ingress is not configured or qualified. Real GitHub-to-Desktop delivery
and ChatGPT Desktop compatibility are not claimed. The GitHub repository was
recreated with Rust-only history and published; the functional revision's
[CI passed](https://github.com/alexx-ftw/codex-wake/actions/runs/41838531726).
