# Validation

## Real MCP actions, 2026-11-04

The goal-description correction was subsequently installed without stopping the
shared receiver. A reviewed exact source alias retained the original runtime
source/binary pins; the receiver PID, executable inode/checksum and both child
PIDs stayed unchanged. All four subscription rows present during installation
(three existing plus a continuity probe) were byte-for-byte unchanged. Both an
already-open MCP and a fresh installed MCP reported healthy; the fresh one
advertised the corrected descriptions and delivered an artifact to the probe
registered before installation. Its actual assistant final reply confirmed
delivery. The host's three hook approvals were revalidated after review.

All twelve tools beyond get_status were invoked through the installed MCP.
Catalog calls returned the real models and projects, including a temporary
project rooted in an isolated Jujutsu workspace. Goal create/read/edit/resume
changed native saved metadata; queued edit and resume templates produced exact
assistant final replies. Queue-only and explicit-resume inputs both produced
their rendered replies; Codex can consume queued input automatically.
An available file was published to an artifact subscription, producing its
expected final reply. Repeating publication matched zero subscriptions.

The temporary [PR #1](https://github.com/alexx-ftw/codex-wake/pull/1) completed
[real CI](https://github.com/alexx-ftw/codex-wake/actions/runs/41868952301).
Its real workflow_run completion payload, obtained from GitHub's delivery API
with HTTP 200 evidence, was ingested with CODEX_WAKE_DEFER=1. recover_ready
dispatched one pending wait and the recipient replied with the run ID and
success conclusion; a subsequent recovery attempted zero deliveries. This is
an explicit replay of an authentic completion, not a fresh webhook recovery.
A nonmatching PR comment created no rule delivery. A matching comment arrived
over the signed HTTPS webhook, created a new chat in the temporary project and
workspace, and produced the expected assistant final reply containing the
GitHub comment ID. Native stored metadata confirmed Sol/low for all recipients.

The run also disproved the previous usage-accounting description: editing the
paused goal retained its token/time counters. Descriptions now leave accounting
to Codex instead of promising a reset. Active-writer preset rejection was
observed; the test did not bypass it. No budgets were set.

Local qualification on 2026-11-04 with the installed Codex Desktop runtime:

- Stable Tailscale Funnel ingress passed
  [real GitHub qualification 41860250112](https://github.com/alexx-ftw/codex-wake/actions/runs/41860250112)
  at revision `a73d40601c91f95db085edf9302cae58db5cdf88`. GitHub's exact delivery
  record confirmed HTTP 200, four exact native assistant replies were observed,
  and SessionStart, Stop and SubagentStop completed automatically after the user
  trusted the updated plugin bundle. The endpoint is mounted only at
  `/hooks/codex-wake` with a loopback proxy and HMAC verification; public GET
  returned 405 at that path and 404 at the root. Tailscale's background serve
  configuration remains active, tailscaled is enabled and user linger was
  already enabled. No machine or Tailscale daemon restart was performed.
  The temporary repository webhook and fixture rows were removed; the stable
  ingress remains configured. No permanent repository webhook was created.
  Funnel ownership is stored privately outside the plugin bundle. Three focused
  mocked-CLI tests cover selective route removal, preservation of changed or
  missing targets, node renaming, unsuccessful removal and unsafe state files;
  all 99 unit tests, integration tests and
  [CI](https://github.com/alexx-ftw/codex-wake/actions/runs/41859647580) passed.
  Live uninstall of the active Funnel route was not performed.

- Real GitHub end-to-end qualification passed with
  [Actions run 41854888860](https://github.com/alexx-ftw/codex-wake/actions/runs/41854888860)
  at revision `466e046af53ece277a92d0bdf89190b2f8398476`.
  GitHub sent the real `workflow_run/completed` payload through a temporary
  HTTPS tunnel to the installed shared receiver. The exact delivery record in
  GitHub confirmed HTTP 200 for that run. Its registered run/attempt/SHA started
  a real Sol/low turn, which spawned and waited for a Luna/low subagent.
  Four exact assistant replies were observed in completed native agent-message
  events: the subagent, the GitHub recipient, the SubagentStop subscriber and
  the Stop subscriber. SessionStart, Stop and SubagentStop ran automatically,
  completed successfully and emitted supported warning entries without plugin
  model-context entries. No hook command or synthetic webhook was invoked.
  The temporary GitHub webhook and fixture subscriptions/wait were removed,
  ephemeral fixture chats unloaded and the tunnel stopped after qualification.
  An initial verification-driver failure was JavaScript rounding a GitHub
  delivery ID beyond its safe integer range; preserving the exact integer
  string corrected the driver before this successful run. Private transcripts,
  webhook configuration and fixture chat/subscription IDs are excluded from the repository.

- Operational telemetry qualification: 96 binary tests, 3 isolated telemetry CLI
  tests, 2 hook CLI tests and the native reply-matcher self-check passed; format
  and Clippy with warnings denied passed. Eight simultaneous CLI processes
  retained every expected terminal record. Retention/cap pruning, daily
  aggregates, private files, missing-state read-only diagnostics, first-write
  migration and logging failures that preserve hook processing were exercised.
  These tests do not start model turns or manipulate the desktop.
  Telemetry distinguishes request success, queue acceptance and unfinished
  observations. Child log capture uses a bounded nonblocking queue; overflow
  counts are emitted when its writer catches up. Operational metadata is local.

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
An additional native MCP discovery check on 2026-11-04 found that Codex 0.166.0
treated `${PLUGIN_ROOT}` literally in this manifest's MCP arguments and working
directory. The package now uses a relative script path and `cwd: "."`.
Startup also persists the installed Codex executable across different MCP PATHs
and supplies the owned user runtime directory to systemctl when the host omits
XDG_RUNTIME_DIR. A regression reuses the same live receiver with only
`/usr/bin:/bin` on PATH and no D-Bus/runtime environment variables.
The native app-server discovered all 13 tools, called get_status successfully,
and a fresh ephemeral Sol/low agent independently called that MCP tool and
finished with `WAKE_MCP_OK`. Existing desktop chats with a cached failed
connection were not restarted or proven refreshed by this check.
The installed Codex 0.166.0 runtime detected MCP configuration but ignored hooks
from the portable root manifest, including its compatibility overlay. Using the
Codex manifest alone made all three hooks discoverable; `hooks/list` confirms
SessionStart, Stop and SubagentStop are enabled and `trusted` after host review.

The shared receiver and its persistent native controller report ready. Both
temporary HTTPS ingress and stable Tailscale Funnel ingress with real
GitHub-to-native-Codex delivery are qualified above. Pixel rendering of hook
results and ChatGPT Desktop compatibility are not claimed. The GitHub repository was
recreated with Rust-only history and published; the functional revision's
[CI passed](https://github.com/alexx-ftw/codex-wake/actions/runs/41852198562).
