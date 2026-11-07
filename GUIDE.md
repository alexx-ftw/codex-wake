# Codex Wake guide

[Overview and installation](README.md) · [Repository](https://github.com/alexx-ftw/codex-wake)

A desktop plugin written in Rust that queues a continuation to an existing
Codex chat when a registered event occurs. A chat can hold many independent
subscriptions at once. No extra model is used to route events or install services.

## Installation and startup

The package contains `.codex-plugin/plugin.json`, `mcp.json`, Rust source and
bundled lifecycle hooks. Add this repository as a local marketplace and install:

```sh
codex plugin marketplace add /absolute/path/to/codex-wake
codex plugin add codex-wake@codex-wake-local
```

The host launches `scripts/run-mcp.sh`. Release packages include a static binary
and its checksum; the launcher verifies it before execution. A source checkout
without that binary downloads the matching versioned GitHub release, verifies
its checksum, and caches it under `$XDG_CACHE_HOME/codex-wake/releases`
(default `~/.cache/codex-wake/releases`). Rust and Cargo are not required for
release installs. Development builds require `CODEX_WAKE_BUILD_FROM_SOURCE=1`
and use a build cache scoped to the absolute plugin path.

Diagnostics go to stderr; stdout is reserved for MCP messages. `codex`, `gh`, `curl`,
GNU `tar`, `sha256sum`, `flock` and a working Linux systemd user manager are
required. Automatic receiver installation supports Linux x86_64. Codex 0.166.0
is the qualification baseline; other versions and platforms are not yet
qualified. See [release qualification](RELEASING.md) for the publication gates.

Binary packages include
[dependency notices](THIRD_PARTY_NOTICES.md) and Rust standard library notices;
those third-party components retain their own licenses.
The bootstrap cache retains its downloaded archive containing those notices.

MCP descriptions, parameter schemas and structured results provide the agent
interface. Optional command skills in `skills/` map directly to the 13 MCP tools,
for example `$codex-wake:register-wait`, `$codex-wake:subscribe`,
`$codex-wake:configure-rule`, `$codex-wake:queue-thread` and `$codex-wake:status`.
Goal commands are `$codex-wake:create-goal`, `$codex-wake:get-goal`,
`$codex-wake:edit-goal` and `$codex-wake:resume-goal`. The remaining commands are
`$codex-wake:publish-result`, `$codex-wake:recover-ready`,
`$codex-wake:list-models` and `$codex-wake:list-projects`.
No onboarding skill or usage instructions are injected by MCP startup.

Open MCP connections retain their tool descriptions until they reconnect.
Use the maintenance upgrade procedure below for runtime changes.

MCP startup runs deterministic code that:

1. Acquires a process-shared installation lock.
2. Installs or checks one private persistent runtime outside the plugin cache.
3. Creates a managed user service and starts deterministic source observers.
4. Starts the private Codex controller and verifies the service identity.
5. Only with `CODEX_WAKE_ENABLE_WEBHOOKS=1`, downloads and verifies
   `adnanh/webhook` 2.8.3, creates a private secret and enables signed HTTP ingress.
6. Arms user-manager cleanup for the installed plugin's cache identity.

Concurrent MCP sessions reuse the same receiver without restarting it. An
unrelated service or conflicting active runtime is left untouched and reported.
For an intentional runtime upgrade, stop/remove the owned service first using
the command below; the next MCP startup installs the current version. State and
the secret are preserved. A live runtime is never rewritten during delivery.

The service also supervises a persistent native Codex app-server controller on
a private Unix socket, using the same `CODEX_HOME` and persisted Desktop state.
Its lifetime is independent of individual RPC/MCP clients so accepted turns
can continue. It does not restart or take over Desktop's existing active writers.
An explicit external control socket can be selected with `CODEX_WAKE_RPC_SOCKET`.

The receiver remains active after all MCP sessions close so it can wake their
chats later. It is enabled under the user's service manager, not installed as
root. Disabling the plugin preserves the service and subscriptions.

Uninstalling the plugin automatically stops the receiver, its controller and
registered MCP processes. It removes subscriptions, secrets, workspaces, runtime,
build cache, owned hook bookkeeping, and the generated local marketplace. The
cleanup service and path watcher remove their own units too. Codex's native
uninstall removes the package cache; the user manager completes external cleanup
after that removal, so cleanup may briefly outlive the uninstall command.
The watcher also works with the receiver stopped, and checks once when the user
manager starts if removal happened while it was offline. No agent or onboarding
skill is involved. Source repositories, user chats and unrelated resources are
not installation artifacts. Shared host/system historical logs are not erased.

```sh
systemctl --user status codex-wake.service
sh /absolute/path/to/installed/codex-wake/scripts/run-mcp.sh remove-service
```

`remove-service` is a maintenance stop, retaining state and the secret. The
uninstall watcher remains armed; another MCP session can recreate the receiver
while the plugin is still installed. It refuses to remove an unrelated unit.
Stopping this service also stops its controller and any turns that controller
owns. Finish those turns before a planned removal or runtime upgrade.

### Maintenance upgrade

1. Finish controller-owned turns, disable Wake and close clients using its MCP.
2. Run the old installed package's launcher with `remove-service`, as above.
   Do not uninstall the plugin: uninstall deliberately deletes its state.
3. Verify the new archive with its `SHA256SUMS`, then unpack it into a fresh
   directory. Add that directory with `codex plugin marketplace add` and run
   `codex plugin add codex-wake@codex-wake-local` to refresh the installed copy.
4. Re-enable Wake and reopen the client. Review and approve the updated hooks.
   The next MCP startup installs the new runtime using the existing state and
   webhook secret. Reconnect other clients so they load the new MCP interface.

The receiver is offline during this maintenance window. Source systems may
retry webhook requests according to their own delivery policy; check their
delivery records and redeliver missed events when needed. This is not a
zero-downtime updater.

## Agent interface

GitHub polling is the default and needs no public endpoint. The tools below
register observations; only matching verified results queue model input.

For optional webhook ingress, enable `CODEX_WAKE_ENABLE_WEBHOOKS=1` when starting
the managed service. To add a stable HTTPS endpoint without a custom domain, enable Tailscale
Funnel for the machine, then mount only the webhook route in the background:

```sh
tailscale funnel --bg --yes --https=443 --set-path=/hooks/codex-wake \
  http://127.0.0.1:9000/hooks/codex-wake
CODEX_WAKE_ENABLE_WEBHOOKS=1 cargo run --locked -- record-funnel
```

`record-funnel` explicitly adopts that exact route into the plugin's private
installation state. `get_status` reports its configured URL. Tailscale manages
HTTPS and persistence across restarts; GitHub HMAC authentication remains in
the receiver. Uninstall removes the adopted path if its proxy is unchanged,
preserving other Tailscale routes and the shared Tailscale installation. A
replaced path is left to its new owner. This does not create repository webhooks
or change tailnet-wide policies automatically.
The status call checks local ingress configuration, not a fresh external
delivery. Its conservative `public_ingress_verified` flag is not a substitute
for the dated external delivery evidence in `VALIDATION.md`.

| MCP tool | Action |
|---|---|
| `register_wait` | Register exact CI repo/run/attempt/SHA and destination chat |
| `subscribe` | Register another exact source/resource/event and destination |
| `publish_result` | Publish a verified provider result and dispatch matching waits |
| `register_obligation` | Record a chat's pending result publication |
| `register_resource_wait` | Record a wait on a non-chat resource and its declared continuation |
| `update_wait_continuation` | Update an active wait’s declared continuation without resolving it |
| `register_coordinator` | Explicitly set the coordinator for a responsible chat |
| `list_obligations` | List a chat's pending publications |
| `resolve_obligation` | Resolve a pending obligation explicitly |
| `propose_obligation_transfer` | Propose transferring a pending obligation to another chat |
| `list_obligation_transfers` | List transfer proposals addressed to a chat |
| `accept_obligation_transfer` | Accept a proposal and become responsible |
| `get_result_conflicts` | Read paginated evidence for an exact job execution and attempt |
| `get_status` | Inspect local receiver health, CI waits, subscriptions and recent coordinator alert states |
| `recover_ready` | Dispatch stored ready events; never retry ambiguous deliveries |
| `configure_rule` | Match a PR comment and create or message a thread |
| `queue_thread` | Render and queue an input, optionally resuming the thread |
| `list_projects` | Read available Codex projects |
| `list_models` | Read available models and supported reasoning efforts |
| `get_goal` | Read a thread's goal through Codex's local app-server |
| `create_goal` | Create an explicitly requested goal without overwriting one |
| `edit_goal` | Edit an existing objective or explicitly requested budget |
| `resume_goal` | Resume an authorized existing goal and separately report queue acceptance |

For conflicting job reports, provide both `execution_id` and the positive `attempt`
to `publish_result`, together with the publisher and supporting evidence in
`source`. Wake compares only reports for the same namespace, resource, execution
and attempt. The response lists up to ten reports when success, failure or
cancellation disagree; use `get_result_conflicts` with the same identity and its
`next` cursor for all pages. It does not determine which is correct or undo any
earlier delivery.
Publications without an execution identity remain supported and are not compared.
A terminal job outcome (`success`, `failure`, or `cancelled`) matches both its
exact event and `completed` subscriptions and resolves matching publication
obligations for both outcomes atomically. Each route retains its own delivery
identity. When no matching subscription is waiting, evidence for
an earlier `completed` subscription includes the outcome it actually received;
it does not prove that the new result was delivered.
If no subscription is waiting but an earlier one matches, the publisher receives
`no_waiting_subscriber` and the available delivery evidence for inspection.

Stored subscriptions and CI waits with a model preset remain ready when the target
is active or `thread/resume` definitively rejects its active writer before input
submission, or when transport fails during preparation before any input-bearing
RPC. They retry after 15 seconds, preserving the preset. An uncertain
`turn/start` result still requires inspection and is never automatically replayed.

Every subscription is independent and one-shot. Completing one doesn't cancel
the others. Re-registering the same subscription is idempotent; it does not rearm
a consumed subscription. Source events received before registration aren't replayed.

| Source (`kind`) | Resource | Supported event |
|---|---|---|
| CI (`register_wait`) | Repo, run ID, attempt, SHA | Completed workflow run |
| `pull_request` | Repo and PR number | `merged`, `closed`, `synchronize`, `base_changed` |
| `review` | Repo and PR number | `submitted`, `approved`, `changes_requested` |
| `deployment` | Repo and deployment ID | `success`, `failure`, `error` |
| `git_ref` | Repo and branch name | `updated` |
| `job` | Namespace and job ID | `completed`, `success`, `failure`, `cancelled` |
| `chat` | Source chat UUID | `completed`, `blocked`, `failed` reported by its owner |
| `thread` | Source chat UUID | `turn_completed` from the `Stop` lifecycle signal |
| `subagent` | Source agent UUID | `completed` from `SubagentStop` |
| `dependency` | Namespace and dependency ID | `progress` resets the inactivity deadline; `recovered` after provider health verification |
| `resource` | Namespace and resource ID | `released` by its owner |
| `artifact` | Namespace and exact artifact ID | `available` |

Dependency subscriptions use `progress_timeout_secs` (default 3600) and persist
the last explicit progress signal and its deadline. When it expires, Wake sends
one request to investigate for that inactivity period; silence is not treated as failure. Publish
`dependency/progress` only when progress is observed and `dependency/recovered`
after recovery is verified. An ambiguous notice delivery is retained as
`needs_attention` and is never replayed automatically.

Subscribe to `git_ref updated` for changes to a PR's base branch. A PR's
`base_changed` reports its base selection changing, a distinct event.
Other provider results remain explicit unless the subscription specifies an
observation below. The plugin does not infer backup health or task success from
silence. A producer can still call `publish_result` for any supported custom source.
Wake reports whether a waiting subscription has a configured automatic observer,
GitHub polling capability, matching pending publication obligations, or no
recorded publisher. An unknown publisher is a warning, not a registration error.
Automatic-source health is unverified: capability and configuration do not prove
that credentials, polling or delivery work, nor that an event will arrive.
After MCP registration, `registration_error` identifies a failed observer setup
and `subscription_error` identifies a failed status lookup; `subscription_id`
still identifies the saved subscription.

## GitHub and external events

The service uses the existing `gh` login and polls only resources with active
subscriptions or rules. Requests are shared across consumers of the same source;
polling and dispatch run independently. Source failures remain diagnostic errors,
not successful events. Cursor state persists across restarts. Polling cannot
reconstruct every intermediate edit or content created and deleted between reads.
GitHub timestamps have second precision: events in the registration's second are
included to avoid losing a later event with the same timestamp. On the first
read this can include an event from just before registration within that second.
Use `poll` for one deterministic observation cycle and `get_status` to inspect
observation health; neither requires a model turn.

When explicitly enabled, the shared HTTP receiver listens only on `127.0.0.1:9000`.
Configure an HTTPS reverse
proxy or persistent tunnel forwarding `/hooks/codex-wake`, and a GitHub JSON
webhook with `workflow_run`, `pull_request`, `pull_request_review`,
`deployment_status` and `push` as needed. Use the private secret from
`~/.config/codex-wake/webhook.secret` (respecting `XDG_CONFIG_HOME`) in the
provider's secret field. Do not commit or print it.

For custom publishers, send `X-GitHub-Event: codex_wake` and the same HMAC-SHA256
signature convention over the exact JSON body:

```json
{"kind":"artifact","repo":"release-pipeline","resource":"package-1.2.3","event":"available","outcome":"available"}
```

Authentication occurs in the external receiver before Rust reads the payload.
The managed handler durably records matching events and returns HTTP success
without waiting for Codex. A worker in the same user service dispatches ready
records. Duplicate deliveries cannot claim the same record twice. Unmatched
events don't create subscriptions. The payload limit is 1 MiB.

Optional public ingress and provider webhooks aren't created automatically. Local
readiness is reported separately from public ingress verification. Webhook-only
events have no retrospective fetch; polling can catch up only data still exposed
by the provider's API.

## Local and native observations

The optional `observation` field on `subscribe` selects a deterministic probe:

| Observation | Subscription | Verified condition |
|---|---|---|
| `{"type":"file","path":"/absolute/package.tar"}` | `artifact/available` | A regular file exists; symlinks are excluded |
| `{"type":"http","url":"https://service.example/health"}` | `dependency/recovered` | The specified endpoint returns HTTP 2xx, without following redirects |
| `{"type":"file_lock","path":"/absolute/worker.lock"}` | `resource/released` | An existing owned regular file permits a nonblocking exclusive `flock` |
| `{"type":"systemd","unit":"build.service","invocation_id":"0123456789abcdef0123456789abcdef"}` | `job/success`, `job/failure` or `job/completed` | That exact user-unit invocation has a matching terminal result |

The CLI accepts the same JSON through `--observe`. Configuration is immutable
for a registered subscription. Polling stops once that subscription is consumed.
External probes run every 60 seconds; native Codex turn probes every five seconds.
Errors, missing paths, refused connections and unknown invocations are diagnostic
states, not successful outcomes. HTTP probes are bounded and do not accept URL
credentials. File presence does not prove a complete, correct artifact: publish
atomically or use an explicit verified producer when that distinction matters.
`file_lock` describes cooperative `flock` availability, not other locking protocols.
Systemd cannot establish user cancellation, so `job/cancelled` remains producer-only.

Thread polling reads turn metadata without starting model work. Native subagents
are polled only when the API verifies their child-thread identity and parent.
The first observation establishes a baseline; historical completed turns are not
replayed. A turn ending is not proof that the task is done. Non-native subagent IDs
and `chat/completed`, `chat/blocked` or `chat/failed` still need their trusted hook
or explicit owner signal. Polling payloads contain observed IDs and statuses, not
the full original hook payload; hook-only template fields may be unavailable.

## Conditional thread actions and templates

`configure_rule` registers PR-comment conditions: repository/PR, author login,
account type (`User` or `Bot`), a literal phrase, and `all`/`any` matching.
New or edited general PR comments (`issue_comment`) and inline review comments
(`pull_request_review_comment`) are supported. Add those events to the GitHub
webhook when using rules. A rule targets an existing chat, or creates a new one
inside the selected Codex project or outside a project, with an optional goal.
Distinct matching comments trigger independently; duplicate deliveries don't
create duplicate chats. Ambiguous creation results require inspection before retry.

Messages and goal objectives support literal dotted placeholders, for example
`{{source.comment.user.login}}`, `{{source.comment.body}}`, `{{event.repo}}`
and `{{event.pr}}`. Subscription inputs also expose `{{target.thread}}`.
Only referenced scalar source values are substituted; no code, shell expansion,
environment lookup or recursive template evaluation occurs. Missing/non-scalar
fields are errors. Templates and rendered messages are limited to 64 KiB.
Matching source JSON used for templates and conditional rules stays in the
private database. Duplicate deliveries don't replace the first matching source data.

CI and other subscriptions accept `message_template` and optional `execution`
(`model`, `reasoning_effort`). Immediate `queue_thread`, goal actions and rules
can also specify their input. Goal edits and input delivery are reported
separately so a failed queue never conceals a successful goal mutation.

New threads default to `gpt-6.1-terra` with effort `medium`; explicit presets are
validated against the owning server's model catalog. Native `codex queue` uses
the existing thread's model and has no per-message model/effort field. Rules
targeting an existing chat omit execution overrides unless configured. An
explicit execution preset for an immediate message uses `turn/start` on an idle/resumable
thread. Goal actions first persist and read back the preset, then mutate the goal.
A busy thread or unavailable API produces an error rather than silently
discarding the preset. A queue-only input cannot carry a per-turn override.

## Duplicate recipient-delivery evidence

Wake only labels a delivery duplicated after observing two distinct native
`userMessage` item IDs with the same stable source event, destination chat, and
`clientId`. The `item/started` and `item/completed` notifications for one item
ID count once. An incoming webhook repeated by itself is not delivery evidence.

Correlation uses live notifications and incremental scans of persisted native
chat history. Rules, waits, and subscription dispatch can be observed when
their source has a stable event ID. Polling can supply source event IDs to those
dispatch paths; a poll result alone is not recipient evidence. Sources without
a stable event ID and CLI fallback sends remain `unknown`. An isolated `queue/add` case
confirmed the `clientUserMessageId`-to-`clientId` mapping; it does not prove
coverage for every Codex version. Scans restart from the newest page after an
error or service restart, refresh the newest page during long scans, and stop a
scan after 1,024 cursors or a cursor cycle. Missing observations remain unknown.
Subscription identity includes its exact event and outcome. Base/ref transitions
and pull request synchronization remain unknown when only old/new refs or commit
SHAs are available, since those values can recur.
Queue acceptance is not confirmation that a warning was delivered.

For an explicitly requested deferred handoff, `queue_thread` accepts
`steer: true` (default `false`). It is incompatible with `resume: true` and
`execution`; normal queue and resume behavior is unchanged. Wake renders the
template first and limits the JSON-encoded rendered string to 2048 UTF-8 bytes,
including JSON quotes and escapes. It remains
`pending` until the destination's own `PostToolUse` or `Stop` hook claims it;
this does not wake an idle chat. Claiming is atomic and single-use. `claimed`
means hook output was prepared, not that Codex accepted it or the model consumed
it. If the process crashes or Codex rejects the output after the claim, Wake
does not replay it automatically. Inspect status and decide whether to submit a
new input. A child hook cannot consume input for its parent thread.

[examples/pr-bot-review.json](examples/pr-bot-review.json) demonstrates a bot/phrase
rule. Configure only rules and objectives actually authorized by the user:

```sh
cargo run --locked -- configure-rule --file examples/pr-bot-review.json
```

Goal and project operations use the local Codex app-server API; they don't edit
Codex databases directly or impersonate user-origin mutations. Creating a goal
refuses to overwrite an existing one. Omitted edit fields retain their values;
Codex controls usage accounting, and editing an objective does not guarantee a reset. All RPC mutations preserve
server restrictions. Creating, editing or activating an active goal can make
Codex continue automatically. Execution presets are applied before the mutation;
optional input is then queued without a separate resume request. The installed
API has no atomic goal-plus-input operation: an automatic continuation may start
before that input is queued, so it can be consumed by a subsequent turn.

## Thread and subagent signals

`register_resource_wait` records an explicit wait for a non-chat resource using
the same continuation declaration. Its resource is shown as `resource:<name>` in
`get_status.circular_waits`; it cannot form a chat-to-chat cycle. Update its
declaration with `update_wait_continuation` without resolving the
wait; use `resolve_circular_wait` when the wait ends. A `none` or `unknown`
declaration triggers the same eligible Stop reminder; Wake does not infer
whether mechanisms exist outside the explicit record.

`register_circular_wait` records an explicit wait from `thread` to `waits_for`,
with evidence supplied by the caller. Ordinary subscriptions do not create waits.
When both directions are active, Wake records a notice for each chat containing
both wait IDs and their evidence. A mutual registration is a possible circular
dependency, not proof of deadlock. `continuation` is the caller's declaration:
`none`, `registered`, or `unknown` (the default); `registered` requires
`continuation_ref` identifying the declared subscription, event, or other
mechanism. Wake does not verify that it works. An eligible Stop continues the
agent once when a wait is declared `none` or `unknown`, asking it to verify the
continuation; neither declaration proves that no mechanism exists outside Wake.
Use `update_wait_continuation` to record a known mechanism without resolving the
wait or changing existing notices. The reentrant Stop does not continue again for that warning.
Use `resolve_circular_wait` when a wait ends; ready notices for that cycle are
cancelled, but a notice already being sent cannot be recalled. Re-registering a
resolved wait creates a new episode. `get_status.circular_waits` exposes waits
and notice states. The receiver and `recover_ready` dispatch notices; a stopped
receiver leaves them ready. Queued means accepted, not read or executed. Sending
and uncertain notices are never retried automatically; inspect status first.
After five minutes in `sending`, `get_status` reports `sending_outcome_unknown`
and includes the notice in `actionable`. This is a read-only diagnostic: the
sender may still be running, and a later result can still update the notice.
An unreadable or future timestamp is also reported as uncertain. Inspect the
sender and destination before acting; elapsed time does not prove failure.

For an expected result, `register_obligation` records the responsible chat and
the exact publication kind, namespace, resource and outcome. At an eligible
`Stop`, Wake reminds that chat of pending obligations; it does not infer that
work has finished or that a result is successful. A matching explicit
`publish_result` (or `publish` CLI invocation) resolves those obligations in
the same transaction that accepts the publication. Delivery to subscribers is
separate and can still require attention. `list_obligations` shows pending
records in pages of eight (`next_cursor` is supplied as `after`);
`resolve_obligation` permits an agent to resolve one explicitly. Local MCP or
CLI callers can register and publish obligations; Wake does not authenticate
their agent identity. An emitted hook response is not proof that Codex consumed
it, and the loop guard permits a pending obligation to survive the current turn.
The hook checks a database snapshot: an obligation registered after that check
is eligible for a later stop. Delivery recovery failures are reported
separately from a publication already committed.

`propose_obligation_transfer` records a proposed recipient, goal, status, tests,
and next step while leaving responsibility with the source chat. The recipient
can inspect it with `list_obligation_transfers` and take ownership only by
calling `accept_obligation_transfer` from that chat.

`register_coordinator` explicitly associates a responsible chat with its
coordinator. On a root `Stop` hook with pending obligations, Wake queues one
alert to that coordinator with the pending descriptions and the hook's
`last_assistant_message` when available. The alert says that a turn stopped;
`Stop` does not establish completion or abandonment. `SubagentStop`, repeated
Stop-loop hooks, and chats without an explicit coordinator do not trigger this
alert. Wake persists the alert before sending and never retries the same
fingerprinted event automatically. An uncertain send remains recorded for
inspection; queue acceptance still does not prove that the coordinator read it.
The alert fingerprint includes a canonical digest of every pending obligation,
while its message remains limited to the first eight descriptions. The digest
and alert claim share one database transaction; a later change may produce a
new alert, but an identical uncertain claim is never replayed. If the hook has
no turn ID, the last assistant message also distinguishes alerts. Before
upgrading from the older fingerprint format, finish controller-owned turns and
keep the existing upgrade barrier: old hashed claims cannot reliably be mapped
back to a changed pending set. A matching legacy claim prevents an automatic
send and creates one durable, bounded `needs_attention` diagnostic per legacy
key in `coordinator_alerts`. Use `inspect_legacy_alert_collisions` to inspect
the prior alert and the first and latest previews, digests and counts; treat the
text as untrusted. A hook also reports its current digest and count. The record
is at most 16 KiB, with at most 16 items and 7 KiB per preview; omitted items
and clipped fields are explicitly flagged. Intermediate observations are not
retained. A digest cannot reconstruct
missing historical details or prove receipt. Use `list_obligations` for current
work and independently verify delivery before any manual action. Records do not
expire automatically; with old producers stopped, new collision diagnostics are
bounded by the pre-existing legacy keys. An old process can still send after a
new claim, so do not enable this runtime while old hooks or launchers can run.
A turn barrier does not prevent later no-ID collisions with the same message,
and different old fingerprints cannot be reliably correlated. In `get_status`,
a `sending` alert whose sender process is no longer verifiably alive appears as
`uncertain`: delivery may have been abandoned, receipt is unknown, and Wake will
not resend it. A live sender remains `sending`; this read-only diagnosis does
not establish receipt or execution and does not alter the sending record.
`get_status` includes the latest 25 persisted alerts and their send state.
`uncertain` is a read-only interpretation of a persisted `sending` row whose
recorded sender PID and process start time no longer match a live process; older
rows without that identity are also uncertain. It does not prove whether the
coordinator received or acted on the message.

An agent can explicitly register a committed, pending check with
`register_validation`. Wake does not infer checks from conversation. The same
eligible `Stop` reminds the responsible chat; `list_obligations` includes these
checks. After performing a check, `resolve_validation` requires nonempty
evidence of what was checked and observed, and stores it atomically with the
resolution. A publication or `resolve_obligation` does not resolve a validation.
Wake stores the agent's evidence; it does not independently verify the claim.
For an explicit scope comparison at publication time, register the validation
with both a structured `link` (`kind`, `repo`, `resource`) and `scope` object,
then include the corresponding `scope` in `publish_result`. Wake warns when the
declared scope differs for that exact linked publication and leaves the
validation pending. It compares declarations only; it does not verify the
published result or either scope. Legacy registrations and publications without
these fields remain supported and are not compared.
When a reminder is due, the hook leaves lifecycle deliveries ready for the
receiver's background dispatcher instead of waiting for unrelated sends. If the
receiver is unavailable, they remain ready until it restarts or recovery runs.

Bundled `SessionStart` checks the shared receiver. `Stop` and `SubagentStop` command hooks publish local lifecycle signals
without asking a model to interpret instructions. Codex requires users to review
and trust plugin hooks before running them; installation alone doesn't trust
them. No trust bypass is installed.

`Stop` describes a turn stopping, not successful completion of its task. Another
hook can still continue the turn. The owner can separately publish `chat
completed` when the task itself is done. Consumers must verify the source's
result before acting. Interruptions, closing a window, and idle status aren't
treated as task success. Self-subscription to a thread's own stop is rejected.

Hook stdout follows Codex's JSON contract. `SessionStart` reports receiver and
controller readiness through `systemMessage`. `Stop` and `SubagentStop` report
newly matched subscriptions and current delivery states for that source; no new
matches produce `{}`. Accepted queue input is explicitly distinguished from
verified execution. Hook failures retain a failing exit code and diagnostics.
These messages surface in the UI/event stream, not as model instructions.
No `additionalContext`, stop decision or forced continuation is emitted for
lifecycle notifications.

When a deferred steer is claimed, `PostToolUse` returns its input as
`hookSpecificOutput.additionalContext`; `Stop` uses the documented continuation
output. When `stop_hook_active: true`, only the steer claim/continuation is
skipped; the `Stop` lifecycle signal is still published. Subagent hooks carry
the parent `session_id`, so they must not consume the parent's queued steer;
only a hook belonging to the destination thread may claim it. A claim records
that output was prepared, not delivered to or consumed by the model. Neither
hook output nor a successful claim grants approval for tools or expands the
task's authorization.

Hooks are supported by manually installed desktop plugins; this package isn't
currently eligible for the public directory while it bundles them. The resume
transport targets Codex chats through the installed `codex queue --resume` CLI;
when Wake's Unix controller is configured or present, `--remote` selects that
same controller instead of requiring another local daemon.
It doesn't implement a ChatGPT chat-resume transport.

## CLI and state

```sh
cargo run --locked -- register --repo owner/repo --run 123 --attempt 1 \
  --sha aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --thread 11111111-1111-4111-8111-111111111111
cargo run --locked -- subscribe --kind artifact --repo release-pipeline \
  --resource package-1.2.3 --event available \
  --thread 11111111-1111-4111-8111-111111111111
cargo run --locked -- subscribe --kind dependency --repo payments \
  --resource database --event recovered --progress-timeout-seconds 1800 \
  --thread 11111111-1111-4111-8111-111111111111
cargo run --locked -- publish --kind dependency --repo payments \
  --resource database --outcome progress
cargo run --locked -- status
cargo run --locked -- subscriptions
cargo run --locked -- recover
cargo run --locked -- diagnostics --days 42
```

The database is `$XDG_STATE_HOME/codex-wake/state.sqlite3` (default
`~/.local/state/codex-wake/state.sqlite3`), overridable by `CODEX_WAKE_DB` or
`--db`. The service and all sessions must share it. The runtime is under
`$XDG_DATA_HOME/codex-wake/runtime`. Secrets and database files are private.

States are `waiting`, `ready`, `sending`, `queued` and `needs_attention`.
`queued` means native or CLI queue acceptance, not proof that a chat resumed.
An accepted queue remains `queued` even if resuming emits a warning;
`resume_daemon_unavailable` identifies a missing local daemon. A crash, timeout
or uncertain warning is never blindly retried. Inspect the target chat before
resolving ambiguous records. Exactly-once delivery across SQLite and the Codex
CLI cannot be guaranteed without an idempotent acknowledgement protocol.

MCP `get_status` places deliveries needing attention and dependency recovery
subscriptions in `actionable`. Each entry includes the original status evidence,
an optional link to the destination chat, and a suggested next action. The
underlying `waits`, `subscriptions` and `rules` inventories remain available.
An event matching a recovery subscription does not by itself prove that the
destination chat resumed or that its work completed.

Every continuation contains fixed routing metadata rather than webhook message
text. It grants no new authority. The receiving agent verifies the event at its
source and continues only the existing authorized task.

## Operational diagnostics

Operational metadata is stored locally in
`$XDG_STATE_HOME/codex-wake/telemetry.sqlite3` (default
`~/.local/state/codex-wake/telemetry.sqlite3`). `diagnostics --days 1..90` and
MCP `get_status` expose daily counts, latency totals/maxima, recent problems,
observation timestamps and queue counts/oldest ages. No model turn is needed.

Records cover CLI/MCP calls (including invalid tool arguments), hooks, event
matching and deduplication, registrations, delivery claims/results, controller
RPCs, process exits and a controller-readiness heartbeat every minute. The
receiver's HTTP access records include status classes and durations; a 403 means
signature or trigger mismatch, not necessarily an authentication attack.
Controller warnings and connection failures are categorized before storage.

Each record includes a timestamp, process/build identity, correlation trace,
operation, outcome, reason category, duration and count. Source/delivery/thread
identifiers are hashed. Prompts, goals, templates, webhook bodies, credentials,
headers, URLs and raw child/error output are excluded from this telemetry.
The operational database still retains original source data where templates
require it; it is separate from the telemetry database.

Detailed records retain up to 42 days or 100,000 entries, whichever is reached
first; daily aggregates retain 90 days. Pruned detail is counted explicitly.
SQLite is limited to 64 MiB and reuses freed pages. Files are private (0600,
directory 0700) and removed with the plugin's state on uninstall. Telemetry
failures emit a fixed diagnostic to stderr and do not stop event processing.
`telemetry_writer_lock_timeout` identifies an exhausted one-second cross-process
writer-lock wait; SQLite busy/locked errors remain `database_busy`, and other
I/O timeouts remain `timeout`. A failed database attempt caused by contention is
saved as a private `telemetry-pending-UUID.json` file, including its original time,
process/build identity and correlation. The next successful telemetry write drains
up to 128 pending records; receiver heartbeats keep recovery progressing when no
other work arrives. Transactional receipts prevent duplicate aggregates if a
process exits after committing a replay but before removing its pending file.
Diagnostics show pending count, accounted bytes and oldest observation time.
Pending storage has a separate 64 MiB cap (each file accounts for at least 4 KiB);
individual records are capped at 64 KiB. Uninstall removes this plugin-owned state.
Writers also allow SQLite up to one second to clear transient contention; read-only
reports retain their 250 ms limit. Contended writes can delay telemetry callers,
and records are deferred to disk when these database waits expire.
Child output is drained independently through a bounded nonblocking queue;
overflow is counted when the writer catches up. Repeated storage warnings are
rate-limited. Full or unavailable storage and termination before a record is durably
saved can still leave missing detail; a stale heartbeat and incomplete spans are diagnostic signals,
not proof that the underlying work failed.

`ok` means that operation succeeded. `queued` means queue/turn-start acceptance,
not verified execution or completion. A `started` record without a terminal
record is an unfinished observation, not proof of failure. Queue snapshots use
duration for the oldest record's age, not request latency. No external analytics
service or automatic model probes are used.
Count completed `mcp.*` operations to measure agent calls, and `dispatch.*`
outcomes to measure deliveries. Starts, nested RPCs and queue snapshots are
separate observations and must not be summed as independent user actions.

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --bin codex-wake
CODEX_WAKE_WEBHOOK=/absolute/path/to/verified/webhook \
  cargo test --locked --test http -- --include-ignored
```

The HTTP test uses the real receiver and a fake Codex executable. The explicitly
opt-in `lifecycle` test creates/reuses the real user service and checks concurrent
MCP sessions and persistence after exit; it does not queue a real chat.

The opt-in `native` test creates a dedicated chat and real model turns, verifies
the assistant reply and persisted execution settings, and exercises goal
create/edit/read. Active goal changes may themselves start continuations.
Its one-shot guard prevents blindly replaying an interrupted accepted event.

`smoke-live --test-thread UUID --webhook PATH` and `smoke-github --repo OWNER/REPO
--test-thread UUID --webhook PATH` are opt-in CLI commands for a dedicated test
chat only. The latter temporarily creates a Cloudflare tunnel and GitHub webhook,
dispatches the supplied `ci.yml`, waits with `gh run watch`, checks exact delivery
HTTP 200 and cleans up its own resources. Never target a work chat. Private
reports stay in ignored `.test-results/`. Neither command proves visible chat
resumption without observing that chat.

See [VALIDATION.md](VALIDATION.md) for the observations on this revision.
Packaging follows [OpenAI's plugin format](https://developers.openai.com/plugins/build/plugins)
and [desktop MCP configuration](https://developers.openai.com/plugins/deploy/desktop-only).
