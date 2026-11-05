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
| `get_status` | Inspect local receiver health, CI waits and subscriptions |
| `recover_ready` | Dispatch stored ready events; never retry ambiguous deliveries |
| `configure_rule` | Match a PR comment and create or message a thread |
| `queue_thread` | Render and queue an input, optionally resuming the thread |
| `list_projects` | Read available Codex projects |
| `list_models` | Read available models and supported reasoning efforts |
| `get_goal` | Read a thread's goal through Codex's local app-server |
| `create_goal` | Create an explicitly requested goal without overwriting one |
| `edit_goal` | Edit an existing objective or explicitly requested budget |
| `resume_goal` | Resume an authorized existing goal and separately report queue acceptance |

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
| `dependency` | Namespace and dependency ID | `recovered` after provider health verification |
| `resource` | Namespace and resource ID | `released` by its owner |
| `artifact` | Namespace and exact artifact ID | `available` |

Subscribe to `git_ref updated` for changes to a PR's base branch. A PR's
`base_changed` reports its base selection changing, a distinct event.
Other provider results remain explicit unless the subscription specifies an
observation below. The plugin does not infer backup health or task success from
silence. A producer can still call `publish_result` for any supported custom source.

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

New threads default to `gpt-6.1-sol` with effort `low`; explicit presets are
validated against the owning server's model catalog. Native `codex queue` uses
the existing thread's model and has no per-message model/effort field. An
explicit execution preset for an immediate message uses `turn/start` on an idle/resumable
thread. Goal actions first persist and read back the preset, then mutate the goal.
A busy thread or unavailable API produces an error rather than silently
discarding the preset. A queue-only input cannot carry a per-turn override.

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
No `additionalContext`, stop decision or forced continuation is emitted.

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
`queued` means CLI acceptance, not proof that a chat resumed. Exit zero plus an
exact queue acknowledgement remains `queued` even if resuming emits a warning;
`resume_daemon_unavailable` identifies a missing local daemon. A crash, timeout
or uncertain warning is never blindly retried. Inspect the target chat before
resolving ambiguous records. Exactly-once delivery across SQLite and the Codex
CLI cannot be guaranteed without an idempotent acknowledgement protocol.

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
