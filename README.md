# Codex Wake

[Repository](https://github.com/alexx-ftw/codex-wake)

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

The host launches `scripts/run-mcp.sh`, which builds the locked Cargo project
into `$XDG_CACHE_HOME/codex-wake/build` (default `~/.cache/codex-wake/build`).
Diagnostics go to stderr; stdout is reserved for MCP messages. Rust/Cargo,
`codex`, `curl`, `tar` and a working Linux systemd user manager are required.
Automatic receiver installation currently supports Linux x86_64.

No usage skill or injected usage instructions are bundled. MCP descriptions,
parameter schemas and structured results provide the agent interface.

MCP startup runs deterministic code that:

1. Acquires a process-shared installation lock.
2. Installs or checks one private persistent runtime outside the plugin cache.
3. Downloads `adnanh/webhook` 2.8.3 and verifies its pinned archive and binary hashes.
4. Creates a persistent private webhook secret and a managed user service.
5. Starts the receiver and verifies service identity, configuration and signed
   HTTP filtering before accepting MCP calls.
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
cargo run --locked -- remove-service
```

`remove-service` is a maintenance stop, retaining state and the secret. The
uninstall watcher remains armed; another MCP session can recreate the receiver
while the plugin is still installed. It refuses to remove an unrelated unit.
Stopping this service also stops its controller and any turns that controller
owns. Finish those turns before a planned removal or runtime upgrade.

## Agent interface

For a stable public HTTPS endpoint without a custom domain, enable Tailscale
Funnel for the machine, then mount only the webhook route in the background:

```sh
tailscale funnel --bg --yes --https=443 --set-path=/hooks/codex-wake \
  http://127.0.0.1:9000/hooks/codex-wake
cargo run --locked -- record-funnel
```

`record-funnel` explicitly adopts that exact route into the plugin's private
installation state. `get_status` reports its configured URL. Tailscale manages
HTTPS and persistence across restarts; GitHub HMAC authentication remains in
the receiver. Uninstall removes the adopted path if its proxy is unchanged,
preserving other Tailscale routes and the shared Tailscale installation. A
replaced path is left to its new owner. This does not create repository webhooks
or change tailnet-wide policies automatically.

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
Provider results are explicit: the plugin doesn't poll arbitrary servers, inspect
backup health, or infer releases or artifact availability. The owner/producer
calls `publish_result` or sends a signed custom event when the condition is true.

## GitHub and external events

The shared receiver listens only on `127.0.0.1:9000`. Configure an HTTPS reverse
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

Public ingress and provider webhooks aren't created automatically. Local
readiness is reported separately from public ingress verification. There is no
offline event inbox or retrospective fetch of missed events.

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
replacing an objective resets its usage accounting. All RPC mutations preserve
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
it doesn't implement a ChatGPT chat-resume transport.

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
`queued` means CLI acceptance, not proof that a chat resumed. A crash, timeout
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
Child output is drained independently through a bounded nonblocking queue;
overflow is counted when the writer catches up. Repeated storage warnings are
rate-limited. If storage stays unavailable or a process is killed, some records
can be missing; a stale heartbeat and incomplete spans are diagnostic signals,
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
