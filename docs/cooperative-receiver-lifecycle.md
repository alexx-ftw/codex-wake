# Experimental cooperative receiver lifecycle

The following direct experiment documents the lower-level primitives; the managed upgrade path is described separately below. It requires the cooperative gate from `cooperative-gate-generation.md`. Do not use it to migrate alpha.2: older processes do not observe this gate.

Run the app-server and webhook as independent, separately managed processes; retain the webhook's configured `CODEX_WAKE_EXECUTABLE` and hook template for as long as it can launch handlers. Start the receiver directly with `CODEX_WAKE_COOPERATIVE_RECEIVER=1`, an external `CODEX_WAKE_RPC_SOCKET`, `CODEX_WAKE_ENABLE_WEBHOOKS=0`, and its matching `CODEX_WAKE_GATE_OWNER` and `CODEX_WAKE_GATE_GENERATION`. The normal installer refuses to activate this mode.

For an experimental process-bound handoff, close the gate with its current owner and generation, wait for the old receiver to exit successfully, arm receiver binding, transfer to a new owner, then start the new receiver in standby. The new receiver opens the armed gate itself after the activation signal. Never reopen before the old receiver has exited: a receiver cannot observe a closure that was already reopened. Each cycle is admitted under a database write transaction; a cycle admitted before closure can still read events afterwards. A successful exit waits for started workers but does not settle uncertain delivery outcomes. Failed or stuck workers must not be treated as drained. This manual protocol alone does not orchestrate the handoff, provide process-authenticated ownership, isolate systemd cgroups, or prove that hooks and other legacy clients have finished.

The ignored `controller_and_webhook_survive_receiver_handoff` test uses an actual Codex app-server and webhook, temporary state and no credentials. It verifies the same controller socket, persistent RPC and HTTP connections across a receiver replacement, a webhook event retained while closed, a distinct event persisted after replacement, and a preinserted `sending` row preserved after replacement. It does not exercise a real sender in progress, different receiver versions, delivery to a real chat, migration of legacy clients, or behavior under systemd.

To reproduce, supply absolute paths to Codex and the official webhook in `WAKE_LIFECYCLE_CODEX` and `WAKE_LIFECYCLE_WEBHOOK`. Build the integration test first with `cargo test --locked --test cooperative_receiver_lifecycle --no-run`; run its printed test executable in private user, mount, PID and network namespaces with a private `/tmp`, loopback enabled, empty HOME and CODEX_HOME, `WAKE_LIFECYCLE_ISOLATED=1`, and those two binary paths. Use `--ignored --exact controller_and_webhook_survive_receiver_handoff`. The qualification used Codex 0.167.0 and webhook 2.8.3 (webhook executable SHA-256 `12c895f29250cbc4289ca45838235d334b39af6cf49d8e17fb43d8efed10372d`). No real manager or credentials are needed. On failure, the harness reports child status, stderr byte count and fixed error categories only; it does not print raw stderr. These categories can be incomplete, including when another process keeps the stderr pipe open.

For example, after building, set `TEST_BIN` to the printed absolute executable path and run the following from a trusted shell:

```sh
unshare --user --map-root-user --mount --net --pid --fork --mount-proc \
  sh -c 'mount --make-rprivate / &&
    mount -t tmpfs -o mode=1777,size=1G tmpfs /tmp && ip link set lo up &&
    mkdir -m 700 /tmp/home &&
    exec env -i PATH=/usr/bin:/bin HOME=/tmp/home CODEX_HOME=/tmp/home/codex \
      TMPDIR=/tmp WAKE_LIFECYCLE_ISOLATED=1 \
      WAKE_LIFECYCLE_CODEX="$1" WAKE_LIFECYCLE_WEBHOOK="$2" \
      "$3" --ignored --exact controller_and_webhook_survive_receiver_handoff' \
  sh "$WAKE_LIFECYCLE_CODEX" "$WAKE_LIFECYCLE_WEBHOOK" "$TEST_BIN"
```

## Standby experiment

A directly launched cooperative receiver can set `CODEX_WAKE_RECEIVER_STANDBY=1` with piped stdin/stdout. After checking the external socket and a closed gate with its exact owner and generation, it writes `receiver-standby-ready-v1` and waits for one byte. EOF, any byte other than `G`, an unarmed gate, or stale ownership causes it to exit without starting workers. On `G` it atomically binds and opens the closed gate itself. The sender must keep the pipe connected and observe the actual child process; the marker alone is not proof that the child remains alive or that its workers can start.

This is a preparation primitive, not an orchestrator. In particular it does not establish that a previous, independently managed receiver exited successfully: on Linux an unrelated process cannot obtain that process's exit status simply by observing its PID. The managed path below adds invocation and cgroup checks to activation. Automatic rollback and a production unit are not included.

## Hosted private-manager qualification (prepared, not run)

The `ci.yml` dispatcher accepts `probe=cooperative-handoff-qualification` on a branch containing the workflow. It runs the existing native lifecycle test in private namespaces and then provisions a temporary user and private systemd manager. The managed test checks two actual handoffs, producer and subscription retention, an uncertain delivery, producer storage while closed, and rejection of manual transfer and standby activation by both the new binary and a binary built from `af65d166`. The controller identity remains unchanged. The sanitized receipt records the source commit and binary and script digests; cleanup must also pass.

This qualification uses private test units and does not activate production orchestration. Opening records the receiver process identity and a process-local random token in the same transaction as the open bit. Participating claims compare that identity inside their claim transaction, so another process cannot claim merely because the bit remains set after the receiver dies. A claim started by the receiver before its death can still have an uncertain external result; this is not a guarantee that all other entry points participate. The test does not establish safety against competing unit restarts or hostile processes, does not test a webhook through the private manager, and does not establish legacy migration, delivery confirmation or active hook completion. Do not use it as authority to update a real installation.

Process binding excludes other processes from claims, even when they carry the same cohort identity. CLI/MCP calls with a stable request ID can be retained for the receiver; calls without one remain explicitly rejected in bound mode because transparent retry cannot distinguish repeated intent from a lost response. Only binaries that implement the process-binding check are fenced: an older cooperative binary that checks only owner/generation can still claim if it obtains the new cohort values. The UUID token and process metadata fence participating code, not a hostile actor with access to the database. This experimental mode must not be enabled for an installation that depends on those callers until their delivery path is implemented and tested.

## Managed cooperative updates

The experimental managed route is separate from the installed alpha.2 service.
It requires an external controller and independently managed webhook, an armed
process-bound gate, a stable producer ID, and a user systemd receiver unit named
`codex-wake-coop-*.service` with `Restart=no`, `KillMode=control-group` and
`RemainAfterExit=yes`. The first managed handoff is explicitly bootstrapped with
`codex-wake cooperative-upgrade --unit UNIT`: the existing receiver must be
running the same executable as that command. An alpha.2 or other unmatched
receiver is rejected before closure or replacement.

After bootstrap, setting `CODEX_WAKE_COOPERATIVE_AUTO=1` together with the
configured `CODEX_WAKE_PRODUCER_ID` makes `ensure` and MCP startup compare the
client executable with the active managed receiver and perform a handoff if it
changed. Producers retain their stable identity; requests with a stable request
ID can be stored while the gate is closed. Subscription and delivery rows are
left in the existing database. Unconfirmed sends remain unconfirmed.

The updater holds `service.lock`, verifies the bound predecessor and its
systemd invocation and executable, stages a digest-named executable, and commits
the closed gate, next owner and durable handoff record together. The successor
independently requires the same predecessor invocation to have exited
successfully, its recorded cgroup to be empty or absent, its own systemd unit
and cgroup to match, and its running executable to have the recorded digest. It
opens and binds the gate in one transaction. A SQLite trigger rejects ordinary
transfers and bindings made by older cooperative binaries that lack the new
handoff checks. The updater requires a fresh successful receiver heartbeat
before reporting readiness and closes the gate on a reported startup failure or
when an automatic check detects that the bound receiver is no longer active.

A failed or interrupted transition can require operator recovery; it must not be
replayed by blindly reopening the gate or resending an uncertain delivery. The
protocol does not migrate or fence legacy alpha.2 clients or arbitrary older
writers which do not implement process-bound claims. It also does not defend
against an actor who can directly alter the user's database, systemd units or
executables. The regular alpha.2 installer and real service remain unchanged.
The hosted private-systemd qualification exercises two managed handoffs,
persistent producer and subscription state, an uncertain delivery, closed-gate
producer storage, and attempted bypass using the exact `af65d166` binary.
