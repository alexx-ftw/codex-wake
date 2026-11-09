# Automatic upgrade for future cooperative participants

`ensure` now performs a serialized receiver replacement for **fresh, explicitly
cooperative installations**. It does not migrate alpha.2, adopt an old database,
replace an overridden unit, change a controller, or update a webhook process.
The legacy installation and its mismatch diagnostic remain in place.

For the first installation, all entry points must use this protocol. Supply an
external `CODEX_WAKE_RPC_SOCKET`, disable integrated webhooks with
`CODEX_WAKE_ENABLE_WEBHOOKS=0`, choose a stable UUID in
`CODEX_WAKE_PRODUCER_ID`, and opt in with `CODEX_WAKE_COOPERATIVE_RECEIVER=1`
when running `ensure`. The service name, state and database must be unused.
Controller and any webhook have independent lifecycles. Producer processes keep
the stable producer UUID across replacements. Requests need stable request IDs;
this does not make external outcomes exactly once.

Subsequent `ensure` calls (including MCP startup and SessionStart) detect the
private `cooperative-upgrade.json` journal automatically. For an identical
binary they only verify readiness. For a different binary they:

1. Hold `service.lock`, verify the exact managed unit, no overrides, executable
   inode/checksum, process membership and systemd invocation. Restart is disabled.
2. Stage the executable and hook template in a checksum-specific directory,
   verify the executable and atomically persist a pending journal before closing
   admission. Previous generation files are retained.
3. Close the claim gate in its writer transaction. Previously admitted workers
   finish; stable producers can retain input while claims remain closed.
4. Require a successful exit of the **same invocation** (`ExecMainCode=1`,
   `ExecMainStatus=0`, `Result=success`, MainPID zero, active/exited) and an empty
   or removed cgroup whose parent can still be inspected. PID disappearance alone
   is not success. No force-stop is used to obtain this proof.
5. Revalidate that proof inside the transfer transaction and update owner,
   generation and successor lifecycle metadata together. A plain gate transfer
   cannot clear an existing process binding, even after SIGKILL.
6. Only then stop the already drained unit, install the successor unit and start
   it. The receiver verifies its own invocation, cgroup, executable and unit
   before atomically binding and opening. Another process cannot claim with its
   owner UUID. Health requires its binding, heartbeat and controller readiness.
7. Verify the same external controller peer/start/executable/cgroup survives and
   publish the ready journal. The controller must be outside the receiver cgroup.

Failure closes admission and retains the journal/evidence. A pending journal is
never resumed automatically, including on subsequent `ensure` calls. There is
no automatic rollback, replay, forced drain, version download, or schema rollback.
An operator must inspect the old/new invocation, cgroups, journal and uncertain
operations before recovery. Read-only health observations may repeat; a lifecycle
command with an uncertain result is never retried. Old `sending`/attention states
are not reset by the updater.

The protocol constant covers the database and unit contract. Only future builds
preserving that contract participate. A changed/unknown contract fails closed;
it needs a separately designed migration. The owner UUID and private journal are
cooperative fences, not protection against hostile same-user database writes or
an administrator deliberately restarting/modifying units. An arbitrary legacy
writer outside this installation cannot be fenced by a new binary. Initial
legacy migration remains planned maintenance. Plugin uninstall integration and
generation retention/collection are not introduced by this path.

## Verification

`automatic_upgrade_cli` runs actual CLI subprocesses with private HOME and a
manager fixture that rejects mutations. It checks untouched legacy state and
repeated rejection/closure of an interrupted transition without replay.
Unit tests reject altered exit status, invocation and cgroup paths, malformed
binding metadata, and manual transfer of a live bound receiver.

The hosted `cooperative-upgrade-qualification` probe (also run on pull requests)
uses a disposable UID and private user manager. It starts the checksum-pinned
released alpha.2, verifies rejection without changing its binary, schema, PID or
invocation, then retires only that fixture. It runs two distinct ELF files of
the current cooperative implementation as generations; these are **not two
historical cooperative releases**. It holds the old receiver with SIGSTOP and a
live cgroup descendant, checks that transfer stays closed until both finish,
retains a producer request, serializes competing updates, verifies controller
continuity and an uncertain send, and kills the coordinator after closure to
check that the journal is not replayed. The existing native controller/HTTP
namespace test also runs with private home and no credentials.

This does not qualify live production upgrades, actual user-chat delivery,
consumption of active hook output, arbitrary schema migrations, or a real active
model turn across the new systemd automatic transition. The independent native
socket test and systemd lifecycle tests must not be described as that proof.
