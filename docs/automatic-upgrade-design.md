# Automatic shared-service upgrade: design and qualification

This is a design under review, not an implemented upgrade protocol.

## Existing installations

An active alpha.2 or alpha.5 receiver cannot be drained by a new client: it
does not participate in a drain protocol. `service.lock` serializes lifecycle
operations, but does not cover the receiver's workers, old MCP requests, hook
processes, or direct queue calls. An empty database snapshot cannot exclude a
new send immediately afterwards. The receiver also owns the app-server and
stopping its service can stop turns already accepted by that controller.

Therefore a new client must not replace or stop an active legacy receiver.
Keep its state and the current mismatch diagnostic; use the existing planned
maintenance procedure for the first transition. A stopped receiver is not by
itself proof that old clients and hooks have drained. A new client must also
avoid changing the shared schema while an incompatible old writer can run.
Unknown or unidentifiable participants are not evidence of quiescence.

## Cooperative receivers

The following requirements apply after every writer involved in the transition
supports the same protocol; merely checking the receiver version is not enough.

1. Identify the installed service, executable and protocol generation, and
   serialize competing update attempts. Never change a foreign unit, an
   overridden unit, or an unverified runtime.
2. Stage and verify the new executable and assets before changing the running
   generation. Keep a verified previous generation for recovery. Keep the
   database, secrets, and subscription identities in place.
3. Close admission atomically across MCP calls, CLI calls, hooks, webhook
   handlers, pollers, and all other processes that can write or send. Account
   for calls already accepted, including direct app-server calls that do not
   create database rows. New work must wait or fail before its first side
   effect; the caller must be told which occurred.
4. Drain all admitted operations and observer workers. A database state of
   `sending`, `creating`, or an uncertain result is not permission to replay.
   Preserve unknown outcomes and their evidence. Ingress during the transition
   must either be durably accepted or explicitly fail so its source can decide
   whether to retry; source retries are not guaranteed.
5. Preserve the existing controller process and its active turns throughout
   the handover. Replacing the receiver must not close its controller's socket,
   kill its process group, or let old and new workers run concurrently. A
   proposed process handover must prove ownership and adoption of the actual
   controller and its output pipes, and fail closed if identity is uncertain.
6. Check schema compatibility for every still-running reader and writer before
   migrating. Do not assume older clients can safely use a newer schema or that
   a failed migration can be rolled back after newer writes. Publish the new
   generation only after its startup and health checks succeed; interrupted
   transitions need durable, unambiguous recovery state.
7. Reopen admission once exactly one verified receiver owns the work. On a
   failed handover, restore a verified compatible receiver when safe; otherwise
   retain the state and expose the failure without replaying uncertain sends.
   A process crash or external termination can still make delivery uncertain.

The concrete handover and cross-process admission mechanisms remain to be
designed and reviewed. In particular, an in-process re-exec is not sufficient
until child ownership, descriptors, worker drainage, failure recovery and
mixed-version clients are demonstrated. Do not treat this list as an
implemented safety guarantee.

An isolated experiment with the published alpha.2 binary found that retaining
the receiver PID across re-exec can leave an interrupted delivery claimed by a
sender that appears alive; recovery and republishing did not release it. The
service lock did not exclude a separate publisher, and an empty primary sending
set did not exclude an in-flight dependency notice. Holding SQLite's write lock
also prevented both accepting another event and recording a received response.
These observations rule out those techniques as sufficient handover barriers;
they do not prove that every external handover protocol is impossible.

In an isolated Codex CLI 0.167.0 experiment, normal `Stop` and `PostToolUse`
hook output reached a simulated model provider. When the hook was killed before
or after writing its output, the provider did not receive that output and Codex
did not rerun the same hook. Successful writing to the pipe did not establish
that Codex had read it. A handover must therefore leave in-flight hooks running;
this experiment does not establish behavior for every possible crash boundary.

## Required isolated CI qualification

- Run the actual previous packaged service and a new package under a private
  user manager and home; verify active legacy instances are left untouched.
- Exercise simultaneous update requests and old/new clients, including a direct
  queue operation, hook, webhook handler, observer and a held delivery. Confirm
  no operation crosses the admission barrier and no send is duplicated.
- Keep a controller-owned turn active across a cooperative handover and verify
  the same controller survives; verify waiting subscriptions and secret survive.
- Inject failures at staging, admission closure, drain, switch, startup, health
  check and recovery, including process death and an ambiguous send. Verify
  state, ownership and no automatic replay at each boundary.
- Exercise compatible and incompatible database versions and a failed
  migration, including concurrent older clients. Verify no unsupported writer
  accesses the migrated database.
- Verify source behavior while ingress is unavailable, and document observed
  behavior without claiming that external events or delivery are exactly once.

The existing `scripts/qualify-package-lifecycle.sh` stops the service before
installing the new package. It checks persistence through a maintenance
restart, not automatic upgrade, worker drainage, or live-turn continuity.
