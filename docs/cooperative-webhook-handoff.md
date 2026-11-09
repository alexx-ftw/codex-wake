# Cooperative handoff: webhook identity and transition control

This is a proposal and test delta, not an installed updater. It assumes a fresh,
fully cooperative deployment with a separately managed controller and webhook.
It does not migrate an existing alpha.2 installation: alpha.2's receiver owns
its children and old processes do not obey the cooperative ownership protocol.

## Keep the ingress identity stable

The existing webhook template launches the executable from its environment;
the existing `handle` command accepts events into SQLite. The receiver already
sets `CODEX_WAKE_DEFER=1` for webhook children. With that setting the handler
skips `recover`, so it does not need the receiver's current owner or generation
to perform this ingress work. A separately managed webhook can keep a fixed,
versioned handler binary and its old environment across a receiver handoff;
there is no need to change that environment at the ownership boundary. The
new receiver must be compatible with that handler's schema and event semantics.
Keep the binary, template and any data needed by existing handlers until the
webhook cannot launch them and all started handlers have finished. Do not assume
renaming or deleting a path proves this.

The CLI regression exercises the real `handle` executable with the original
owner/generation, deferred mode and an isolated database before and after a gate
transfer. It checks two registered workflow completions become ready, a duplicate
does not overwrite the recorded outcome, and the controller executable is not
called. The existing native controller/webhook lifecycle test is also prepared
with the webhook retaining generation 1 while receivers change generations;
it requires the private namespace CI environment and is not exercised by the
CLI regression. Neither test proves all event types, cross-version compatibility,
external redelivery or exactly-once HTTP delivery. `rules::accept` and the other
ingress acceptors are separate operations; a later failure can leave a partial
result. No automatic source retry is assumed.

## Transition controller requirements

A future controller should use the already existing service lock and the gate's
owner/generation and process-bound standby, not a second independent Rust
supervisor. It must first verify the effective managed units, absence of foreign
or overridden ownership, protocol/schema compatibility of every retained writer,
and staged executable and asset identity. It must establish that competing
starts and restarts cannot replace the observed invocation during the operation.
A same-UID actor outside this cooperation remains outside that guarantee.

The proposed journal operation must use a validated private Wake connection.
In one `BEGIN IMMEDIATE` transaction it records intent and closes the matching
armed gate. Current `cooperative-gate` paths can bypass the experimental journal;
they must be fenced or reconciled before an orchestrator relies on it. No caller
or recovery currently exists. The standalone journal prototype is deliberately
not included in this delta or connected to installation.

The controller must then observe successful termination of the *same* systemd
invocation and drainage of its cgroup, retaining the controller and webhook. A
closed gate or missing PID is not that evidence. Atomically record verified old
exit and transfer ownership, start the staged successor in standby, and let it
bind/open its own process identity. Confirm readiness tied to that invocation
before publishing the new receiver. Persist each externally meaningful phase;
on restart reconcile journal, gate, process and invocation, refusing uncertain
or contradictory cases. Do not replay `sending` or `needs_attention` work.

Recovery also needs tests for a killed coordinator at every boundary, concurrent
coordinators, old receiver failure, successor death, stale/changed systemd
invocation, and inaccessible or changed controller and webhook. The existing
private-manager qualification demonstrates pieces of that path but is not the
production controller, does not establish all ingress and old-handler outcomes,
and does not authorize an alpha.2 migration. Do not activate this design until
those requirements and the journal caller and recovery are implemented and
reviewed together.
