# Experimental cooperative claim gate ownership

This component is opt-in and is not an upgrade or migration procedure. When no
owner columns exist and no owner environment is set, the existing claim gate
behavior is unchanged. A configured owner cannot claim against a database that
has no owner columns. No installer,
service or automatic updater calls these commands.

`cooperative-gate init --owner UUID` creates the owner record at generation 1
and closes the claim gate in one SQLite writer transaction. `open` and `close`
require `--owner UUID --generation N`; `transfer` additionally requires
`--next-owner UUID`, requires the gate to be closed, changes owner and increments
the generation while leaving it closed. An old owner or generation is rejected.
Generation is monotonic only within the current database history; a restored or
copied database can roll it back.

Participating claimers receive `CODEX_WAKE_GATE_OWNER` and
`CODEX_WAKE_GATE_GENERATION`. Once ownership exists, a missing, malformed or
stale pair cannot claim through `claims_open`; the check and the existing claim
run in the same SQLite writer transaction. A claim committed before close may
finish and record its outcome after transfer. Closing does not wait for such
claims, kill their processes, or confirm external delivery.

The owner UUID identifies a cooperative cohort; it does not authenticate a
process, prove cgroup membership or prove exclusive possession. A client that
bypasses the check, including alpha.2 and earlier versions, is not fenced.
Several entry points, direct calls, webhook ingress, hook stdout consumption and
controller lifetime are not covered by this component. Do not use these commands
as a global admission barrier, to migrate alpha.2, or to update a real service.
No installed unit sets the owner environment or runs these commands.

An explicit `arm --owner UUID --generation N` on a closed gate enables experimental process binding permanently for that database history. After arming, the ordinary `open` command is rejected; a standby receiver itself binds its process identity and opens atomically. Subsequent cooperative claim checks require the same process and process-local token. Closing and transferring clears the binding but does not disarm it; a new receiver must bind the new generation. The stored open bit can remain set after death, but other participating processes cannot claim through it. This does not fence callers that omit the new process-binding check (including earlier cooperative versions that know the new cohort), or settle operations already in flight.

## Experimental stable producer identity

For an already armed, closed cooperative gate, `cooperative-gate producer
--owner UUID --generation N --producer-id UUID` records one stable producer
identity in the existing gate row. Repeating the same setup is idempotent;
a different identity is rejected. The command opens an existing owned private
Wake database without creating or migrating it and rejects an unarmed legacy
gate. No installer configures this automatically.

A producer configured with `CODEX_WAKE_PRODUCER_ID` can retain direct CLI/MCP
queue, goal and steer requests across receiver owner/generation changes. It
cannot claim work: the receiver's owner, generation, PID and process-local
token checks still govern claims. This is a cooperative installation identity,
not authentication against a same-user actor; copied databases retain it. Use a
stable request ID before the first call to identify a retry after a lost reply.
The existing generated-ID caveat remains.

This is only producer retention. Closing, confirming the old invocation and its
cgroup, staging a verified successor, recording crash-recovery state, transferring
and reopening safely are not implemented by this identity. It does not migrate
alpha.2, fence incompatible processes, confirm hook consumption, or constitute
a global event barrier.

The [automatic cooperative lifecycle](cooperative-automatic-upgrade.md) now owns
verified bound transfers. A plain `transfer` fails once a receiver PID is bound;
closing alone cannot authorize replacement. Strict lifecycle metadata also
requires the receiver to verify its own unit, executable, invocation and cgroup
before binding. The older unbound gate remains an experiment, not migration authority.
