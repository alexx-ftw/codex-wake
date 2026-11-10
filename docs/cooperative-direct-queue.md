# Cooperative direct MCP queue experiment

`queue_thread` accepts an optional `request_id` UUID for native direct delivery.
Without it the existing behavior is unchanged. With it, Wake stores the request
identity and a digest of the rendered input, target, resume flag and execution
options before attempting the send. In the original unbound mode, the application
payload is not stored in this record; bound mode is described below. Request IDs are scoped to this database and must never be reused for
a different operation. A randomly generated database namespace is stored once
and included in the native client message ID. Independent databases obtain
different namespaces; a copied or restored database retains its namespace and
must not be treated as an independent installation.

Repeating the same request returns its persisted state and does not resend it.
A different operation with the same ID is rejected. `queued` means the native
API acknowledged acceptance, not that the input was read or executed. An error
or unconfirmed outcome is `needs_attention`; a process that stops while sending leaves an unconfirmed outcome. On a repeat,
a sender proved dead by PID, start time, boot and PID namespace is marked
`needs_attention`; an active or unverifiable sender remains `sending`. Neither
state is automatically retried. A process exit does not establish that its
descendants stopped or that its external send was not accepted. In unbound mode,
a request rejected while admission is closed is not retained: the caller must
keep it and retry the same ID. There is no automatic reconciliation. The unbound ID-based path does not support `steer`.

This is not a complete upgrade or owner-transfer protocol. Other MCP tools and
hooks are not covered by this operation record, and the gate is not a global
barrier. Legacy processes
ignore this mechanism. No automatic alpha.2 migration is provided. The local
RPC test simulates a lost response; it does not prove behavior of a real Codex
process or confirm hook-output delivery.

## Experimental process-bound mode

When receiver binding is armed, a call with the matching
`CODEX_WAKE_GATE_OWNER`/`CODEX_WAKE_GATE_GENERATION` stores a `pending` request
in `cooperative_direct_pending`, including the rendered message and execution
options. Its database namespace is committed with the first request, including
when the database is copied before the first send. The response confirms local persistence, not Codex acceptance. The
owned SQLite database remains private, but deleted SQLite/WAL pages are not a
secure-erasure guarantee. The receiver atomically checks its own bound identity,
claims one pending request as `sending` in the same transaction. The payload is
kept for unconfirmed outcomes, and removed from the active table only when queue
acceptance is recorded. On lost or unconfirmed results, the operation remains
`sending` or `needs_attention` and is never automatically resent. Request IDs and the
per-database client ID namespace retain their existing meaning.

A request with matching owner and generation can be retained while claims are
closed. After transfer, an old owner cannot submit a new request; it receives an
error and must retain and retry its ID under the new owner. An identical retry
of an already stored ID reports its state; a different payload with the same ID
is rejected. `queue-direct` provides the same operation to CLI callers through
JSON on stdin, with the fields of MCP `queue_thread`. An armed cooperative MCP starts without activating the legacy receiver. In bound mode, `queue_thread`, `create_goal`, `edit_goal`, and `resume_goal` retain requests without an ID using a freshly generated UUID. `request_id_generated` identifies this case; `retry_safe_if_response_lost` is false because a caller cannot recover that UUID from a lost response. Supply and retain a stable ID before the first call to make retry identification possible. Repeating a no-ID call is a new operation.

Bound `steer` is retained in the same queue and then atomically moved to the existing steer table when the bound receiver dispatches it. `queued` with `awaiting_destination_hook` does not confirm hook output or consumption. Bound goal calls retain the goal operation, optional input template and execution options together. `pending` is only a durable acknowledgement; `goal_applied` or `goal_applied_input_queued` records a successful response from the respective APIs, not completed execution. If any goal or input operation has an uncertain outcome, the whole request remains `needs_attention` and is never replayed automatically. Preset preparation, goal mutation/activation and input enqueue are separate external phases: a later error does not undo earlier phases. The queue record persists `goal_progress`: the last started or confirmed phase, a confirmed preset flag when applicable, the confirmed goal returned by Codex, and the exact rendered message before queue/add. These fields may contain private goal and input data; they remain in the private database and are returned on an identical request ID replay. If saving evidence fails after an external effect, the last recorded phase may still be uncertain. A goal might already have changed even if its input is uncertain; inspect each outcome before any manual recovery. The hook claims steer before writing stdout; neither `claimed` nor writing stdout proves the target consumed it. A receiver cycle claims at most one direct request before
continuing to other queues; that single send can still take its normal timeout.
If a pending payload is corrupt or unsupported, it remains stored and blocks
later direct requests until it is resolved; other receiver queues continue.
MCP started with cooperative owner/generation variables also requires the gate
to have been armed; it fails rather than automatically starting the old receiver
before arming. Existing unconfigured MCP startup remains on the old path.

There is no safe transparent exactly-once retry for the pre-existing no-ID
interface: after a lost response, a retry and a second intentional identical
message are indistinguishable. The JSON-RPC request ID is a transport-level ID,
and the rmcp client generates it per request; it is not a persistent operation
key. A cooperative client must create and retain a stable ID before its first
call. A generated ID retains an accepted request, but cannot make a lost acknowledgement retry-safe. Older clients and other direct entry points remain outside this guarantee.
