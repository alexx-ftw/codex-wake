#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Exercise the exact snapshot and exit checks without accessing a real manager.
eval "$(sed -n '/^field() {/,/^drain_group() {/ { /^drain_group() {/q; p; }' "$root/scripts/qualify-cooperative-handoff.sh")"
invocation=11111111111111111111111111111111
fixture="InvocationID=$invocation
ActiveState=active
SubState=exited
Result=success
MainPID=0
ExecMainCode=1
ExecMainStatus=0"
ctl() { printf '%s\n' "$fixture"; }
wait_terminal fake.service "$invocation"
successful_terminal "$TERMINAL"
for changed in 'ExecMainStatus=1' 'ExecMainCode=2' 'ExecMainCode=exited' 'Result=signal' 'ActiveState=failed' 'MainPID=55'; do
  key=${changed%%=*}
  altered=$(awk -F= -v key="$key" -v value="$changed" '$1 == key {$0=value} {print}' <<< "$fixture")
  if successful_terminal "$altered"; then printf 'accepted invalid terminal result\n' >&2; exit 1; fi
done
fixture=${fixture/InvocationID=$invocation/InvocationID=22222222222222222222222222222222}
if wait_terminal fake.service "$invocation"; then printf 'accepted changed invocation\n' >&2; exit 1; fi
printf 'handoff invocation and exit status checks passed\n'
