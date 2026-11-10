#!/usr/bin/env bash
# Run only under the private user manager provisioned by qualify-systemd-controller.sh.
set -euo pipefail
[[ ${WAKE_PRIVATE_QUALIFICATION:-} == 1 && $HOME =~ ^/tmp/wq\.[[:alnum:]]{8}/h$ && $(id -u) != 0 && $# == 3 ]] || exit 1
root=${HOME%/h}
wake=$1
codex=$2
socket=$3
[[ $wake == "$root/wake" && $codex == "$root/codex" && $socket == "$root/socket" ]] || exit 1
export TMPDIR="$root/t" XDG_STATE_HOME="$HOME/s" XDG_DATA_HOME="$HOME/d" XDG_CONFIG_HOME="$HOME/f" XDG_CACHE_HOME="$HOME/a"
export CODEX_WAKE_CODEX="$codex" CODEX_WAKE_GH=/usr/bin/false CODEX_WAKE_ENABLE_WEBHOOKS=0 CODEX_WAKE_RPC_SOCKET="$socket"
owner_a=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
owner_b=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
export CODEX_WAKE_COOPERATIVE_RECEIVER=1 CODEX_WAKE_GATE_OWNER=$owner_a CODEX_WAKE_GATE_GENERATION=1
child=
opened=0
cleanup_handoff() {
  local rc=$?
  trap - EXIT
  if [[ $opened == 1 ]]; then gate close --owner "$owner_b" --generation 2 >/dev/null || rc=1; fi
  if [[ -n $child ]]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  for unit in wake-handoff-failed.service wake-handoff-old.service; do
    /usr/bin/systemctl --user stop "$unit" >/dev/null 2>&1 || rc=1
  done
  exit "$rc"
}
trap cleanup_handoff EXIT
ctl() { /usr/bin/systemctl --user "$@" 2>/dev/null; }
gate() { "$wake" cooperative-gate "$@" 2>/dev/null; }
start_old() {
  local unit=$1
  /usr/bin/systemd-run --user --unit="$unit" --property=Type=exec --property=Restart=no \
    --property=RemainAfterExit=yes --property=KillMode=control-group --property=NoNewPrivileges=yes \
    --property=StandardOutput=null --property=StandardError=null --property="WorkingDirectory=$HOME" \
    /usr/bin/env -i "HOME=$HOME" "CODEX_HOME=$CODEX_HOME" "TMPDIR=$TMPDIR" PATH=/usr/bin:/bin \
    "XDG_STATE_HOME=$XDG_STATE_HOME" "XDG_DATA_HOME=$XDG_DATA_HOME" "XDG_CONFIG_HOME=$XDG_CONFIG_HOME" \
    "XDG_CACHE_HOME=$XDG_CACHE_HOME" "CODEX_WAKE_CODEX=$CODEX_WAKE_CODEX" CODEX_WAKE_GH=/usr/bin/false \
    CODEX_WAKE_ENABLE_WEBHOOKS=0 "CODEX_WAKE_RPC_SOCKET=$CODEX_WAKE_RPC_SOCKET" \
    CODEX_WAKE_COOPERATIVE_RECEIVER=1 "CODEX_WAKE_GATE_OWNER=$owner_a" CODEX_WAKE_GATE_GENERATION=1 \
    "$wake" receiver >/dev/null 2>&1
}
field() { sed -n "s/^$1=//p" <<< "$2"; }
snapshot() { ctl show "$1" -p InvocationID -p ActiveState -p SubState -p Result -p MainPID -p ExecMainCode -p ExecMainStatus -p ControlGroup; }
wait_started() {
  local unit=$1 snap pid i ready
  for ((i=0; i<300; i++)); do
    snap=$(snapshot "$unit") || return 1
    pid=$(field MainPID "$snap")
    if [[ $(field ActiveState "$snap") == active && $pid =~ ^[1-9][0-9]*$ && -f $XDG_STATE_HOME/codex-wake/telemetry.sqlite3 ]]; then
      ready=$(sqlite3 -readonly "$XDG_STATE_HOME/codex-wake/telemetry.sqlite3" "SELECT EXISTS(SELECT 1 FROM events WHERE pid=$pid AND operation='receiver.heartbeat' AND outcome='ok');" 2>/dev/null || true)
      if [[ $ready == 1 && $(stat -Lc '%d:%i' "/proc/$pid/exe") == "$(stat -Lc '%d:%i' "$wake")" ]]; then
        OLD_INVOCATION=$(field InvocationID "$snap")
        OLD_CGROUP=$(field ControlGroup "$snap")
        [[ $OLD_INVOCATION =~ ^[0-9a-f]{32}$ && $OLD_INVOCATION != 00000000000000000000000000000000 && $OLD_CGROUP == /user.slice/* ]] || return 1
        return 0
      fi
    fi
    sleep 0.1
  done
  return 1
}
wait_terminal() {
  local unit=$1 invocation=$2 snap i
  for ((i=0; i<300; i++)); do
    snap=$(snapshot "$unit") || return 1
    [[ $(field InvocationID "$snap") == "$invocation" ]] || return 1
    if [[ $(field MainPID "$snap") == 0 && ( $(field SubState "$snap") == exited || $(field ActiveState "$snap") == failed ) ]]; then
      TERMINAL=$snap
      return 0
    fi
    sleep 0.1
  done
  return 1
}
successful_terminal() {
  local snap=$1
  [[ $(field ActiveState "$snap") == active && $(field SubState "$snap") == exited && $(field Result "$snap") == success && $(field MainPID "$snap") == 0 && $(field ExecMainCode "$snap") == 1 && $(field ExecMainStatus "$snap") == 0 ]]
}
drain_group() {
  local dir="/sys/fs/cgroup$1" parent="/sys/fs/cgroup${1%/*}" events i
  events="$dir/cgroup.events"
  [[ -d $parent && -x $parent ]] || return 1
  for ((i=0; i<100; i++)); do
    if [[ ! -e $dir && ! -L $dir ]]; then return 0; fi
    [[ -d $dir && ! -L $dir && -r $events && ! -L $events ]] || return 1
    grep -qx 'populated 0' "$events" && return 0
    sleep 0.1
  done
  return 1
}
assert_closed() {
  local value
  value=$(sqlite3 -readonly "$XDG_STATE_HOME/codex-wake/state.sqlite3" "SELECT is_open || ':' || owner || ':' || generation FROM wake_delivery_claim_gate WHERE id=1;")
  [[ $value == "0:$1:$2" ]]
}
close_gate() {
  local value
  value=$(gate close --owner "$1" --generation "$2")
  jq -e --arg owner "$1" --argjson generation "$2" '.open == false and .owner == $owner and .generation == $generation' <<< "$value" >/dev/null
  assert_closed "$1" "$2"
}

gate init --owner "$owner_a" >/dev/null
gate open --owner "$owner_a" --generation 1 >/dev/null
start_old wake-handoff-failed
wait_started wake-handoff-failed.service
failed_invocation=$OLD_INVOCATION
failed_cgroup=$OLD_CGROUP
ctl kill --kill-whom=main --signal=SIGKILL wake-handoff-failed.service
wait_terminal wake-handoff-failed.service "$failed_invocation"
if successful_terminal "$TERMINAL"; then exit 1; fi
drain_group "$failed_cgroup"
close_gate "$owner_a" 1
# No transfer follows the failed invocation.
gate open --owner "$owner_a" --generation 1 >/dev/null
start_old wake-handoff-old
wait_started wake-handoff-old.service
old_invocation=$OLD_INVOCATION
old_cgroup=$OLD_CGROUP
close_gate "$owner_a" 1
wait_terminal wake-handoff-old.service "$old_invocation"
successful_terminal "$TERMINAL"
drain_group "$old_cgroup"
gate arm --owner "$owner_a" --generation 1 >/dev/null
gate transfer --owner "$owner_a" --generation 1 --next-owner "$owner_b" >/dev/null
export CODEX_WAKE_GATE_OWNER=$owner_b CODEX_WAKE_GATE_GENERATION=2
spawn_candidate() {
  coproc CANDIDATE { exec env CODEX_WAKE_RECEIVER_STANDBY=1 "$wake" receiver 2>/dev/null; }
  child=$CANDIDATE_PID
  exec {read_fd}<&"${CANDIDATE[0]}" {write_fd}>&"${CANDIDATE[1]}"
  local line
  IFS= read -r -t 30 line <&"$read_fd"
  [[ $line == receiver-standby-ready-v1 ]]
}
candidate_alive() {
  local stat_line state
  kill -0 "$child" 2>/dev/null || return 1
  stat_line=$(cat "/proc/$child/stat") || return 1
  stat_line=${stat_line##*) }
  state=${stat_line%% *}
  [[ $state != Z && $state != X && $(stat -Lc '%d:%i' "/proc/$child/exe") == "$(stat -Lc '%d:%i' "$wake")" ]]
}
spawn_candidate
candidate_alive
kill "$child"
wait "$child" 2>/dev/null || true
child=
exec {read_fd}<&- {write_fd}>&-
assert_closed "$owner_b" 2
spawn_candidate
candidate_alive
opened=1
printf G >&"$write_fd"
# A marker is not a durable health guarantee; confirm the same child emitted its heartbeat.
for ((i=0; i<300; i++)); do
  candidate_alive
  ready=$(sqlite3 -readonly "$XDG_STATE_HOME/codex-wake/telemetry.sqlite3" "SELECT EXISTS(SELECT 1 FROM events WHERE pid=$child AND operation='receiver.heartbeat' AND outcome='ok');" 2>/dev/null || true)
  [[ $ready == 1 ]] && break
  sleep 0.1
done
[[ $ready == 1 ]]
close_gate "$owner_b" 2
opened=0
for ((i=0; i<300; i++)); do
  candidate_alive || break
  sleep 0.1
done
if candidate_alive; then exit 1; fi
wait "$child"
child=
exec {read_fd}<&- {write_fd}>&-
printf 'cooperative handoff qualification passed\n'
