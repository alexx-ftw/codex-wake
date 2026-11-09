#!/usr/bin/env bash
# Run only under the private user manager provisioned by qualify-systemd-controller.sh.
set -Eeuo pipefail
[[ ${WAKE_PRIVATE_QUALIFICATION:-} == 1 && $HOME =~ ^/tmp/wq\.[[:alnum:]]{8}/h$ && $(id -u) != 0 && $# == 4 ]] || exit 1
root=${HOME%/h}
trap 'printf "handoff_failure_line=%d\n" "$LINENO" > "$root/handoff-failure"' ERR
wake=$1
codex=$2
socket=$3
legacy=$4
[[ $wake == "$root/wake" && $codex == "$root/codex" && $socket == "$root/socket" && $legacy == "$root/legacy" ]] || exit 1
export TMPDIR="$root/t" XDG_STATE_HOME="$HOME/s" XDG_DATA_HOME="$HOME/d" XDG_CONFIG_HOME="$HOME/f" XDG_CACHE_HOME="$HOME/a"
export CODEX_WAKE_CODEX="$codex" CODEX_WAKE_GH=/usr/bin/false CODEX_WAKE_ENABLE_WEBHOOKS=0 CODEX_WAKE_RPC_SOCKET="$socket"
owner_a=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
export CODEX_WAKE_COOPERATIVE_RECEIVER=1 CODEX_WAKE_GATE_OWNER=$owner_a CODEX_WAKE_GATE_GENERATION=1
successor_unit=
first_successor=
cleanup_handoff() {
  local rc=$?
  trap - EXIT
  for unit in "$successor_unit" "$first_successor" codex-wake-coop-failed.service codex-wake-coop-old.service; do
    [[ -n $unit ]] || continue
    /usr/bin/systemctl --user stop "$unit" >/dev/null 2>&1 || rc=1
  done
  exit "$rc"
}
trap cleanup_handoff EXIT
ctl() { /usr/bin/systemctl --user "$@" 2>/dev/null; }
gate() { "$wake" cooperative-gate "$@" 2>/dev/null; }
start_old() {
  local unit=$1
  local -a stdin=() standby=()
  if [[ ${2:-} == standby ]]; then
    stdin=("--property=StandardInput=file:$root/standby.fifo")
    standby=(CODEX_WAKE_RECEIVER_STANDBY=1)
  fi
  /usr/bin/systemd-run --user --unit="$unit" --property=Type=exec --property=Restart=no \
    --property=RemainAfterExit=yes --property=KillMode=control-group --property=NoNewPrivileges=yes \
    --property=StandardOutput=null --property=StandardError=null --property="WorkingDirectory=$HOME" "${stdin[@]}" \
    /usr/bin/env -i "HOME=$HOME" "CODEX_HOME=$CODEX_HOME" "TMPDIR=$TMPDIR" PATH=/usr/bin:/bin \
    "XDG_STATE_HOME=$XDG_STATE_HOME" "XDG_DATA_HOME=$XDG_DATA_HOME" "XDG_CONFIG_HOME=$XDG_CONFIG_HOME" \
    "XDG_CACHE_HOME=$XDG_CACHE_HOME" "CODEX_WAKE_CODEX=$CODEX_WAKE_CODEX" CODEX_WAKE_GH=/usr/bin/false \
    CODEX_WAKE_ENABLE_WEBHOOKS=0 "CODEX_WAKE_RPC_SOCKET=$CODEX_WAKE_RPC_SOCKET" \
    CODEX_WAKE_COOPERATIVE_RECEIVER=1 "CODEX_WAKE_GATE_OWNER=$owner_a" CODEX_WAKE_GATE_GENERATION=1 "${standby[@]}" \
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
start_old codex-wake-coop-failed
wait_started codex-wake-coop-failed.service
failed_invocation=$OLD_INVOCATION
failed_cgroup=$OLD_CGROUP
ctl kill --kill-whom=main --signal=SIGKILL codex-wake-coop-failed.service
wait_terminal codex-wake-coop-failed.service "$failed_invocation"
if successful_terminal "$TERMINAL"; then exit 1; fi
drain_group "$failed_cgroup"
close_gate "$owner_a" 1
gate arm --owner "$owner_a" --generation 1 >/dev/null
producer=cccccccc-cccc-4ccc-8ccc-cccccccccccc
gate producer --owner "$owner_a" --generation 1 --producer-id "$producer" >/dev/null
mkfifo -m 600 "$root/standby.fifo"
exec {standby_fd}<>"$root/standby.fifo"
start_old codex-wake-coop-old standby
printf G >&"$standby_fd"
wait_started codex-wake-coop-old.service
old_invocation=$OLD_INVOCATION
old_cgroup=$OLD_CGROUP
db="$XDG_STATE_HOME/codex-wake/state.sqlite3"
sqlite3 "$db" "INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('private/test',987654,1,'11111111-1111-4111-8111-111111111111','0123456789012345678901234567890123456789','waiting');"
sqlite3 "$db" "INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('private/test',987655,1,'11111111-1111-4111-8111-111111111111','0123456789012345678901234567890123456789','sending');"
result=$("$wake" cooperative-upgrade --unit codex-wake-coop-old.service)
successor_unit=$(jq -er '.unit' <<< "$result")
owner_b=$(jq -er '.owner' <<< "$result")
[[ $(jq -er '.generation' <<< "$result") == 2 ]]
wait_terminal codex-wake-coop-old.service "$old_invocation"
successful_terminal "$TERMINAL"
drain_group "$old_cgroup"
export CODEX_WAKE_GATE_OWNER=$owner_b CODEX_WAKE_GATE_GENERATION=2
successor_pid=$(field MainPID "$(snapshot "$successor_unit")")
for ((i=0; i<300; i++)); do
  ready=$(sqlite3 -readonly "$XDG_STATE_HOME/codex-wake/telemetry.sqlite3" "SELECT EXISTS(SELECT 1 FROM events WHERE pid=$successor_pid AND operation='receiver.heartbeat' AND outcome='ok');" 2>/dev/null || true)
  [[ $ready == 1 ]] && break
  sleep 0.1
done
[[ $ready == 1 ]]
[[ $(sqlite3 -readonly "$db" "SELECT producer_id FROM wake_delivery_claim_gate WHERE id=1") == "$producer" ]]
[[ $(sqlite3 -readonly "$db" "SELECT state FROM waits WHERE run_id=987654") == waiting ]]
[[ $(sqlite3 -readonly "$db" "SELECT state FROM waits WHERE run_id=987655") == sending ]]
current=$(CODEX_WAKE_COOPERATIVE_AUTO=1 CODEX_WAKE_PRODUCER_ID=$producer "$wake" ensure)
[[ $(jq -er '.state' <<< "$current") == current && $(jq -er '.unit' <<< "$current") == "$successor_unit" ]]
first_successor=$successor_unit
install -m 700 "$wake" "$root/wake-next"
printf '\nprivate-upgrade-qualification\n' >> "$root/wake-next"
result=$(CODEX_WAKE_COOPERATIVE_AUTO=1 CODEX_WAKE_PRODUCER_ID=$producer "$root/wake-next" ensure)
successor_unit=$(jq -er '.unit' <<< "$result")
owner_c=$(jq -er '.owner' <<< "$result")
[[ $(jq -er '.generation' <<< "$result") == 3 && $successor_unit != "$first_successor" ]]
[[ $(sqlite3 -readonly "$db" "SELECT producer_id FROM wake_delivery_claim_gate WHERE id=1") == "$producer" ]]
[[ $(sqlite3 -readonly "$db" "SELECT state FROM waits WHERE run_id=987654") == waiting ]]
[[ $(sqlite3 -readonly "$db" "SELECT state FROM waits WHERE run_id=987655") == sending ]]
successor_invocation=$(field InvocationID "$(snapshot "$successor_unit")")
ctl kill --kill-whom=main --signal=SIGKILL "$successor_unit"
wait_terminal "$successor_unit" "$successor_invocation"
if CODEX_WAKE_COOPERATIVE_AUTO=1 CODEX_WAKE_PRODUCER_ID="$producer" "$root/wake-next" ensure >/dev/null 2>&1; then exit 1; fi
assert_closed "$owner_c" 3
request=eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee
queued=$(printf '{"thread":"11111111-1111-4111-8111-111111111111","message_template":"private fixture","request_id":"%s"}' "$request" | CODEX_WAKE_PRODUCER_ID="$producer" "$root/wake-next" queue-direct)
[[ $(jq -er '.state' <<< "$queued") == pending ]]
[[ $(sqlite3 -readonly "$db" "SELECT count(*) FROM cooperative_direct_pending WHERE request_id='$request'") == 1 ]]
if gate transfer --owner "$owner_c" --generation 3 --next-owner "$owner_a"; then exit 1; fi
if printf G | env CODEX_WAKE_RECEIVER_STANDBY=1 CODEX_WAKE_GATE_OWNER="$owner_c" CODEX_WAKE_GATE_GENERATION=3 "$root/wake-next" receiver >/dev/null 2>&1; then exit 1; fi
if "$legacy" cooperative-gate transfer --owner "$owner_c" --generation 3 --next-owner "$owner_a" >/dev/null 2>&1; then exit 1; fi
if printf G | env CODEX_WAKE_RECEIVER_STANDBY=1 CODEX_WAKE_GATE_OWNER="$owner_c" CODEX_WAKE_GATE_GENERATION=3 "$legacy" receiver >/dev/null 2>&1; then exit 1; fi
assert_closed "$owner_c" 3
printf 'cooperative handoff qualification passed\n'
