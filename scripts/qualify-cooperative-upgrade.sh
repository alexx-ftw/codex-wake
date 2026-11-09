#!/usr/bin/env bash
# Actual lifecycle under the disposable hosted user's manager, never the real service.
set -Eeuo pipefail
[[ ${WAKE_PRIVATE_QUALIFICATION:-} == 1 && $HOME =~ ^/tmp/wq\.[[:alnum:]]{8}/h$ && $(id -u) != 0 && $# == 3 ]] || exit 1
root=${HOME%/h}
wake=$1 codex=$2 socket=$3
[[ $wake == "$root/wake" && $codex == "$root/codex" && $socket == "$root/socket" && -x $root/legacy ]] || exit 1
# Unit files must use the search path of the independently started user manager.
export TMPDIR="$root/t" XDG_STATE_HOME="$HOME/s" XDG_DATA_HOME="$HOME/d" XDG_CONFIG_HOME="$HOME/.config" XDG_CACHE_HOME="$HOME/a"
export CODEX_WAKE_CODEX="$codex" CODEX_WAKE_GH=/usr/bin/false CODEX_WAKE_ENABLE_WEBHOOKS=0 CODEX_WAKE_RPC_SOCKET="$socket"
ctl() { /usr/bin/systemctl --user "$@"; }
receiver_journal() { /usr/bin/journalctl --user -u codex-wake.service -n 40 --no-pager -o cat; }
state=$XDG_STATE_HOME/codex-wake
db=$state/state.sqlite3
unit=$XDG_CONFIG_HOME/systemd/user/codex-wake.service
runtime=$XDG_DATA_HOME/codex-wake/runtime
journal=$state/cooperative-upgrade.json
upgrader='' contender='' helper='' stopped=''
stage=legacy
failure() {
  local status=$1 line=$2 class=other
  trap - ERR
  local error="$root/upgrade-error"
  if [[ $stage == legacy* ]]; then error="$root/legacy-error"; fi
  if [[ -f $error ]]; then
    if grep -qF 'systemctl show' "$error"; then class=manager_query; fi
    if grep -qF 'No such file' "$error"; then class=missing_file; fi
    if grep -qF 'uninstalled' "$error"; then class=installation; fi
    if grep -qF 'configuration' "$error"; then class=configuration; fi
    if grep -qF 'no rows' "$error"; then class=missing_marker; fi
    if grep -qF 'unit' "$error"; then class=unit_contract; fi
    if grep -qF 'cgroup' "$error"; then class=cgroup; fi
    if grep -qF 'Controller' "$error"; then class=controller; fi
    if grep -qF 'deadline' "$error"; then class=deadline; fi
  fi
  printf 'stage=%s line=%s status=%s class=%s\n' "$stage" "$line" "$status" "$class" > "$root/upgrade-failure"
  diagnose "$status" "$line" "$class" || true
}
receiver_error_codes() {
jq -Rsc '[
      ["unit_contract","Cooperative unit contract changed"],
      ["unit_override","Unverified cooperative unit"],
      ["unit_file","Cooperative unit file changed"],
      ["not_running","Cooperative receiver is not running"],
      ["cgroup","Receiver process/cgroup mismatch"],
      ["executable","Receiver executable identity changed"],
      ["invocation","Receiver invocation is not this process"],
      ["controller_group","Controller shares receiver cgroup"],
      ["bind_changed","Receiver gate closed state or ownership changed"],
      ["binding_record","Receiver has not bound its lifecycle generation"],
      ["stale_health","Receiver health is stale or failed"],
      ["later_error","Receiver reported an error after its health marker"],
      ["activation_journal","Receiver activation journal mismatch"],
      ["preparation","Controller preparation failed"],
      ["missing_rows","returned no rows"],
      ["missing_table","no such table"],
      ["locked","database is locked"]
    ] as $rules | . as $message | [$rules[] | . as $rule | select($message | contains($rule[1])) | $rule[0]]'
}
diagnose() {
  local state_json gate_json health_json codes phase matches expected actual unit_pid
  state_json=$(ctl show codex-wake.service -p LoadState -p ActiveState -p SubState -p MainPID -p Result -p ExecMainCode -p ExecMainStatus |
    jq -Rn '[inputs | split("=") | {(.[0]):.[1]}] | add') || state_json='{}'
  unit_pid=$(jq -r '.MainPID // "0"' <<< "$state_json")
  [[ $unit_pid =~ ^[0-9]+$ ]] || unit_pid=0
  gate_json=$(sqlite3 -readonly "$db" "SELECT json_object('open',is_open,'generation',generation,'bound',receiver_pid IS NOT NULL,'pid_matches_unit',receiver_pid=$unit_pid,'start_present',receiver_start IS NOT NULL,'lifecycle_present',receiver_lifecycle IS NOT NULL,'owner_matches_lifecycle',owner=json_extract(receiver_lifecycle,'$.owner'),'generation_matches_lifecycle',generation=json_extract(receiver_lifecycle,'$.generation')) FROM wake_delivery_claim_gate WHERE id=1;" 2>/dev/null) || gate_json='{}'
  health_json=$(sqlite3 -readonly "$state/telemetry.sqlite3" "SELECT json_group_array(json_object('operation',operation,'outcome',outcome,'count',n,'latest_ms',latest)) FROM (SELECT operation,outcome,count(*) n,max(at_ms) latest FROM events WHERE pid=$unit_pid AND operation IN ('receiver.prepared','receiver.heartbeat','receiver.start','receiver.dispatch','receiver.worker','cli.receiver') GROUP BY operation,outcome);" 2>/dev/null) || health_json='[]'
  # Only fixed codes leave this private fixture; never export error strings or journal messages.
  codes=$({ cat "$root/upgrade-error" 2>/dev/null || true; receiver_journal 2>/dev/null || true; } |
    receiver_error_codes) || codes='[]'
  [[ -n $gate_json ]] || gate_json='{}'
  [[ -n $health_json ]] || health_json='[]'
  phase=$(jq -r '.phase | select(. == "ready" or . == "pending")' "$journal" 2>/dev/null) || phase=unknown
  expected=$(jq -r .spec.unit "$journal" 2>/dev/null) || expected=missing
  actual=$(sha256sum "$unit" 2>/dev/null | cut -d' ' -f1) || actual=absent
  matches=false; [[ $expected == "$actual" ]] && matches=true
  jq -n --arg stage "$stage" --arg phase "$phase" --arg class "$3" --argjson line "$2" --argjson status "$1" \
    --argjson service "$state_json" --argjson gate "$gate_json" --argjson health "$health_json" \
    --argjson codes "$codes" --argjson unit_matches "$matches" \
    '{stage:$stage,line:$line,status:$status,error_class:$class,journal_phase:$phase,service:$service,gate:$gate,health:$health,error_codes:$codes,unit_matches_journal:$unit_matches}' > "$root/upgrade-diagnostic.json"
}
trap 'failure "$?" "$LINENO"' ERR
cleanup_upgrade() {
  local rc=$?
  trap - EXIT
  if [[ -n $stopped ]]; then kill -CONT "$stopped" 2>/dev/null || true; fi
  for pid in "$upgrader" "$contender" "$helper"; do
    if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  done
  ctl stop codex-wake.service >/dev/null 2>&1 || rc=1
  exit "$rc"
}
trap cleanup_upgrade EXIT
# A real released alpha.2 remains active, with the same binary, invocation and DB.
"$root/legacy" ensure > "$root/legacy-result" 2> "$root/legacy-error"
legacy_id=$(ctl show codex-wake.service -p MainPID -p InvocationID)
legacy_pid=$(ctl show codex-wake.service -p MainPID --value)
# Freeze only the fixture before its baseline: its own worker migrations are unrelated to ensure.
[[ $legacy_pid =~ ^[1-9][0-9]*$ ]]
for ((i=0;i<100;i++)); do [[ -f $db ]] && break; sleep .05; done
[[ -f $db ]]
stopped=$legacy_pid
# Acquire the writer lock first so SIGSTOP cannot strand an exclusive schema transaction.
sqlite3 -batch "$db" <<SQL
.bail on
.timeout 10000
BEGIN IMMEDIATE;
.shell /bin/kill -STOP $legacy_pid
COMMIT;
SQL
grep -q '^State:.*T' "/proc/$legacy_pid/status"
legacy_binary=$(sha256sum "$runtime/codex-wake")
legacy_schema=$(sqlite3 -readonly "$db" '.schema')
if CODEX_WAKE_COOPERATIVE_RECEIVER=1 "$wake" ensure > /dev/null 2>&1; then exit 1; fi
stage=legacy_identity
[[ $legacy_id == "$(ctl show codex-wake.service -p MainPID -p InvocationID)" ]]
stage=legacy_binary
[[ $legacy_binary == "$(sha256sum "$runtime/codex-wake")" ]]
stage=legacy_schema
[[ $legacy_schema == "$(sqlite3 -readonly "$db" '.schema')" ]]
stage=legacy_journal
[[ ! -e $journal ]]
kill -CONT "$legacy_pid"; stopped=
# Retire only this fixture's legacy installation before creating a fresh cooperative cohort.
ctl stop codex-wake.service
rm -- "$unit"
ctl daemon-reload
# These paths are exclusively owned by this disposable user and test.
rm -rf -- "$XDG_STATE_HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
export CODEX_WAKE_PRODUCER_ID=dddddddd-dddd-4ddd-8ddd-dddddddddddd
export CODEX_WAKE_COOPERATIVE_RECEIVER=1
stage=bootstrap
# Distinct ELF files of one supported protocol; no claim about historical cooperative releases.
cp -- "$wake" "$root/old"
printf '\ncooperative-previous-generation\n' >> "$root/old"
"$root/old" ensure > "$root/first" 2> "$root/upgrade-error"
jq -e '.local_ready == true and .generation == 1' "$root/first" >/dev/null
old_pid=$(ctl show codex-wake.service -p MainPID --value)
old_invocation=$(ctl show codex-wake.service -p InvocationID --value)
old_group=$(ctl show codex-wake.service -p ControlGroup --value)
old_owner=$(jq -r .spec.owner "$journal")
delivery_thread=$("$root/probe" create-thread "$codex" "$socket")
controller=$(ctl show wake-qualification-controller.service -p MainPID -p InvocationID)
secret=$HOME/preserved-secret
printf fixture-secret > "$secret"
# A claimed, uncertain send must never be made ready again by replacement.
sqlite3 "$db" "INSERT INTO waits(repo,run_id,attempt,thread,sha,state) VALUES('fixture/repo',9,1,'11111111-1111-4111-8111-111111111111','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','sending');"
# A live descendant must keep the barrier closed after MainPID has exited.
stage=descendant
sleep 120 & helper=$!
printf '%s\n' "$helper" > "/sys/fs/cgroup$old_group/cgroup.procs"
kill -STOP "$old_pid"; stopped=$old_pid
stage=closure
mkdir "$root/delayed"
cat > "$root/delayed/systemctl" <<'DELAY'
#!/bin/bash
/usr/bin/systemctl "$@" || exit $?
if [[ $1 == --user && $2 == start ]]; then sleep 18; fi
DELAY
chmod 700 "$root/delayed/systemctl"
PATH="$root/delayed:/usr/bin:/bin" CODEX_WAKE_CODEX=/usr/bin/false "$wake" --codex "$codex" ensure > "$root/second" 2> "$root/upgrade-error" & upgrader=$!
for ((i=0;i<300;i++)); do
  [[ $(sqlite3 -readonly "$db" 'SELECT is_open FROM wake_delivery_claim_gate') == 0 ]] && break
  kill -0 "$upgrader"
  sleep .05
done
[[ $(sqlite3 -readonly "$db" 'SELECT is_open || ":" || owner || ":" || generation FROM wake_delivery_claim_gate') == "0:$old_owner:1" ]]
# Ordinary gate commands cannot bypass this live/draining invocation.
if "$wake" cooperative-gate transfer --owner "$old_owner" --generation 1 --next-owner bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb >/dev/null 2>&1; then exit 1; fi
"$wake" ensure > "$root/contender-result" 2> "$root/contender-error" & contender=$!
# A stable producer may retain input while closed; it cannot dispatch it.
payload=$(jq -nc --arg thread "$delivery_thread" '{thread:$thread,message_template:"fixture",request_id:"22222222-2222-4222-8222-222222222222"}')
printf '%s' "$payload" | "$wake" queue-direct > "$root/retained"
jq -e '.state == "pending"' "$root/retained" >/dev/null
kill -CONT "$old_pid"; stopped=
stage=drain
for ((i=0;i<300;i++)); do
  [[ $(ctl show codex-wake.service -p MainPID --value) == 0 ]] && break
  sleep .05
done
[[ $(ctl show codex-wake.service -p MainPID --value) == 0 ]]
[[ $(ctl show codex-wake.service -p InvocationID --value) == "$old_invocation" ]]
[[ $(sqlite3 -readonly "$db" 'SELECT is_open || ":" || owner || ":" || generation FROM wake_delivery_claim_gate') == "0:$old_owner:1" ]]
kill -0 "$upgrader"
grep -qx 'populated 1' "/sys/fs/cgroup$old_group/cgroup.events"
kill "$helper"; wait "$helper" 2>/dev/null || true; helper=
stage=activation
wait "$upgrader"; upgrader=
wait "$contender"; contender=
for file in second contender-result; do jq -e '.local_ready == true and .generation == 2' "$root/$file" >/dev/null; done
new_pid=$(ctl show codex-wake.service -p MainPID --value)
prepared_span=$(sqlite3 -readonly "$state/telemetry.sqlite3" "SELECT max(at_ms)-min(at_ms) FROM events WHERE pid=$new_pid AND operation='receiver.prepared' AND outcome='ok';")
[[ $prepared_span =~ ^[0-9]+$ && $prepared_span -ge 15000 ]]
# The retained input reaches the native controller only after activation and is not sent again.
printf '%s' "$payload" | "$wake" queue-direct > "$root/delivered"
jq -e '.state == "queued" and .replayed == true and .reason == "accepted"' "$root/delivered" >/dev/null
[[ $(sqlite3 -readonly "$db" "SELECT count(*) FROM cooperative_direct_pending WHERE request_id='22222222-2222-4222-8222-222222222222';") == 0 ]]
[[ $(ctl show codex-wake.service -p InvocationID --value) != "$old_invocation" ]]
[[ $(ctl show codex-wake.service -p MainPID --value) != "$old_pid" ]]
[[ $(sqlite3 -readonly "$db" 'SELECT state FROM waits WHERE run_id=9') == sending ]]
[[ $(cat "$secret") == fixture-secret && $controller == "$(ctl show wake-qualification-controller.service -p MainPID -p InvocationID)" ]]
# Hold the coordinator after start returns but before it can observe preparation or activate.
stage=interruption
cp -- "$wake" "$root/third"
printf '\ncooperative-next-generation\n' >> "$root/third"
mkdir "$root/commands"
cat > "$root/commands/systemctl" <<'WRAPPER'
#!/bin/bash
/usr/bin/systemctl "$@" || exit $?
if [[ $1 == --user && $2 == start ]]; then
  kill -STOP "$PPID"
  printf paused > "$HOME/../coordinator-paused"
fi
WRAPPER
chmod 700 "$root/commands/systemctl"
PATH="$root/commands:/usr/bin:/bin" "$root/third" ensure > /dev/null 2>&1 & upgrader=$!
for ((i=0;i<300;i++)); do
  [[ -f $root/coordinator-paused && $(sqlite3 -readonly "$db" 'SELECT generation || ":" || is_open || ":" || (receiver_pid IS NOT NULL) FROM wake_delivery_claim_gate') == 3:0:1 ]] && break
  sleep .05
done
[[ -f $root/coordinator-paused && $(sqlite3 -readonly "$db" 'SELECT generation || ":" || is_open || ":" || (receiver_pid IS NOT NULL) FROM wake_delivery_claim_gate') == 3:0:1 ]]
kill -KILL "$upgrader"; wait "$upgrader" 2>/dev/null || true; upgrader=
journal_hash=$(sha256sum "$journal")
if "$root/third" ensure > /dev/null 2>&1; then exit 1; fi
[[ $journal_hash == "$(sha256sum "$journal")" && $(sqlite3 -readonly "$db" 'SELECT generation || ":" || is_open FROM wake_delivery_claim_gate') == 3:0 ]]
# No uncertain send is replayed, even after an interrupted automatic transition.
[[ $(sqlite3 -readonly "$db" 'SELECT state FROM waits WHERE run_id=9') == sending ]]
printf 'cooperative automatic upgrade qualification passed\n'
