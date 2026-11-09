#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Test only the pure classifier, never a manager, journal or service.
eval "$(sed -n '/^receiver_error_codes() {/,/^}/p' "$root/scripts/qualify-cooperative-upgrade.sh")"
codes=$(printf '%s\n' 'PRIVATE_TEST_TOKEN Cooperative unit file changed' 'Receiver has not bound its lifecycle generation /private/home' | receiver_error_codes)
jq -e '. == ["unit_file","binding_record"]' <<< "$codes" >/dev/null
[[ $codes != *PRIVATE_TEST_TOKEN* && $codes != */private/home* ]]
[[ $(printf unknown-private-error | receiver_error_codes) == '[]' ]]
printf 'upgrade diagnostics classify known causes without exposing raw errors\n'
# Exercise the actual report with private SQLite files and fake data sources.
eval "$(sed -n '/^diagnose() {/,/^}/p' "$root/scripts/qualify-cooperative-upgrade.sh")"
scratch=$(mktemp -d)
child=
trap 'if [[ -n $child ]]; then kill -CONT "$child" 2>/dev/null || true; kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi; rm -rf -- "$scratch"' EXIT
# shellcheck disable=SC2034
root=$scratch state=$scratch stage=bootstrap
# shellcheck disable=SC2034
unit=$scratch/unit journal=$scratch/journal db=$scratch/state.sqlite3
printf fixture-unit > "$unit"
printf '{"phase":"pending","spec":{"unit":"%s"}}' "$(sha256sum "$unit" | cut -d' ' -f1)" > "$journal"
sqlite3 "$db" <<'SQL'
CREATE TABLE wake_delivery_claim_gate(id INTEGER PRIMARY KEY,is_open INTEGER,generation INTEGER,receiver_pid INTEGER,receiver_start INTEGER,receiver_lifecycle TEXT,owner TEXT);
INSERT INTO wake_delivery_claim_gate VALUES(1,0,1,123,1,'{"owner":"owner","generation":1}','owner');
SQL
sqlite3 "$scratch/telemetry.sqlite3" <<'SQL'
CREATE TABLE events(pid INTEGER,operation TEXT,outcome TEXT,at_ms INTEGER,reason TEXT);
INSERT INTO events VALUES(123,'receiver.prepared','ok',1,'');
SQL
ctl() { printf 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'; }
receiver_journal() { printf 'PRIVATE_TEST_TOKEN Receiver has not bound its lifecycle generation'; }
diagnose 1 90 other
jq -e '.stage == "bootstrap" and .gate.bound == 1 and .gate.pid_matches_unit == 1 and .unit_matches_journal == true and .error_codes == ["binding_record"] and (.health | length == 1)' "$scratch/upgrade-diagnostic.json" >/dev/null
if rg -q 'PRIVATE_TEST_TOKEN|private/home' "$scratch/upgrade-diagnostic.json"; then exit 1; fi
printf 'upgrade report preserves useful state and excludes private strings\n'
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
eval "$(sed -n '/^freeze_receiver() {/,/^}/p' "$repo/scripts/qualify-cooperative-upgrade.sh")"
touch "$state/telemetry-pending.lock"
for lock in "$state/telemetry.sqlite3" "$state/telemetry-pending.lock"; do
  rm -f "$scratch/locked"
  bash -c 'exec 9<"$1"; flock -x 9; touch "$2"; sleep .3; flock -u 9; exec sleep 30' sh "$lock" "$scratch/locked" & child=$!
  for ((i=0;i<100;i++)); do [[ -f $scratch/locked ]] && break; sleep .01; done
  [[ -f $scratch/locked ]]
  freeze_receiver "$child"
  flock -n "$lock" true
  kill -CONT "$child"
  kill "$child"
  wait "$child" 2>/dev/null || true
  child=
done
printf 'freezing waits for telemetry writers and leaves both locks available\n'
eval "$(sed -n '/^wait_cgroup_empty() {/,/^}/p' "$repo/scripts/qualify-cooperative-upgrade.sh")"
mkdir "$scratch/group"
printf 'populated 1\n' > "$scratch/group/cgroup.events"
# shellcheck disable=SC2329
sleep() { :; }
if wait_cgroup_empty "$scratch/group"; then exit 1; fi
unset -f sleep
printf 'populated 0\n' > "$scratch/group/cgroup.events"
wait_cgroup_empty "$scratch/group"
rm "$scratch/group/cgroup.events"
if wait_cgroup_empty "$scratch/group"; then exit 1; fi
rmdir "$scratch/group"
wait_cgroup_empty "$scratch/group"
ln -s "$scratch" "$scratch/group"
if wait_cgroup_empty "$scratch/group"; then exit 1; fi
if wait_cgroup_empty "$scratch/missing/group"; then exit 1; fi
printf 'drain requires an empty or removed cgroup with an observable parent\n'
