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
trap 'rm -rf -- "$scratch"' EXIT
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
CREATE TABLE events(pid INTEGER,operation TEXT,outcome TEXT,at_ms INTEGER);
INSERT INTO events VALUES(123,'receiver.prepared','ok',1);
SQL
ctl() { printf 'LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nResult=success\nExecMainCode=0\nExecMainStatus=0\n'; }
receiver_journal() { printf 'PRIVATE_TEST_TOKEN Receiver has not bound its lifecycle generation'; }
diagnose 1 90 other
jq -e '.stage == "bootstrap" and .gate.bound == 1 and .gate.pid_matches_unit == 1 and .unit_matches_journal == true and .error_codes == ["binding_record"] and (.health | length == 1)' "$scratch/upgrade-diagnostic.json" >/dev/null
if rg -q 'PRIVATE_TEST_TOKEN|private/home' "$scratch/upgrade-diagnostic.json"; then exit 1; fi
printf 'upgrade report preserves useful state and excludes private strings\n'
