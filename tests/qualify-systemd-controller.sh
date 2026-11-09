#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$root/scripts/qualify-systemd-controller.sh"
sudo -n true
scratch=$(mktemp -d /tmp/wq-test.XXXXXXXX)
qual_root=
real_pid=
launcher=
finish() {
  if [[ -n $real_pid ]]; then sudo kill "$real_pid" 2>/dev/null || true; fi
  if [[ -n $launcher ]]; then wait "$launcher" 2>/dev/null || true; fi
  [[ -z $qual_root || ! $qual_root =~ ^/tmp/wq\.[[:alnum:]]{8}$ ]] || sudo rm -rf -- "$qual_root"
  [[ ! $scratch =~ ^/tmp/wq-test\.[[:alnum:]]{8}$ ]] || sudo rm -rf -- "$scratch"
}
trap finish EXIT
assert() { "$@" || { printf 'regression failed: %s\n' "$*" >&2; exit 1; }; }

# Exercise the actual cleanup with a directory the invoking runner cannot traverse.
run_case() {
  local name=$1 expected=$2 receipt=$3 rc=0
  qual_root=$(mktemp -d /tmp/wq.XXXXXXXX)
  if [[ $receipt != missing ]]; then
    printf '%s\n' "$receipt" > "$scratch/input"
    sudo install -m 600 -o 65534 -g 65534 "$scratch/input" "$qual_root/receipt.json"
  fi
  sudo chown 65534:65534 "$qual_root"
  sudo chmod 700 "$qual_root"
  [[ ! -f $qual_root/receipt.json ]] || { printf 'fixture directory is traversable\n' >&2; exit 1; }
  (
    manager_owned=0 linger_attempted=0 bus_active=0 created=0 uid_safe=0 qual_uid=65534
    handoff_mode=${CASE_HANDOFF_MODE:-0} handoff_done=${CASE_HANDOFF_DONE:-0} handoff_sha=test
    qual_user=unused stage=receiver_restart native_sha=test wake_sha=test probe_sha=test
    GITHUB_SHA=0123456789012345678901234567890123456789 output="$scratch/$name.json"
    cleanup
  ) || rc=$?
  if [[ $expected == pass ]]; then
    [[ $rc == 0 ]] && receipt_passed "$scratch/$name.json" && jq -e '.temporary_user_manager_cleanup_verified == true' "$scratch/$name.json" >/dev/null || exit 1
  else
    [[ $rc != 0 ]] && jq -e '.status == "failed" and .raw_logs == false' "$scratch/$name.json" >/dev/null || exit 1
  fi
  ! grep -q 'PRIVATE_TEST_TOKEN' "$scratch/$name.json" || exit 1
  qual_root=
}
full='{"status":"passed","stage":"complete","raw_logs":false,"controller_ip_sockets_blocked":true,"separate_cgroups_verified":true,"receiver_readiness_verified":true,"same_controller_socket_connection_after_restart":true,"controller_failure_and_cgroup_drain_verified":true,"receiver_cgroup_drain_verified":true,"untrusted":"PRIVATE_TEST_TOKEN"}'
run_case full pass "$full"
CASE_HANDOFF_MODE=1 CASE_HANDOFF_DONE=0 run_case handoff-incomplete fail "$full"
assert jq -e '.cooperative_handoff_qualification_passed == false' "$scratch/handoff-incomplete.json"
CASE_HANDOFF_MODE=1 CASE_HANDOFF_DONE=1 run_case handoff-complete pass "$full"
assert jq -e '.cooperative_handoff_qualification_passed == true and .handoff_script_sha256 == "test"' "$scratch/handoff-complete.json"
run_case missing fail missing
run_case partial fail '{"status":"running","stage":"receiver_restart","raw_logs":false,"receiver_readiness_verified":true,"untrusted":"PRIVATE_TEST_TOKEN"}'
assert jq -e '.receiver_readiness_verified == true and .stage == "receiver_restart"'  "$scratch/partial.json"
run_case incomplete fail '{"status":"passed","stage":"complete","raw_logs":false}'
run_case malformed fail '{"status":'
run_case unsafe fail '{"status":"failed","stage":"starting","raw_logs":false,"error_class":"PRIVATE_TEST_TOKEN"}'
# An unsafe UID must preserve the created account and private directory.
# The fake account is a file; no real account or manager is touched.
qual_root=$(mktemp -d /tmp/wq.XXXXXXXX)
touch "$scratch/account"
rc=0
(
  sudo() {
    if [[ $1 == userdel ]]; then
      touch "$scratch/userdel-called"
      rm -f -- "$scratch/account"
      return 0
    fi
    command sudo "$@"
  }
  manager_owned=0 linger_attempted=0 bus_active=0 created=1 uid_safe=0 qual_uid=12345
  qual_user=fake-account stage=setup native_sha=test wake_sha=test probe_sha=test
  GITHUB_SHA=0123456789012345678901234567890123456789 output="$scratch/unsafe-uid.json"
  cleanup
) 2>"$scratch/unsafe-uid-stderr" || rc=$?
[[ $rc != 0 && -f $scratch/account && ! -e $scratch/userdel-called && -d $qual_root ]] || {
  printf 'unsafe UID cleanup did not preserve the account and directory\n' >&2
  exit 1
}
assert jq -e '.status == "failed" and .temporary_user_manager_cleanup_verified == false' "$scratch/unsafe-uid.json"
sudo rm -rf -- "$qual_root"
qual_root=
(
  sudo() { [[ $1 == pgrep && ( $2 == -u || $2 == -U ) && $3 == 12345 ]] || return 99; if [[ $2 == -u ]]; then return "$effective_status"; else return "$real_status"; fi; }
  effective_status=0 real_status=1; if uid_has_no_processes 12345; then exit 1; fi
  effective_status=1 real_status=0; if uid_has_no_processes 12345; then exit 1; fi
  effective_status=1 real_status=1; uid_has_no_processes 12345
  effective_status=2 real_status=1; if uid_has_no_processes 12345; then exit 1; fi
  effective_status=1 real_status=2; if uid_has_no_processes 12345; then exit 1; fi
)
# A real process whose real UID differs from its effective UID must be found.
command -v setpriv >/dev/null
probe_uid=$((2000000000 + $$))
uid_has_no_processes "$probe_uid" || { printf 'test UID collision or inspection failure\n' >&2; exit 1; }
sudo setpriv --ruid "$probe_uid" --euid 65534 --clear-groups /bin/sleep 20 &
launcher=$!
for ((i=0; i<100; i++)); do
  real_pid=$(sudo pgrep -U "$probe_uid" 2>/dev/null | head -n 1 || true)
  if [[ -n $real_pid ]] && [[ $(awk '/^Uid:/ {print $2, $3}' "/proc/$real_pid/status" 2>/dev/null || true) == "$probe_uid 65534" ]]; then break; fi
  real_pid=
  sleep 0.05
done
[[ -n $real_pid ]] || { printf 'different-UID fixture did not start\n' >&2; exit 1; }
if sudo pgrep -u "$probe_uid" >/dev/null 2>&1; then
  printf 'fixture UID unexpectedly has an effective-UID process\n' >&2; exit 1
fi
if uid_has_no_processes "$probe_uid"; then
  printf 'real UID process was not detected\n' >&2; exit 1
fi
sudo kill "$real_pid"
wait "$launcher" 2>/dev/null || true
real_pid=
launcher=
uid_has_no_processes "$probe_uid" || { printf 'fixture process did not exit\n' >&2; exit 1; }
# shellcheck disable=SC2016
ruby -e 's=File.read(ARGV[0]); p=s.index(%q{if ! uid_has_no_processes "$qual_uid"}); a=s.index(%q{sudo loginctl enable-linger}); abort "UID preflight is not before manager activation" unless p && a && p < a' "$root/scripts/qualify-systemd-controller.sh"
printf 'receipt export, unsafe UID cleanup, redaction and UID preflight regressions passed\n'
