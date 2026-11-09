#!/usr/bin/env bash
# Hosted-CI-only experiment; it is not an installer or production upgrade path.
set -euo pipefail

uid_has_no_processes() {
  local status option
  for option in -u -U; do
    if sudo pgrep "$option" "$1" >/dev/null 2>&1; then return 1; else status=$?; fi
    [[ $status == 1 ]] || return 2
  done
}

export_receipt() {
  local source=$1 destination=$2
  # Root must traverse the private 0700 directory. Emit only the approved fields.
  # The redirect intentionally creates a runner-owned output file.
  # shellcheck disable=SC2024
  if sudo jq -se '
    select(length == 1) | .[0] | select(type == "object" and .raw_logs == false) |
    select(.status == "running" or .status == "failed" or .status == "passed") |
    select(.stage == "starting" or .stage == "controller_ready" or .stage == "receiver_restart" or
      .stage == "controller_failure" or .stage == "receiver_cleanup" or .stage == "complete") |
    select(.error_class == null or .error_class == "deadline" or .error_class == "cgroup" or
      .error_class == "peer_identity" or .error_class == "socket_changed" or
      .error_class == "controller_changed" or .error_class == "receiver_not_restarted" or
      .error_class == "rpc_rejected" or .error_class == "other") |
    select([.controller_ip_sockets_blocked, .separate_cgroups_verified, .receiver_readiness_verified,
      .same_controller_socket_connection_after_restart, .controller_failure_and_cgroup_drain_verified,
      .receiver_cgroup_drain_verified] | all(. == null or . == true)) |
    {status, stage, raw_logs, error_class, controller_ip_sockets_blocked, separate_cgroups_verified,
      receiver_readiness_verified, same_controller_socket_connection_after_restart,
      controller_failure_and_cgroup_drain_verified, receiver_cgroup_drain_verified} |
    with_entries(select(.value != null))
  ' "$source" > "$destination.tmp" 2>/dev/null; then
    mv -- "$destination.tmp" "$destination"
  else
    rm -f -- "$destination.tmp"
    return 1
  fi
}

receipt_passed() {
  jq -e '.status == "passed" and .stage == "complete" and .raw_logs == false and
    .controller_ip_sockets_blocked == true and .separate_cgroups_verified == true and
    .receiver_readiness_verified == true and .same_controller_socket_connection_after_restart == true and
    .controller_failure_and_cgroup_drain_verified == true and .receiver_cgroup_drain_verified == true' "$1" >/dev/null 2>&1
}

as_qual_user() {
  sudo -u "$qual_user" env -i HOME="$qual_root/h" CODEX_HOME="$qual_root/h/c" \
    XDG_RUNTIME_DIR="/run/user/$qual_uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$qual_uid/bus" \
    PATH=/usr/bin:/bin WAKE_PRIVATE_QUALIFICATION=1 "$@"
}

remove_owned_daemon_socket() {
  local daemon="/tmp/codex-daemon-$qual_uid" entry name socket
  local -a entries locks sockets
  if ! sudo test -e "$daemon" && ! sudo test -L "$daemon"; then return 0; fi
  sudo test -d "$daemon" && ! sudo test -L "$daemon" || return 1
  [[ $(sudo stat -c '%u %a' "$daemon") == "$qual_uid 700" ]] || return 1
  mapfile -d '' -t entries < <(sudo find "$daemon" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
  locks=()
  sockets=()
  for entry in "${entries[@]}"; do
    name=${entry##*/}
    ! sudo test -L "$entry" || return 1
    [[ $(sudo stat -c '%u %h' "$entry") == "$qual_uid 1" ]] || return 1
    if [[ $name =~ ^[0-9a-fA-F]{64}$ ]] && sudo test -S "$entry"; then
      sockets+=("$entry")
    elif [[ $name =~ ^[0-9a-fA-F]{64}\.lock$ ]] && sudo test -f "$entry"; then
      locks+=("$entry")
    else
      return 1
    fi
  done
  for socket in "${sockets[@]}"; do
    sudo test -f "$socket.lock" && ! sudo test -L "$socket.lock" || return 1
  done
  for entry in "${locks[@]}"; do
    socket=${entry%.lock}
    as_qual_user "$qual_root/probe" cleanup-lock "$socket" "$entry" >/dev/null 2>&1 || return 1
  done
  sudo rmdir -- "$daemon" || return 1
  ! sudo test -e "$daemon" && ! sudo test -L "$daemon"
}

cleanup() {
  local result=$? clean=1 slice events i unit load_state manager_state runtime_state process_status group_status
  trap - EXIT
  if [[ $manager_owned == 1 ]]; then
    if [[ $bus_active == 1 ]]; then
      for unit in codex-wake.service wake-handoff-failed.service wake-handoff-old.service wake-qualification-receiver.service wake-qualification-controller.service; do
        load_state=$(as_qual_user /usr/bin/systemctl --user show "$unit" --property=LoadState --value 2>/dev/null) || load_state=not-found
        if [[ $load_state != not-found ]]; then
          as_qual_user /usr/bin/systemctl --user stop "$unit" >/dev/null 2>&1 || clean=0
        fi
      done
    fi
  fi
  if [[ $linger_attempted == 1 ]]; then
    sudo loginctl disable-linger "$qual_user" >/dev/null 2>&1 || clean=0
    if sudo test -e "/var/lib/systemd/linger/$qual_user"; then clean=0; fi
  fi
  if [[ $manager_owned == 1 ]]; then
    sudo systemctl stop "user@${qual_uid}.service" >/dev/null 2>&1 || clean=0
    manager_state=$(sudo systemctl show "user@${qual_uid}.service" --property=ActiveState --value 2>/dev/null) || manager_state=unknown
    if [[ $manager_state != inactive && $manager_state != failed ]]; then clean=0; fi
    slice="/sys/fs/cgroup/user.slice/user-${qual_uid}.slice/cgroup.events"
    for ((i=0; i<100; i++)); do
      [[ ! -e $slice ]] && break
      events=$(cat "$slice" 2>/dev/null) || { clean=0; break; }
      [[ $events == *$'populated 0'* ]] && break
      sleep 0.1
    done
    if [[ -e $slice ]] && ! grep -qx 'populated 0' "$slice"; then clean=0; fi
    for ((i=0; i<100; i++)); do
      if uid_has_no_processes "$qual_uid"; then break; else process_status=$?; fi
      if [[ $process_status != 1 ]]; then clean=0; break; fi
      sleep 0.1
    done
    uid_has_no_processes "$qual_uid" || clean=0
    if [[ $clean == 1 ]]; then remove_owned_daemon_socket || clean=0; fi
    uid_has_no_processes "$qual_uid" || clean=0
    manager_state=$(sudo systemctl show "user@${qual_uid}.service" --property=ActiveState --value 2>/dev/null) || manager_state=unknown
    if [[ $manager_state != inactive && $manager_state != failed ]]; then clean=0; fi
    if [[ -e $slice ]] && ! grep -qx 'populated 0' "$slice"; then clean=0; fi
    if [[ $clean == 1 ]]; then
      sudo systemctl stop "user-runtime-dir@${qual_uid}.service" >/dev/null 2>&1 || clean=0
      runtime_state=$(sudo systemctl show "user-runtime-dir@${qual_uid}.service" --property=ActiveState --value 2>/dev/null) || runtime_state=unknown
      if [[ $runtime_state != inactive && $runtime_state != failed ]] || [[ -e /run/user/$qual_uid ]]; then clean=0; fi
    fi
  fi
  if [[ $created == 1 && $uid_safe != 1 ]]; then clean=0; fi
  if [[ $created == 1 && $clean == 1 ]] && ! uid_has_no_processes "$qual_uid"; then clean=0; fi
  if [[ $created == 1 && $clean == 1 ]]; then
    sudo userdel "$qual_user" >/dev/null 2>&1 || clean=0
    if id "$qual_user" >/dev/null 2>&1; then clean=0; fi
    if getent group "$qual_user" >/dev/null 2>&1; then clean=0; else group_status=$?; if [[ $group_status != 2 ]]; then clean=0; fi; fi
  fi
  if export_receipt "$qual_root/receipt.json" "$output"; then
    if [[ $result == 0 ]] && ! receipt_passed "$output"; then result=1; fi
  else
    result=1
    printf '{"status":"failed","stage":"%s","raw_logs":false}\n' "$stage" > "$output" || clean=0
  fi
  if [[ -f $output ]]; then
    jq --arg native "$native_sha" --arg wake "$wake_sha" --arg probe "$probe_sha" --arg commit "$GITHUB_SHA" \
      '. + {"native_sha256":$native,"wake_sha256":$wake,"probe_sha256":$probe,"source_commit":$commit}' \
      "$output" > "$output.tmp" && mv "$output.tmp" "$output" || clean=0
  fi
  if [[ ${handoff_mode:-0} != 0 && -f $output ]]; then
    if [[ ${handoff_done:-0} == 1 && $result == 0 ]]; then
      jq --arg sha "$handoff_sha" '. + {"cooperative_handoff_qualification_passed":true,"handoff_script_sha256":$sha}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || clean=0
    else
      result=1
      jq '. + {"status":"failed","cooperative_handoff_qualification_passed":false}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || clean=0
    fi
  fi
  if [[ $clean == 1 && $qual_root =~ ^/tmp/wq\.[[:alnum:]]{8}$ ]]; then
    sudo rm -rf -- "$qual_root" || clean=0
  else
    clean=0
  fi
  if [[ $clean == 1 ]]; then
    if [[ $result == 0 ]]; then
      jq '. + {"temporary_user_manager_cleanup_verified":true}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || clean=0
    else
      jq '. + {"status":"failed","temporary_user_manager_cleanup_verified":true}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || clean=0
    fi
  fi
  if [[ $clean != 1 ]]; then
    if [[ -f $output ]]; then
      jq '. + {"status":"failed","temporary_user_manager_cleanup_verified":false}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || true
    fi
    printf 'systemd qualification: private cleanup could not be verified\n' >&2
    result=1
  fi
  if [[ $result == 0 ]] && { ! receipt_passed "$output" || ! jq -e '.temporary_user_manager_cleanup_verified == true' "$output" >/dev/null 2>&1; }; then
    result=1
    jq '. + {"status":"failed","error_class":"invalid_receipt"}' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || true
  fi
  if [[ -f $output.upgrade && $result == 0 ]]; then
    jq --slurpfile upgrade "$output.upgrade" '. + $upgrade[0]' "$output" > "$output.tmp" && mv "$output.tmp" "$output" || result=1
    rm -- "$output.upgrade" || result=1
  fi
  exit "$result"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return 0; fi

fail() { printf 'systemd qualification: %s\n' "$1" >&2; exit 1; }
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && ${CI:-} == true ]] \
  || fail 'refusing to run outside a GitHub-hosted Actions runner'
[[ $# == 4 && ${RUNNER_TEMP:-} == /* && $4 == "$RUNNER_TEMP/"* ]] \
  || fail 'usage: NATIVE_CODEX WAKE_BINARY PROBE_BINARY RUNNER_TEMP/RECEIPT'
[[ $(id -u) != 0 && -d /run/systemd/system && -f /sys/fs/cgroup/cgroup.controllers ]] \
  || fail 'requires a non-root hosted runner with systemd and cgroup v2'
for tool in sudo loginctl systemctl systemd-run useradd userdel getent jq timeout pgrep find stat; do
  command -v "$tool" >/dev/null || fail 'required qualification tool is missing'
done
native=$(realpath -- "$1")
wake=$(realpath -- "$2")
probe=$(realpath -- "$3")
output=$4
handoff_mode=${WAKE_QUALIFY_HANDOFF:-0}
[[ $handoff_mode == 0 || $handoff_mode == 1 || $handoff_mode == 2 ]] || fail 'invalid qualification mode'
handoff_done=0
handoff_sha=
if [[ $handoff_mode != 0 ]]; then
  script=qualify-cooperative-handoff.sh
  if [[ $handoff_mode == 2 ]]; then script=qualify-cooperative-upgrade.sh; fi
  handoff_script=$(realpath -- "$(dirname "$0")/$script")
  [[ -f $handoff_script && ! -L $handoff_script ]] || fail 'handoff qualification script missing'
  command -v sqlite3 >/dev/null || fail 'sqlite3 is required for handoff qualification'
  handoff_sha=$(sha256sum "$handoff_script" | cut -d' ' -f1)
fi
[[ ! -e $output && ! -L $output && ! -e $output.tmp && ! -L $output.tmp ]] || fail 'receipt destination already exists'
[[ -x $native && -x $wake && -x $probe ]] || fail 'qualification binary is missing'
[[ ${GITHUB_SHA:-} =~ ^[0-9a-f]{40}$ ]] || fail 'missing exact source commit'
native_sha=$(sha256sum "$native" | cut -d' ' -f1)
wake_sha=$(sha256sum "$wake" | cut -d' ' -f1)
probe_sha=$(sha256sum "$probe" | cut -d' ' -f1)
qual_user="wq$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
qual_root=$(mktemp -d /tmp/wq.XXXXXXXX)
created=0
uid_safe=0
manager_owned=0
linger_attempted=0
bus_active=0
qual_uid=
stage=setup

trap cleanup EXIT

if id "$qual_user" >/dev/null 2>&1; then fail 'temporary user collision'; fi
if getent group "$qual_user" >/dev/null 2>&1; then
  fail 'temporary group collision'
else
  group_status=$?
  [[ $group_status == 2 ]] || fail 'cannot inspect temporary group'
fi
if sudo test -e "/var/lib/systemd/linger/$qual_user"; then fail 'temporary linger record collision'; fi
sudo useradd --user-group --no-create-home --home-dir "$qual_root/h" --shell /usr/sbin/nologin "$qual_user" || fail 'cannot create temporary user'
created=1
qual_uid=$(id -u "$qual_user")
[[ $qual_uid =~ ^[1-9][0-9]*$ ]] || fail 'invalid temporary UID'
if ! uid_has_no_processes "$qual_uid"; then fail 'temporary UID has existing processes or cannot be inspected'; fi
manager_state=$(sudo systemctl show "user@${qual_uid}.service" --property=ActiveState --value 2>/dev/null) || fail 'cannot inspect temporary manager'
runtime_state=$(sudo systemctl show "user-runtime-dir@${qual_uid}.service" --property=ActiveState --value 2>/dev/null) || fail 'cannot inspect temporary runtime'
slice="/sys/fs/cgroup/user.slice/user-${qual_uid}.slice/cgroup.events"
if [[ $manager_state != inactive || $runtime_state != inactive || -e /run/user/$qual_uid ]] || \
   { [[ -e $slice ]] && ! grep -qx 'populated 0' "$slice"; } || \
   sudo test -e "/tmp/codex-daemon-$qual_uid" || sudo test -L "/tmp/codex-daemon-$qual_uid"; then
  fail 'temporary UID already has a runtime or user manager'
fi
uid_safe=1
sudo chown "$qual_user:$qual_user" "$qual_root"
sudo chmod 700 "$qual_root"
sudo install -d -m 700 -o "$qual_user" -g "$qual_user" "$qual_root/h" "$qual_root/h/c" "$qual_root/t"
sudo install -m 700 -o "$qual_user" -g "$qual_user" "$native" "$qual_root/codex"
sudo install -m 700 -o "$qual_user" -g "$qual_user" "$wake" "$qual_root/wake"
sudo install -m 700 -o "$qual_user" -g "$qual_user" "$probe" "$qual_root/probe"
if [[ $handoff_mode != 0 ]]; then
  sudo install -m 700 -o "$qual_user" -g "$qual_user" "$handoff_script" "$qual_root/handoff"
  [[ $handoff_sha == "$(sudo sha256sum "$qual_root/handoff" | cut -d' ' -f1)" ]] || fail 'handoff script checksum mismatch'
  if [[ $handoff_mode == 2 ]]; then
    [[ -x ${WAKE_QUALIFY_LEGACY:-} ]] || fail 'legacy fixture missing'
    sudo install -m 700 -o "$qual_user" -g "$qual_user" "$WAKE_QUALIFY_LEGACY" "$qual_root/legacy"
    cmp <(sudo cat "$qual_root/legacy") "$WAKE_QUALIFY_LEGACY" || fail 'legacy fixture copy changed'
  fi
fi
[[ $native_sha == "$(sudo sha256sum "$qual_root/codex" | cut -d' ' -f1)" && \
   $wake_sha == "$(sudo sha256sum "$qual_root/wake" | cut -d' ' -f1)" && \
   $probe_sha == "$(sudo sha256sum "$qual_root/probe" | cut -d' ' -f1)" ]] || fail 'copied binary checksum mismatch'

stage=private_manager
linger_attempted=1
manager_owned=1
sudo loginctl enable-linger "$qual_user" >/dev/null 2>&1 || fail 'cannot enable temporary user manager'
sudo systemctl start "user@${qual_uid}.service" >/dev/null 2>&1 || fail 'cannot start temporary user manager'
as_qual_user /usr/bin/systemctl --user show-environment >/dev/null 2>&1 || fail 'temporary user bus is unavailable'
bus_active=1

common=(--user --property=Type=exec --property=KillMode=control-group --property=Restart=no
  --property=TimeoutStopSec=4s --property=NoNewPrivileges=yes --property=SystemCallArchitectures=native
  --property=RestrictAddressFamilies=AF_UNIX --property=StandardOutput=null --property=StandardError=null
  "--property=WorkingDirectory=$qual_root/h")
stage=controller_start
as_qual_user /usr/bin/systemd-run "${common[@]}" --unit=wake-qualification-controller \
  /usr/bin/env -i "HOME=$qual_root/h" "CODEX_HOME=$qual_root/h/c" "TMPDIR=$qual_root/t" PATH=/usr/bin:/bin \
  WAKE_PRIVATE_QUALIFICATION=1 "$qual_root/probe" controller "$qual_root/codex" "$qual_root/socket" "$qual_root/helper.pid" >/dev/null 2>&1 \
  || fail 'cannot start isolated controller unit'
stage=controller_readiness
as_qual_user /usr/bin/timeout 60 "$qual_root/probe" ready "$qual_root/codex" "$qual_root/socket" >/dev/null 2>&1 \
  || fail 'isolated controller readiness or identity failed'
if [[ $handoff_mode != 0 ]]; then
  stage=cooperative_handoff
  controller_identity=$(as_qual_user /usr/bin/systemctl --user show wake-qualification-controller.service -p MainPID -p InvocationID) \
    || fail 'cannot identify isolated controller'
  as_qual_user /usr/bin/timeout 240 "$qual_root/handoff" "$qual_root/wake" "$qual_root/codex" "$qual_root/socket" >/dev/null 2>&1 \
    || fail 'cooperative handoff qualification failed'
  controller_after=$(as_qual_user /usr/bin/systemctl --user show wake-qualification-controller.service -p MainPID -p InvocationID) \
    || fail 'cannot reidentify isolated controller'
  [[ $controller_identity == "$controller_after" ]] || fail 'isolated controller changed during handoff'
  as_qual_user /usr/bin/timeout 60 "$qual_root/probe" ready "$qual_root/codex" "$qual_root/socket" >/dev/null 2>&1 \
    || fail 'isolated controller did not remain ready after handoff'
  handoff_done=1
  if [[ $handoff_mode == 2 ]]; then
    printf '%s\n' '{"cooperative_upgrade_qualification_passed":true,"legacy_alpha2_untouched":true,"descendant_drain_verified":true,"concurrent_updates_serialized":true,"interrupted_transition_not_retried":true,"uncertain_send_preserved":true}' > "$output.upgrade"
  fi
fi
stage=receiver_start
as_qual_user /usr/bin/systemd-run "${common[@]}" --unit=wake-qualification-receiver \
  /usr/bin/env -i "HOME=$qual_root/h" "CODEX_HOME=$qual_root/h/c" "TMPDIR=$qual_root/t" PATH=/usr/bin:/bin \
  "XDG_STATE_HOME=$qual_root/h/s" "XDG_DATA_HOME=$qual_root/h/d" "XDG_CONFIG_HOME=$qual_root/h/f" "XDG_CACHE_HOME=$qual_root/h/a" \
  "CODEX_WAKE_CODEX=$qual_root/codex" CODEX_WAKE_GH=/usr/bin/false CODEX_WAKE_ENABLE_WEBHOOKS=0 \
  "CODEX_WAKE_RPC_SOCKET=$qual_root/socket" "$qual_root/wake" receiver >/dev/null 2>&1 \
  || fail 'cannot start isolated receiver unit'
stage=continuity_and_failure
as_qual_user /usr/bin/timeout 120 "$qual_root/probe" verify "$qual_root/codex" "$qual_root/socket" "$qual_root/helper.pid" "$qual_root/receipt.json" >/dev/null 2>&1 \
  || fail 'continuity, failure or cgroup cleanup check failed'
printf 'systemd qualification: isolated continuity, failure and cgroup checks passed\n'
