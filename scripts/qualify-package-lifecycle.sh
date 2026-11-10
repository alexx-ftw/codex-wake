#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'package-lifecycle: %s\n' "$*" >&2
  exit 1
}

[[ $# == 2 ]] || fail "usage: $0 ARTIFACT_DIRECTORY PREVIOUS_ARCHIVE"
[[ -n "${CODEX_CLI:-}" && -x "$CODEX_CLI" ]] || fail "CODEX_CLI must point to the installed Codex CLI"
command -v sudo >/dev/null || fail "runner has no sudo"
command -v loginctl >/dev/null || fail "runner has no loginctl; isolated user systemd cannot be tested"
command -v systemctl >/dev/null || fail "runner has no systemctl; isolated user systemd cannot be tested"
node_dir=$(dirname "$(command -v node)")
[[ -d /run/systemd/system ]] || fail "runner is not booted with systemd; isolated user service is unavailable"

artifact_dir=$(realpath -- "$1")
[[ -f "$artifact_dir/SHA256SUMS" ]] || fail "package artifact has no SHA256SUMS"
shopt -s nullglob
archives=("$artifact_dir"/codex-wake-*-linux-x86_64.tar.gz)
[[ ${#archives[@]} == 1 ]] || fail "expected exactly one Linux x86_64 package archive"
archive=${archives[0]}
previous_archive=$(realpath -- "$2")
[[ -f "$previous_archive" ]] || fail "previous release archive not found"
(cd "$artifact_dir" && sha256sum --check SHA256SUMS)

archive_name=${archive##*/}
version=${archive_name#codex-wake-}
version=${version%-linux-x86_64.tar.gz}
[[ "$version" != "$archive_name" && -n "$version" ]] || fail "invalid package archive name: $archive_name"

qual_user="wakeq${GITHUB_RUN_ID: -8}"
qual_root=$(mktemp -d /tmp/codex-wake-lifecycle.XXXXXX)
user_created=0
uid=
cleanup() {
  if [[ $user_created == 1 ]]; then
    sudo loginctl disable-linger "$qual_user" >/dev/null 2>&1 || true
    if [[ -n "$uid" ]]; then
      sudo systemctl stop "user@${uid}.service" >/dev/null 2>&1 || true
    fi
    sudo userdel --remove "$qual_user" >/dev/null 2>&1 || true
  fi
  sudo rm -rf -- "$qual_root"
}
trap cleanup EXIT

if ! sudo useradd --no-create-home --home-dir "$qual_root/home" --shell /usr/sbin/nologin "$qual_user"; then
  fail "could not create isolated qualification user"
fi
user_created=1
uid=$(id -u "$qual_user")
sudo chown "$qual_user:$qual_user" "$qual_root"
sudo install -d -o "$qual_user" -g "$qual_user" "$qual_root/home"
sudo cp -a "$(dirname "$(dirname "$(dirname "$CODEX_CLI")")")" "$qual_root/codex-cli"
sudo chown -R "$qual_user:$qual_user" "$qual_root/codex-cli"
CODEX_CLI="$qual_root/codex-cli/node_modules/.bin/codex"

if ! sudo loginctl enable-linger "$qual_user"; then
  fail "loginctl could not enable linger for the isolated user"
fi
if ! sudo systemctl start "user@${uid}.service"; then
  fail "systemd could not start the isolated user's manager"
fi

qual_home="$qual_root/home"
codex_home="$qual_home/.codex"
plugin_parent="$codex_home/plugins/cache/codex-wake-local"
plugin_root="$plugin_parent/codex-wake/$version"
runtime_dir="/run/user/$uid"
sudo install -d -m 700 -o "$qual_user" -g "$qual_user" "$codex_home"

as_qual_user() {
  sudo -u "$qual_user" env \
    HOME="$qual_home" \
    XDG_CONFIG_HOME="$qual_home/.config" \
    XDG_DATA_HOME="$qual_home/.local/share" \
    XDG_STATE_HOME="$qual_home/.local/state" \
    XDG_CACHE_HOME="$qual_home/.cache" \
    CODEX_HOME="$codex_home" \
    CODEX_WAKE_CODEX="$CODEX_CLI" \
    CODEX_WAKE_GH=/usr/bin/false \
    CODEX_WAKE_ENABLE_WEBHOOKS=0 \
    CODEX_WAKE_PLUGIN_ROOT="$plugin_root" \
    XDG_RUNTIME_DIR="$runtime_dir" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus" \
    PATH="$node_dir:/usr/local/bin:/usr/bin:/bin" \
    "$@"
}

if ! as_qual_user systemctl --user show-environment >/dev/null; then
  fail "isolated user systemd bus is unavailable after enabling linger; no system-service fallback is allowed"
fi
as_qual_user systemctl --user set-environment \
  "PATH=$node_dir:/usr/local/bin:/usr/bin:/bin" \
  "XDG_RUNTIME_DIR=$runtime_dir" \
  "DBUS_SESSION_BUS_ADDRESS=unix:path=$runtime_dir/bus"
as_qual_user "$CODEX_CLI" --version
probe_status=0
as_qual_user timeout 3 "$CODEX_CLI" app-server --listen "unix://$qual_home/probe.sock" </dev/null || probe_status=$?
[[ $probe_status == 124 ]] || fail "isolated Codex app-server exited during preflight (status $probe_status)"

sudo mkdir -p "$qual_root/unpacked"
sudo tar -xzf "$archive" -C "$qual_root/unpacked"
sudo tar -xzf "$previous_archive" -C "$qual_root/unpacked"
sudo test -d "$qual_root/unpacked/codex-wake-$version" || fail "archive root does not match version $version"
sudo test -d "$qual_root/unpacked/codex-wake-0.2.0-alpha.2" || fail "previous archive root is missing"
sudo install -d -o "$qual_user" -g "$qual_user" "$plugin_parent/codex-wake"
sudo cp -a "$qual_root/unpacked/codex-wake-0.2.0-alpha.2" "$plugin_root"
sudo chown -R "$qual_user:$qual_user" "$plugin_root"
sudo test -x "$plugin_root/bin/codex-wake" || fail "release package has no executable bin/codex-wake"

printf 'package-lifecycle: installing previous release into isolated HOME\n'
if ! as_qual_user "$plugin_root/bin/codex-wake" ensure; then
  as_qual_user systemctl --user --no-pager --full status codex-wake.service || true
  as_qual_user journalctl --user -u codex-wake.service --no-pager -n 80 || true
  fail "isolated receiver did not start"
fi
as_qual_user systemctl --user is-active --quiet codex-wake.service || fail "user receiver did not become active"
main_pid=$(as_qual_user systemctl --user show codex-wake.service --property=MainPID --value)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || fail "user receiver has no running MainPID"
controller_pid=$(as_qual_user pgrep -P "$main_pid" -f 'app-server --listen' || true)
[[ "$controller_pid" =~ ^[1-9][0-9]*$ ]] || fail "user receiver has no unique app-server child"
subscription=$(as_qual_user "$plugin_root/bin/codex-wake" subscribe \
  --kind artifact --repo qualification --resource pending --event available \
  --thread 11111111-1111-4111-8111-111111111111 | jq -er .subscription_id)
as_qual_user "$plugin_root/bin/codex-wake" subscriptions | \
  jq -e --arg id "$subscription" 'any(.[]; .id == $id and .state == "waiting")' >/dev/null
candidate_root="$plugin_parent/codex-wake/candidate-$version"
sudo cp -a "$qual_root/unpacked/codex-wake-$version" "$candidate_root"
sudo chown -R "$qual_user:$qual_user" "$candidate_root"
runtime="$qual_home/.local/share/codex-wake/runtime/codex-wake"
runtime_hash=$(as_qual_user sha256sum "$runtime")
if legacy_output=$(as_qual_user env CODEX_WAKE_PLUGIN_ROOT="$candidate_root" \
  "$candidate_root/bin/codex-wake" ensure 2>&1); then
  fail "candidate replaced or accepted an active legacy receiver"
fi
grep -Fq 'Active receiver uses a different runtime' <<<"$legacy_output" \
  || fail "candidate failed for a reason other than the legacy runtime barrier"
[[ "$(as_qual_user systemctl --user show codex-wake.service --property=MainPID --value)" == "$main_pid" ]] \
  || fail "candidate changed the active legacy receiver"
[[ "$(as_qual_user pgrep -P "$main_pid" -f 'app-server --listen' || true)" == "$controller_pid" ]] \
  || fail "candidate changed the legacy app-server child"
[[ "$(as_qual_user sha256sum "$runtime")" == "$runtime_hash" ]] \
  || fail "candidate changed the active legacy runtime"
as_qual_user "$plugin_root/bin/codex-wake" subscriptions | \
  jq -e --arg id "$subscription" 'any(.[]; .id == $id and .state == "waiting")' >/dev/null \
  || fail "candidate changed the waiting legacy subscription"
printf 'package-lifecycle: service active (MainPID %s); upgrading to %s\n' "$main_pid" "$archive_name"

as_qual_user systemctl --user stop codex-wake.service
sudo rm -rf -- "$plugin_root"
sudo cp -a "$qual_root/unpacked/codex-wake-$version" "$plugin_root"
sudo chown -R "$qual_user:$qual_user" "$plugin_root"
as_qual_user "$plugin_root/bin/codex-wake" ensure
as_qual_user systemctl --user is-active --quiet codex-wake.service || fail "user receiver did not return after restart"
restarted_pid=$(as_qual_user systemctl --user show codex-wake.service --property=MainPID --value)
[[ "$restarted_pid" =~ ^[1-9][0-9]*$ ]] || fail "user receiver has no MainPID after restart"
as_qual_user "$plugin_root/bin/codex-wake" subscriptions | \
  jq -e --arg id "$subscription" 'any(.[]; .id == $id and .state == "waiting")' >/dev/null \
  || fail "waiting subscription did not survive restart"

cancel_subscription=$(as_qual_user "$plugin_root/bin/codex-wake" subscribe \
  --kind artifact --repo qualification --resource cancel-test --event available \
  --thread 11111111-1111-4111-8111-111111111111 | jq -er .subscription_id)
as_qual_user timeout 30 node - "$plugin_root/bin/codex-wake" "$cancel_subscription" <<'NODE'
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const child = spawn(process.argv[2], ['mcp'], { stdio: ['pipe', 'pipe', 'inherit'] });
const send = value => child.stdin.write(`${JSON.stringify(value)}\n`);
let cancelled = false;
readline.createInterface({ input: child.stdout }).on('line', line => {
  const reply = JSON.parse(line);
  if (reply.id === 1 && !reply.error) {
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: {
      name: 'cancel_subscription', arguments: { subscription_id: process.argv[3] },
    } });
  } else if (reply.id === 2) {
    cancelled = reply.result?.structuredContent?.cancelled === true && !reply.result?.isError;
    child.stdin.end();
  }
});
child.on('exit', code => { if (code !== 0 || !cancelled) process.exitCode = 1; });
send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
  protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'lifecycle', version: '1' },
} });
NODE
as_qual_user "$plugin_root/bin/codex-wake" subscriptions | \
  jq -e --arg kept "$subscription" --arg cancelled "$cancel_subscription" \
    'any(.[]; .id == $kept and .state == "waiting") and all(.[]; .id != $cancelled)' >/dev/null \
  || fail "MCP cancellation changed the retained subscription or did not cancel its target"

printf 'package-lifecycle: removing isolated plugin cache and waiting for product cleanup\n'
sudo rm -rf -- "$plugin_parent/codex-wake"
for _ in $(seq 1 30); do
  if sudo test ! -e "$qual_home/.config/systemd/user/codex-wake.service" \
     && sudo test ! -e "$qual_home/.config/systemd/user/codex-wake-cleanup.service" \
     && sudo test ! -e "$qual_home/.config/systemd/user/codex-wake-cleanup.path" \
     && sudo test ! -e "$qual_home/.config/codex-wake" \
     && sudo test ! -e "$qual_home/.cache/codex-wake" \
     && sudo test ! -e "$qual_home/.local/share/codex-wake" \
     && sudo test ! -e "$qual_home/.local/state/codex-wake" \
     && sudo test ! -e "$codex_home/plugins/data/codex-wake-local/codex-wake" \
     && ! as_qual_user systemctl --user is-active --quiet codex-wake.service; then
    printf 'package-lifecycle: PASS start, restart, and uninstall cleanup (Codex app-server only; no model inference)\n'
    exit 0
  fi
  sleep 1
done

as_qual_user systemctl --user --no-pager --full status codex-wake.service codex-wake-cleanup.service || true
as_qual_user journalctl --user -u codex-wake-cleanup.service --no-pager -n 80 || true
fail "product cleanup did not remove the isolated service and its owned state within 30 seconds"
