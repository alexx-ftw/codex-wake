#!/bin/sh
set -eu
umask 077
state="${XDG_STATE_HOME:-$HOME/.local/state}/codex-wake"
case "$state" in /*) ;; *) exit 1 ;; esac
[ -d "$state" ] && [ ! -L "$state" ] || exit 1
[ "$(stat -c %u -- "$state")" = "$(id -u)" ] || exit 1
mode=$(stat -c %a -- "$state")
[ "$mode" = 700 ] || exit 1
[ -f "$state/service.lock" ] && [ ! -L "$state/service.lock" ] || exit 1
exec 9< "$state/service.lock"
flock -s -w 2 9 || { echo 'codex-wake: interrupt record blocked by lifecycle operation' >&2; exit 1; }
[ "$(stat -Lc '%d:%i' "/proc/$$/fd/9")" = "$(stat -c '%d:%i' "$state/service.lock")" ] || exit 1
tmp=$(mktemp "$state/.interrupt.XXXXXXXX.tmp")
trap 'rm -f -- "$tmp"' EXIT HUP INT TERM
head -c 16385 > "$tmp"
[ "$(wc -c < "$tmp")" -le 16384 ] || { echo 'codex-wake: interrupt record exceeds limit' >&2; exit 1; }
mv -- "$tmp" "${tmp%.tmp}.json"
trap - EXIT HUP INT TERM
printf '{}\n'
