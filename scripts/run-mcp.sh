#!/bin/sh
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -eq 0 ]; then set -- mcp; fi
export CODEX_WAKE_PLUGIN_ROOT="$root"

if [ "${CODEX_WAKE_BUILD_FROM_SOURCE:-0}" = 1 ]; then
    target="${XDG_CACHE_HOME:-$HOME/.cache}/codex-wake/build$root"
    cargo build --locked --quiet --manifest-path "$root/Cargo.toml" --target-dir "$target" >&2
    exec "$target/debug/codex-wake" "$@"
fi

verify_binary() {
    verify_path=$1
    verify_sum=$2
    [ -f "$verify_path" ] && [ ! -L "$verify_path" ] && [ -f "$verify_sum" ] && [ ! -L "$verify_sum" ] || return 1
    awk -v name="$(basename -- "$verify_path")" 'NF == 2 && $1 ~ /^[0-9a-fA-F]+$/ && length($1) == 64 && $2 == name { count++; next } { bad=1 } END { if (bad || count != 1) exit 1 }' "$verify_sum" || return 1
    (cd "$(dirname -- "$verify_path")" && sha256sum -c "$(basename -- "$verify_sum")" >/dev/null 2>&1)
}

binary="$root/bin/codex-wake"
if [ -e "$binary" ] || [ -L "$binary" ]; then
    verify_binary "$binary" "$root/bin/codex-wake.sha256" || { echo "invalid bundled codex-wake binary/checksum" >&2; exit 1; }
    exec "$binary" "$@"
fi

version=$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
printf '%s\n' "$version" | awk 'match($0, /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/) { ok=1 } END { exit !ok }' || { echo "invalid codex-wake semver" >&2; exit 1; }
case "$(uname -s):$(uname -m)" in
    Linux:x86_64|Linux:amd64) ;;
    *) echo "codex-wake release bootstrap supports Linux x86_64 only" >&2; exit 1 ;;
esac

cache="${XDG_CACHE_HOME:-$HOME/.cache}/codex-wake/releases/$version/linux-x86_64"
mkdir -p "$(dirname -- "$cache")"
lock="$(dirname -- "$cache")/.${version}.linux-x86_64.lock"
exec 9>"$lock"
flock 9
binary="$cache/bin/codex-wake"
if ! verify_binary "$binary" "$cache/bin/codex-wake.sha256"; then
    staging=$(mktemp -d "$(dirname -- "$cache")/.${version}.linux-x86_64.XXXXXX")
    trap 'rm -rf "$staging"' EXIT HUP INT TERM
    archive="$staging/release.tar.gz"
    sums="$staging/SHA256SUMS"
    base="https://github.com/alexx-ftw/codex-wake/releases/download/v${version}"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 300 "$base/codex-wake-${version}-linux-x86_64.tar.gz" -o "$archive"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 "$base/SHA256SUMS" -o "$sums"
    expected="codex-wake-${version}-linux-x86_64.tar.gz"
    hash=$(awk -v name="$expected" 'NF == 2 && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && $2 == name { if (found++) exit 1; print $1 } END { if (!found) exit 1 }' "$sums") || { echo "release SHA256SUMS has no unique exact archive entry" >&2; exit 1; }
    printf '%s  %s\n' "$hash" "$(basename -- "$archive")" > "$staging/archive.sha256"
    (cd "$staging" && sha256sum -c archive.sha256 >/dev/null)
    member="codex-wake-${version}/bin/codex-wake"
    sidecar="$member.sha256"
    tar -tzf "$archive" > "$staging/archive.paths"
    awk -v prefix="codex-wake-${version}/" -v a="$member" -v b="$sidecar" '
        { path=$0; sub(/\/$/, "", path); if (path != substr(prefix, 1, length(prefix)-1) && index(path, prefix) != 1) exit 1
          n=split(path, parts, "/"); for (i=1; i<=n; i++) if (parts[i] == ".." || parts[i] == "." || parts[i] == "") exit 1
          if (path == a) ac++; if (path == b) bc++ }
        END { if (ac != 1 || bc != 1) exit 1 }
    ' "$staging/archive.paths" || { echo "release archive has unsafe paths or missing/duplicate binary files" >&2; exit 1; }
    tar -tvzf "$archive" > "$staging/archive.details"
    cut -c1 "$staging/archive.details" | awk '$1 != "-" && $1 != "d" { exit 1 }' || { echo "release archive contains a link or special file" >&2; exit 1; }
    for entry in "$member" "$sidecar"; do
        tar -tvzf "$archive" "$entry" | cut -c1 | awk 'NR != 1 || $1 != "-" { exit 1 } END { if (NR != 1) exit 1 }' || { echo "release archive binary/checksum is not a regular file" >&2; exit 1; }
    done
    mkdir "$staging/unpacked"
    tar -xzf "$archive" -C "$staging/unpacked" --no-same-owner --no-same-permissions "$member" "$sidecar"
    [ -f "$staging/unpacked/$member" ] && [ ! -L "$staging/unpacked/$member" ] && [ -f "$staging/unpacked/$sidecar" ] && [ ! -L "$staging/unpacked/$sidecar" ] || { echo "release archive binary/checksum must be regular files" >&2; exit 1; }
    mkdir -p "$staging/install/bin"
    cp "$staging/unpacked/$member" "$staging/install/bin/codex-wake"
    inner=$(awk 'NF == 2 && length($1) == 64 && $1 ~ /^[0-9a-fA-F]+$/ && $2 == "codex-wake" { if (found++) exit 1; print $1 } END { if (!found) exit 1 }' "$staging/unpacked/$sidecar") || { echo "invalid release binary checksum" >&2; exit 1; }
    printf '%s  codex-wake\n' "$inner" > "$staging/install/bin/codex-wake.sha256"
    verify_binary "$staging/install/bin/codex-wake" "$staging/install/bin/codex-wake.sha256" || { echo "release binary checksum failed" >&2; exit 1; }
    cp "$archive" "$staging/install/release.tar.gz"
    rm -rf "$cache"
    mv "$staging/install" "$cache"
    trap - EXIT HUP INT TERM
    rm -rf "$staging"
fi
flock -u 9
exec 9>&-
exec "$binary" "$@"
