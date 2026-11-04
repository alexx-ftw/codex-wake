#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=${XDG_CACHE_HOME:-$HOME/.cache}/codex-wake/build
cargo build --locked --quiet --manifest-path "$root/Cargo.toml" --target-dir "$target" >&2
if [ "$#" -eq 0 ]; then set -- mcp; fi
exec "$target/debug/codex-wake" "$@"
