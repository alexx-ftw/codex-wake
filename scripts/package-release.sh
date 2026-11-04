#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
[ "$#" -eq 2 ] || { echo "usage: $0 STATIC_BINARY OUTPUT_DIRECTORY" >&2; exit 1; }
[ -f "$1" ] && [ ! -L "$1" ] || { echo "binary must be a regular file" >&2; exit 1; }
binary=$(realpath -- "$1")
out=$(realpath -m -- "$2")
[ -f "$binary" ] && [ ! -L "$binary" ] || { echo "binary must be a regular file" >&2; exit 1; }
file "$binary" | grep -Eq 'ELF 64-bit.*x86-64.*(statically linked|static-pie linked)' || { echo "expected a static Linux x86_64 binary" >&2; exit 1; }
version=$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+-]*\)"$/\1/p' Cargo.toml | head -n 1)
[ -n "$version" ] || { echo "missing version" >&2; exit 1; }
git diff --quiet HEAD -- || { echo "release requires a committed clean source tree" >&2; exit 1; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
name="codex-wake-$version"
mkdir -p "$stage/$name" "$out"
git archive --output="$stage/source.tar" HEAD
tar -xf "$stage/source.tar" -C "$stage/$name"
mkdir -p "$stage/$name/bin"
cp "$binary" "$stage/$name/bin/codex-wake"
chmod 755 "$stage/$name/bin/codex-wake"
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' rust-toolchain.toml)
stdlib_notices="$(rustup run "$toolchain" rustc --print sysroot)/share/doc/rust/COPYRIGHT-library.html"
[ -f "$stdlib_notices" ] || { echo "Rust standard library notices are missing" >&2; exit 1; }
cp "$stdlib_notices" "$stage/$name/bin/RUST_STDLIB_NOTICES.html"
(cd "$stage/$name/bin" && sha256sum codex-wake > codex-wake.sha256)
epoch=$(git show -s --format=%ct HEAD)
archive="$name-linux-x86_64.tar.gz"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -cf "$stage/package.tar" -C "$stage" "$name"
gzip -n -c "$stage/package.tar" > "$out/$archive"
(cd "$out" && sha256sum "$archive" > SHA256SUMS)
printf '%s\n' "$out/$archive" "$out/SHA256SUMS"
