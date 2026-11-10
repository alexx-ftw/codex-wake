#!/usr/bin/env bash
set -Eeuo pipefail
cd /work
lab=/work/scripts/alpha2-vm
# shellcheck source=dependencies.env
source "$lab/dependencies.env"
mkdir /deps /output
fetch() {
  local url=$1 hash=$2 file=$3 algorithm=${4:-256}
  curl --fail --location --retry 3 --max-time 240 --silent --show-error "$url" -o "$file"
  printf '%s  %s\n' "$hash" "$file" | "sha${algorithm}sum" --check
}
fetch "$KERNEL_URL" "$KERNEL_SHA256" /deps/kernel.deb
fetch "$EXTRACT_URL" "$EXTRACT_SHA256" /deps/extract-vmlinux
fetch "$LEGACY_URL" "$LEGACY_SHA256" /deps/legacy.tar.gz
fetch "$CODEX_URL" "$CODEX_SHA512" /deps/codex.tgz 512
dpkg-deb -x /deps/kernel.deb /deps/kernel
cp "/deps/kernel/boot/vmlinuz-$KERNEL_VERSION" /output/kernel
cp "/deps/kernel/boot/config-$KERNEL_VERSION" /output/kernel.config
for option in BPF_LSM DEBUG_INFO_BTF CGROUPS SECURITY SECURITY_PATH DEVTMPFS BLK_DEV_INITRD RD_ZSTD BPF_SYSCALL; do
  grep -qx "CONFIG_$option=y" /output/kernel.config
done
sh /deps/extract-vmlinux /output/kernel > /deps/vmlinux
bpftool btf dump file /deps/vmlinux format c > "$lab/vmlinux.h"
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wno-missing-declarations -Werror=pass-failed -I "$lab" \
  -c "$lab/fence.bpf.c" -o /deps/fence.bpf.o
tar -xzf /deps/legacy.tar.gz -C /deps codex-wake-0.2.0-alpha.2/bin/codex-wake
tar -xzf /deps/codex.tgz -C /deps package/vendor/x86_64-unknown-linux-musl/bin/codex
cp /deps/codex-wake-0.2.0-alpha.2/bin/codex-wake /deps/legacy
cp /deps/package/vendor/x86_64-unknown-linux-musl/bin/codex /deps/codex
cargo build --locked --release --jobs "$(nproc)" --bin codex-wake
cargo build --locked --release --jobs "$(nproc)" --manifest-path "$lab/Cargo.toml" --bin alpha2-vm-probe
node "$lab/build-root.mjs"
cd /rootfs
find . -print0 | LC_ALL=C sort -z | cpio --null --reproducible -o --owner=0:0 -H newc | zstd -T0 -3 -o /output/initramfs.cpio.zst
cp /packages.tsv /output/packages.tsv
cp /rootfs/guest/inputs.sha256 /output/inputs.sha256
cp /work/source.json /output/source.json
cd /output
sha256sum kernel kernel.config initramfs.cpio.zst packages.tsv inputs.sha256 source.json > SHA256SUMS
