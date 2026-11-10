#!/usr/bin/env bash
set -Eeuo pipefail
cd "${1:-/output}"
sha256sum --check SHA256SUMS
[[ ${LAB_ACCEL:-tcg} == tcg || ${LAB_ACCEL:-tcg} == kvm ]] || exit 2
accel=${LAB_ACCEL:-tcg}
printf '%s\n' "$accel" > accelerator.txt
nonce=$(cat /proc/sys/kernel/random/uuid)
printf '%s\n' "$nonce" > nonce.txt
# No host disks, shares, networking, monitors, guest agents or inherited sockets.
timeout --foreground --signal=TERM --kill-after=10s 1200s \
  qemu-system-x86_64 -nodefaults -machine q35 -accel "$accel" -cpu max \
    -smp "$(nproc)" -m 4096 -kernel kernel -initrd initramfs.cpio.zst \
    -append "console=ttyS0 rdinit=/init panic=-1 wake_lab_vm=1 wake_lab_nonce=$nonce lsm=landlock,lockdown,yama,bpf systemd.unit=lab.target systemd.log_target=console systemd.show_status=no quiet" \
    -display none -monitor none -serial stdio -nic none -no-reboot \
    > console.log 2> qemu.stderr
node "$(dirname -- "${BASH_SOURCE[0]}")/receipt.mjs" create "$PWD"
