# Isolated alpha.2 laboratory for hosted Actions

Prepared against `144e1b08bad400b33964265e22a87b6e49c57b32`. This adds a
**manual-only** workflow; it does not change the existing CI or production Wake.
The laboratory deliberately reproduces hazards before checking its corrected
transaction. A successful experiment does **not** qualify a production migration.

## Imported sources

Only `vm.rs`, `integrated.rs`, `persistent.rs`, `hazards.rs`, `transition.rs`,
`fence.bpf.c` and the laboratory Cargo lock were imported. The manifest only
builds the VM probe. No databases, existing rootfs, compiled executables,
review homes or existing logs are inputs. The host-generated `vmlinux.h` is
replaced by a header generated from the pinned **guest** kernel's BTF.
Guest suite behavior is retained; `integrated.rs` also checks the VM boot marker
before other mounts and verifies/reports its input hashes, source SHA and nonce.

## Build and isolation

The Rust 1.98.0 image is fixed by an amd64 manifest digest. Debian dependencies
come from the dated snapshot in `dependencies.env`; its package index has an
explicit SHA-256 pin and apt verifies Debian's signed package metadata/hashes.
Both Cargo locks fix Rust dependency versions and checksums. Kernel deb, kernel
extraction script, public alpha.2 archive and public Codex 0.166.0 package have
explicit SHA-256/SHA-512 checks. Runtime package versions are preserved.
The alpha.2 executable is only used **inside the guest**, without uninstall.

`ci.sh` requires a clean checkout whose full SHA matches its argument and which
descends from the preparation base. Its build context is a `git archive` allowlist:
Wake build sources, embedded hook inputs, and these laboratory sources.
It forwards no credentials, host state, sockets, homes or volumes to the container.
The guest receives only its kernel and freshly built initramfs. QEMU has no NIC,
host filesystem/disks, monitor, guest agent or network endpoint. Internal guest
Unix sockets remain necessary for the test. Only the guest loads/attaches BPF.

The runtime container uses `--network none`, drops all capabilities and enables
`no-new-privileges`. It uses KVM when `/dev/kvm` is readable/writable, otherwise
TCG, with all available CPUs. `run.sh` defaults to TCG. A KVM initialization
failure fails the run; it is not silently retried. The guest has 4 GiB RAM,
a 900-second service deadline and a 1200-second QEMU deadline, within a 45-minute
Actions job. TCG performance on hosted runners remains to be measured.

## Receipt and review

The manually selected `expected_sha` must equal the workflow's `github.sha`.
The receipt binds that SHA and Git tree, individual source hashes, Actions run
ID/attempt, runner image version, package inventory, kernel/config/initramfs and
guest executable hashes, console/stderr hashes, selected accelerator and a fresh
nonce echoed by the guest. Creation requires one successful final result for the
corrected suite and one `VM_EXIT=0`, after the result. Failed or timed-out guests
retain diagnostic evidence but do not produce a success receipt.
Ordering uses the marker line positions, including when valid JSON has spaces.
The v2 synthetic RPC counter observes a deliberately lost reply and all RPCs
targeting that uncertain thread, including unknown methods and notifications.
The receipt requires one accepted uncertain delivery, zero measured retries and
two delivered positive controls. This measures the laboratory fixture and its
synthetic server; it does not qualify production delivery semantics.

After an authorized run, download its exact artifact and verify it using this
script from the tested commit, in a repository containing that commit:

```sh
node scripts/alpha2-vm/receipt.mjs verify /absolute/artifact-directory FULL_COMMIT_SHA
```

Verification checks the checksum chain and compares all source hashes/tree to
Git objects at that exact SHA. The receipt is an integrity record, not a signed
attestation: authentication relies on obtaining the artifact from the matching
GitHub repository/run/attempt. It does not prove that an untrusted runner behaved
honestly or that initramfs generation is byte-reproducible.

## Local checks without booting or dispatching CI

```sh
node --test scripts/alpha2-vm/test.mjs
shellcheck -x -P scripts/alpha2-vm scripts/alpha2-vm/{build,run,ci}.sh
actionlint .github/workflows/alpha2-vm.yml
cargo check --locked --manifest-path scripts/alpha2-vm/Cargo.toml
```

The launcher regression substitutes QEMU; it proves argument isolation, TCG/KVM
selection and timeout handling, not actual guest boot, BPF verifier acceptance,
systemd behavior or the integrated hazard assertions. Building a BPF object is
also separate from loading it. Existing unused-code warnings from the imported
laboratory remain; production source files are unchanged.
