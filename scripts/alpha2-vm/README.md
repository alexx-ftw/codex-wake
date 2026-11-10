# Isolated alpha.2 laboratory for hosted Actions

Prepared against `144e1b08bad400b33964265e22a87b6e49c57b32`. This adds a
**manual-only** laboratory job to the existing `ci.yml`, using its `probe` input.
Ordinary push/PR CI keeps its existing routing; production Wake is unchanged.
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
The image build runs `cargo test --manifest-path scripts/alpha2-vm/Cargo.toml`
with the pinned toolchain, locked dependencies and release profile before
packaging the probe/rootfs. All three RPC counter tests must pass; any failure
stops construction before packaging or guest boot.

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

The SHA explicitly provided in `probe=alpha2-vm-qualification:FULL_SHA` must equal
the workflow's `github.sha`. Checkout and the build wrapper use that exact SHA.
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

The job verifies the full raw receipt, kernel/config/initramfs, package and
guest-input inventories, source files against Git, console/stderr, nonce and
guest result **before creating the export directory**. Raw files stay inside
the job. A failed verification exports nothing and skips artifact upload.

Only two explicitly listed files are uploaded: `receipt.json` (schema 2,
`alpha2-vm-sanitized`) and its `SHA256SUMS`. The receipt contains allowlisted
source/run identifiers and hashes, fixed verified check results, guest executable
hashes and Debian package versions. Arbitrary guest results, RPC payloads, paths,
logs and extra source metadata are omitted. No binary, rootfs, database or full
console is uploaded. The package and guest-input data are also checked against
their verified raw hashes before export.

After an authorized run, download its exact sanitized artifact and verify it
using this script in a repository containing the tested commit:

```sh
node scripts/alpha2-vm/receipt.mjs verify-export /absolute/artifact-directory FULL_COMMIT_SHA
```

This checks the export checksum, SHA/tree/source hashes against Git and the
version/input inventories against their original verified hashes. It cannot
rehash omitted binaries or console: that full verification occurs inside the
job before selection. For retained local raw evidence, the original
`receipt.mjs verify RAW_DIRECTORY FULL_COMMIT_SHA` command remains available.

The receipt is an integrity record, not a signed
attestation: authentication relies on obtaining the artifact from the matching
GitHub repository/run/attempt. It does not prove that an untrusted runner behaved
honestly or that initramfs generation is byte-reproducible.

## Manual invocation after review

The dispatch uses `ci.yml`, which already exists on the default branch, and only
its existing `probe` input. No new workflow registration or dispatch input is
required. A branch/tag containing the reviewed change must be available remotely.
This is the command for a later authorized run; preparing it does not dispatch:

```sh
gh workflow run ci.yml --repo alexx-ftw/codex-wake --ref REVIEWED_BRANCH_OR_TAG \
  -f probe=alpha2-vm-qualification:FULL_REVIEWED_COMMIT_SHA
```

If the selected ref resolves to a different SHA, validation fails before the VM
build. This probe selects only `alpha2-vm`: ordinary tests, package,
package-lifecycle and controller qualification do not run. Malformed values in
the laboratory probe namespace also fail its preflight instead of starting
ordinary jobs. Existing probes keep their previous behavior.

GitHub requires a default-branch workflow and a branch/tag ref for dispatch:
[workflow dispatch documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch),
[dispatch API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).

## Local checks without booting or dispatching CI

```sh
node --test scripts/alpha2-vm/test.mjs scripts/alpha2-vm/workflow.test.mjs
shellcheck -x -P scripts/alpha2-vm scripts/alpha2-vm/{build,run,ci}.sh
actionlint .github/workflows/ci.yml
cargo check --locked --manifest-path scripts/alpha2-vm/Cargo.toml
```

The launcher regression substitutes QEMU; it proves argument isolation, TCG/KVM
selection and timeout handling, not actual guest boot, BPF verifier acceptance,
systemd behavior or the integrated hazard assertions. Building a BPF object is
also separate from loading it. Existing unused-code warnings from the imported
laboratory remain; production source files are unchanged.
