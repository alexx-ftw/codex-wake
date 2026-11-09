# Private systemd controller qualification (proposed)

This is a manually dispatched **hosted-CI experiment**, not an installation,
upgrade or production service change. The workflow is prepared locally and has
not been dispatched or verified on a GitHub-hosted runner. The earlier Rust
supervisor prototype and its evidence are retained separately; neither approach
is connected to the existing installer or cleanup.

## What the experiment is intended to establish

The test creates a fresh temporary Linux user and a separate `systemd --user`
manager on an Ubuntu 24.04 GitHub-hosted runner. Two test-only transient units
have distinct cgroups and `KillMode=control-group`:

1. The controller unit runs a tiny test entrypoint which confirms that creating
   IPv4 and IPv6 sockets is denied, starts a known `sleep` child for the cgroup
   cleanup check, and immediately `exec`s the pinned native Codex binary. The
   native binary remains the systemd main PID; the entrypoint does not supervise
   it after exec.
2. The receiver unit runs the actual built `codex-wake receiver` with the
   existing external `CODEX_WAKE_RPC_SOCKET` path and webhooks disabled.
3. Readiness requires an `initialize` handshake and `thread/loaded/list` reply,
   with the socket peer PID/UID and `/proc/PID/exe` device/inode matching the
   native controller unit. The receiver's own `receiver.start` telemetry and
   executable identity are checked before and after its restart.
4. The probe keeps one WebSocket open, restarts **only the test receiver**, and
   verifies the same controller PID and process start time, controller cgroup,
   socket/link inode and still-responsive WebSocket. Receiver PID/start must
   change, and the two service cgroups must be distinct and non-overlapping.
5. The probe kills the controller unit's main PID, expects the unit to fail
   without an automatic restart, waits for its entire observed cgroup to be
   empty, checks the known helper is gone or a zombie, and verifies that the
   receiver remains active and that the original WebSocket closes. It then
   stops the receiver and checks its cgroup is empty too.
6. The outer script disables linger, stops the temporary manager and its runtime
   directory service, verifies the temporary user's slice and processes are
   empty, removes only validated test-owned socket/lock files while holding both
   POSIX record and `flock` locks, and confirms that the user, group and runtime
   directory are gone. If ownership, a lock, a process or cleanup cannot be
   verified, it fails and preserves the questionable resources for inspection.

The probe records only fixed stages, boolean checks, coarse error classes, the
source commit and binary SHA-256 hashes. Both units use `StandardOutput=null`
and `StandardError=null`; journal contents, RPC payloads and unfiltered child
output are never uploaded. A receipt is written incrementally, and the outer
script marks failures and cleanup status. A missing receipt or missing cleanup
flag is not a pass.

## Isolation and activation

The existing [workflow](../.github/workflows/ci.yml) reserves the already
available manual input `probe=controller-systemd-qualification` for this test.
That value selects the isolated job and skips the unrelated `test` and `package`
jobs; `package-lifecycle` is skipped because it needs `package`. Push, pull
request and other manual runs retain their existing selection. Reusing the
existing input avoids depending on a new input schema on the default branch.

The isolated job uses `ubuntu-24.04`, pins the Codex npm package to `0.166.0`,
resolves its **native** payload and does not persist checkout credentials. It
builds the test receiver and probe from the selected commit. Once the changes
are published to a branch and a manual run is authorized, the existing
workflow can be requested with:

```sh
gh workflow run ci.yml --ref BRANCH -f probe=controller-systemd-qualification
```

GitHub requires the workflow file on the default branch for manual dispatch;
the selected branch must contain this proposed job and its supporting files.
No dispatch of this proposal has been attempted.
The [script](../scripts/qualify-systemd-controller.sh) refuses to run outside a
GitHub-hosted Actions runner. It creates a random new username/UID, checks for
pre-existing processes with the UID as real or effective user, user manager,
runtime, slice and daemon socket directory, and only
stops the manager and units belonging to that new UID. A UID with existing
processes, or an inconclusive process check, fails before manager activation;
the account is retained if safe cleanup cannot be established. Receipt export
uses privileged reads and retains only approved fields. Exit success requires
the complete passing receipt and verified cleanup.

The test user has a new private HOME/CODEX_HOME, and the controller and receiver
are started with `env -i`. Their units allow only AF_UNIX socket creation; the
controller explicitly tests that ordinary AF_INET and AF_INET6 `socket()` calls
fail before starting Codex. This is a test constraint, not a general sandbox
security claim: systemd documents limitations including inherited sockets.
No credentials or inference request are supplied. Standard files and services
of the hosted runner still exist; this is not a full filesystem namespace.
The receiver's provider is `/usr/bin/false`, and no real external event or chat
is queued.

A separate local process-only check of the supplied native Codex 0.167.0 was
run in an empty HOME/CODEX_HOME and isolated PID, mount and network namespaces,
without systemd. It showed that its socket symlink pointed into
`/tmp/codex-daemon-UID` even with a private `TMPDIR`; after SIGKILL the socket
and its `.lock` file remained. An ordinary `flock` probe succeeded while Codex
was running, so that probe alone cannot establish lock ownership. The proposed
cleanup consequently validates the new UID and filenames, requires empty
cgroups and no remaining UID processes, and holds both record and `flock` locks
before unlinking. Unknown entries or an unavailable lock make it fail closed.
This local observation does not establish the behavior of CI's 0.166.0 binary.

The socket check permits only a user-owned direct socket or a user-owned socket
link into the newly created user's validated `/tmp/codex-daemon-UID` directory
(or the test's private temporary directory). It checks the endpoint before
connecting. The external directory must not exist before the test and is not
removed recursively; only validated socket/lock pairs are removed after draining.

## Local checks and remaining evidence

Before publishing, local checks can compile and exercise the probe without a
systemd manager or real service:

```sh
cargo test --locked --jobs "$(nproc)" --example controller-systemd-qualification
cargo clippy --locked --jobs "$(nproc)" --example controller-systemd-qualification -- -D warnings
rustfmt --check --edition 2024 examples/controller-systemd-qualification.rs
bash -n scripts/qualify-systemd-controller.sh tests/qualify-systemd-controller.sh
shellcheck scripts/qualify-systemd-controller.sh tests/qualify-systemd-controller.sh
bash tests/qualify-systemd-controller.sh
```

These checks exercise socket-path rejection, lock retention, receipt formatting,
a local synthetic WebSocket exchange, receipt export from an inaccessible
directory, UID preflight failure cases and a real process with different real
and effective UIDs. The shell regression needs passwordless
sudo for temporary test files but does not start a user manager. They do **not** verify systemd,
cgroup drainage or the hosted runner. The GitHub workflow has not been run;
its user-manager lifecycle, native 0.166.0 behavior and artifact remain to be
validated when the workflow is explicitly published and dispatched.

Even a passing run would cover only these transient test units, one known helper
and the stated failure path. It would not prove continuity of an active
inference turn, arbitrary escaped descendants, external ingress, cross-version
writer admission, safe legacy migration, production uninstall or global safety.
See [the existing upgrade design](automatic-upgrade-design.md) for those gates.

References: [systemd kill semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html),
[Ubuntu systemd address-family restrictions](https://manpages.ubuntu.com/manpages/noble/man5/systemd.exec.5.html),
and [GitHub-hosted runner environment](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).
