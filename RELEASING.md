# Linux x86_64 alpha releases

The alpha targets Linux x86_64 with a systemd user manager. Codex 0.166.0 is
the qualification baseline. Other platforms and Codex versions are not yet
qualified. Desktop requires manual approval of the bundled hooks.

## Build and package

Use the pinned Rust toolchain in `rust-toolchain.toml`, GNU tar, gzip, Git,
coreutils, `file`, and a musl C compiler. Build with the committed lockfile:

```sh
rustup target add x86_64-unknown-linux-musl
CC=musl-gcc cargo build --locked --release --target x86_64-unknown-linux-musl
sh scripts/package-release.sh \
  target/x86_64-unknown-linux-musl/release/codex-wake \
  .test-results/release
```

Packaging requires a clean committed tree. It includes
tracked source and plugin files, the static binary and its checksum. It excludes
ignored build outputs and private test evidence. The tar archive has normalized
ordering, timestamps and ownership; gzip omits its timestamp. Identical source
commit and binary bytes must produce identical archives. This does not establish
that different compiler environments produce identical binary bytes.

Before publishing, verify both archive checksums and repeat packaging into a
second directory to compare bytes. Keep the release tag, Cargo package version
and plugin version identical. Upload the archive and `SHA256SUMS` together.
Never replace assets under an existing release tag: publish a new version.

## Qualification gate

Run the unit, launcher, telemetry and real HTTP suites. In a clean Linux user
environment without Cargo, verify installation from the unpacked package,
hook approval, concurrent MCP startup, persistence across session closure,
service restart, and a signed webhook delivery. Then verify a maintenance
upgrade retains the secret and waiting subscriptions without replaying delivered
messages. Finally uninstall and inspect plugin-owned services, state and caches.
Do not run lifecycle tests against an unrelated active service.

A green unit suite alone does not qualify the release. Record the exact source
commit, binary and archive hashes, Codex version, environment and results before
publishing. The initial alpha is for limited beta testing before broad promotion.
