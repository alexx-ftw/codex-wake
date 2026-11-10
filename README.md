# Codex Wake

A Rust plugin that wakes a Codex chat when an event arrives, without keeping a
model polling. Each chat can subscribe to several events at once.

- Continue after GitHub Actions, PR reviews, deployments or branch changes.
- React to another thread or subagent stopping, or a producer reporting a job,
  resource or artifact result.
- Match PR comments by author and phrase to message an existing chat or create
  one, optionally with a goal.
- Set input templates, model and reasoning effort where the Codex transport
  supports them.

**Alpha:** qualified on Linux x86_64 with a systemd user manager and Codex
0.166.0. It targets local Codex chats, not ordinary ChatGPT web chats.

## Install

Download and extract the archive from the
[latest release](https://github.com/alexx-ftw/codex-wake/releases), verify its
`SHA256SUMS`, then add the extracted directory:

```sh
codex plugin marketplace add /absolute/path/to/codex-wake
codex plugin add codex-wake@codex-wake-local
```

Release installs need no Rust toolchain. They require `codex`, `gh`, `curl`, GNU `tar`,
`sha256sum`, `flock` and a working systemd user manager.

Review and approve the bundled `PreToolUse`, `PostToolUse`, `SessionStart`, `Stop` and `SubagentStop` hooks
in Codex. MCP startup automatically sets up one private receiver shared by all
sessions. Tools describe their parameters directly; optional [command skills](skills/)
provide shortcuts such as `$codex-wake:subscribe` and `$codex-wake:status`.

For GitHub, sign in with `gh auth login`. The service polls subscribed resources;
no public endpoint, Funnel or repository webhook is required.
See [source monitoring](GUIDE.md#github-and-external-events).

## Use

Ask the agent to subscribe this chat to a particular CI run, PR event or producer
result, with the input it should receive when that event happens. The MCP tools
also expose thread inputs, conditional rules and goal operations.

Subscriptions are independent and one-shot. Explicit observations can check
files, health endpoints, file locks and systemd jobs; other custom results need
a producer. The agent does not spend model turns polling.
Queue acceptance is not proof of execution. Ambiguous deliveries require
inspection and are not automatically replayed.

The receiver stays active when chats close. Disabling the plugin preserves its
state; **uninstalling deletes subscriptions, secrets and plugin-owned runtime
data**. Use the [maintenance upgrade procedure](GUIDE.md#maintenance-upgrade)
to retain state when upgrading.

## Documentation

- [User and operations guide](GUIDE.md): tools, events, templates, hooks,
  service lifecycle, CLI and diagnostics.
- [Validation evidence](VALIDATION.md): what was tested and its limits.
- [Release qualification](RELEASING.md), [security](SECURITY.md) and
  [third-party notices](THIRD_PARTY_NOTICES.md).
