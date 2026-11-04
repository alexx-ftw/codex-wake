# Reporting security issues

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/alexx-ftw/codex-wake/security/advisories/new).
Do not include webhook secrets, Codex credentials, private chat contents or
unredacted state databases in public issues.

Include the Wake version, Codex version, operating system, reproduction steps
and expected versus observed behavior. The alpha currently targets Linux
x86_64 with a systemd user manager; support is limited to the latest published
alpha. No response-time guarantee is offered.

Webhook inputs are authenticated, but matching events can trigger configured
chat actions. Rule authors and text filters are optional: omitting them can
allow any matching comment author in the selected repository and resource.
Review those conditions before enabling a rule.
