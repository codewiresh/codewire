# Codewire documentation

The user guide lives at [codewire.sh/docs](https://codewire.sh/docs). This
directory holds the architecture reference and developer documentation.

## Product and architecture

- [ARCHITECTURE.md](ARCHITECTURE.md): platform, placements, daemon, access,
  credentials.
- [GLOSSARY.md](GLOSSARY.md): canonical terms.
- [CONFIGURATION.md](CONFIGURATION.md): the registries and hosts a deployment
  configures, and which values are required.
- [dev/SANDBOX-DAEMON.md](dev/SANDBOX-DAEMON.md): the in-environment daemon,
  its SSH server, tailnet peer and credential bridge.
- [dev/DERP-STUN.md](dev/DERP-STUN.md): how `cw` reaches an environment
  (direct UDP, UDP relay, DERP, WebSocket fallback).
- [dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md](dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md):
  `commodity` and `confidential` runtime profiles and Docker inside the VM.
- [dev/SECRETS-AND-CREDENTIALS.md](dev/SECRETS-AND-CREDENTIALS.md): application
  secrets, provider credentials and credential profiles.
- [dev/AUTH-POLICY.md](dev/AUTH-POLICY.md): authentication credential flavors.
- [dev/SANDBOX-PREVIEWS.md](dev/SANDBOX-PREVIEWS.md): preview URLs.

## Using `cw`

- [dev/CLI-MANAGED-INSTALL.md](dev/CLI-MANAGED-INSTALL.md): installing and
  updating `cw`.
- [dev/LINUX-LOCAL-VMS.md](dev/LINUX-LOCAL-VMS.md): local VMs on Linux.
- [dev/MACOS-CLI.md](dev/MACOS-CLI.md): local VMs on macOS.
- [dev/CLI-ORCHESTRATION.md](dev/CLI-ORCHESTRATION.md): durable sessions and
  managed agents.
- [dev/TERMINAL-LAUNCH-LIFETIME.md](dev/TERMINAL-LAUNCH-LIFETIME.md) and
  [dev/TERMINAL-RETENTION.md](dev/TERMINAL-RETENTION.md): session launch
  budgets and transcript retention.

## Developing Codewire

- [dev/LOCAL-DEV.md](dev/LOCAL-DEV.md): local development loop.
- [TESTING.md](TESTING.md): dashboard and full-stack testing.
- [dev/CONTRACT-TESTING.md](dev/CONTRACT-TESTING.md): contract tests.
- [dev/DATABASE-MIGRATIONS.md](dev/DATABASE-MIGRATIONS.md): schema histories.
- [dev/PROTO-STYLE.md](dev/PROTO-STYLE.md): protobuf authoring rules.
- [dev/BROWSER-TERMINALS.md](dev/BROWSER-TERMINALS.md) and
  [dev/BROWSER-ACCOUNT-SESSIONS.md](dev/BROWSER-ACCOUNT-SESSIONS.md):
  dashboard contracts.
- [dev/AGENT-WORKFLOW.md](dev/AGENT-WORKFLOW.md): the maintainers' command
  reference for the repository rules in `AGENTS.md`.
