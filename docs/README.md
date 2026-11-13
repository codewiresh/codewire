# Codewire documentation

Where each kind of documentation lives, and who it is for:

| Audience | Start at | What it holds |
| --- | --- | --- |
| Users of `cw` and the dashboard | [codewire.sh/docs](https://codewire.sh/docs), built from `apps/docs/zola/content` | Install, first environment, concepts, how-to guides, the CLI reference, the security model as a user sees it |
| Engineers and self-hosters | [SPEC.md](../SPEC.md) | The one current specification: product model, components, contracts, access paths, security model, configuration and delivery |
| Contributors | [CONTRIBUTING.md](../CONTRIBUTING.md), then this directory | How the system is built, verified and documented |
| Maintainers and agents | `AGENTS.md`, [dev/AGENT-WORKFLOW.md](dev/AGENT-WORKFLOW.md) | Repository rules and the commands behind them |

Shipped behaviour is documented here, under `docs/`. Designs, plans and
research live in the maintainers' private design repository, never here. The
public site under `apps/docs/zola` is the user guide; `crates/README.md`,
`proto/README.md`, `scripts/README.md` and the other READMEs describe one
directory each.

## Product and architecture

- [SPEC.md](../SPEC.md): the specification, and the place to start.
- [ARCHITECTURE.md](ARCHITECTURE.md): how the hosted platform is put
  together on Kubernetes: CRDs, warm pools, runtime profiles, the workspace
  Pod and the environment lifecycle.
- [GLOSSARY.md](GLOSSARY.md): canonical terms.
- [CONFIGURATION.md](CONFIGURATION.md): the registries and hosts a
  deployment configures, and which values are required.
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
- [dev/CI-CONFIGURATION.md](dev/CI-CONFIGURATION.md): the Forgejo settings
  and Actions variables a site that runs Codewire's CI sets.
- [dev/BROWSER-TERMINALS.md](dev/BROWSER-TERMINALS.md) and
  [dev/BROWSER-ACCOUNT-SESSIONS.md](dev/BROWSER-ACCOUNT-SESSIONS.md):
  dashboard contracts.
- [dev/AGENT-WORKFLOW.md](dev/AGENT-WORKFLOW.md): the maintainers' command
  reference for the repository rules in `AGENTS.md`.
- [journeys/README.md](journeys/README.md): acceptance journeys, one file
  per feature: what to run, what must be seen, and when it was last seen.
