+++
title = "CLI reference"
description = "Every cw command and flag, grouped the way cw --help groups them."
weight = 40
sort_by = "weight"
+++

```sh
curl -fsSL https://get.codewire.sh | sh
cw --help
cw env create --help
```

{{ card_grid(
  titles=["Environments", "Sessions", "Agents", "Secrets and credentials", "Networking", "Account and organizations", "cw itself", "Configuration"],
  hrefs=["/docs/cli/environments", "/docs/cli/sessions", "/docs/cli/agents", "/docs/cli/secrets-and-credentials", "/docs/cli/networking", "/docs/cli/account", "/docs/cli/cw", "/docs/cli/configuration"],
  descriptions=["env, use, current, init, shell, vscode, config-ssh, preset", "run, list, attach, logs, send, wait, stop, restart", "msg, steer, interrupt, inbox", "secrets, credentials", "network, mesh, control, member", "setup, login, logout, whoami, org, api-keys, cost", "install, update, doctor, config, completion", "Files and environment variables"]
) }}

## Global options

| Option | Meaning |
| --- | --- |
| `-s, --server URL` | Platform server URL override for this invocation |
| `--member NAME` | Run a session command against a pinned trusted host member (Linux); conflicts with `--server` |
| `-h, --help`, `-V, --version` | |

## Conventions

- **Placement.** `cw env` subcommands, `cw use`, `cw secrets` and
  `cw credentials` take `--local` or `--cloud`. Without either, environment
  commands resolve a name across trusted hosts, local VMs and the current
  organization and refuse an ambiguous one; secret and credential commands
  ask at a terminal and fail without a flag otherwise.
- **ENV and SESSION.** An environment is a name or ID; a session is a name
  or ID within an environment, and `session-<uuid>` matches by ID only.
  Session commands default to the environment selected with `cw use`.
- **Output.** `--output json` (or `-o json` where offered) prints machine
  output and never prompts; the default is `text`.
- **Secrets on stdin.** API keys, tokens and secret values are read from a
  hidden prompt or standard input, never from arguments.
- Commands shown as `cw env --local upgrade` take the placement flag before
  the subcommand, where it is defined.
