---
title: herdr
description: Open shells and coding agents in Codewire environments as herdr tabs with the Codewire plugin, or reach any environment over SSH from a herdr pane.
updated: 2026-11-12
weight: 7
---

[herdr](https://herdr.dev) is a terminal workspace manager for coding agents.
The Codewire plugin lists your environments in a herdr overlay and opens a
shell or Claude Code in the one you choose, each in its own tab. herdr tracks
the agent's status as it does for a local one.

## Prerequisites

- herdr 0.9.0 or later, on Linux or macOS.
- `cw`, [installed](@/install.md); for cloud environments, `cw login`.
- `jq`, which the environment list uses.

## Install the plugin

```sh
herdr plugin install codewiresh/codewire/integrations/herdr
```

From a checkout of the Codewire repository, link the folder instead:

```sh
herdr plugin link "$PWD/integrations/herdr"
```

## Use it

| Action | What it does |
| --- | --- |
| `codewire.environments` | Lists every environment. Type its number and `s` for a shell or `a` for Claude Code, for example `2a`; Enter cancels |
| `codewire.new` | Runs `cw create`'s guided setup in a tab, then lists environments |
| `codewire.shell` | A shell in the environment `cw use` selected |
| `codewire.agent` | Claude Code in the environment `cw use` selected |
| `codewire.doctor` | Runs `cw doctor` beside the current pane |

Run an action with `herdr plugin action invoke codewire.environments`, or bind
it to a key in herdr's `config.toml`:

```toml
[[keys.command]]
key = "prefix+c"
type = "plugin_action"
command = "codewire.environments"
description = "Codewire environments"
```

A shell is `cw shell` and an agent is `cw run claude`, so each runs in a
durable [terminal session](@/access/sessions.md) in the environment. Closing
the tab or losing the connection leaves it running: reconnect with
`cw attach ENV --session SESSION`, as the tab prints when it starts. Claude
Code signs in with the environment's
[credential profile](@/secrets/credentials.md).

## Without the plugin

Every environment is an SSH host once you run
[`cw setup ssh`](@/access/ssh-and-vscode.md), so a herdr pane can reach one
directly:

```sh
ssh cw-cloud-my-app
```

## Troubleshooting

**"cw is not installed".** herdr's server may not have your shell's `PATH`.
The plugin also looks in `~/.local/bin`, `/usr/local/bin` and
`/opt/homebrew/bin`; install `cw` in one of them.

**A tab closes as soon as it opens.** A shell or agent that fails keeps its
tab open with the exit status; one that ends normally closes it. Run
`codewire.doctor` to check `cw`.
