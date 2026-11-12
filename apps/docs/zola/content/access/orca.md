---
title: Orca
description: Run each Orca workspace in its own Codewire environment, a local VM or a cloud sandbox, with the Codewire plugin, or connect Orca to an environment you already have over SSH.
updated: 2026-11-12
weight: 6
---

[Orca](https://www.onorca.dev) runs coding agents in parallel, each in its
own Git worktree. It works with Codewire in two ways: the Codewire plugin
gives each new Orca workspace an environment of its own, and any environment
you already have is an SSH host Orca can run on. Either way, Orca installs a
small relay in the environment and runs agents, terminals and Git there,
while its editor and diff views stay on your computer.

## Prerequisites

- Orca 1.4.245 or later.
- `cw`, [installed](@/install.md), and the SSH hosts that
  [`cw setup ssh`](@/access/ssh-and-vscode.md) writes. Orca reaches every
  environment through them.
- For cloud sandboxes, `cw login`.

Orca runs its relay on a Node runtime that it downloads from `nodejs.org` on
your computer and uploads into the environment, so Orca itself needs to reach
`nodejs.org`; a firewall that blocks it stalls the first connection.

Orca's remote terminals need node-pty, which Orca compiles inside the
environment, so the environment needs a C++ compiler. The
[workspace image](@/environments/workspace-image.md) has one. An image
without one still connects, and files, Git and the editor work, but terminals
don't start; add `build-essential` (or your distribution's equivalent) to the
image.

## The Codewire plugin

The plugin adds two choices under **Run on** when you create a workspace:
**Codewire local VM** and **Codewire cloud sandbox**. Orca runs the plugin's
commands on your computer as the workspace is created, put to sleep, woken and
deleted.

To install it from a checkout of the Codewire repository, open Orca's
**Settings → Plugins → Development folders**, add the `integrations/orca`
folder, and review and enable it. Orca shows every command the plugin runs
before you enable it. From a terminal, `orca plugin dev load
integrations/orca` does the same and prints the approval to confirm.

Run on is an experimental Orca feature: turn on **Settings → Experimental →
Cloud VM** first. Then create a workspace in a local Git project and choose
one of the Codewire recipes under **Run on**.

| Orca | Codewire local VM | Codewire cloud sandbox |
| --- | --- | --- |
| Create | `cw --local create --path . --path-mode clone`: a VM with a clone of the project's committed state and its remotes, with no host mounts and no Mesh network | `cw --cloud create`: a sandbox that clones the project's `origin`, with the [workspace image](@/environments/workspace-image.md) unless the project has a `codewire.yaml` |
| Sleep | `cw --local stop` | `cw --cloud stop` |
| Wake | `cw --local start` | `cw --cloud start` |
| Delete | `cw --local rm` | `cw --cloud rm` |

A new local VM takes a minute or two to boot the first time; sleeping and
waking it after that takes seconds. Each environment is named after the
workspace's Orca instance,
`orca-` and a UUID, so `cw ls` shows them. If a create fails, the plugin
removes the environment it started.

What goes in:

- A local VM gets only committed work. Uncommitted changes and untracked
  files stay on your computer, and so do usernames and tokens in `http(s)`
  remote URLs, which are removed before the remotes are copied in. The VM
  cannot change your project folder.
- A cloud sandbox gets what is pushed to `origin`, every branch of it.
  Private repositories use your
  [Git access](@/access/git.md); nothing from your computer's Git
  credentials is sent.

## Connect to an existing environment

These steps are not yet verified in Orca itself; the SSH connection they make
is the one the plugin's recipes use.

Any environment is also an ordinary SSH target. Confirm that you can reach it
from a terminal:

```sh
ssh cw-cloud-my-app
```

1. In Orca, open **Settings → SSH** and select **Add Target**.
2. Enter `cw-cloud-my-app`, or `cw-local-my-vm` for a local VM, as the host
   and `codewire` as the username. Keep the default port and leave the
   identity file empty.
3. Select **Test**, then **Save**.
4. Create a worktree and choose the environment under **Run on**.

The host matches the block `cw setup ssh` wrote, so Orca connects through
`cw` with the host key Codewire recorded for the environment, and never asks
you to trust a key on first use. The first connection installs Orca's relay,
so it can take a moment.

## Run an agent

Orca starts the agent you choose for a workspace; an environment doesn't start
one for you. Orca offers only agents it finds installed on the host, and the
workspace image has [Claude Code and Codex](@/agents/supported.md).

A cloud sandbox uses your default
[credential profile](@/secrets/credentials.md): agents and `git push` sign in
through it, and no provider key enters the sandbox.

A local VM from the plugin is created without a credential profile, because
a profile's GitHub connection changes the remote URLs Git reports, and Orca
would no longer recognise the VM's checkout as your project. Orca's
environment checks then say Claude Code and Codex are not signed in and that
a push to `origin` was refused. Sign the agents in inside the VM
(`claude auth login`, `codex login --device-auth`), and give Git a credential
there before you push.

## Troubleshooting

**No Run on choice.** Turn on **Settings → Experimental → Cloud VM**. The
choice appears only for local Git projects.

**Run on has no Codewire recipes.** Orca lists a plugin's recipes only while
the plugin is approved, and it asks again whenever a recipe's commands
change, such as after an update. Check **Settings → Plugins**: a plugin
waiting for approval shows as pending until you review and enable it. You
don't need Orca's Cloud VM setup skill, which is for recipes a project
defines in its own `orca.yaml`.

**"the Codewire SSH hosts are not set up or are out of date".** Run
`cw setup ssh`, then try again.

**A cloud sandbox doesn't have my latest commits.** It clones `origin`; push
the branch first.

**"Imported folder does not match the selected project identity".** The
project needs a Git remote: Orca matches the VM's checkout to your project
by its remotes. Add one (`git remote add origin URL`), then add the project
to Orca again.

**An environment is left over.** `cw ls` lists every `orca-` environment;
remove one with `cw rm NAME`.
