---
title: Environments
description: What an environment contains, how its lifecycle works, and what the daemon inside it does.
weight: 1
---

An environment is an isolated development machine. Every `cw` command that
does work names one, by name or ID, or uses the one you selected with
`cw use`.

## What it contains

- **A runtime image.** The Codewire workspace image by default (`--image
  workspace`), or any OCI image. The workspace image carries Docker, common
  toolchains, and the Codex and Claude Code clients.
- **Workspace storage.** `/workspace` holds your repositories or your mounted
  project directory, and `/home/codewire` is the user's home. Both survive a
  stop and a start. This is live storage, not a snapshot: Codewire does not
  keep point-in-time copies of it.
- **Resources.** CPU, memory and disk, chosen at creation and changed with
  `cw resize`. Disks grow and never shrink.
- **Sessions.** Shells, commands and managed agent conversations, owned by
  the environment and kept across your disconnects. See
  [Sessions and agents](@/concepts/sessions-and-agents.md).
- **Ports.** Published as HTTPS preview URLs on the platform, or on
  `127.0.0.1` of your machine for a local VM.
- **Selected sources.** Which application secrets reach its processes and
  which credential profile its agents and Git use. See
  [Secrets and credentials](@/concepts/secrets-and-credentials.md).
- **Docker.** A Docker daemon runs inside the VM, with its own data disk on a
  local VM.

A `codewire.yaml` in the project describes most of this once; see
[The project file](@/guides/project-file.md).

## The daemon

Inside every environment runs the Codewire daemon: the same `cw` binary, in a
private mode. It serves terminal and agent sessions, file transfer, an SSH
server with SFTP and SCP on port 2222, and the environment's tailnet peer. The
dashboard terminal, `cw shell`, `ssh`, `scp` and VS Code all end at this
daemon. `cw daemon status ENV` shows its version and health, and
`cw daemon repair ENV` reconciles it without recreating the environment.

## Lifecycle

```sh
cw create ...
cw stop ENV      # compute released, storage kept
cw start ENV
cw restart ENV   # local VMs and hosts
cw rm ENV        # gone, with its storage
```

Stopping gives every process SIGTERM and a few seconds before the VM powers
off. Starting a hosted sandbox again resumes the managed agent conversations
it held; see [Orchestrate agents](@/guides/run-agents.md).

The states an environment reports are listed in
[Environment statuses](@/reference/environment-statuses.md). `cw info ENV`
shows the current one, with the error code when something failed.

## Selecting an environment

```sh
cw use                 # choose from your local and cloud environments
cw use my-app          # the default for session commands
cw use --local my-app  # when a local and a hosted environment share a name
cw current
```

Only `cw use` selects: creating an environment does not, and removing the
current one leaves none selected.

Environment commands take `--local` or `--cloud` to restrict a name to one
placement; without either, `cw` looks in trusted hosts, local VMs and the
current organization, and refuses an ambiguous name.

## Hosted environments

A hosted environment belongs to one organization, counts toward its plan, and
is visible to the organization's members according to their role and to any
access grant on that environment. The dashboard calls it a *Sandbox*: **Create
Sandbox** is the form behind `cw create`, and the Sandbox page offers the
browser terminal, **Open in VS Code**, the Ports dialog, Start, Stop, Resize
and Delete. Deleting is immediate.

Hosted-only lifecycle extras: `--ttl` deletes an environment after a
lifetime (`cw extend ENV --hours N` postpones it); `cw protect ENV`
refuses deletion until `cw unprotect`; `cw prune` removes
environments stuck in error, creating or pending states.
