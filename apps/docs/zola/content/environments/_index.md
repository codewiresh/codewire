---
title: Environments
description: What an environment contains, where it can run (hosted sandbox, local VM or trusted host session), its lifecycle, and the daemon inside it.
weight: 20
aliases: ["/concepts/placements", "/concepts/environments"]
sort_by: weight
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
  [Agents](@/agents/_index.md).
- **Ports.** Published as HTTPS preview URLs on the platform, or on
  `127.0.0.1` of your machine for a local VM.
- **Selected sources.** Which application secrets reach its processes and
  which credential profile its agents and Git use. See
  [Secrets and credentials](@/secrets/_index.md).
- **Docker.** A Docker daemon runs inside the VM, with its own data disk on a
  local VM.

A `codewire.yaml` in the project describes most of this once; see
[`codewire.yaml`](@/environments/codewire-yaml.md).

## Where it runs

An environment runs in one of three placements. The same `cw` commands drive
all of them.

A placement is where an environment runs. The same `cw` commands work in all
three; what differs is isolation, who owns the compute, and a few features.

```sh
cw create --name app --image workspace            # hosted sandbox
cw create --local --name app --path .             # local VM
cw create --local --type host --name app --path . # trusted host session
```

| | Hosted sandbox | Local VM | Trusted host |
| --- | --- | --- | --- |
| Runs on | the Codewire platform | your Linux x86_64 machine or Apple Silicon Mac | your machine, as your user |
| Isolation | one VM per environment | one VM per environment | none |
| Needs | an account and an organization | KVM or macOS 26+ | Linux or macOS |
| Shell, durable sessions, logs | yes | yes | yes |
| Managed Codex and Claude Code | yes | yes | yes, with your own installed clients |
| Provider credentials | platform profile | local or platform profile, host broker | your own logins |
| SSH, `scp`, VS Code | yes | `cw shell`, `cw cp` | `cw shell` |
| Ports | HTTPS preview URLs | `127.0.0.1` on your host | n/a |
| Docker inside | yes | yes | your Docker |
| Resize | yes | yes | n/a |
| Codewire Mesh | n/a | when a network is selected | as a member |

### Hosted sandbox

The platform schedules one VM per environment (Kata Containers with Cloud
Hypervisor) holding a workspace container and a guest-local Docker daemon.
The workspace runs your image with persistent storage and starts the daemon,
which binds to the platform, serves SSH and joins the tailnet. The platform
meters running compute per second and bills the organization.

You reach it with `cw shell`, `ssh`, VS Code and the dashboard terminal, and
expose applications through preview URLs. Agents use credentials through a
platform broker; secrets and credentials are selected from the organization's
and your own stores.

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

### Local VM

`cw create --local` runs the environment in a VM on your machine, using
the runtime that your `cw` release pins and `cw setup --local` installs:
Cloud Hypervisor on KVM with the Codewire guest kernel on Linux,
Virtualization.framework through a signed helper on macOS. A supervisor on the
host owns the VM lifecycle, its state and host ports; the guest runs the same
workspace image and daemon as the platform.

Your project directory is mounted live by default. Dependency and build
folders listed in `workspace.vm_only` stay on the VM disk, so the mount stays
fast and the host stays clean. Local credentials live in your Secret Service
or Keychain and reach the VM only as a bounded capability through a broker on
the host. A local VM joins Codewire Mesh only when you select a network.

A local VM runs its host's architecture, so on a Mac the image needs a
`linux/arm64` variant; the Codewire workspace image has one.

### Trusted host session

`--type host` runs sessions as your own account with your own tools and
`HOME`. Use it for your own machine's toolchain, or when the work has to
touch the host.

{% aside(kind="caution") %}
  A trusted host session has no containment. Codewire owns process cleanup,
  not filesystem or network isolation: an agent here can read and change
  anything you can.
{% end %}

A host runs the Codex, Claude Code or noel client you installed, with your own
logins; no credential profile is involved. On Linux, a host can also be
enrolled in Codewire Mesh as a member that another machine controls with
`cw --member`; see [Networking](@/reference/cli/networking.md). Removing a host
environment deletes only Codewire's records and keeps the project directory.

### Choosing

- Code you do not trust yet, parallel agents, previews for a team: hosted
  sandbox.
- Your laptop, no account, fast file access to a checkout you are editing:
  local VM.
- The host's own hardware, tools or logins, and you accept no containment:
  trusted host.

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
it held; see [Run and orchestrate](@/agents/run.md).

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
