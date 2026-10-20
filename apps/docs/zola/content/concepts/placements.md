---
title: Placements
description: Hosted sandbox, local VM and trusted host session, and what each one gives you.
weight: 2
---

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

## Hosted sandbox

The platform schedules one VM per environment (Kata Containers with Cloud
Hypervisor) holding a workspace container and a guest-local Docker daemon.
The workspace runs your image with persistent storage and starts the daemon,
which binds to the platform, serves SSH and joins the tailnet. The platform
meters running compute per second and bills the organization.

You reach it with `cw shell`, `ssh`, VS Code and the dashboard terminal, and
expose applications through preview URLs. Agents use credentials through a
platform broker; secrets and credentials are selected from the organization's
and your own stores.

## Local VM

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

## Trusted host session

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
`cw --member`; see [Networking](@/cli/networking.md). Removing a host
environment deletes only Codewire's records and keeps the project directory.

## Choosing

- Code you do not trust yet, parallel agents, previews for a team: hosted
  sandbox.
- Your laptop, no account, fast file access to a checkout you are editing:
  local VM.
- The host's own hardware, tools or logins, and you accept no containment:
  trusted host.
