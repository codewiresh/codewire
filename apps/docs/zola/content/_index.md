---
title: What is Codewire?
description: A Linux VM for every coding agent and developer, on your machine or on ours, driven by one CLI.
template: section.html
sort_by: weight
in_search_index: true
aliases: ["/concepts", "/guides"]
---

Codewire gives you and your coding agents Linux machines to work in. Each
environment is its own VM with its own kernel, your project inside it, Docker,
Claude Code and Codex. Commands and agents keep running when you disconnect.
The same `cw` command runs one on your own machine for free, or on the
Codewire platform where it stays up and is reachable from anywhere.

{% aside(kind="note") %}
  If you are an agent, fetch [/docs/llms-full.txt](/docs/llms-full.txt): the
  whole documentation as one Markdown file. Every page is also Markdown at its
  URL plus `.md`, and [/docs/llms.txt](/docs/llms.txt) lists them all.
{% end %}

## Try it

```sh
curl -fsSL https://get.codewire.sh | sh     # install cw
cw setup --local                            # install the local VM runtime
cw create --local --name my-app --path .    # a VM with this folder mounted live
cw run claude --in my-app                   # Claude Code in the VM; Ctrl-B, then D detaches
```

The [Quickstart](@/quickstart.md) walks through it with the output of every
step, then does the same on the platform.

## What people use it for

{{ card_grid(
  titles=["Development sandboxes", "Preview environments", "Coding agents", "Personal assistants", "Sandboxes", "Agentic collaboration"],
  hrefs=["/docs/use-cases/development-sandboxes", "/docs/use-cases/preview-environments", "/docs/use-cases/coding-agents", "/docs/use-cases/personal-assistants", "/docs/use-cases/sandboxes", "/docs/use-cases/agentic-collaboration"],
  descriptions=["An environment per project that is the same on every machine, local or hosted for a team.", "A sandbox per branch with its own HTTPS preview URL that deletes itself.", "One agent per VM, a lead and workers, results you read later.", "An agent that stays up with your project and answers your messages.", "Code you do not trust yet, with a copy of your project and no credentials.", "Agents across environments and machines on one private Mesh network."]
) }}


## Why a VM for each environment

- **The agent cannot reach your machine.** An agent runs whatever it writes
  and whatever its dependencies pull in. In a VM that code has its own
  kernel, so the hypervisor is the boundary, not your user account or a
  shared kernel.
- **Your keys stay out.** API keys, GitHub access and SSH keys stay outside
  the VM. The agent gets a placeholder; a broker adds the real key to each
  request and redacts it from the response. The
  [security model](@/reference/security.md) lists the two sign-in tokens that
  are the exception.
- **Your machine stays clean.** Toolchains, `node_modules`, databases and
  Docker images live in the VM. Remove it and they are gone.
- **Run as many as you need.** One VM per agent, per branch or per pull
  request, each with its own files, processes and ports.

## How it compares

| | Agent on your own machine | Containers | Codewire |
| --- | --- | --- | --- |
| Isolation | none: the agent runs as you | a shared host kernel | its own kernel per environment |
| Your files and keys | all readable | whatever you mount | your project only; credentials brokered |
| Docker inside | your own Docker | needs a privileged container | a Docker daemon in every VM |
| Close the terminal | the agent stops, unless you use tmux | depends on your setup | sessions keep running; reattach anywhere |
| Where it runs | your machine | your machine or a server | your machine, or the platform with preview URLs and SSH |

Hosted development environments are mostly built for a person in an editor.
Codewire is built for agents that run unattended: a VM boundary, durable
sessions, managed agent conversations, and the same commands on your machine
and hosted.

## What you get

- **Durable sessions.** Every command and agent runs in a session that belongs
  to the environment. Detach, close the laptop, reattach from another
  terminal. See [Agents](@/agents/_index.md).
- **Claude Code and Codex built in.** `cw run claude` opens Claude Code in the
  VM. Managed conversations add a lead and workers, queued tasks and recorded
  results. See [Run and orchestrate](@/agents/run.md).
- **Your project, live.** `--path .` mounts your folder in a local VM;
  `--repo` clones a repository into a hosted sandbox. See
  [`codewire.yaml`](@/environments/codewire-yaml.md).
- **Ports and previews.** Publish a port on `127.0.0.1` from a local VM, or
  as an HTTPS preview URL from a hosted sandbox. See
  [Ports and preview URLs](@/access/ports.md).
- **SSH, VS Code and files.** `ssh`, `scp`, VS Code Remote and a browser
  terminal. See [Access](@/access/_index.md).
- **Secrets and credentials.** Application secrets delivered as environment
  variables, provider credentials kept outside. See
  [Credentials](@/secrets/credentials.md) and
  [Application secrets](@/secrets/application-secrets.md).
- **Private networks.** Environments and your own machines on one encrypted
  Mesh network. See [Mesh networks](@/networking/mesh.md).
- **Teams.** Organizations, members, shared presets and secrets. See
  [Members and sharing](@/organizations/members.md).

## Where it runs

| Placement | Where it runs | Isolation | Account |
| --- | --- | --- | --- |
| Local VM | your Linux x86_64 machine or Apple Silicon Mac | Cloud Hypervisor on KVM; Virtualization.framework on macOS | none |
| Hosted sandbox | the Codewire platform | one VM per environment | an organization; [billed per second](@/organizations/usage.md) |
| Trusted host session | your machine, as your own user | none: process ownership only | none |

See [Environments](@/environments/_index.md#where-it-runs) for what each one supports, and the
[security model](@/reference/security.md) for what each one protects.

## How the documentation is organized

Each section is one part of Codewire, and each topic has one page, whether a
person or an agent uses it.

- [Quickstart](@/quickstart.md) and [Install and sign in](@/install.md).
- [Use cases](@/use-cases/_index.md): recipes from start to finish.
- [Environments](@/environments/_index.md): what an environment is, how to
  describe it, its size, image and lifecycle.
- [Access](@/access/_index.md): terminals, SSH and VS Code, Git, files and
  ports.
- [Agents](@/agents/_index.md): managed Claude Code and Codex conversations,
  messages and skills.
- [Secrets and credentials](@/secrets/_index.md): provider credentials and
  application secrets.
- [Networking](@/networking/_index.md): Mesh networks and egress policies.
- [Organizations](@/organizations/_index.md): accounts, members, API keys and
  usage.
- [Reference](@/reference/_index.md): the CLI, `codewire.yaml` keys, statuses,
  the security model, troubleshooting, and the
  [documentation for agents](@/reference/for-agents.md).

## Status

Codewire is pre-1.0. Breaking changes can land between releases. The source
is open under AGPL-3.0-only.
