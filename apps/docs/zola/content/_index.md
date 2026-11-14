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
curl -fsSL https://get.codewire.sh | sh                  # install cw
cw setup                                                 # sign in in your browser
cw create --name hello --image workspace                 # a sandbox on the platform
cw run --in hello --name web --detach -- python3 -m http.server 3000
cw ports hello --publish 3000                            # an HTTPS preview URL
cw rm hello                                              # when you are done
```

No account? `cw setup --local` and `cw create --local --name hello --path .`
run the same in a VM on your own machine. The [Quickstart](@/quickstart.md)
walks through it with the output of every step, and adds a credential and a
secret on the way.

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

## Where it runs

An environment is a hosted sandbox on the Codewire platform, a local VM on your
Linux x86_64 machine or Apple Silicon Mac, or a trusted host session that runs
as your own user with no isolation. A local VM and a trusted host session need
no account; a hosted sandbox needs an organization and is
[billed per second](@/organizations/usage.md). See
[Environments](@/environments/_index.md#where-it-runs) for what each supports,
and the [security model](@/reference/security.md) for what each protects.

## How the documentation is organized

Each section is one part of Codewire, and each topic has one page, whether a
person or an agent uses it.

- [Quickstart](@/quickstart.md), [Install and sign in](@/install.md) and
  [Update and roll back](@/update.md).
- [Use cases](@/use-cases/_index.md): recipes from start to finish.
- [Environments](@/environments/_index.md): what an environment is, how to
  describe it, its size, image and lifecycle.
- [Access](@/access/_index.md): terminals, SSH and VS Code, Git, files and
  ports.
- [Integrations](@/integrations/_index.md): Codewire in other terminal and
  agent tools.
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
