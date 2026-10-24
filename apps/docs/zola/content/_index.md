---
title: What is Codewire?
description: Isolated development environments for developers and AI coding agents.
template: section.html
sort_by: weight
in_search_index: true
---

Codewire gives a developer or an AI coding agent its own development machine:
a Linux environment with persistent storage, durable terminal and agent
sessions, Docker, and access over SSH, a browser terminal, file transfer and
preview URLs.

Each environment runs in its own hardware-virtualized VM with its own kernel.
Agents run untrusted code, whatever they generate and whatever dependency they
pull, so the hypervisor boundary is the security boundary.

{% aside(kind="note") %}
  If you are an agent, fetch [/docs/llms-full.txt](/docs/llms-full.txt): the
  whole documentation as one Markdown file. Every page is also Markdown at its
  URL plus `.md`, and [/docs/llms.txt](/docs/llms.txt) lists them all.
{% end %}

## One CLI, three placements

The same `cw` command drives every environment, wherever it runs.

| Placement | Where it runs | Isolation |
| --- | --- | --- |
| Hosted sandbox | the Codewire platform | one VM per environment |
| Local VM | your Linux or Apple Silicon machine | Cloud Hypervisor on KVM; Virtualization.framework on macOS |
| Trusted host session | your machine, as your own user | process ownership only, no containment |

A local VM needs no account. A hosted sandbox adds organizations, members,
billing, preview URLs and remote access.

## Try it

```sh
curl -fsSL https://get.codewire.sh | sh    # install cw
cw setup --local                           # install the local VM runtime
cw create --local --name my-app --path .
cw shell my-app                            # a shell in the VM
cw run claude --in my-app                  # Claude Code in the VM; Ctrl-B, then D detaches
```

{{ card_grid(
  titles=["Install the CLI", "Your first local VM", "Your first hosted sandbox", "CLI reference"],
  hrefs=["/docs/getting-started/install", "/docs/getting-started/local-vm", "/docs/getting-started/hosted-sandbox", "/docs/cli"],
  descriptions=["One command installs a managed cw that updates itself.", "Run an environment on your own machine, no account needed.", "Sign in, create a sandbox on the platform and run an agent in it.", "Every command, grouped the way cw --help groups them."]
) }}

## How the documentation is organized

- [Get started](@/getting-started/_index.md): install, then the first local VM
  and the first hosted sandbox.
- [Concepts](@/concepts/_index.md): environments, placements, sessions and
  agents, secrets and credentials, networking, organizations.
- [Guides](@/guides/_index.md): one task per page, grouped by what you are
  working on.
- [CLI reference](@/cli/_index.md): every command and flag.
- [Reference](@/reference/_index.md): environment statuses, plans, the
  [security model](@/reference/security.md), FAQ, and the
  [documentation for agents](@/reference/for-agents.md).

## Status

Codewire is pre-1.0. Breaking changes can land between releases. The source
is open under AGPL-3.0-only.
