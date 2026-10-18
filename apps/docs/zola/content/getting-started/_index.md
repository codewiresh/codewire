+++
title = "Get started"
description = "Install cw, then run your first environment on your own machine or on the platform."
weight = 10
sort_by = "weight"
+++

Four short pages. The first two need no account.

{{ card_grid(
  titles=["Install the CLI", "Your first local VM", "Your first hosted sandbox", "Account and organization"],
  hrefs=["/docs/getting-started/install", "/docs/getting-started/local-vm", "/docs/getting-started/hosted-sandbox", "/docs/getting-started/account"],
  descriptions=["One command installs a managed cw; cw update keeps it current.", "A VM on your Linux or Apple Silicon machine, with a shell and durable sessions.", "Sign in, create a sandbox on the platform and run a managed agent in it.", "Request access, set up two-factor authentication and create an organization."]
) }}

## What you need

| To use | You need |
| --- | --- |
| A local VM | an x86_64 Linux machine with KVM, or an Apple Silicon Mac on macOS 26 or later |
| A trusted host session | Linux or macOS |
| A hosted sandbox | a Codewire account and an organization |
| Managed agents (Codex, Claude Code) | a credential profile with a provider credential for the agent |

Everything else is one `curl` away.
