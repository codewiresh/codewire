---
title: Environments overview
description: Understanding sandbox environments in Codewire
---


Environments are isolated cloud development machines for agents and developers. Each environment belongs to one organization, runs from a repo-aware preset, and exposes terminal, SSH, file, preview, and session access through Codewire.

## What an environment includes

- A sandbox runtime with dedicated CPU, memory, and persistent storage
- Repo configuration, presets, ports, logs, files, exec, SSH, and preview access
- Organization membership and access controls
- Usage metering and billing at the organization level

## Lifecycle

Environments move through a small set of states:

1. **Creating** - Codewire analyzes the repo, prepares the sandbox, and applies the selected preset.
2. **Running** - terminal, SSH, file, preview, and agent sessions are available.
3. **Stopped** - compute is released while persistent data is retained.
4. **Deleting** - Codewire tears down runtime state and related access records.

See [Environment statuses](@/reference/environment-statuses.md) for the full status reference.

## Common tasks

{{ card_grid(
  titles=["Create an environment", "Manage environments", "Connect to an environment"],
  hrefs=["/docs/environments/create-environment", "/docs/environments/manage-environments", "/docs/environments/connect"],
  descriptions=["Launch from a repository with AI-assisted setup.", "Start, stop, delete, and inspect environments.", "Use terminal, SSH, files, previews, and agent sessions."]
) }}
