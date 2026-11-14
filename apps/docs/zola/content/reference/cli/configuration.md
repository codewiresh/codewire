---
title: Configuration
description: Where cw keeps its files and which environment variables it reads.
updated: 2026-11-14
weight: 9
aliases: ["/cli/configuration"]
---

## Files

| Path | Contents |
| --- | --- |
| `~/.config/cw/config.json` | Platform server URL and default organization (`CW_CONFIG_DIR` changes the directory) |
| `~/.config/cw/credentials.json` | Your platform sign-in |
| `~/.codewire/config.toml` | The local Mesh service's endpoint and identity, the current `cw use` target in the form earlier releases read, the local credential store kind |
| `~/.codewire/current-environment.toml` | The current environment `cw use` selected: its location, canonical ID, name and, for a cloud environment, organization |
| `~/.codewire/network_selection.json` | The network new environments join, with its Mesh endpoint and organization (`cw network use`) |
| `~/.codewire/native-v1/` | Local VM state, disks and logs |
| `~/.codewire/credentials-v1/` | Local credential records (material is in the Secret Service or Keychain) |
| `~/.cache/codewire/local-vmm-v1/` | The pinned local VM runtime |
| `~/.local/share/codewire/cli/` | The managed `cw` version store; `~/.local/bin/cw` links into it |
| `~/.ssh/config` | The managed `# ---- START CODEWIRE ----` block written by `cw setup ssh` |
| `~/.config/rex/init.lua`, `~/.config/rex/plugins/codewire/` | The managed `-- >>> codewire >>>` block and the plugin it loads, written by `cw setup rex` (`REX_CONFIG` moves both) |

Session records and output live inside each environment; there is no
host-side session database.

```sh
cw config inspect --output json
```

## Environment variables

Every variable `cw` reads is in
[Environment variables](@/reference/cli/environment-variables.md).

## Guided preset and policy creation

At an interactive terminal, `cw preset create` asks for a missing slug and
image. Optional settings are available through **Edit optional settings**;
review the organization, image and resource defaults before creation.
`cw --local policy create` asks for a missing name, offers `locked` or an
existing policy as its base, and lets you enter allowed destinations. Targets
without a port allow ports 22, 80 and 443. The review shows the base and added
rules. Policies are stored on this computer; cloud policy storage is not yet
available. Supplied arguments skip their questions. Noninteractive and JSON
calls require explicit inputs and never open a menu.
