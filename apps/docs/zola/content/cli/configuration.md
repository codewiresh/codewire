---
title: Configuration
description: Where cw keeps its files and which environment variables it reads.
weight: 8
---

## Files

| Path | Contents |
| --- | --- |
| `~/.config/cw/config.json` | Platform server URL and default organization (`CW_CONFIG_DIR` changes the directory) |
| `~/.config/cw/credentials.json` | Your platform sign-in |
| `~/.codewire/config.toml` | The local Mesh service's endpoint and identity, the current `cw use` target, the local credential store kind |
| `~/.codewire/network_selection.json` | The network new environments join, with its Mesh endpoint and organization (`cw network use`) |
| `~/.codewire/native-v1/` | Local VM state, disks and logs |
| `~/.codewire/credentials-v1/` | Local credential records (material is in the Secret Service or Keychain) |
| `~/.cache/codewire/local-vmm-v1/` | The pinned local VM runtime |
| `~/.local/share/codewire/cli/` | The managed `cw` version store; `~/.local/bin/cw` links into it |
| `~/.ssh/config` | The managed `# ---- START CODEWIRE ----` block written by `cw setup ssh` |

Session records and output live inside each environment; there is no
host-side session database.

```sh
cw config inspect --output json
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `CODEWIRE_SERVER_URL` | Platform server; `--server` overrides it. It must match the saved server unless an API key is used |
| `CODEWIRE_API_KEY` | A `cw_` API key instead of the saved sign-in; it acts in its organization |
| `CW_CONFIG_DIR` | Platform configuration directory (default `~/.config/cw`) |
| `CW_MESH_DATA_DIR` | Local state directory (default `~/.codewire`); must be an absolute path |
| `CODEWIRE_MESH_URL` | One exact Mesh endpoint for network commands without `--cloud` or `--local`, like `--mesh-url` |
| `CODEWIRE_MESH_AUTH_TOKEN` | Bearer token for an explicit Mesh endpoint (`--mesh-url` or `CODEWIRE_MESH_URL`) |
| `CODEWIRE_MESH_NETWORK` | The Mesh network to use, over the saved selection |
| `XDG_DATA_HOME`, `XDG_BIN_HOME` | Managed install store and entry directories |
| `SHELL` | Used by `cw completion --install` and `cw doctor` |

Diagnostics for the hosted transport (`cw shell`, `ssh`):

| Variable | Effect |
| --- | --- |
| `CW_DEBUG_TAILNET` | Print a transport timeline on stderr |
| `CW_SSH_TRANSPORT` | `auto` (default), `tailnet` or `websocket` |
| `CW_DERP_ONLY` | Force the DERP relay |
| `CW_TAILNET_DIRECT_WAIT`, `CW_TAILNET_PEER_TIMEOUT`, `CW_TAILNET_DIAL_TIMEOUT` | Timing overrides (defaults 2 s, 10 s, 20 s) |

Inside an environment, a managed conversation launched on a trusted host sees
`CW_ENVIRONMENT` and `CW_SESSION_ID`.
