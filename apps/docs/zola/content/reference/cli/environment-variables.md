---
title: Environment variables
description: "Every environment variable cw reads: the server and API key, configuration and state directories, Mesh, output, and transport diagnostics."
updated: 2026-10-26
weight: 10
---

## Server, sign-in and state

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

## Output

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Any non-empty value turns colour off; progress still shows |
| `CODEWIRE_REDUCED_MOTION` | Any value other than empty or `0` replaces spinners with steady progress lines |
| `TERM=dumb` | No live redraw, no colour, ASCII only |
| `LC_ALL`, `LC_CTYPE`, `LANG` | A non-UTF-8 locale, including `C` and `POSIX`, switches output to ASCII |

`--output json` turns progress, colour and prompts off whatever these say.

## Hosted transport diagnostics

For `cw shell` and `ssh`:

| Variable | Effect |
| --- | --- |
| `CW_DEBUG_TAILNET` | Print a transport timeline on stderr |
| `CW_SSH_TRANSPORT` | `auto` (default), `tailnet` or `websocket` |
| `CW_DERP_ONLY` | Force the DERP relay |
| `CW_TAILNET_DIRECT_WAIT`, `CW_TAILNET_PEER_TIMEOUT`, `CW_TAILNET_DIAL_TIMEOUT` | Timing overrides (defaults 2 s, 10 s, 20 s) |

## Inside an environment

A managed conversation launched on a trusted host sees `CW_ENVIRONMENT` and
`CW_SESSION_ID`, so it can launch its own workers with
`cw run --in "$CW_ENVIRONMENT" --parent "$CW_SESSION_ID"`.

## Related

- [API keys](@/organizations/api-keys.md): `CODEWIRE_API_KEY` in scripts and
  CI.
- [Configuration](@/reference/cli/configuration.md): where `cw` keeps its
  files.
