---
title: Configuration
description: CLI configuration, local environment state, and environment variables.
---

Platform identity and organization selection are stored in
`~/.config/cw/config.json` by default. Set `CW_CONFIG_DIR` to use another
platform configuration directory.

Local environment and Mesh client state live under `~/.codewire/`:

```text
~/.codewire/
├── config.toml
├── local_instances.toml
├── mesh_runtime.json
└── codewire-mesh.log
```

`local_instances.toml` contains local lifecycle metadata and the managed
per-environment daemon endpoint/token. The directory and file are hardened and
the token is not printed by normal CLI output.

Session records and output live inside the selected environment. There is no
host-owned session database.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `CODEWIRE_SERVER_URL` | Platform server override |
| `CODEWIRE_API_KEY` | Machine authentication for the platform |
| `CW_CONFIG_DIR` | Platform configuration directory |
| `CODEWIRE_MESH_URL` | Mesh base URL override |
| `CODEWIRE_MESH_AUTH_TOKEN` | Organization-scoped `cw_` API key for a standalone Mesh client |
| `CODEWIRE_MESH_NETWORK` | Selected Mesh network |

Browser users authenticate with `cw login` through the system browser. Local
daemon credentials are managed internally and are not supplied through these
variables.

## Inspect

```bash
cw config inspect
cw config inspect --output json
cw current
cw current --verbose
```

Global `--server` and `--token` flags override the platform target for one
invocation.
