---
title: Overview
description: Install the Codewire CLI and use its environment-first model.
---

The Rust `cw` CLI creates Codewire environments and manages durable sessions
owned by those environments. Native local and platform placements use the same
session commands.

## Install

During the private preview, build or install the CLI from an authorized source
checkout:

```bash
make cli-build
make cli-install
```

## Local environment

```bash
cw env create --local \
  --name my-app \
  --image workspace \
  --path .

cw run my-app -- cargo test
cw list my-app
cw logs my-app <session-id>
cw attach my-app <session-id>
```

On Linux, the local supervisor runs each environment as a native VM. The
workspace image is the supported local runtime image; the retired full image is
not used.

## Platform environment

```bash
cw setup
cw env create --name my-app --image workspace
cw run my-app -- cargo test
cw shell my-app
```

`cw use my-app` selects either kind of environment so later session commands
can omit the environment argument.

## One runtime owner

The supervised daemon inside each environment owns its sessions and optional
Mesh participation. The CLI does not run a second host-owned node, process
server, messaging service, or MCP session server.

See [Sessions](@/cli/sessions.md), [Platform commands](@/cli/platform.md),
[Mesh](@/cli/mesh.md), and [Configuration](@/cli/configuration.md).
