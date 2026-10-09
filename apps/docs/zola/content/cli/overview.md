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

On Linux, local sandbox environments use a native VM owned by the local
supervisor. An explicit `--local --type host` environment runs as the local
user under its host daemon. The workspace image is the supported sandbox
runtime image; the retired full image is not used.

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

A daemon owns the durable sessions for each environment: an owner-local daemon
for a trusted Linux host, or the provisioned daemon inside a sandbox. Managed
agent drivers handle native protocol messages and worker results. The native
supervisor owns VM lifecycle separately from the guest's session owner.

See [Agent orchestration](@/cli/orchestration.md), [Sessions](@/cli/sessions.md),
[Platform commands](@/cli/platform.md), [Mesh](@/cli/mesh.md), and
[Configuration](@/cli/configuration.md).
