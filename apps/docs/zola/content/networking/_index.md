---
title: Networking
description: How you reach an environment, how environments reach each other over Codewire Mesh, and what an environment may reach on the Internet.
weight: 60
sort_by: weight
aliases: ["/concepts/networking"]
---

Networking covers three directions:

- **You to an environment.** `cw shell`, SSH, VS Code and the dashboard
  terminal reach an environment over an encrypted tunnel, described below.
  Application ports are published separately; see
  [Ports and preview URLs](@/access/ports.md).
- **Environment to environment.** Codewire Mesh puts environments, and your
  own machines, on a private network where members reach each other's
  application ports and nothing else can. See
  [Mesh networks](@/networking/mesh.md) and
  [Environment to environment](@/networking/environment-to-environment.md).
- **Environment to the Internet.** A network policy decides what an
  environment may reach. See [Egress policies](@/networking/egress.md).

## Reaching a hosted environment

```text
cw / OpenSSH / VS Code
  -> WireGuard tunnel to the daemon's SSH server (port 2222 inside the VM)
       direct UDP -> shared UDP relay -> DERP (TCP)
  -> WebSocket SSH proxy through the platform (last resort)
dashboard terminal -> platform -> daemon
```

`cw shell`, `ssh cw-ENV`, `scp`, `sftp`, `rsync` and VS Code all take the
first path that works. `cw setup ssh` (run by `cw setup`) writes an OpenSSH
block whose `KnownHostsCommand` asks the platform for the environment's
recorded host key, so there is no trust-on-first-use. `cw doctor tailnet ENV`
shows which transport you got and why.
