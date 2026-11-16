---
title: Environment to environment
description: Reach an application port on another member of the same Mesh network from inside an environment, with cw network connect.
updated: 2026-11-16
weight: 2
---

Members of the same [Mesh network](@/networking/mesh.md) reach each other's
published ports; members of other networks are never reachable. A member
serves only the ports published with `cw ports`, so publish the port first:

```sh
cw ports api --publish 8000
```

The default access, `creator`, keeps the port's preview URL to you; members
of the network reach the port either way.

Inside an environment, `cw network connect NODE PORT` opens one TCP stream to
a port on another member of the same network, on standard input and output:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | cw network connect api 8000
```

A port that isn't published gives an empty result.

`cw network connect` works anywhere a tool takes a proxy command, so an agent
in one environment can test a service in another, call a tool another agent
runs, or reach a database a teammate runs in their local VM.

## Related

- [Agentic collaboration](@/use-cases/agentic-collaboration.md)
- [CLI: networking](@/reference/cli/networking.md)
