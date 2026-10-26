---
title: Environment to environment
description: Reach an application port on another member of the same Mesh network from inside an environment, with cw network connect.
updated: 2026-10-26
weight: 2
---

Members of the same [Mesh network](@/networking/mesh.md) reach each other's
application ports; members of other networks are never reachable. A member
serves only its own application ports.

Inside an environment, `cw network connect NODE PORT` opens one TCP stream to
a port on another member of the same network, on standard input and output:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | cw network connect api 8080
```

`cw network connect` works anywhere a tool takes a proxy command, so an agent
in one environment can test a service in another, call a tool another agent
runs, or reach a database a teammate runs in their local VM.

## Related

- [Agentic collaboration](@/use-cases/agentic-collaboration.md)
- [CLI: networking](@/reference/cli/networking.md)
