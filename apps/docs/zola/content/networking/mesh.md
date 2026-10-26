---
title: Mesh networks
description: Codewire Mesh, hosted or your own, the networks inside it, and how hosted sandboxes, local VMs and trusted hosts join one.
updated: 2026-10-26
weight: 1
---

Codewire Mesh is a private network for environments and your own machines.
A **network** is a membership scope inside it: members of the same network
can reach each other's application ports, over direct UDP, then a UDP relay,
then DERP. Members of other networks are never reachable.

## Hosted Mesh or your own

You can use the hosted Mesh or run your own, and choose per network:

- **Codewire Cloud Mesh** is the hosted Mesh of the platform you are signed
  in to (`mesh.codewire.sh` for codewire.sh). It uses your Codewire sign-in
  and nothing to operate. Network commands reach it with `--cloud`.
- **Your own Mesh.** `cw mesh up` runs a standalone Mesh service, with its own
  DERP relay, on a machine you control; network commands reach it with
  `--local`. A self-hosted Codewire server serves its own Mesh at its own
  address the same way the hosted platform does. `--mesh-url URL` names any
  one endpoint exactly.

Where an environment runs and which Mesh it joins are independent: a local VM
can join either.

## Who joins

- **A hosted sandbox** joins a Cloud Mesh network when you create it with
  `cw --cloud create --network cloud:NAME`. You must be a member of the
  network. The sandbox's node takes the environment's name and rejoins after
  every start, and it carries no credential of yours.
- **A local VM** joins when a network is chosen at creation: `--network
  cloud:NAME`, `--network local:NAME`, a bare `--network NAME` on the selected
  network's Mesh, `CODEWIRE_MESH_NETWORK`, or the network chosen with
  `cw network use`. Your host owns the Mesh identity; the VM sees only admitted
  streams for its declared ports.
- **A trusted host** (Linux) can be enrolled as a member that another of your
  machines drives with `cw --member`.

```sh
cw --cloud network create team --org ORG_ID          # also selects it
cw --cloud create --name api --image workspace --network cloud:team
cw --local create --name app --path . --network cloud:team
cw --cloud network nodes --org ORG_ID
```

## Run your own Mesh

```sh
cw mesh up                                   # the service and a DERP relay on this machine
cw --local network create team               # a network on it
cw --local create --name app --path . --network local:team
cw mesh status
cw mesh down
```

`--listen` and `--base-url` put the service where other machines can reach
it. A hosted sandbox refuses `--network local:NAME`, because it cannot reach
a Mesh on your network.

## Related

- [Environment to environment](@/networking/environment-to-environment.md):
  reach a port on another member.
- [Agentic collaboration](@/use-cases/agentic-collaboration.md): agents in
  several environments on one network, from start to finish.
- [CLI: networking](@/reference/cli/networking.md)
