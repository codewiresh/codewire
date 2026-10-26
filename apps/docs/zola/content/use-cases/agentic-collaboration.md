---
title: Agentic collaboration
description: Put agents and services in different environments, and on your own machines, on one private Mesh network, hosted by Codewire or run by you.
updated: 2026-10-26
weight: 6
---

Let agents work together across environments: a lead in one sandbox, the
service it tests in another, a worker on your own Linux machine, a teammate's
local VM. Codewire Mesh puts them on one private network, so they reach each
other's ports without a public address, and nothing outside the network can.

## Choose a Mesh

- **Codewire Cloud Mesh, hosted.** Nothing to run. It uses your Codewire
  sign-in, and hosted sandboxes and local VMs can both join. Commands reach it
  with `--cloud`.
- **Your own Mesh.** `cw mesh up` runs a standalone Mesh service, with its own
  DERP relay, on a machine you control, and a self-hosted Codewire server
  serves one at its own address. Local VMs and trusted hosts join it; hosted
  sandboxes cannot, because they cannot reach a Mesh on your network. Commands
  reach it with `--local`, or `--mesh-url URL` names one endpoint exactly.

See [Mesh networks](@/networking/mesh.md#who-joins) for how
a network admits its members.

## 1. Create a network

```sh
cw --cloud network create docs-collab --org ORG_ID
```

```text
✓ Network docs-collab created
  Mesh          Codewire Cloud Mesh
  Endpoint      {mesh endpoint}
  Organization  ORG_ID
```

`cw --cloud network list --org ORG_ID` lists your networks. `cw network
invite` and `cw network join` add other members. Deleting a network retires
its name for good.

## 2. Put environments on it

```sh
cw --cloud create --name api --image workspace --network cloud:docs-collab
cw --cloud create --name lead --image workspace --network cloud:docs-collab --profile platform:agents-dev
cw --local create --name laptop --path . --network cloud:docs-collab
```

Each joins as a node named after the environment, and rejoins after every
start. `cw info api` shows whether it joined, for example `Network:
cloud:docs-collab (attached)`. A hosted sandbox's node carries no credential
of yours.

## 3. Reach one from another

Start a service in `api`:

```sh
cw run --in api --name server --detach -- python3 -m http.server 8000
```

From inside `lead`, `cw network connect` opens one TCP stream to a port on
another member, on standard input and output, so it works anywhere a tool
takes a proxy command:

```sh
cw run --in lead --name probe --no-tty -- sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | cw network connect api 8000 | head -1'
```

An agent in `lead` can do the same while it works: test the service in
`api`, call a tool another agent runs, or reach a database a teammate runs in
their local VM. A member serves only its own application ports, and members
of other networks are never reachable.

## 4. Drive agents on your own machine

On Linux, a trusted host session on one of your machines can be enrolled as
a member that another of your machines controls. The grant names the exact
caller and target, and which actions it allows:

```sh
cw --member build-box run --name worker --agent codex --detach --prompt 'Run the slow integration suite and report failures.'
cw --member build-box ls
```

See [CLI: networking](@/reference/cli/networking.md#trusted-host-members-linux) for
enrollment and grants.

## Run your own Mesh

```sh
cw mesh up                                   # the service and a DERP relay on this machine
cw --local network create team               # a network on it
cw --local create --name app --path . --network local:team
cw mesh status
cw mesh down
```

`--listen` and `--base-url` put the service where other machines can reach
it. A hosted sandbox refuses `--network local:NAME`.

## Related

- [Coding agents](@/use-cases/coding-agents.md): a lead and workers in one
  environment.
- [Networking](@/networking/_index.md)
- [CLI: networking](@/reference/cli/networking.md)
