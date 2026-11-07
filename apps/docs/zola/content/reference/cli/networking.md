---
title: Networking
description: network, mesh, control and member, and the global --member option for driving an enrolled trusted host.
updated: 2026-11-07
weight: 6
aliases: ["/cli/networking"]
---

Codewire Mesh connects local VMs and trusted hosts; see
[Networking and previews](@/networking/_index.md). Network commands work
on one Mesh at a time:

- `--cloud`: Codewire Cloud Mesh, the hosted Mesh of the platform you are
  signed in to (`mesh.codewire.sh` for codewire.sh; a self-hosted server such
  as a local Kind cluster serves it on its own address). It uses only your
  platform sign-in.
- `--local`: the Local Mesh service that `cw mesh up` runs. It is never used
  for a `--cloud` command, and `--local` never falls back to the cloud.
- `--mesh-url URL` (or `CODEWIRE_MESH_URL`): one exact endpoint; not combined
  with `--cloud` or `--local`.

Without any of them, a command uses the Mesh of the selected network, else
the one Mesh available; when both the local service and the cloud are
available it asks for `--local` or `--cloud`. Every result names the Mesh,
its endpoint and the organization.

## cw network

```sh
cw --cloud network list --org ORG_ID [--output json]                # alias: ls
cw --cloud network create NAME --org ORG_ID [--no-use]              # selects it unless --no-use
cw --cloud network use NAME [--auto-connect]                        # for new environments only
cw network current [--output json]
cw network clear
cw --cloud network nodes --org ORG_ID [--network NAME | --all] [--output json]
cw --cloud network invite --org ORG_ID [--network NAME] [--ttl 1h] [--output json]
cw network join INVITE_CODE --mesh-url URL
cw --cloud network enroll create --org ORG_ID [--network NAME] [--node-name NAME] [--ttl 10m]
cw network enroll redeem ENROLLMENT_CODE --mesh-url URL [--node-name NAME]
cw --cloud network revoke NODE_NAME --org ORG_ID [--network NAME]
cw --cloud network delete NAME --org ORG_ID [--yes]
```

Use `--local` in place of `--cloud` for the local Mesh service, whose
organization is printed by `cw mesh status`.

`network use` saves the Mesh endpoint, the organization that owns new
environments there (your default organization on the cloud; the local
service's own on `--local`) and the network together, after checking the
network exists in that organization. It never searches other organizations
and attaches nothing: existing environments keep their attachments. `create`
selects the new network only in that owner organization. `join` adds you to
a network and prints how to select it.

A local VM joins `--network cloud:NAME` (Codewire Cloud Mesh, even while a
local Mesh service runs), `--network local:NAME` (the local Mesh service), or
a bare `--network NAME` on the selected network's Mesh. Without `--network`
it uses `CODEWIRE_MESH_NETWORK` or the selection; at a terminal `cw create
--local` asks first unless the selection was made with `--auto-connect`, and
`--no-network` opts out.

A cloud environment joins a Codewire Cloud Mesh network with `cw --cloud
create --network cloud:NAME` (or a bare `NAME`). You must be a member of the
network: `create` checks this before anything is created, and Mesh admits
the node only while you remain one. `--network local:NAME` is refused,
because a cloud environment cannot reach a local Mesh service.

The node takes the environment's name and serves its application ports. It
rejoins after every start. It carries no credential of yours: each time it
connects, the platform issues it a code that works once, for that running
environment only.

`cw info` and the create and start results show whether it has joined, for
example `Network: cloud:NAME (attached)`, or why not. A network owner can
remove the node with `cw network revoke`; it then stays out of that network.

Inside such an environment, `cw network connect NODE PORT` opens one TCP
stream to PORT on another member of the same network. NODE is the other
environment's name. The stream is carried on standard input and output, so
it works with tools that take a proxy command:

```sh
printf 'GET / HTTP/1.0\r\n\r\n' | cw network connect app-2 8080
```

A member serves only its own application ports, and members of other
networks are never reachable.

`network nodes` lists enrolled nodes. A node is online while it holds a live
session with the Mesh, and shows offline within 45 seconds of going silent;
LAST SEEN says when the Mesh last heard from it. It does not check
connectivity between members. A network owner can revoke any node; a member
can revoke only a node they enrolled, such as a local VM they attached.
`cw --local rm` revokes a removed VM's node itself; if that fails, it prints
the exact `cw network revoke` command.
Deleting a network retires its name for good
(old connections must never reach a replacement); stop or detach its
environments and revoke its nodes first. Deletion shows the exact Mesh,
endpoint and organization before asking, and reports a saved selection it
could not clear as a partial failure.

## cw mesh

```sh
cw mesh up [--listen 127.0.0.1:18090] [--base-url URL] [--derp-listen 127.0.0.1:18091] [--derp-url URL] [--no-derp]
cw mesh status
cw mesh down
```

Runs a standalone Codewire Mesh service, with a managed local DERP relay
unless `--no-derp`, for a setup that does not use the hosted one. It is a
service to operate on with `--local`, not a way to attach this machine to a
hosted network. `cw mesh status` shows the local service's state and
organization, the selected network and its Mesh, and the default Mesh, apart
from connectivity, which it does not check. `cw mesh down` stops the service
and forgets its endpoint; its organization stays for the next `cw mesh up`.

The installed `cw` runs the service and its relay itself, on Linux and macOS
alike; the `--binary` and `--derp-binary` options that named separate programs
were removed. A Mesh service started by an earlier `cw` is not stopped by this
one: `cw mesh status` shows it as `unknown`, and `cw mesh up` and `down` name
its processes and the record to remove once you have stopped them yourself.

## Trusted host members (Linux)

A trusted host environment (`cw create --local --type host`) can be
enrolled in a Mesh network and driven from another Linux machine. This is
delegated control over your own machines, not sharing with other accounts:
every grant names the exact caller and target keys.

```sh
# On the host:
cw control info --environment HOST
cw control grant --environment HOST --grant-id UUID --org ORG --network NET \
  --caller-key HEX --target-key HEX --allow read,launch,input,stop,managed-launch,managed-message \
  --expected-book-revision N --expected-grant-revision 0
cw control list --environment HOST
cw control revoke --environment HOST --grant-id UUID --expected-book-revision N --expected-grant-revision N
cw member up HOST --mesh-url URL --org ORG --network NET --enrollment-stdin    # one-use enrollment from stdin
cw member status
cw member down

# On the controlling machine:
cw member identity                        # this machine's control_key and wg_key
cw member add NAME --mesh-url URL --org ORG --network NET --environment UUID --node NODE \
  --target-key HEX --target-wg-key HEX --grant-id UUID --grant-revision N [--derp-only] [--require-transport direct_udp|derp]
cw member info NAME [--expect-transport direct_udp|derp] [--path-timeout 15s]
cw member observe NAME REQUEST_ID
```

Grant verbs: `read`, `launch`, `input`, `stop`, `managed-launch`,
`managed-message`, `managed-steer`, `managed-interrupt`, `managed-stop`,
`managed-restart`, `managed-read`.

## The --member option

```sh
cw --member NAME run --name lead --agent codex --detach --prompt '...'
cw --member NAME ls
cw --member NAME msg session-UUID 'text'
cw --member NAME wait --message MESSAGE_ID --timeout 10m
cw --member NAME stop --session session-UUID --request-id UUID --expected-launch-generation N
cw member observe NAME REQUEST_UUID
```

`--member` applies to `run`, `ls`, `send`, `logs`, `wait`, `stop`,
`restart`, `msg`, `steer`, `interrupt` and `inbox`. Sessions are addressed
by canonical `session-UUID` IDs, with `--session` for `stop`, `restart` and
`logs`, which never act on the whole environment under `--member`; an
environment named alongside must be the pinned one, and `--local` or `--cloud`
is refused; command runs need `--no-tty`; attaching is
unsupported; `--request-id` and `--expected-launch-generation` make a control
operation observable after a lost reply. Under `--member`, `wait --session`
reports only the session's final state and exit code; read its output with
`logs --session`. Member control exists on Linux only:
macOS offers no public way to find a session's processes after their parent
exits, so on a Mac run sessions in a local VM instead.

## Guided network selection

At an interactive terminal, `cw network create` asks for a missing network
name and owner organization, then reviews the Mesh and ownership before
creation. `cw network use` without a name offers the networks belonging to
the selected Mesh owner. An empty list explains how to create one.
Noninteractive calls require the name and any required `--org` explicitly.
