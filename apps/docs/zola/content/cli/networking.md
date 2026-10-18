---
title: Networking
description: network, mesh, control and member, and the global --member option for driving an enrolled trusted host.
weight: 5
---

Codewire Mesh connects local VMs and trusted hosts; see
[Networking and previews](@/concepts/networking.md). Hosted Mesh at
`mesh.codewire.sh` is used when you are signed in; `--mesh-url` or
`CODEWIRE_MESH_URL` points at a standalone service.

## cw network

```sh
cw network list --org ORG_ID [--mesh-url URL] [--output json]      # alias: ls
cw network create NAME --org ORG_ID [--no-use]                      # selects it unless --no-use
cw network use NAME [--auto-connect]                                # local selection only
cw network current
cw network clear
cw network nodes --org ORG_ID [--network NAME | --all] [--output json]
cw network invite --org ORG_ID [--network NAME] [--ttl 1h] [--output json]
cw network join INVITE_CODE [--mesh-url URL]                        # becomes the selected network
cw network enroll create --org ORG_ID [--network NAME] [--node-name NAME] [--ttl 10m]
cw network enroll redeem ENROLLMENT_CODE [--node-name NAME]
cw network revoke NODE_NAME --org ORG_ID [--network NAME]
cw network delete NAME --org ORG_ID [--yes]
```

A local VM joins the network given by `--network`, `CODEWIRE_MESH_NETWORK` or
the selection from `network use`; at a terminal `cw env create --local` asks
first unless the selection was made with `--auto-connect`, and `--no-network`
opts out. Deleting a network retires its name for good (old connections must
never reach a replacement); stop or detach its environments and revoke its
nodes first.

## cw mesh

```sh
cw mesh up [--listen 127.0.0.1:18090] [--base-url URL] [--derp-listen 127.0.0.1:18091] [--derp-url URL] [--no-derp]
           [--binary PATH] [--derp-binary PATH]
cw mesh status
cw mesh down
```

Runs a standalone Codewire Mesh service, with a managed local DERP relay
unless `--no-derp`, for a setup that does not use the hosted one.

## Trusted host members (Linux)

A trusted host environment (`cw env create --local --type host`) can be
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
cw --member NAME list
cw --member NAME msg session-UUID 'text'
cw --member NAME wait --message MESSAGE_ID --timeout 10m
cw --member NAME stop session-UUID --request-id UUID --expected-launch-generation N
cw member observe NAME REQUEST_UUID
```

`--member` applies to `run`, `list`, `send`, `logs`, `wait`, `stop`,
`restart`, `msg`, `steer`, `interrupt` and `inbox`. Sessions are addressed
by canonical `session-UUID` IDs; command runs need `--no-tty`; attaching is
unsupported; `--request-id` and `--expected-launch-generation` make a control
operation observable after a lost reply. Member control exists on Linux only:
macOS offers no public way to find a session's processes after their parent
exits, so on a Mac run sessions in a local VM instead.
