---
title: Codewire Mesh
description: Manage Mesh networks and environment-owned node inventory.
---

Mesh supplies private connectivity for Codewire environments. Environment
daemons own runtime participation; the CLI manages user networks, enrollment,
and inventory.

## Hosted network

```bash
cw login
cw network create project-alpha --org ORG_ID
cw network use project-alpha
cw network nodes --org ORG_ID
```

Invite another user:

```bash
cw network invite --org ORG_ID --ttl 1h
cw network join <invite-code>
```

Create a short-lived environment enrollment:

```bash
cw network enroll create --org ORG_ID --node-name dev-1 --ttl 10m
cw network enroll redeem <enrollment-code> --node-name dev-1
```

The supervised environment daemon consumes its provisioned enrollment. No
standalone CLI node process is started.

## Inventory

```bash
cw network nodes --org ORG_ID
cw network nodes --org ORG_ID --network project-alpha
cw network nodes --org ORG_ID --all --output json
```

This is inventory only. Sessions remain addressed by separate environment and
session arguments.

## Delete a network

Only a network owner can delete it. First stop or detach its environments and
revoke every remaining registered node, including offline nodes:

```bash
cw network nodes --org ORG_ID --network project-alpha
cw network revoke dev-1 --org ORG_ID --network project-alpha
cw network delete project-alpha --org ORG_ID
```

Deletion asks you to type the network name. Use `--yes` in scripts. It removes
the network and its invitations, enrollments, groups, policies, stored values,
access grants and task history. It does not delete environments or revoke nodes
automatically. A matching local selection is cleared after successful deletion.

Deleted names cannot be reused: old connections and capabilities must never
reach a replacement network. Create a network with a new name instead.

## Local Mesh service

The optional `cw mesh` family manages a local `codewire-mesh` service:

```bash
cw mesh up
cw mesh status
cw mesh down
```

Point network commands at a standalone service with `--mesh-url` or
`CODEWIRE_MESH_URL`.

## Transport

SSH and other peer traffic use the supported transport ladder: direct UDP,
relay UDP, DERP, then the platform WebSocket fallback where applicable.
