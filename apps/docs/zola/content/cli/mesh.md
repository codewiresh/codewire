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
cw network create project-alpha
cw network use project-alpha
cw network nodes
```

Invite another user:

```bash
cw network invite --ttl 1h
cw network join <invite-token>
```

Create a short-lived environment enrollment:

```bash
cw network enroll create --node-name dev-1 --ttl 10m
cw network enroll redeem <enrollment-token> --node-name dev-1
```

The supervised environment daemon consumes its provisioned enrollment. No
standalone CLI node process is started.

## Inventory

```bash
cw network nodes
cw network nodes --network project-alpha
cw network nodes --all --output json
```

This is inventory only. Sessions remain addressed by separate environment and
session arguments.

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
