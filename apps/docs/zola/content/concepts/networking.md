---
title: Networking and previews
description: How cw reaches an environment, how preview URLs and local ports work, and what Codewire Mesh adds.
weight: 5
---

## Reaching a hosted environment

```text
cw / OpenSSH / VS Code
  -> WireGuard tunnel to the daemon's SSH server (port 2222 inside the VM)
       direct UDP -> shared UDP relay -> DERP (TCP)
  -> WebSocket SSH proxy through the platform (last resort)
dashboard terminal -> platform -> daemon
```

`cw shell`, `ssh cw-ENV`, `scp`, `sftp`, `rsync` and VS Code all take the
first path that works. `cw config-ssh` (run by `cw setup`) writes an OpenSSH
block whose `KnownHostsCommand` asks the platform for the environment's
recorded host key, so there is no trust-on-first-use. `cw doctor tailnet ENV`
shows which transport you got and why.

## Preview URLs

A preview is an HTTPS URL that forwards HTTP requests to one application port
inside a hosted environment:

```text
https://{label}-{sandbox-id-prefix}-{organization-slug}.{preview domain}
```

```sh
cw env port add 3000 --label web --access public -e my-app
cw env port list -e my-app
cw env port rm web -e my-app
```

Access is `creator` (default), `org_members` or `public`. A private preview
sends a signed-out browser through the normal sign-in, then returns to the
page; Codewire's own cookies and headers never reach the application, and the
proxy removes the credential it authenticated with. Labels are 2 to 22
lowercase letters, digits or hyphens; port 2222 is reserved for SSH. The
dashboard's **Ports** dialog does the same.

A preview is not a public TCP port. Removing every preview disables this
mechanism only; it is not network isolation for the environment.

## Local VM ports

A local VM has no public address. Publish a guest port on your machine's
loopback:

```sh
cw env port add 3000 --host-port 3000 -e my-app     # 127.0.0.1:3000 -> VM:3000
```

A stopped VM records the change and publishes it at the next start.
`codewire.yaml` can declare the same ports; see
[The project file](@/guides/project-file.md).

## Codewire Mesh

Codewire Mesh is the network control plane for nodes that are not platform
sandboxes: local VMs and trusted hosts. A **network** is a membership scope
inside it; nodes in the same network can discover and reach each other, over
direct UDP, then a UDP relay, then DERP.

A local VM joins Mesh only when a network is selected at creation: with
`--network NAME`, `CODEWIRE_MESH_NETWORK`, or the network chosen with
`cw network use`. Your host owns the Mesh identity; the VM sees only admitted
streams for its declared ports. Hosted Mesh at `mesh.codewire.sh` uses your
Codewire sign-in; `cw mesh up` runs a standalone service for an isolated
setup.

```sh
cw network create team --org ORG_ID     # also selects it
cw env create --local --name app --path . --network team
cw network nodes --org ORG_ID
```

Hosted sandboxes do not join Mesh; they are reached as described above. See [CLI: networking](@/cli/networking.md).

## Docker

A Docker daemon runs inside every hosted sandbox and local VM (`--no-docker`
turns it off for an image without Docker tooling). Containers you start are
inside the same VM; the host's Docker socket is never mounted into an
environment.
