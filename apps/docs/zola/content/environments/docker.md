---
title: Docker inside an environment
description: Every hosted sandbox and local VM runs its own Docker daemon, so agents and builds can use containers without touching your machine's Docker.
updated: 2026-10-27
weight: 6
aliases: ["/guides/docker"]
---

Each environment has its own Docker daemon, inside the VM. Containers you or
an agent start run there, with their own images and volumes; your machine's
Docker socket is never mounted into an environment.

The output below is from a real run in a local VM named `app`.

## Run a container

```sh
cw run --in app --name hello --no-tty -- docker run --rm hello-world
```

```text
✓ Started session app/hello · local VM
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
4f55086f7dd0: Pull complete
Digest: sha256:11a3eb1597e864c51b3f56733cb2e8a90bf0c284bfc05f9444d81c558bc848aa
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.
```

Use Docker as you would on any Linux machine: `docker compose up` in a
session, `docker build` in your project folder, databases for tests.

A hosted sandbox is ready as soon as you can connect to it, and its Docker
daemon finishes starting a moment later. A `docker` command run before then,
or an install command or startup script, waits up to a minute for Docker
instead of failing.

## Disk and opting out

On a local VM, Docker's images and volumes live on a separate data disk:

| Flag on `cw create --local` | Meaning |
| --- | --- |
| `--docker-disk SIZE` | the data disk, 8 GiB by default |
| `--no-docker` | no Docker daemon, for an image without Docker tooling |

`cw info app` shows the disk as `Docker: 8Gi`. An image without Docker
tooling fails to create with `create_guest_docker_tooling_missing` until you
pass `--no-docker`.

## Ports from containers

A container's published port is a port inside the VM. Publish it from the
environment like any other: `cw ports app --publish 5432` on a local VM, or a
preview URL from a hosted sandbox. See [Ports and preview URLs](@/access/ports.md).

## Related

- [Sandboxes](@/use-cases/sandboxes.md)
- [Security model](@/reference/security.md): Docker inside an environment is a
  daemon inside that VM.
