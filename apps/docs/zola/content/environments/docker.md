---
title: Docker inside an environment
description: Every hosted sandbox and local VM runs its own Docker daemon, so agents and builds can use containers without touching your machine's Docker.
updated: 2026-11-19
weight: 7
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
| `--no-docker` | no Docker daemon and no root for the workload, for an image without Docker tooling or a confined workload |

`cw info app` shows the disk as `Docker: 8Gi`. An image without Docker
tooling fails to create with `create_guest_docker_tooling_missing` until you
pass `--no-docker`.

## Root inside a local VM

In a local VM, Docker is on by default and the workload's user is in the
`docker` group. So anything running in the environment, an agent included,
can start a privileged container and act as root inside the VM. In a real run,
the workload's user (`uid=1000(codewire)`) could not read `/etc/shadow`, but a
container it started had every capability and entered the VM's init process
as root:

```sh
cw run --in app --no-tty -- docker run --rm --privileged --pid=host alpine \
  nsenter -t 1 -m -u -i -n -p -- sh -c 'id -u; cat /proc/1/comm'
```

```text
0
init
```

`sudo` gives the same user root more directly, without a password, as in a
hosted sandbox: `sudo apt-get install` works.

The VM is still the boundary. Root inside it reaches the VM's own disks and
the folders shared into it, such as your project folder, which is mounted live
and can be read and changed; nothing else on your machine. Its network policy is
enforced outside the VM, by the [egress broker](@/networking/egress.md) on your
machine. To keep the workload confined inside the VM, create it with
`--no-docker`; it then has no Docker daemon, no Docker socket and no root:
`sudo` refuses with "no new privileges".

## Ports from containers

A container's published port is a port inside the VM. Publish it from the
environment like any other: `cw ports app --publish 5432` on a local VM, or a
preview URL from a hosted sandbox. See [Ports and preview URLs](@/access/ports.md).

## Related

- [Sandboxes](@/use-cases/sandboxes.md)
- [Security model](@/reference/security.md): Docker inside an environment is a
  daemon inside that VM.
