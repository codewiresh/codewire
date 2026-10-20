---
title: Your first local VM
description: Run an environment in a VM on your own machine, with a shell and durable sessions, without an account.
weight: 2
---

A local VM runs the same workspace image and the same in-environment daemon as
a hosted sandbox, on your own machine. On Linux it is Cloud Hypervisor on KVM;
on an Apple Silicon Mac it is Virtualization.framework.

## 1. Check the host

**Linux** (x86_64):

- KVM: Intel VT-x or AMD-V enabled, the `kvm_intel` or `kvm_amd` module
  loaded, and your user able to open `/dev/kvm` (usually the `kvm` group).
- `vhost_vsock` loaded, with `/dev/vhost-vsock` readable and writable by you.
- Linux 6.2 or later with Landlock. Ubuntu 22.04 HWE or 24.04, Debian 13 and
  Fedora work; the Debian 12 and Ubuntu 22.04 GA kernels are too old.
- `e2fsprogs` (`mkfs.ext4`, `e2fsck`, `resize2fs`, `debugfs`).
- `git` at `/usr/bin/git`, only to clone a repository into a VM.
- A Secret Service (GNOME Keyring, KWallet) running and unlocked, for local
  credentials and application secrets.
- Your own user: `cw` refuses to run local VMs as root.

**macOS**: an Apple Silicon Mac on macOS 26 or later. The runtime ships its
own `git` and `e2fsprogs`; nothing else is installed.

{% aside(kind="tip") %}
  You do not have to check these yourself. `cw setup --local`,
  `cw create --local` and `cw start --local` check them first and
  name every unmet requirement with its fix.
{% end %}

## 2. Install the VM runtime

```sh
cw setup --local
```

A release's `cw` pins the exact digest of every runtime file (the hypervisor,
the guest kernel and root, and the `cw` that runs inside the VM). Setup
downloads exactly those files into `~/.cache/codewire/local-vmm-v1/`, checks
each one, and prints `Local VM runtime installed (<id>).` Running it again
downloads nothing.

## 3. Create the environment

From your project directory:

```sh
cw create --local --name my-app --path .
```

At a terminal, `cw` shows the name, workspace, image, resources, Docker,
credentials and ports it will use and asks `[Y]es / [e]dit / [n]o`. The
defaults:

| Setting | Default |
| --- | --- |
| CPU, memory, disk | 2 vCPU, 4 GiB, 20 GiB (`--cpu`, `--memory`, `--disk`) |
| Docker data disk | 8 GiB (`--docker-disk`; `--no-docker` for an image without Docker) |
| Image | the Codewire workspace image (`--image` for any OCI image) |
| Workspace | `--path .` mounted live, read-write, at `/workspace/<directory>` |

With the live mount, you and the VM edit the same files. Dependency and build
folders (`node_modules`, `target` and `.venv` by default) live on the VM's
disk instead; see [The project file](@/guides/project-file.md) to change the
list. `--path-mode snapshot|clone|copy|empty` copies the directory once or
starts empty instead of mounting it.

While it works, one line names the current stage (sources, disk, image, VM,
boot). A failed create leaves nothing behind.

## 4. Use it

```sh
cw shell my-app                       # an interactive shell in the VM
cw run claude --in my-app             # Claude Code in the VM (or codex)
cw run --in my-app -- cargo test      # a durable session that streams output
cw run --in my-app --name dev --detach -- npm run dev
cw ls my-app                          # sessions in this environment
cw logs my-app --session dev          # saved output
cw attach my-app --session dev        # reattach; Ctrl-B, then D detaches
```

`cw use my-app` selects the environment so the session commands can omit it.
Sessions belong to the environment and keep running when you close the
terminal. See [Sessions and agents](@/concepts/sessions-and-agents.md).

To reach a server running inside the VM from your browser, publish its port
on `127.0.0.1`:

```sh
cw ports my-app --publish 3000
```

## 5. Stop, start, remove

```sh
cw stop my-app      # SIGTERM to every process, 5 s, then power off
cw start my-app
cw rm my-app        # deletes the VM and its disks; your project directory stays
```

A stopped VM keeps its workspace storage and its disks; `cw start` brings
them back. `cw resize my-app --cpu 4 --memory 8GB` changes resources
(disks grow, never shrink).

## Next

- [Orchestrate agents](@/guides/run-agents.md): a managed Codex or Claude
  conversation in the VM needs a [credential profile](@/guides/credentials.md).
- [Troubleshoot local VMs](@/guides/troubleshoot-local-vms.md) when a
  command names an unmet requirement.
