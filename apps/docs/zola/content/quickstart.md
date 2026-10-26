---
title: Quickstart
description: Install cw, run your project in a VM on your own machine, start Claude Code in it, open a dev server, then do the same on the platform.
updated: 2026-10-26
weight: 5
aliases: ["/getting-started", "/getting-started/install", "/getting-started/local-vm", "/getting-started/hosted-sandbox"]
---

In about ten minutes you install `cw`, run your project in a VM on your own
machine, start Claude Code in it, open a dev server from the VM in your
browser, and clean up. The local part needs no account. The last section does
the same on the Codewire platform.

| To use | You need |
| --- | --- |
| A local VM | an x86_64 Linux machine with KVM, or an Apple Silicon Mac on macOS 26 or later |
| A hosted sandbox | a Codewire [account and organization](@/organizations/account.md) |

## 1. Install cw

```sh
curl -fsSL https://get.codewire.sh | sh
```

```text
==> Installed cw v0.4.1 to /home/user/.local/bin/cw
```

The installer downloads the stable release for your platform, checks it
against the release's `SHA256SUMS` and installs a managed `cw` that
`cw upgrade` keeps current. If it prints `NOTE: add ... to your PATH`, add
`~/.local/bin` to your `PATH`. See [Install and sign in](@/install.md).

## 2. Install the local VM runtime

```sh
cw setup --local
```

```text
Downloading the local VM runtime (6 files, 186 MiB)...
Local VM runtime installed (e818b56a224a).
```

Your `cw` release pins the exact hypervisor, guest kernel and guest files it
runs. Setup downloads those, checks each one, and does nothing the next time.

{% aside(kind="tip") %}
  `cw setup --local` and `cw create --local` check the host first and name
  every unmet requirement with its fix, such as joining the `kvm` group. The
  full list is in [Troubleshooting](@/reference/troubleshooting.md#host-requirements).
{% end %}

## 3. Create a VM for your project

From your project directory:

```sh
cd my-app
cw create --local --name my-app --path .
```

`cw` shows what it will create and asks before it starts:

```text
Create a local sandbox
  Name         my-app
  Config       flags only, no codewire.yaml found; default workspace image
  Workspace    mount ~/my-app at /workspace/my-app (live, read-write)
               Kept in the VM: node_modules, target, .venv
  Image        Codewire workspace (default)
  Resources    2 vCPU · 4 GiB RAM · 20 GiB disk
  Docker       on (8 GiB data disk)
  Credentials  none
  Ports        none
  Guest root can read, change and delete files in the mounted directory.
Create with these settings? [Y]es / [e]dit / [n]o: y
```

Press Enter. The first create downloads the workspace image, which takes a
minute or two; one line names each stage as it runs:

```text
  ✓ Preparing sources  0.0s
  ✓ Checking the VM runtime  1.2s
  ✓ Checking credential access  0.0s
  ✓ Preparing the workspace disk  0.0s
  ✓ Pulling the image  1m 27s
  ✓ Starting the VM runner  0.2s
  ✓ Starting the VM  1m 16s
  ✓ Booting the workspace  1.8s
✓ Environment my-app created · local VM
  2 vCPU · 4 GiB RAM · 20 GiB disk
→ cw --local run claude --in my-app
```

Your folder is mounted live: you and the VM edit the same files. Dependency
and build folders (`node_modules`, `target`, `.venv`) live on the VM's own
disk instead, so the mount stays fast and your machine stays clean. The
workspace image has Python, Node.js, Rust, Go, Git, Docker, Claude Code and
Codex. A failed create leaves nothing behind.

`cw` prints the next command to run after most steps, as on the last line
above.

## 4. Run a command in the VM

```sh
cw run --in my-app --no-tty -- ls /workspace/my-app
```

```text
✓ Started session my-app/ls · local VM
index.html
node_modules
target
```

Everything after `--` runs in a *session*: a process that belongs to the
environment, not to your terminal, with its output saved. For an
interactive shell, run `cw shell my-app`.

To stop typing `--in my-app`, select it once:

```sh
cw use my-app
```

```text
✓ Current environment: my-app
  local VM · running
```

## 5. Start Claude Code

```sh
cw run claude --in my-app
```

```text
✓ Started Claude Code in my-app/claude · local VM
  Detach: Ctrl-B, then D · Reconnect: cw --local attach my-app --session claude
```

Claude Code opens in the VM, in your project folder. The first time, it asks
you to pick a theme and sign in, as it does on your own machine. `cw run codex`
starts Codex the same way.

Press **Ctrl-B**, then **D**, to detach. Claude Code keeps working in the VM
after you close the terminal. Come back to it with:

```sh
cw attach my-app --session claude
```

To have Codewire hold the provider credentials instead, so they never enter
the VM, see [Credentials](@/secrets/credentials.md).

## 6. Run a server and open it

Start a server in a detached session:

```sh
cw run --in my-app --name web --detach -- python3 -m http.server 3000
cw logs my-app --session web
```

```text
✓ Started session my-app/web · local VM
Serving HTTP on 0.0.0.0 port 3000 (http://0.0.0.0:3000/) ...
```

A local VM has no public address. Publish the port on your machine:

```sh
cw ports my-app --publish 3000
```

```text
Published http://127.0.0.1:3000 -> my-app:3000
my-app publishes:
  127.0.0.1:3000 -> 3000
```

Open [http://127.0.0.1:3000](http://127.0.0.1:3000) and you see your
project's `index.html`, served from inside the VM.

## 7. See what is running

```sh
cw ls
```

```text
  NAME    LOCATION  STATE    SESSIONS  NETWORK
› my-app  local     running  3         —
```

```sh
cw ls my-app
```

```text
NAME    STATE    MODE    PARENT  SESSION                                       COMMAND
ls      Exited   normal  -       session-1f0f1127-1be1-49a9-8029-cdd5c4ae86b0  ls /workspace/my-app
claude  Running  normal  -       session-2a5c60a8-65c3-4b25-9b12-25b6edb0590d  claude
web     Running  normal  -       session-9179312a-57f2-4878-badb-8120b2186589  python3 -m http.server 3000
```

`cw logs my-app --session ls` shows a finished session's output again, and
`cw stop my-app --session web` stops one session.

## 8. Stop and remove

```sh
cw stop my-app
```

```text
✓ Environment my-app stopped
  local VM · environment disk retained
```

Stopping ends every session and powers the VM off; its disks and published
ports stay. `cw start my-app` boots it again, and you start your sessions
again. When you are done:

```sh
cw rm my-app
```

```text
✓ Environment my-app removed
  local VM · environment disk removed
```

`cw rm` deletes the VM and its disks. Your project folder on your machine is
not touched.

## 9. The same on the platform

A hosted sandbox runs on Codewire's machines instead of yours. It keeps
running when your laptop sleeps, is reachable over SSH and VS Code from any
device, and publishes ports as HTTPS preview URLs. It needs an
[account and an organization](@/organizations/account.md), and running compute is
[billed per second](@/organizations/usage.md).

```sh
cw setup                                   # sign in in your browser, pick an organization
cw create --name my-app --image workspace  # or --repo URL to clone a repository
```

```text
my-app · cloud VM
  2 vCPU · 8 GiB RAM · 10 GiB disk
```

The same session and agent commands work, now against Codewire's machines:

```sh
cw run claude --in my-app
```

```text
✓ Started Claude Code in my-app/claude · cloud
  Detach: Ctrl-B, then D · Reconnect: cw --cloud attach my-app --session claude
```

A port becomes an HTTPS preview URL instead of a port on your machine:

```sh
cw run --in my-app --name web --detach -- python3 -m http.server 3000
cw ports my-app --publish 3000 --label web
```

```text
✓ Started session my-app/web · cloud
  * Port 3000 registered as web
  URL: https://web-cd593-{organization-slug}.{preview domain}
  Access: creator
```

`creator` means only you can open it; `--access org_members` or
`--access public` widens that. Stopping releases the compute and keeps the
storage; it happens in the background:

```sh
cw stop my-app
```

```text
  cloud VM · state: stop requested
```

`cw rm my-app` deletes the sandbox and its storage. `cw setup` also writes
the SSH configuration, so `ssh cw-cloud-my-app` and `cw vscode my-app` work
from any device. The output above is from a real run on a Codewire platform;
your IDs and preview domain will differ.

## Next

- [Run and orchestrate](@/agents/run.md): a lead and workers, tasks and
  results, steering and recovery.
- [`codewire.yaml`](@/environments/codewire-yaml.md): put the image, repositories,
  setup and ports in `codewire.yaml`.
- [SSH, VS Code and files](@/access/ssh-and-vscode.md) and
  [Ports and preview URLs](@/access/ports.md).
- [Environments](@/environments/_index.md#where-it-runs): what a local VM, a hosted sandbox
  and a trusted host session each give you.

## FAQ

**Do I need an account?** Not for a local VM or a trusted host session. A
hosted sandbox needs an account and an organization.

**Do I need to know Kubernetes?** No. The platform runs the infrastructure;
you create an environment and use it.
