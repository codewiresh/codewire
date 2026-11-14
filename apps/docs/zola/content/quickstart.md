---
title: Quickstart
description: Install cw, sign in, add an SSH key and a secret, launch a sandbox, open a server in it through a preview URL, and stop it; then the same in a VM on your own machine.
updated: 2026-11-14
weight: 5
aliases: ["/getting-started", "/getting-started/install", "/getting-started/local-vm", "/getting-started/hosted-sandbox"]
---

In about ten minutes you install `cw`, sign in, add an SSH key and a secret,
launch a sandbox on the Codewire platform, run a server in it, open the server
in your browser, and clean up. The last section does the same in a VM on your
own machine, with no account.

| To use | You need |
| --- | --- |
| A hosted sandbox | a Codewire [account and organization](@/organizations/account.md) |
| A local VM | an x86_64 Linux machine with KVM, or an Apple Silicon Mac on macOS 26 or later |

The output below is from real runs; your IDs, organization and preview domain
will differ.

## 1. Install cw

```sh
curl -fsSL https://get.codewire.sh | sh
```

```text
==> Installed cw v0.4.19 to /home/user/.local/bin/cw
```

The installer downloads the stable release for your platform, checks it
against the release's `SHA256SUMS` and installs a managed `cw` that
`cw upgrade` keeps current. If it prints `NOTE: add ... to your PATH`, add
`~/.local/bin` to your `PATH`. See [Install and sign in](@/install.md).

## 2. Sign in

```sh
cw setup
```

`cw setup` opens your browser to sign in, shows a code to confirm there, and
saves your default organization, offering to create one if you have none. It
also writes the SSH configuration that `ssh` and your editor use to reach your
sandboxes. `cw whoami` shows who you are signed in as.

## 3. Add a credential

A provider credential is a key or sign-in that a tool uses, such as a model API
key or an SSH key. Codewire keeps it outside every sandbox and uses it on the
sandbox's behalf. Start with an SSH key:

```sh
cw credentials --cloud generate ssh --name my-key
```

```text
9f4dbf33-2fcd-4049-97d7-a54f94024771  "my-key"  ssh  active  revision 1
  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINViKs7x1MGMhO20b4YPkuS1y6m9AX4DlM6BYfSe/Pu7
  SHA256:nJ2EuAARU4gU4AO3DRH6WE7H9l1tE3Xs4Goldxbnl+8
Add the public key above to GitHub: https://github.com/settings/ssh/new
```

Add the public key to your Git host. Then put the key in a credential profile,
the set of credentials a sandbox gets:

```sh
cw credentials --cloud --profile me set ssh my-key
```

The first `set` creates the profile. Your first profile becomes your default,
and every sandbox you create without naming a profile uses it. Model API keys,
your GitHub connection and agent sign-ins are added the same way; see
[Credentials](@/secrets/credentials.md).

## 4. Add a secret

An application secret is a value your own code reads, such as `DATABASE_URL`.
Store one in your personal scope:

```sh
cw secrets --cloud --user set GREETING
```

`cw` asks for the value without showing it, or reads it from standard input:

```text
Secret GREETING set.
```

Lists show only the key, never the value. See
[Application secrets](@/secrets/application-secrets.md) for organization and
project secrets.

## 5. Launch a sandbox

Run this from your project folder or an empty one: `cw create` reads the
nearest `codewire.yaml`, if there is one.

```sh
cw create --name hello --image workspace --user-secrets platform
```

`cw` lists the secrets and the credential profile it will select and asks you
to confirm (`--yes` skips the question in scripts). Then it names each stage as
it starts:

```text
hello · cloud VM
  2 vCPU · 8 GiB RAM · 80 GiB disk

  Credentials: platform:me
  Secrets:     personal secrets (platform)
  Network:     not attached
...
✓ Environment hello created · cloud VM
```

`--user-secrets platform` selects your personal secrets; the profile is your
default. Check that both arrived:

```sh
cw exec --in hello -- sh -c 'echo "$GREETING"'
cw exec --in hello -- ssh-add -l
```

```text
hello from a personal secret
256 SHA256:nJ2EuAARU4gU4AO3DRH6WE7H9l1tE3Xs4Goldxbnl+8 codewire-selected-key (ED25519)
```

The first line is the value you typed. The second is your key's fingerprint,
offered by an agent socket: `git` and `ssh` in the sandbox sign with it, and
the private key never enters the sandbox. `cw exec` runs a command once and
waits for it.

## 6. Run a server and open it

`cw run` starts a command in a *session*: a process that belongs to the sandbox,
not to your terminal, and keeps running when you disconnect.

```sh
cw run --in hello --name web --detach -- python3 -m http.server 3000
```

```text
✓ Started session hello/web · cloud
→ cw --cloud attach hello --session web
```

Publish the port as an HTTPS preview URL:

```sh
cw ports hello --publish 3000 --label web
```

```text
  * Port 3000 registered as web
  URL: https://web-02e72-{organization-slug}.{preview domain}
  Access: creator
```

Open the URL in the browser you signed in with. `creator` means only you can
open it; `--access org_members` or `--access public` widens that, and
`cw ports hello --unpublish 3000` takes it down. See
[Ports and preview URLs](@/access/ports.md).

## 7. See what is running

```sh
cw ls
cw ls hello
```

```text
  NAME   LOCATION  STATE    SESSIONS  NETWORK
  hello  cloud     running  1         —

NAME  STATE    MODE    PARENT  SESSION                                       COMMAND
web   Running  normal  -       session-b0b40691-65f6-4dbf-8cdf-2c73275d9aed  python3 -m http.server 3000
```

`cw logs hello --session web` shows a session's output, and
`cw attach hello --session web` reconnects to it.

## 8. Stop and remove

```sh
cw stop hello
```

```text
✓ Environment hello stopped
  cloud VM

→ cw --cloud start hello
```

Stopping ends every session and releases the compute; the disk stays, and
`cw start hello` brings the sandbox back. Running compute is
[billed per second](@/organizations/usage.md). When you are done:

```sh
cw rm hello
```

```text
✓ Removal started: hello
  cloud VM · state: destroying
```

`cw rm` asks before it deletes the sandbox and its disk; `--yes` skips the
question in scripts.

## 9. The same on your own machine

A local VM needs no account. Install its runtime once:

```sh
cw setup --local
```

```text
Downloading the local VM runtime (6 files, 186 MiB)...
Local VM runtime installed (e818b56a224a).
```

Your `cw` release pins the exact hypervisor, guest kernel and guest files it
runs; setup checks each one and does nothing the next time. It also checks the
host and names every unmet requirement with its fix, such as joining the `kvm`
group; the list is in
[Troubleshooting](@/reference/troubleshooting.md#host-requirements).

Create a VM with your project folder mounted live:

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
  App secrets  none
  Policy       open
  Ports        none
  Guest root can read, change and delete files in the mounted directory.
Create with these settings?
› Create environment
  Edit settings
  Cancel
```

Press Enter. The first create downloads the workspace image, which takes a
minute or two. You and the VM edit the same files; dependency and build folders
(`node_modules`, `target`, `.venv`) stay on the VM's own disk.

The same session and port commands work. A local VM has no public address, so
a published port opens on your machine's `127.0.0.1`:

```sh
cw run --in my-app --name web --detach -- python3 -m http.server 3000
cw ports my-app --publish 3000
```

```text
Published http://127.0.0.1:3000 -> my-app:3000
my-app publishes:
  127.0.0.1:3000 -> 3000
```

Credentials and secrets for a local VM can live on your machine instead:
`cw credentials --local` and `cw secrets --local --user` keep them in the Secret
Service on Linux or the Keychain on macOS, and `--profile local:NAME` and
`--user-secrets local` select them. `cw stop my-app` and `cw rm my-app` work as
above; `cw rm` deletes the VM and its disks, never your project folder.

## Next

- [Run and orchestrate](@/agents/run.md): `cw run claude --in hello` opens
  Claude Code in a session, and `cw run codex` opens Codex. Managed
  conversations add a lead and workers, tasks and results.
- [`codewire.yaml`](@/environments/codewire-yaml.md): put the image,
  repositories, secrets, setup and ports in a file.
- [SSH, VS Code and files](@/access/ssh-and-vscode.md): `ssh cw-cloud-hello`
  and `cw vscode hello` work from any device after `cw setup`.
- [Environments](@/environments/_index.md#where-it-runs): what a hosted sandbox,
  a local VM and a trusted host session each give you.

## FAQ

**Do I need an account?** Not for a local VM or a trusted host session. A
hosted sandbox needs an account and an organization.

**Why did `cw create` pick up settings I didn't pass?** It reads the nearest
`codewire.yaml`, searching up to the root of the Git repository you are in.
Run it from an empty folder, or pass `--file`, to choose.

**Do I need to know Kubernetes?** No. The platform runs the infrastructure;
you create an environment and use it.
