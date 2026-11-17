---
title: Quickstart
description: Give your agent a setup prompt, or install cw, create a sandbox, and run a TanStack Router and Vite app yourself.
updated: 2026-11-17
weight: 5
aliases: ["/getting-started", "/getting-started/install", "/getting-started/local-vm", "/getting-started/hosted-sandbox"]
---

Run a real app inside a sandbox, then open it in your browser. Start with a
prompt for your agent, or follow the human walkthrough below.

## Start with your agent

### On your machine

{% agent_prompt() %}
Read https://codewire.sh/docs/quickstart.md. Help me run https://github.com/codewiresh/example in a local Codewire VM. Check host requirements, existing names and codewire.yaml first. Install cw and its local runtime if needed. Show me the mounted folder and create settings before proceeding. The public example needs no credentials: use --no-profile. Install and build inside the VM, start the dev server in a named session on port 3000, publish the port, and verify the counter, navigation and route refresh. Return the local URL. Ask before deleting the VM's disk.
{% end %}

### In the cloud

{% agent_prompt() %}
Read https://codewire.sh/docs/quickstart.md. Help me run https://github.com/codewiresh/example in a hosted Codewire sandbox. Install cw if needed and pause for browser sign-in. Check existing names and configuration, then show me the create settings. The public repository needs no credentials: use --no-profile. Install and build inside the sandbox, start the dev server in a named session on port 3000, and publish a creator-only preview. Verify the app and return its preview URL. Never print credential or secret values. Ask before deleting the sandbox's disk.
{% end %}

## Do it yourself: local VM

You need x86_64 Linux with KVM, or an Apple Silicon Mac on macOS 26 or later.
A local VM needs no Codewire account. Node.js and npm come with the workspace
image; you don't need them on your own machine.

The [example repository](https://github.com/codewiresh/example) is a small
React, TanStack Router and Vite app. Its counter and two pages let you check
that interaction, navigation and refresh work through a published port.

### 1. Install cw

```sh
curl -fsSL https://get.codewire.sh | sh
cw version
cw setup --local
```

The installer verifies the release checksum and installs a managed `cw` that
`cw upgrade` keeps current. If it asks you to add `~/.local/bin` to your `PATH`,
do that before continuing. See [Install and sign in](@/install.md).

`cw setup --local` checks your machine and installs the pinned VM runtime.
It names unmet requirements with their fixes, such as joining the `kvm` group.
The first download can take a few minutes; subsequent runs check that the
runtime is ready.

### 2. Add a credential when you need private Git access

**Skip this step for the public example.** A provider credential is a key or
sign-in that a tool uses. Codewire keeps it outside the VM and uses it on the
VM's behalf. For your own private repository, generate an SSH key and put it
in a local credential profile:

```sh
cw credentials --local generate ssh --name quickstart-key
cw credentials --local --profile quickstart set ssh quickstart-key
```

Add the **public** key printed by the first command to your Git host. The
second command creates a profile: the set of credentials a VM can use.
Use fresh names if these already exist. The private key remains in your
machine's protected store; Git and SSH in the VM sign through an agent socket.

When creating a VM for that private project, use `--profile local:quickstart`
instead of `--no-profile`. See [Credentials](@/secrets/credentials.md).
Application secrets such as `DATABASE_URL` are separate; this example needs
none. See [Application secrets](@/secrets/application-secrets.md).

### 3. Get the example and create a VM

```sh
git clone https://github.com/codewiresh/example.git
cd example
cw create --local --name hello --path . --no-profile
```

Review the mounted folder, image, resources and credential selection before
confirming. The repository's `codewire.yaml` selects the workspace image.
The public example needs no Git credential, and `--no-profile` avoids
selecting an existing default profile.

Wait for `hello` to be running. Your project is mounted live at
`/workspace/example`: you and the VM edit the same files. Dependency and
build folders stay on the VM's own disk. The VM can change files in this
mounted folder, so only mount a project you intend it to work on.

If `hello` already exists, choose another name and use it throughout the
remaining commands. `cw ls --local` lists your existing VMs.

### 4. Build and start the server

Install and build **inside the VM**:

```sh
cw exec --local --in hello -- npm ci
cw exec --local --in hello -- npm run build
```

`cw exec` waits for the command and returns its exit status. The build checks
TypeScript and produces the app's production assets; fix any build error
before continuing.

Start Vite in a named session, then read its output:

```sh
cw run --local --in hello --name web --detach -- npm run dev
cw logs --local hello --session web
```

The example's dev command listens on all interfaces at port 3000. Its
`--strictPort` setting makes a second server fail rather than quietly choose
another port. A `cw run` session survives a terminal disconnect. You can also
run `cw exec --local --in hello -- npm run dev` in the foreground; closing
that connection ends the server.

### 5. Open the app

```sh
cw ports --local hello --publish 3000
```

Open `http://127.0.0.1:3000`. The heading says **Hello from Codewire.** Click
the counter, visit **How it works**, and refresh that page. All three should
work. Edit `src/main.tsx` in your project folder to see Vite update the page.

A local published port listens on your machine's loopback address. If port
3000 is occupied, choose a different host binding:

```sh
cw ports --local hello --publish 3000 --host-port 3001
```

Then open `http://127.0.0.1:3001`. See [Ports and preview URLs](@/access/ports.md).

### 6. Stop and clean up

```sh
cw stop --local hello
```

Stopping ends the sessions and keeps the VM's disk. To return later:

```sh
cw start --local hello
cw run --local --in hello --name web-again --detach -- npm run dev
```

The port mapping is retained, so open the same URL. Session names are unique
within a VM, including exited sessions; choose a fresh name when starting
another dev server. `cw ls --local hello` lists sessions and `cw logs --local
hello --session web-again` reads their output.

When you no longer need the VM:

```sh
cw rm --local hello
```

Codewire asks before removing the VM and its disks. Your mounted project
folder stays on your machine.

## Do it yourself: hosted sandbox {#2-sign-in}

A hosted sandbox needs a Codewire [account and organization](@/organizations/account.md).
Use the same CLI installer above, then sign in:

```sh
cw setup
cw whoami
```

`cw setup` opens a browser for sign-in and saves your default organization.
Check that `cw whoami` names the account and organization you intend to use.

### Create the sandbox

Run from an empty folder so there is no project configuration to inherit:

```sh
cw create --cloud --name hello --image workspace \
  --repo https://github.com/codewiresh/example.git --no-profile --no-file
```

Review the image, repository and resources before confirming. The public
repository needs no credential. For a private repository, generate an SSH
key with `cw credentials --cloud generate ssh --name quickstart-key`, add its
public key to your Git host, and put it in a profile with `cw credentials
--cloud --profile quickstart set ssh quickstart-key`. Then select
`--profile platform:quickstart` instead of `--no-profile`.

### Build and run inside the sandbox

The repository is checked out at `/workspace/example`:

```sh
cw exec --cloud --in hello -w /workspace/example -- npm ci
cw exec --cloud --in hello -w /workspace/example -- npm run build
cw run --cloud --in hello -w /workspace/example \
  --name web --detach -- npm run dev
cw logs --cloud hello --session web
```

Wait for Vite to report that it is listening on port 3000. Then publish it:

```sh
cw ports --cloud hello --publish 3000 --label web --access creator
```

Open the HTTPS URL Codewire prints in the browser you signed in with. Check
the counter, navigation and page refresh, as in the local walkthrough.
`creator` means only you can open the preview. A signed-out request is
refused. Keep that access for this walkthrough; see
[Ports and preview URLs](@/access/ports.md) for sharing.

### Stop and remove

```sh
cw stop --cloud hello
```

Stopping ends sessions and releases compute while keeping the disk. Running
compute is [billed per second](@/organizations/usage.md). To return later,
run `cw start --cloud hello` and start a dev session with a fresh name.

When you no longer need the sandbox:

```sh
cw rm --cloud hello
```

Codewire asks before deleting the sandbox and its disk.

## Next

- [Run and orchestrate](@/agents/run.md): run Claude Code, Codex and other agents in sessions.
- [`codewire.yaml`](@/environments/codewire-yaml.md): keep image, repository, setup and port settings in a file.
- [SSH, VS Code and files](@/access/ssh-and-vscode.md): connect your terminal or editor.

## FAQ

**Do I need an account?** A local VM needs no account. A hosted sandbox needs
an account and an organization.

**Why did create pick up settings I didn't pass?** It reads the nearest
`codewire.yaml`, searching up to the root of your Git repository. Review the
configuration it names; `--file` selects a file and `--no-file` uses flags only.

**Do I need Node.js on my machine?** No. The workspace image supplies Node.js
and npm, and the install, build and server commands run inside the VM or
hosted sandbox.
