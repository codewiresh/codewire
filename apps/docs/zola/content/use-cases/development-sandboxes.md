---
title: Development sandboxes
description: A development environment per project that is the same on every machine, on your laptop with no account or hosted for a whole team, described once in codewire.yaml or a preset.
updated: 2026-10-26
weight: 1
aliases: ["/use-cases/local-first", "/use-cases/team-workspaces"]
---

Give every project an environment that is the same for everyone: the image,
the install command, the resources and the folders that stay off your
machine. Start on your laptop with no account. When a team needs the same
thing hosted, describe it once as a preset and everyone creates from it.

The output below is from real runs: the local part on Linux with no account,
the team part on a Codewire platform. Your IDs will differ.

## On your machine, no account

Everything about local environments works without signing up: VMs,
sessions, agents with your own logins, ports and `codewire.yaml`. No
Codewire server is involved; `cw` downloads only its VM runtime and the
workspace image.

### Describe it once

Put a `codewire.yaml` in the project's root:

```yaml
version: 1
install_command: python3 -m venv .venv
```

The install command runs once, when the environment is created. `.venv` is
one of the folders that live on the VM's disk instead of your machine, so
the virtual environment never mixes with your host's Python. See
[`codewire.yaml`](@/environments/codewire-yaml.md) for repositories, resources,
environment variables and agents.

### Create it on your machine

```sh
cw create --local --name notes
```

```text
Create a local sandbox
  Name         notes
  Config       ~/notes/codewire.yaml; default workspace image
  Workspace    mount ~/notes at /workspace/notes (live, read-write)
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

```text
✓ Environment notes created · local VM
```

`cw create` finds the nearest `codewire.yaml` and names it on the `Config`
line. Anyone who clones the project gets the same environment with the same
command.

```sh
cw run --in notes --no-tty -- sh -c 'pwd; .venv/bin/python --version'
```

```text
✓ Started session notes/sh · local VM
/workspace/notes
Python 3.12.3
```

### Or skip the VM

When you want your own tools and your own logins rather than isolation, a
trusted host session runs as you, in your folder:

```sh
cw create --local --type host --name notes-host --path .
cw run --in notes-host --no-tty -- sh -c 'whoami; pwd'
```

```text
notes-host	host	running	/home/user/notes
✓ Started session notes-host/sh · host
you
/home/user/notes
```

Sessions, logs, `cw attach` and managed agents work the same way, with your
own installed Claude Code or Codex.

{% aside(kind="caution") %}
  A trusted host session has no containment. An agent in it can read and
  change anything you can. Use a VM for anything you would not run yourself.
{% end %}

### See both

```sh
cw ls
```

```text
  NAME        LOCATION  STATE    SESSIONS  NETWORK
  notes       local     running  1         —
  notes-host  host      running  1         —

  NETWORK is the saved attachment
  Cloud environments are not listed: no Codewire server is set up (`cw login`)
```

The last line is the only sign that an account exists: without one, `cw`
lists your local environments and tells you cloud ones were skipped.

## For a team, hosted

### Create a preset for the team

```sh
cw preset create team-web --name 'Team web' --image workspace \
  --install 'python3 --version' --ttl 2h --description 'Workspace image for the web team'
```

```text
Preset created: Team web.
  ID:    d3dbefb6-881a-4225-b4f8-ac05ace76ddd
```

A preset belongs to the organization, so every member sees it in
`cw preset list` and in the dashboard's **Create Sandbox** form. It records
the image, install and startup commands, resources and lifetime. Remove it
with `cw preset rm ID`.

### Everyone creates from it

```sh
cw create --name ana-web --preset team-web --repo https://github.com/octocat/Hello-World
```

```text
ana-web · cloud VM
  2 vCPU · 8 GiB RAM · 80 GiB disk
  ✓ Cloning repositories  2s
  ✓ Running install command  0s
  ✓ scheduled shutdown after ttl 7200s
  ✓ Setup complete
✓ Environment ana-web created · cloud VM
```

The preset supplied the install command and the two-hour lifetime. Each
person's sandbox is their own: separate files, sessions and credentials.
A `codewire.yaml` in the repository does the same job without a preset;
see [`codewire.yaml`](@/environments/codewire-yaml.md).

### Invite people and share a sandbox

```sh
cw org invite ana@example.com --role member   # prints the invitation link once
cw share list ana-web
cw share grant ana-web --user USER_ID --permission operator   # viewer by default
cw share revoke ana-web --user USER_ID
```

`cw share list ana-web` lists each user who can use the sandbox, with their
permission (`owner`, `operator` or `viewer`), who granted it and when. A new
sandbox lists only you, as `owner`.

See [Members and sharing](@/organizations/members.md) for roles and what each
permission lets a teammate do, and [Usage and costs](@/organizations/usage.md)
for what members cost.

## Related

- [Quickstart](@/quickstart.md)
- [`codewire.yaml`](@/environments/codewire-yaml.md) and [Presets](@/environments/presets.md)
- [Environments](@/environments/_index.md#where-it-runs): what a hosted
  sandbox, a local VM and a trusted host session each give you.
- [Members and sharing](@/organizations/members.md)
