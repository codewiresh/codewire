---
title: codewire.yaml
description: Describe an environment once in codewire.yaml so that cw create builds it the same way every time, locally or on the platform.
updated: 2026-10-26
weight: 1
aliases: ["/guides/project-file"]
---

`codewire.yaml` in a project's root describes the environment that project
wants. One file describes the whole environment, including every repository
it clones. Explicit flags override the file.

```sh
cw init                                                   # writes codewire.yaml from the current directory
cw init --image workspace --install 'pnpm install' --startup 'pnpm dev'
cw create --local --name app             # a local VM from the nearest codewire.yaml
cw create --cloud --name app             # the same file, for a cloud environment
cw create --cloud --name app --file codewire.ci.yaml   # another file
cw create --cloud --name app --image workspace --no-file   # flags only
cw create --name app --image workspace --write-preset  # write the resolved preset back
```

## Which file is used

`cw create` looks for `codewire.yaml` in the current directory (`--path`
for `--local`) and then in each parent, up to the root of its Git
repository; outside a Git repository it checks only that directory. The
nearest file wins, and only that file is read: a nested repository's own
`codewire.yaml`, and any file inside a cloned repository, is never merged
in. `--file` selects another file and `--no-file` uses the flags alone.

Before it creates anything, `cw create` names the configuration it uses
(`Configuration: ~/src/app/codewire.yaml`), and `--output json` returns it
as `configuration`. Without `--path`, a file found in a parent folder makes
that folder the local VM's project directory, exactly as if you had run the
command beside the file; the review shows the folder and where you are.

A file that names no `image` or `preset` gets the Codewire workspace image.
Only a cloud create without a file, image or preset uses the defaults the
platform saved for its first repository, and says so.

Starting, restarting or attaching to an existing environment never reads a
file: it keeps the configuration it was created with, even after the file
changes. A new `cw create` reads the file again.

`cw init` refuses to overwrite an existing file without `--force`. Given only
direct inputs (image, commands, resources, variables) it works offline;
resolving a preset, a repository or a branch needs a signed-in platform.

## Save an existing environment

`cw export ENV` writes an environment's saved configuration as `./codewire.yaml`,
the file the next `cw create` in that folder reads. `--file PATH` writes
elsewhere, `--stdout` prints it, and an existing file is kept unless you pass
`--force`. Export only reads: it never starts or changes the environment.

The file holds the repositories with their branch or revision, setup
commands, resources, ports, agents, and secret and credential references as
exact IDs, never their values. Declared `environment` values are left out
and named. The workspace's host folder is reported, never turned into a
repository: create again from that folder to mount it. `local:` references
resolve only on the machine that created them. A cloud environment's
confidential isolation and time to live are create flags, so they are
reported rather than written.

## Example

```yaml
version: 1
image: workspace
working_directory: /workspace/app

repositories:
  - source: https://github.com/owner/app
    branch: main
    destination: app

install_command: pnpm install
startup_script: pnpm dev

environment:
  LOG_LEVEL: info

secrets:
  organization: true
  project: development

credentials:
  profile: platform:work

ports:
  - port: 3000
    label: web
    access: org_members

cpu: "2"
memory: 4Gi
disk: 20Gi

workspace:
  vm_only:
    - node_modules
    - target
    - .venv
```

## Keys

Every key, its type and its limits are in
[codewire.yaml keys](@/reference/codewire-yaml.md). Unknown keys are
rejected, and secret values never belong in the file: `secrets` and
`credentials` select sources by name only.

## Local-only behaviour

Repositories, from the file or from repeatable `--repo
URL[@branch][::/workspace/path]`, are isolated clones that the host's Git
fetches; `--repo` replaces the file's list rather than adding to it, and no
host directory is mounted. `mounts` and `workspace.vm_only` apply to local
VMs, where `--path` is mounted live by default; a cloud create ignores
`workspace.vm_only` and refuses `mounts` and host ports. `cw create --local`
shows the resolved settings and asks before creating.
