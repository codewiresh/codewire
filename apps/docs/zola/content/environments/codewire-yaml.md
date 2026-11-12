---
title: codewire.yaml
description: Describe an environment once in codewire.yaml so that cw create builds it the same way every time, locally or on the platform.
updated: 2026-11-11
weight: 1
aliases: ["/guides/project-file"]
---

`codewire.yaml` in a project's root describes the environment that project
wants. One file describes the whole environment, including every repository
it clones. An optional `codewire.local.yaml` beside it holds your own settings
for local VMs, and explicit flags override both.

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
nearest file wins: a nested repository's own `codewire.yaml`, and any file
inside a cloned repository, is never merged in. `--file` selects another
file and `--no-file` uses the flags alone.

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

## Override files

A local create also reads `codewire.local.yaml` from the folder of the
`codewire.yaml` it found, and merges it over that file. Use it for settings
that are yours or only make sense on your machine: a `local:` credential
profile, more CPU or memory, extra environment variables, `mounts`, host
ports. A cloud create never reads it, and its review says so. Most projects
keep it out of Git; `--no-local-file` skips it for one create.

```yaml
# codewire.local.yaml
credentials:
  profile: local:work
memory: "16Gi"
environment:
  LOG_LEVEL: debug
```

Repeat `--file` to merge files you name, in order, for variants such as CI
or a GPU machine. Named files replace the search, so `codewire.local.yaml`
is read only if you name it:

```sh
cw create --cloud --name ci --file codewire.yaml --file codewire.ci.yaml
```

Files merge the same way however they are chosen:

- mappings merge by key, at any depth (`environment`, `secrets`, `agents`,
  `workspace`);
- a later value or list replaces the earlier one whole, so a variant that
  changes `repositories`, `ports` or `mounts` restates the list;
- `key: null` in a later file removes the key, such as `cpu: null` or
  `LOG_LEVEL: null` under `environment`.

Each file must be valid YAML with known keys and value types on its own,
but only the merged result must be a complete, valid environment. A
relative `mounts` source resolves from the folder of the file that declares
it. The review before creating lists every file it merged
(`Configuration: ~/src/app/codewire.yaml + codewire.local.yaml`), and
`--output json` lists them under `configuration.files`.

## Save an existing environment

`cw export ENV` writes an environment's saved configuration as `./codewire.yaml`,
the file the next `cw create` in that folder reads. It writes one file with
the merged result; it does not split it back into override files. `--file PATH` writes
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

## Repositories inside a repository

A repository's `destination` may lie inside another's, for a root repository
that holds others:

```yaml
repositories:
  - source: https://github.com/your-org/platform.git
    destination: /workspace/platform
  - source: https://github.com/your-org/web.git
    destination: /workspace/platform/web
```

Codewire clones the outer repository first, then the ones inside it, and
adds each inner path to the outer checkout's `.git/info/exclude`, so its
`git status` shows only its own files. A path the outer repository's commit
tracks, or a file on the way to it, fails the create and is named. `mounts`
cannot nest with repositories or each other.

The outer repository may be `/workspace` itself, so the workspace is that
checkout:

```yaml
repositories:
  - source: https://github.com/your-org/platform.git
    destination: /workspace
  - source: https://github.com/your-org/web.git
    destination: /workspace/web
```

`/workspace` must start empty for this. A local VM's always does, and with
`--path-mode mount` the folder is mounted at `/workspace` itself. A cloud
environment's does on the standard tier where the deployment mounts only the
disk's `workspace/` folder there; elsewhere, and on the confidential tier for
now, the create is refused (`workspace_root_repository_unavailable`) before
anything starts. Codewire never removes or empties `/workspace` to make room.

## Keys

Every key, its type and its limits are in
[codewire.yaml keys](@/reference/codewire-yaml.md). Unknown keys are
rejected, and secret values never belong in the file: `secrets` and
`credentials` select sources by name only.

## Local-only behaviour

Repositories, from the file or from repeatable `--repo
URL[@branch][::/workspace/path]`, are isolated clones that the host's Git
fetches; `--repo` replaces the file's list rather than adding to it, and no
host directory is mounted unless you ask for your own checkouts (below). `mounts` and `workspace.vm_only` apply to local
VMs, where `--path` is mounted live by default; a cloud create ignores
`workspace.vm_only` and refuses `mounts` and host ports. `cw create --local`
shows the resolved settings and asks before creating.

### Mount a folder as /workspace itself

A live (`direct`) mount may be `/workspace` itself, so the folder is the whole
workspace rather than a folder inside it:

```yaml
mounts:
  - source: .
    destination: /workspace
    mode: direct
    read_only: false
```

It must be the environment's only workspace source: no `repositories` and no
other `mounts`. `workspace.vm_only` folders are kept on the VM's disk inside
it, as for any live mount. A snapshot of such a VM holds no workspace files,
only the reference to this folder, so creating from it needs
`--share-mounts`. An older local VM runtime refuses it before creating
anything; `cw setup --local --replace` installs a current one.

### Use your own checkouts instead of clones

`cw create --local --path-mode mount` with a file that lists repositories
uses the checkouts already in the folder instead of cloning them. The folder
is mounted live at `/workspace/<folder name>`, as it is without repositories,
so each repository's `destination` must be that folder itself or lie inside
it, and already be a Git checkout there:

```yaml
# ~/src/platform/codewire.yaml: the folder holds web/ and api/ checkouts
repositories:
  - source: https://github.com/your-org/web.git
    destination: /workspace/platform/web
  - source: https://github.com/your-org/api.git
    destination: /workspace/platform/api
working_directory: /workspace/platform
```

A cloud create, or a local create without `--path-mode mount`, clones both to
the same paths. To mount by default in a folder, put `workspace.path_mode:
mount` in its `codewire.local.yaml`; `--path-mode clone` then clones them for
one create. With the mount, nothing is cloned and the file's `branch` and
`revision` are not applied: each checkout stays as it is, and the review says
so. A missing checkout, a link, or a destination outside the folder fails
before anything is created and is named.

`mounts` declared beside it are kept, for a folder you want in the VM that is
not inside this one, such as a checkout elsewhere on your machine. Put them in
`codewire.local.yaml`, since a cloud create refuses `mounts`:

```yaml
# ~/src/platform/codewire.local.yaml
workspace:
  path_mode: mount
mounts:
  - source: /srv/checkouts/infra
    destination: /workspace/infra
    mode: direct
    read_only: false
```

A declared mount may not be the folder's own mount point or lie inside it, and
a local VM serves at most 16 live mounts in all, the folder's included.

The VM can change anything in the mounted folder, including Git hooks and
settings that git on your machine later runs. For code you don't trust, use
`--path-mode clone` so the repositories are cloned.
