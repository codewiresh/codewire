---
title: Environments
description: ls, info, create, start, stop, restart, rm, update, ports, cp and the environment administration commands, plus use, current, init, shell, vscode, setup ssh and preset.
weight: 1
---

Environment commands are top-level. `--local` restricts a name to local
environments and `--cloud` to the current organization's; either flag goes
before or after the command (`cw --cloud stop app` is `cw stop --cloud app`)
and never falls back to the other placement. Without either, a name is looked
up across trusted hosts, local VMs and the current organization, and a name
that exists in both placements is refused. Cloud-only and local-only commands
are marked.

## cw create

```sh
cw create [REPO_URL]... [OPTIONS]
```

Creates a cloud sandbox unless `--local` is given, from the nearest
`codewire.yaml` (see [the project file](@/guides/project-file.md)) and the
flags, which win over it. Repositories are `URL[@branch][::/workspace/path]`,
as positionals or with `--repo`; they replace the file's repositories.

| Flag | Meaning |
| --- | --- |
| `--name NAME` | Environment name |
| `--type sandbox\|host` | Sandbox (default) or explicitly trusted host execution; `host` needs `--local` |
| `--image IMAGE` | Container image; `workspace` is shorthand for the Codewire workspace image |
| `--preset SLUG`, `--preset-id ID` | Cloud: create from a preset |
| `--repo URL`, `--branch` | Repositories to clone, each to its own path |
| `--file FILE` | Project YAML file instead of the nearest `codewire.yaml` (relative to `--path` for local creation) |
| `--no-file` | Use only the flags; read no `codewire.yaml` |
| `--path PATH` | Local: the project directory, where the `codewire.yaml` search starts (default `.`) |
| `--path-mode mount\|copy\|clone\|empty` | Local: mount the directory live (default), copy it once as it is now, clone the Git repository's committed state once, or start empty |
| `--cpu`, `--memory`, `--disk` | Resources, for example `--cpu 2 --memory 8GB --disk 40GB` |
| `--docker-disk SIZE`, `--no-docker` | Local: the guest Docker data disk (default 8 GiB), or no Docker daemon |
| `--install CMD`, `--startup CMD` | Install command and startup script |
| `--env KEY=VALUE` | Cloud: plain environment variables (repeatable) |
| `--profile NAME` | Credential profile: `local:NAME` or `platform:NAME` |
| `--secrets NAME`, `--user-secrets local\|platform`, `--org-secrets` | Application-secret sources |
| `--ttl 8h` | Cloud: delete after a lifetime |
| `--isolation standard\|confidential` | Cloud: isolation tier |
| `--network NAME`, `--no-network` | Local: join a Codewire Mesh network, or none |
| `--no-wait` | Cloud: return at once instead of watching startup |
| `--write-preset`, `--save-preset NAME` | Cloud: write the resolved preset to `./codewire.yaml`, or save it on the server |
| `-y, --yes` | Skip confirmation prompts |
| `--output json` | |

At a terminal a local create shows the resolved settings and asks
`[Y]es / [e]dit / [n]o`. A trusted host (`--local --type host`) takes only
`--name` and `--path`.

## cw ls, info, report

```sh
cw ls [--type sandbox|host] [--state STATE] [-a|--all] [--output json]   # alias: list
cw ls ENV [--output json]
cw info ENV
cw report ENV        # isolation, runtime and trust evidence (cloud and host)
```

Without `ENV`, `ls` lists every environment, running or stopped: trusted
hosts, local VMs and, when signed in, the current organization's, one row
each with its location (`local`, `cloud` or `host`), state, session count and
saved network attachment (`cloud:NAME` or `local:NAME`, the Mesh it was
attached to; not a connectivity check); `›` marks the current environment
(`cw use`). When you are not signed in, a note says that cloud environments
were not listed. `--all` includes destroyed cloud environments.
An environment whose sessions cannot be read keeps its row, its SESSIONS
marked `unavailable` (the reason is in the JSON `error`), and `ls` still
succeeds. When a location cannot be listed at all, such as the cloud or the
local runtime, `ls` prints every environment it could list, names the
missing location and exits non-zero: an unavailable location is never shown
as empty. With `ENV`, `ls` lists that environment's sessions with their
mode: `normal` for a terminal or command session, `managed` for a managed
agent conversation.

## cw start, stop, restart, rm

```sh
cw start ENV
cw stop ENV
cw restart ENV       # local VMs and hosts; a cloud environment restarts sessions only
cw rm ENV [-y]       # a host asks first and keeps its project directory; a VM or sandbox is removed at once
```

`stop` and `restart` without `--session` act on the whole environment and
need `ENV` (or `--in ENV`). With `--session` they act on one session instead;
see [Sessions](@/cli/sessions.md).

## cw update, resize, refresh-skills

```sh
cw update ENV [--secrets NAME] [--user-secrets local|platform] [--org-secrets] [--clear-secrets]
              [--profile NAME] [--clear-profile] [-y]
cw resize ENV [--cpu N] [--memory SIZE] [--disk SIZE] [--force] [--allow-restart] [-y]
cw refresh-skills ENV   # local VM: re-snapshot user and repository skills
```

`update` (also `cw update --in ENV`) changes only the selected
application-secret sources and credential profile, with a confirmed restart
that keeps workspace data; without `ENV` it is refused. It never upgrades
`cw` itself: that is `cw upgrade`. `resize` runs a wizard at a terminal when
no quantity is given; disks never shrink; a local VM restarts, and `--force`
ends active cloud sessions when a restart is required.

## cw ports

```sh
cw ports [ENV]
cw ports ENV --publish PORT [--host-port PORT]                                  # local
cw ports ENV --publish PORT [-l|--label LABEL] [-a|--access creator|org_members|public]   # cloud
cw ports ENV --unpublish PORT [--host-port PORT | --label LABEL]
```

Without `--publish` or `--unpublish`, `ports` lists the published ports and
never starts an environment. `ENV` (or `--in ENV`) defaults to the selected
environment. One port changes per call, and publishing needs a running
environment: a stopped one is refused with the `cw start ENV` repair.

For a local VM, a port is published on `127.0.0.1` of your machine,
`--host-port` choosing the host port (default: the guest port); `--label` and
`--access` are refused. In the cloud the port becomes a preview URL labelled
`port-PORT` unless `--label` names it, with `creator` access unless
`--access` says otherwise; `--host-port` is refused. `--unpublish` names the
guest port; when a local guest port is published on several host ports,
`--host-port` chooses one, and when a cloud port has several previews,
`--label` does.

## cw share (cloud)

```sh
cw share grant ENV --user USER_ID [--permission viewer|operator|owner]   # default viewer
cw share list ENV
cw share revoke ENV --user USER_ID
```

## cw logs --setup, daemon, agent (cloud)

```sh
cw logs ENV --setup [--follow]               # how the environment was set up
cw daemon status [ENV] [--output json]       # version, capabilities, health; also local VMs and hosts
cw daemon logs [ENV]
cw daemon repair [ENV]                       # reconcile the daemon without recreating the environment
cw agent info ENV                            # qualified managed agents
cw agent observe ENV --request-id UUID       # observe a managed request without replaying it
```

`cw logs ENV --setup` shows how a cloud environment was set up:
provisioning, repository clones, and the install and startup steps.
`--follow` keeps streaming until setup ends.

## cw extend, protect, unprotect, cancel-delete, prune, nuke (cloud)

```sh
cw extend ENV [--hours N]                  # postpone a TTL deletion (default 1)
cw protect ENV                             # refuse deletion
cw unprotect ENV
cw cancel-delete ENV
cw prune [--state error,creating,pending] [--dry-run] [-y]
cw nuke [-y]                               # delete every environment in the organization; asks you to type a phrase
```

These accept `--cloud` and refuse `--local`.

## cw cp

```sh
cw cp ./local my-app:/workspace/remote
cw cp my-app:/workspace/remote ./local
```

Exactly one side names an environment (cloud sandbox or local VM).

## Local VMs on an older cw

After an upgrade, local VMs keep running on the `cw` that started them.
`cw upgrade --vms` restarts them onto the selected `cw`; see
[Update cw](@/guides/update.md).

## cw access, runtime (advanced)

`cw --local access ENV` inspects a local environment's access profile.
`cw runtime info|update|rollback|observe|cancel ENV` selects the `cw` that
runs inside a running environment without restarting it; `info` shows the
bootstrap and current selection.

## cw use, cw current

```sh
cw use [ENV] [--local|--cloud]
cw current [-v|--verbose] [--output json]
```

`use ENV` makes `ENV`, by name or ID, the current environment: the one
commands use when you name none. `--local` or `--cloud` says where to look
and settles a name that exists in both; a name found in one place while the
other could not be listed is refused rather than guessed.

Without `ENV`, in an interactive terminal, `use` opens a list of your local
VMs and cloud environments with their location, state, vCPU, RAM, disk and
credential profile. Type to filter, move with the arrow keys, Enter selects
and Escape or Ctrl-C cancels without changing anything; `--local` or
`--cloud` limits the list. Trusted hosts are selected by name only. Outside
an interactive terminal `ENV` is required. Selecting a stopped environment
does not start it.

The selection keeps the environment's identity, not just its name: a local
VM that was removed and created again under the same name is not current
until you select it again. Removing the current environment clears the selection;
nothing else becomes current.

`current` shows the current environment's location, state and saved network
attachment, says when it no longer exists, or says that none is selected.
`--verbose` adds its ID and organization; `--output json` returns
`{"selected": false}` or the selection with `status` `found`, `missing` or
`unavailable`.

## cw init

```sh
cw init [REPO_URL]... [--image IMAGE] [--install CMD] [--startup CMD] [--cpu MILLICORES] [--memory MB] [--disk GB]
        [-e KEY=VALUE] [--preset SLUG] [--repo URL] [--branch B] [--file codewire.yaml] [--force] [-y]
```

Writes `codewire.yaml`. With only direct inputs it works offline; a preset,
repository or branch is resolved by the platform. It refuses to overwrite
without `--force`. See [The project file](@/guides/project-file.md).

## cw shell

```sh
cw shell [ENV]
cw shell --stdio ENV     # for OpenSSH ProxyCommand (cloud)
```

Opens a login shell as a new session in the selected or named environment.

## cw vscode (cloud)

```sh
cw vscode [ENV] [--folder /workspace] [--org ORG]
```

Refreshes the SSH config, as `cw setup ssh` does, and opens VS Code with
Remote-SSH on `cw-<id>`.

## cw setup ssh

```sh
cw setup ssh [--ssh-config-file ~/.ssh/config] [-o|--ssh-option OPTION]... [-n|--dry-run]
cw setup ssh remove [--ssh-config-file ~/.ssh/config] [-n|--dry-run]
```

Writes the managed `Host cw-*` block with `ProxyCommand cw shell --stdio %n`
and `KnownHostsCommand cw ssh known-hosts %H`, so that `ssh`, `scp`, `sftp`,
`rsync` and VS Code Remote-SSH reach cloud environments, and reports whether
the block was written or unchanged. `--dry-run` shows the change to the
managed block without writing it; the rest of the file is not printed.
`cw setup` writes the same block unless `--skip-ssh` is given.

`cw setup ssh remove` deletes only the managed block and keeps every other
line. It reports nothing to remove when there is no block or no file, and
creates nothing. It refuses, changing nothing, when one of the two marker
lines is missing or the file is not writable.

## cw preset (cloud)

```sh
cw preset list                                   # alias: ls
cw preset create SLUG --image IMAGE [--name N] [--install CMD] [--startup CMD]
                 [--cpu MILLICORES] [--memory MB] [--disk GB] [--ttl 1h] [--description TEXT]
cw preset info SLUG|slug:SLUG|id:ID
cw preset rm ID
```
