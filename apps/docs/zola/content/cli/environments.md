---
title: Environments
description: cw env and its subcommands, plus use, current, init, shell, vscode, config-ssh and preset.
weight: 1
---

## cw env

`cw env [--local|--cloud] SUBCOMMAND`. `--local` restricts a name to local
environments, `--cloud` to the current organization's. Hosted-only and
local-only subcommands are marked.

### env create

```sh
cw env create [REPO_URL]... [OPTIONS]
```

Creates a hosted sandbox unless `--local` is given. Repositories are
`URL[@branch][::/workspace/path]`, as positionals or with `--repo`.

| Flag | Meaning |
| --- | --- |
| `--name NAME` | Environment name |
| `--type sandbox\|host` | Sandbox (default) or explicitly trusted host execution; `host` needs `--local` |
| `--image IMAGE` | Container image; `workspace` is shorthand for the Codewire workspace image |
| `--preset SLUG`, `--preset-id ID` | Hosted: create from a preset |
| `--repo URL`, `--branch` | Hosted: repositories to check out |
| `--file FILE` | Project YAML file (relative to `--path` for local creation) |
| `--path PATH` | Local: the project directory (default `.`) |
| `--path-mode mount\|snapshot\|clone\|copy\|empty` | Local: mount the directory live (default), copy it once (a Git repository's committed state, or the directory), or start empty |
| `--cpu`, `--memory`, `--disk` | Resources, for example `--cpu 2 --memory 8GB --disk 40GB` |
| `--docker-disk SIZE`, `--no-docker` | Local: the guest Docker data disk (default 8 GiB), or no Docker daemon |
| `--install CMD`, `--startup CMD` | Install command and startup script |
| `--env KEY=VALUE` | Hosted: plain environment variables (repeatable) |
| `--profile NAME` | Credential profile: `local:NAME` or `platform:NAME` |
| `--secrets NAME`, `--user-secrets local\|platform`, `--org-secrets` | Application-secret sources |
| `--ttl 8h` | Hosted: delete after a lifetime |
| `--isolation standard\|confidential` | Hosted: isolation tier |
| `--network NAME`, `--no-network` | Local: join a Codewire Mesh network, or none |
| `--no-wait` | Hosted: return at once instead of watching startup |
| `--write-preset`, `--save-preset NAME` | Hosted: write the resolved preset to `./codewire.yaml`, or save it on the server |
| `-y, --yes` | Skip confirmation prompts |
| `--output json` | |

At a terminal a local create shows the resolved settings and asks
`[Y]es / [e]dit / [n]o`. A trusted host (`--local --type host`) takes only
`--name` and `--path`.

### env list, info, report

```sh
cw env list [--type TYPE] [--state STATE] [-a|--all] [--output json]   # alias: ls
cw env info ENV
cw env report ENV        # isolation, runtime and trust evidence (hosted and host)
```

`list` merges trusted hosts, local VMs and, when signed in, the current
organization; `--all` includes destroyed environments.

### env start, stop, restart, rm

```sh
cw env start ENV
cw env stop ENV
cw env restart ENV       # local VMs and hosts
cw env rm ENV [-y]       # a host asks first and keeps its project directory; a VM or sandbox is removed at once
```

### env update, resize, refresh-skills

```sh
cw env update ENV [--secrets NAME] [--user-secrets local|platform] [--org-secrets] [--clear-secrets]
                  [--profile NAME] [--clear-profile] [-y]
cw env resize ENV [--cpu N] [--memory SIZE] [--disk SIZE] [--force] [--allow-restart] [-y]
cw env refresh-skills ENV   # local VM: re-snapshot user and repository skills
```

`update` changes only the selected application-secret sources and credential
profile, with a confirmed restart that keeps workspace data. `resize` runs a
wizard at a terminal when no quantity is given; disks never shrink; a local VM
restarts, and `--force` ends active hosted sessions when a restart is
required.

### env port

```sh
cw env port add PORT [-l|--label LABEL] [-a|--access creator|org_members|public] [--host-port PORT] [-e|--env ENV]
cw env port list [-e ENV]       # alias: ls
cw env port rm LABEL_OR_HOST_PORT [-e ENV]
```

On the platform, `--label` is required and the port becomes a preview URL
(`--access` defaults to `creator`). For a local VM, `--host-port` (default:
the guest port) binds `127.0.0.1` on your machine; `--label` and `--access`
are refused. `-e` defaults to the selected environment.

### env share (hosted)

```sh
cw env share grant ENV --user USER_ID [--permission viewer|operator|owner]   # default viewer
cw env share list ENV
cw env share revoke ENV --user USER_ID
```

### env logs, daemon, agent (hosted)

```sh
cw env logs ENV [--follow true|false]          # setup logs
cw env daemon status [ENV] [--output json]      # version, capabilities, health; also local VMs and hosts
cw env daemon logs [ENV]
cw env daemon repair [ENV]                      # reconcile the daemon without recreating the environment
cw env agent info ENV                           # qualified managed agents
cw env agent observe ENV --request-id UUID      # observe a managed request without replaying it
```

### env extend, protect, unprotect, cancel-delete, prune, nuke (hosted)

```sh
cw env extend ENV [--hours N]                  # postpone a TTL deletion (default 1)
cw env protect ENV                             # refuse deletion
cw env unprotect ENV
cw env cancel-delete ENV
cw env prune [--state error,creating,pending] [--dry-run] [-y]
cw env nuke [-y]                               # delete every environment in the organization; asks you to type a phrase
```

### env cp

```sh
cw env cp ./local my-app:/workspace/remote
cw env cp my-app:/workspace/remote ./local
```

Exactly one side names an environment (hosted sandbox or local VM).

### env upgrade (local)

```sh
cw env --local upgrade [--yes]
```

Restarts the local VMs still running on a previous `cw` so they use this one.
See [Update cw](@/guides/update.md).

### env access, runtime (advanced)

`cw env --local access ENV` inspects a local environment's access profile.
`cw env runtime info|update|rollback|observe|cancel ENV` selects the `cw`
that runs inside a running environment without restarting it; `info` shows
the bootstrap and current selection.

## cw use, cw current

```sh
cw use ENV [--local|--cloud]
cw current [-v|--verbose]
```

`use` makes `ENV` the default for session commands, looking in trusted hosts,
then local VMs, then the current organization; `--local` or `--cloud` settles
a name that exists in both.

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
cw shell --stdio ENV     # for OpenSSH ProxyCommand (hosted)
```

Opens a login shell as a new session in the selected or named environment.

## cw vscode (hosted)

```sh
cw vscode [ENV] [--folder /workspace] [--org ORG]
```

Refreshes the SSH config and opens VS Code with Remote-SSH on `cw-<id>`.

## cw config-ssh

```sh
cw config-ssh [--ssh-config-file ~/.ssh/config] [-o|--ssh-option OPTION]... [-n|--dry-run]
```

Writes the managed `Host cw-*` block with `ProxyCommand cw shell --stdio %n`
and `KnownHostsCommand cw ssh known-hosts %H`, so that `ssh`, `scp`, `sftp`,
`rsync` and VS Code Remote-SSH reach hosted environments.

## cw preset (hosted)

```sh
cw preset list                                   # alias: ls
cw preset create SLUG --image IMAGE [--name N] [--install CMD] [--startup CMD]
                 [--cpu MILLICORES] [--memory MB] [--disk GB] [--ttl 1h] [--description TEXT]
cw preset info SLUG|slug:SLUG|id:ID
cw preset rm ID
```
