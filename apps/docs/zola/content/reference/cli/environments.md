---
title: Environments
description: ls, info, create, start, stop, restart, rm, update, ports, cp and the environment administration commands, plus use, current, init, shell, vscode, setup ssh, setup rex, checkpoint and preset.
updated: 2026-11-13
weight: 2
aliases: ["/cli/environments"]
---

Environment commands are top-level. `--local` restricts a name to local
environments and `--cloud` to the current organization's; either flag goes
before or after the command (`cw --cloud stop app` is `cw stop --cloud app`)
and never falls back to the other placement. Without either, a name is looked
up across trusted hosts, local VMs and the current organization, and a name
that exists in both placements is refused. When the local VMs can't be checked,
because their supervisor can't be reached or refuses this `cw`, a cloud
environment's ID still works: the command says the cloud answered. A cloud
name or ID prefix is then refused, since a local VM may have the same name;
add `--cloud` to use the cloud one. Cloud-only and local-only commands are
marked.

## cw create

```sh
cw create [REPO_URL]... [OPTIONS]
```

Creates a cloud sandbox unless `--local` is given, from the nearest
[`codewire.yaml`](@/environments/codewire-yaml.md) and the
flags, which win over it. Repositories are `URL[@branch][::/workspace/path]`,
as positionals or with `--repo`; they replace the file's repositories.

| Flag | Meaning |
| --- | --- |
| `--name NAME` | Environment name |
| `--type sandbox\|host` | Sandbox (default) or explicitly trusted host execution; `host` needs `--local` |
| `--image IMAGE` | Container image; `workspace` is shorthand for the Codewire workspace image |
| `--preset SLUG`, `--preset-id ID` | Cloud: create from a preset |
| `--repo URL`, `--branch` | Repositories to clone, each to its own path |
| `--file FILE` | Project YAML file instead of the nearest `codewire.yaml` (relative to `--path` for local creation); repeat to merge files in order |
| `--no-file` | Use only the flags; read no `codewire.yaml` |
| `--no-local-file` | Local: do not merge the `codewire.local.yaml` beside the nearest `codewire.yaml` |
| `--path PATH` | Local: the project directory, where the `codewire.yaml` search starts (default `.`) |
| `--path-mode mount\|copy\|clone\|empty` | Local: mount the directory live and read-write (default; the VM can change anything in it, including Git hooks and settings that git on your machine later runs, so use `clone` for untrusted code), copy it once as it is now, clone the Git repository's committed state once, or start empty. Overrides `workspace.path_mode`; with repositories in `codewire.yaml`, `mount` uses the checkouts already in the folder and `clone` (the default) clones them |
| `--cpu`, `--memory`, `--disk` | Resources, for example `--cpu 2 --memory 8GB --disk 40GB`; CPU is in cores (`0.5` or `500m` for half a core on a hosted sandbox). A hosted sandbox defaults to 2 vCPU, 8 GiB and an 80 GiB disk, and its disk is at most 200 GiB |
| `--docker-disk SIZE`, `--no-docker` | Local: the guest Docker data disk (default 8 GiB), or no Docker daemon |
| `--install CMD`, `--startup CMD` | Install command and startup script |
| `--env KEY=VALUE` | Cloud: plain environment variables (repeatable) |
| `--profile NAME`, `--no-profile` | Credential profile: `local:NAME` or `platform:NAME`, or none. A cloud create with neither uses the `codewire.yaml` profile, then your default profile |
| `--secrets NAME`, `--user-secrets local\|platform`, `--org-secrets` | Application-secret sources |
| `--ttl 8h` | Cloud: delete after a lifetime |
| `--isolation standard\|confidential` | Cloud: isolation tier |
| `--network NAME`, `--no-network` | Local: join a Codewire Mesh network, or none |
| `--no-wait` | Cloud: return at once instead of watching startup |
| `--write-preset`, `--save-preset NAME` | Cloud: write the resolved preset to `./codewire.yaml`, or save it on the server |
| `-y, --yes` | Skip confirmation prompts |
| `--output json` | |

At a terminal, a create without `--name` asks for a name and, unless placement
is explicit, where to create the environment. Cloud setup offers optional
resource, image, repository and source-reference settings before its review.
Local creation shows the resolved settings with **Create environment**, **Edit
settings** and **Cancel** choices. Edit one setting at a time, then return to
review. Escape, Ctrl-C or closed input cancels; `--yes` and JSON output skip
these walkthroughs. A trusted host (`--local --type host`) takes only
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

Example, with one local VM and no account:

```sh
cw ls
```

```text
  NAME    LOCATION  STATE    SESSIONS  NETWORK
› my-app  local     running  3         —

  › current environment · NETWORK is the saved attachment
  Cloud environments are not listed: no Codewire server is set up (`cw login`)
```

```sh
cw info app
```

```text
Environment: app
Backend:     cloud-hypervisor
State:       running
CPU:         2
Memory:      4Gi
Disk:        20Gi
Workspace:   1 input(s), plan c865a6961c91009f0dcd5ec510524a9727d3e2f940fa3e80f097c1fed3de2004
Working dir: /workspace/my-app
Access:      none
Install:     none
Env vars:    none
Agents:      none
Docker:      8Gi
Generation:  1
Secrets:     none
Credentials: none
```

## cw start, stop, restart, rm

```sh
cw start ENV
cw stop ENV
cw restart ENV       # local VMs and hosts; a cloud environment restarts sessions only
cw rm ENV [-y]       # a host asks first and keeps its project directory; a VM or sandbox is removed at once
```

A cloud `start` returns once the environment is usable: its Git identity is
set and its startup script has finished, as after `create`. A long startup
script makes the start as long, so start servers in a session instead.
Ctrl-C ends only the wait; the start carries on. With `--output json`, a
cloud `start` prints `{"status": "running"}` when it returns, and `stop`
prints `{"status": "stopped"}`.

A cloud `create` or `start` in an organization with no compute credit exits
with status 1, names the organization and links its billing page; see
[When credit runs out](@/organizations/usage.md#when-credit-runs-out).

`stop` and `restart` without `--session` act on the whole environment and
need `ENV` (or `--in ENV`). With `--session` they act on one session instead;
see [Sessions](@/reference/cli/access.md).

Example:

```sh
cw stop app
cw rm app
```

```text
✓ Environment app stopped
  local VM · environment disk retained
✓ Environment app removed
  local VM · environment disk removed
```

See [Lifecycle](@/environments/lifecycle.md).

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
no quantity is given; disks never shrink, and a cloud disk grows up to
200 GiB; a local VM restarts, and `--force`
ends active cloud sessions when a restart is required.

Example:

```sh
cw resize app --cpu 4 --memory 8GB -y
```

```text
Environment: app (local · Cloud Hypervisor)

              Current   Desired
CPU       2         4
Memory    4 Gi      8 Gi
Disk      20 Gi     20 Gi

Active sessions: none
Codewire will stop the VM, grow the disk offline if requested, and restore its prior running state. Disk growth cannot be reversed.
```

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

Example, on a local VM:

```sh
cw ports app --publish 8080
cw ports app --unpublish 8080
```

```text
Published http://127.0.0.1:8080 -> app:8080
app publishes:
  127.0.0.1:8080 -> 8080
Withdrew 127.0.0.1:8080 -> app:8080
```

On a hosted sandbox the same command prints the preview URL; see
[Ports and preview URLs](@/access/ports.md).

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

These accept `--cloud` and refuse `--local`, except `prune`, which with
`--local` means the next section.

## cw prune --local

```sh
cw prune --local [--dry-run] [-y]
```

Removing a local VM keeps the workspace image it was created from, so the
next create downloads nothing: the newest pulled image of each of at most two
image repositories stays on disk, most recently used first, and a newer image
of a repository replaces its older one. `cw prune --local` lists those images
and deletes them, freeing their disk except what another VM or a disk
snapshot still uses; `--dry-run` only lists them and says what deleting would
free. `--state` does not apply. The next create of a deleted image downloads
it again.

## cw cp

```sh
cw cp ./local my-app:/workspace/remote
cw cp my-app:/workspace/remote ./local
```

Exactly one side names an environment (cloud sandbox or local VM).

Example:

```sh
cw cp notes.txt cpt:/workspace/notes.txt
cw cp cpt:/workspace/result.txt ./result.txt
```

```text
Uploaded notes.txt -> cpt:/workspace/notes.txt
Downloaded cpt:/workspace/result.txt -> ./result.txt (6 bytes)
```

On a local VM the environment side must be under `/workspace`. Files of any
size stream; a cloud upload over 64 MiB goes in resumable parts, so running
the same command again after an interruption resumes it. See
[Files](@/access/files.md).

## cw checkpoint (local, Linux)

```sh
cw checkpoint create ENV --name NAME
cw checkpoint ls
cw checkpoint inspect NAME
cw checkpoint restore NAME [--yes]
cw checkpoint rm NAME
cw create --local --checkpoint NAME [--name NEW]
```

A VM checkpoint saves a running local VM's memory, device state and disks at
one instant, on this host. It holds everything the VM's memory held, delivered
sign-ins included, until they expire, and is never exported. The VM keeps
running; it stands still for the moment its memory is written.

`restore` puts the checkpoint's own environment back at that instant: its
running processes and every disk change since are discarded, after asking
unless `--yes` is given. To keep the environment and run the checkpoint beside
it, fork it with `cw create --local --checkpoint NAME`. VM checkpoints need a
Linux host for now; on macOS the command says so.

## Local VMs on an older cw

After an upgrade, local VMs keep running on the `cw` that started them.
`cw upgrade --vms` restarts them onto the selected `cw`; see
[Update cw](@/install.md).

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
VMs, cloud environments and trusted hosts with their location, state, vCPU,
RAM, disk and credential profile (a trusted host has none). Type to filter,
move with the arrow keys, Enter selects and Escape or Ctrl-C cancels without
changing anything; `--local` or `--cloud` limits the list. With no
environments at all, it offers to create a local VM or a cloud environment,
reviewed before it is made, and selects it. Outside an interactive terminal
`ENV` is required. Selecting a stopped environment does not start it.

The selection keeps the environment's identity, not just its name: a local
VM that was removed and created again under the same name is not current
until you select it again. Removing the current environment clears the selection;
nothing else becomes current.

`current` shows the current environment's location, state and saved network
attachment, says when it no longer exists, or says that none is selected.
`--verbose` adds its ID and organization; `--output json` returns
`{"selected": false}` or the selection with `status` `found`, `missing` or
`unavailable`.

Example:

```sh
cw use app
cw current
```

```text
✓ Current environment: app
  local VM · running
  2 vCPU · 4 GiB RAM · 20 GiB disk
  Credentials: none
app · local VM · running
  Network:     not attached
```

## cw init

```sh
cw init [REPO_URL]... [--image IMAGE] [--install CMD] [--startup CMD] [--cpu CPU] [--memory MB] [--disk GB]
        [-e KEY=VALUE] [--preset SLUG] [--repo URL] [--branch B] [--file codewire.yaml] [--force] [-y]
        [--profile PROFILE | --no-profile] [--secrets PROJECT]
```

Writes `codewire.yaml`. With only direct inputs it works offline; a preset,
repository or branch is resolved by the platform. It refuses to overwrite
without `--force`. At a terminal, bare `cw init` asks for an image,
then offers optional resources, setup commands, credential-profile and
secret-project references. It shows a review before writing. References contain
no credential or secret material. Explicit direct inputs and `--yes` keep the
flag-based path. See [`codewire.yaml`](@/environments/codewire-yaml.md).

## cw shell

```sh
cw shell [ENV]
cw shell --durable [ENV]
cw shell --stdio ENV     # for OpenSSH ProxyCommand (cw-local-NAME, cw-cloud-NAME)
```

Opens a login shell as a new session in the selected or named environment, on
every placement: cloud, local VM and trusted host. The shell ends when you
leave it, as `ssh` does, and `cw shell` exits with the shell's status. Every
key goes to the shell, Ctrl-B included. If the connection drops, the shell
waits 10 minutes for `cw attach ENV --session SESSION` before it ends.

With `--durable`, the shell is a named session that keeps running after you
detach with Ctrl-B, then d. An environment whose daemon predates the 10-minute
shell gets the durable one, and `cw shell` says so.

The shell gets your terminal's `TERM`. If the environment has no terminfo
entry for it, `cw shell` sends your machine's own entry (`infocmp -x`) and the
shell installs it in `~/.terminfo`, as kitty's ssh kitten does. When there is
no entry to send, the shell uses `xterm-256color` and says so.

## cw vscode

```sh
cw vscode [ENV] [--folder /workspace] [--org ORG]
cw --local vscode [ENV] [--folder /workspace]
```

Refreshes the SSH config, as `cw setup ssh` does, and opens VS Code with
Remote-SSH on `cw-cloud-<id>`, or on `cw-local-<id>` for a local VM.

## cw setup ssh

```sh
cw setup ssh [--ssh-config-file ~/.ssh/config] [-o|--ssh-option OPTION]... [-n|--dry-run]
cw setup ssh remove [--ssh-config-file ~/.ssh/config] [-n|--dry-run]
```

Writes the managed `Host cw-local-*` and `Host cw-cloud-*` blocks, whose `ProxyCommand` runs `cw [--local|--cloud] shell --stdio %n` and
whose `KnownHostsCommand` runs `cw [--local|--cloud] ssh known-hosts %H`, so
that `ssh`, `scp`, `sftp`, `rsync` and VS Code Remote-SSH reach cloud
environments as `cw-cloud-NAME`, and local VMs as `cw-local-NAME`. It reports whether the block was written or unchanged. There is no bare
`cw-NAME` alias. `--dry-run` shows the change to the
managed block without writing it; the rest of the file is not printed.
`cw setup` writes the same block unless `--skip-ssh` is given.

`cw setup ssh remove` deletes only the managed block and keeps every other
line. It reports nothing to remove when there is no block or no file, and
creates nothing. It refuses, changing nothing, when one of the two marker
lines is missing or the file is not writable.

## cw setup rex

```sh
cw setup rex
cw setup rex remove
```

Adds Codewire to the command palette of [Rex](https://superlogical.com), the
terminal multiplexer: it writes a Lua plugin to `plugins/codewire/init.lua`
beside Rex's config and a managed block between `-- >>> codewire >>>` and
`-- <<< codewire <<<` in the config that loads it with this `cw`. The config is
`REX_CONFIG`, else `rex/init.lua` in your configuration directory
(`~/.config/rex/init.lua`). The block also names the environment `cw use`
selected; `cw use` and `cw rm` rewrite that line and reload Rex's config, so
the palette follows the selection. It checks the result with `rex config
check`, puts the config back as it was if Rex refuses it, and asks a running
Rex server to reload it. A config Rex already refuses is left unchanged. See
[Rex](@/access/rex.md) for the actions.

`cw setup rex remove` deletes only the managed block and the plugin, keeping
the rest of the config. Both refuse, changing nothing, when one of the two
marker lines is missing. `--local` and `--cloud` do not apply.

## cw preset (cloud)

```sh
cw preset list                                   # alias: ls
cw preset create SLUG --image IMAGE [--name N] [--install CMD] [--startup CMD]
                 [--cpu CPU] [--memory MB] [--disk GB] [--ttl 1h] [--description TEXT]
cw preset info SLUG|slug:SLUG|id:ID
cw preset rm ID
```

Example:

```sh
cw preset create team-web --name 'Team web' --image workspace --install 'python3 --version' --ttl 2h
```

```text
Preset created: Team web.
  ID:    d3dbefb6-881a-4225-b4f8-ac05ace76ddd
```

See [Presets](@/environments/presets.md).

## Guided snapshot creation

At an interactive terminal, `cw snapshot create` without an environment asks
for a supported location, then lists eligible stopped environments. Choose a
source and snapshot name and review before creating the snapshot. Workload
files are retained; Codewire-delivered sign-ins are removed. Local disk
snapshots currently require Linux; other hosts offer cloud snapshots.
Noninteractive and JSON calls must name the source environment explicitly.

## Cloud snapshots

`cw --cloud snapshot create ENV [--name NAME]` saves a stopped cloud
environment's workspace disk. The snapshot is private to you, and
Codewire-delivered sign-ins are cleared from it. `cw --cloud create --snapshot
NAME [--count N]` starts new environments from it, each with fresh identity;
`cw --cloud snapshot ls`, `inspect` and `rm` manage it.

A cloud snapshot is kept on the storage node that holds the environment's disk
and is not backed up: if that node is lost, so is the snapshot. New
environments made from it start on that node too, so while the node is
unavailable a create from the snapshot waits for it and can time out. Keep
anything you cannot recreate somewhere else as well, such as in a repository. An
organization holds at most 32 snapshots, and captures four at a time.
