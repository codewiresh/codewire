---
title: cw itself
description: install, upgrade, doctor, config and completion.
weight: 7
---

## cw install

```sh
cw install --managed [--bin-dir DIR] [--store DIR] [--json]
```

Installs the running `cw` into the managed version store and selects it. The
install script does this for you; `make cli-install` from a source checkout
does the same. A `cw` built without source provenance (a plain
`cargo build`) is refused.

## cw upgrade

```sh
cw upgrade                       # at a terminal: choose what to upgrade
cw upgrade [--cli] [--vms] [--channel stable | --version vX.Y.Z | --from DIR --sha256 HEX]
           [--expect-generation N] [--store DIR] [--json]
cw upgrade status [--json]
cw upgrade rollback [--to VERSION] [--expect-generation N] [--vms]
```

At a terminal, bare `cw upgrade` checks the stable channel for a newer `cw`
and finds the local VMs that would be left running on an older one, then
offers a checklist of what applies: the newer CLI, checked, and a restart of
those VMs, unchecked because a restart ends the work running in them. Space
toggles an item, Enter applies the checked ones, and Escape or Ctrl-C changes
nothing. Without a terminal, or with `--json`, it upgrades the CLI only and
names any VMs left on an older `cw` with the `cw upgrade --vms` repair.

| Flag | Meaning |
| --- | --- |
| `--cli` | Select the newer CLI without asking; a source flag implies it |
| `--vms` | Restart local VMs still running on an older `cw` onto the selected one; the flag is the consent. Alone, it restarts them without selecting or fetching a CLI |
| `--channel stable` | The default source: the newest signed stable release; refuses an installed-version regression |
| `--version vX.Y.Z` | An explicit signed release; a downgrade is permitted |
| `--from DIR --sha256 HEX` | A pinned local release directory (`cw` and `cw-runtime.json`) |
| `--expect-generation N` | Refuse unless the selection generation is still `N` |
| `rollback --to` | A retained version by SHA-256, a unique 8+ digit prefix, or package version; default the previous one |

`cw upgrade` changes the CLI; `cw update ENV` changes an environment. See
[Update cw](@/guides/update.md).

## cw doctor

```sh
cw doctor [--output json]
cw doctor local [--output json]
cw doctor tailnet ENV [--direct-wait 15s] [--peer-timeout 10s] [--expect any|direct_udp|udp_relay|derp] [--skip-forced-derp]
```

`doctor` checks the build, the platform connection, the organization, shell
completion and the SSH config block. `local` reports local VM files and
processes no environment owns, without changing anything. `tailnet` probes
the transport paths to a hosted environment.

## cw config

```sh
cw config inspect [--output json]
```

Shows the resolved, non-secret configuration: directories, server, how the
platform token was supplied, the Mesh URL and selected network, and the local
credential store. See [Configuration](@/cli/configuration.md).

## cw completion

```sh
cw completion [bash|zsh|fish|powershell]
cw completion --install
```

Prints a completion script (zsh by default), or installs one for the shell in
`$SHELL` (zsh, bash or fish).
