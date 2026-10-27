---
title: cw itself
description: install, upgrade, doctor, config and completion.
updated: 2026-10-27
weight: 8
aliases: ["/cli/cw"]
---

## cw install

```sh
cw install --managed [--bin-dir DIR] [--store DIR] [--verbose] [--json]
```

Installs the running `cw` into the managed version store and selects it. The
install script does this for you; `make cli-install` from a source checkout
does the same. A `cw` built without source provenance (a plain
`cargo build`) is refused.

## cw upgrade

```sh
cw upgrade                       # at a terminal: choose what to upgrade
cw upgrade [--cli] [--vms] [--channel stable | --version vX.Y.Z | --from DIR --sha256 HEX]
           [--expect-generation N] [--store DIR] [--verbose] [--json]
cw upgrade status [--json]
cw upgrade rollback [--to VERSION] [--expect-generation N] [--vms] [--verbose]
```

At a terminal, bare `cw upgrade` checks the stable channel for a newer `cw`
and finds the local VMs that would be left running on an older one, then
offers a checklist of what applies: the newer CLI, checked, and a restart of
those VMs, unchecked because a restart ends the work running in them. Space
toggles an item, Enter applies the checked ones, and Escape or Ctrl-C changes
nothing. Without a terminal, or with `--json`, it upgrades the CLI only and
names any VMs left on an older `cw` with the `cw upgrade --vms` repair.

The CLI upgrade never depends on the local VM supervisor: when the local VMs
cannot be checked, it says why and how to recover, and upgrades the CLI
anyway.

```text
Checking for a newer cw…
› [x] Codewire CLI v0.4.1 → v0.4.3
Upgraded cw to v0.4.3.
Running cw processes keep v0.4.1 until they exit. To go back: cw upgrade rollback
```

`--verbose` adds the selected version's SHA-256, entry, store, selection
generation and build identity; `--json` reports every field.

| Flag | Meaning |
| --- | --- |
| `--cli` | Select the newer CLI without asking; a source flag implies it |
| `--vms` | Restart local VMs still running on an older `cw` onto the selected one; the flag is the consent. Alone, it restarts them without selecting or fetching a CLI |
| `--channel stable` | The default source: the newest signed stable release; refuses an installed-version regression |
| `--version vX.Y.Z` | An explicit signed release; a downgrade is permitted |
| `--from DIR --sha256 HEX` | A pinned local release directory (`cw` and `cw-runtime.json`) |
| `--expect-generation N` | Refuse unless the selection generation is still `N` |
| `--verbose` | Also show the digest, entry, store, generation and build identity |
| `rollback --to` | A retained version by SHA-256, a unique 8+ digit prefix, or package version; default the previous one |

`cw upgrade` changes the CLI; `cw update ENV` changes an environment. See
[Update cw](@/install.md).

Example:

```sh
cw upgrade status
```

```text
Managed cw installation
  entry:      /home/user/.local/bin/cw
  store:      /home/user/.local/share/codewire/cli
  platform:   linux-x86_64
  generation: 2
  current:    v0.4.1 (b3b4954a258e27870495e90dc338aba50415faf670780fa650b984c0eedf3cf5)
  previous:   v0.4.0 (faa90dd9b1ba7dd80f4355e945086c838c4bfc3b179924c7dcc8c60a5517deed)
  retained:   2 version(s)
  * b3b4954a258e27870495e90dc338aba50415faf670780fa650b984c0eedf3cf5 v0.4.1 (pinned release)
    faa90dd9b1ba7dd80f4355e945086c838c4bfc3b179924c7dcc8c60a5517deed v0.4.0 (self-install)
```

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

Example:

```sh
cw doctor local
```

```text
Native local VM orphans: none
```

## cw config

```sh
cw config inspect [--output json]
```

Shows the resolved, non-secret configuration: directories, server, how the
platform token was supplied, the Mesh URL and selected network, and the local
credential store. See [Configuration](@/reference/cli/configuration.md).

Example, before signing in:

```sh
cw config inspect
```

```text
platform_config_dir=/home/user/.config/cw
mesh_data_dir=/home/user/.codewire
platform=unconfigured
mesh=unconfigured
local_credential_store=secret-service
```

## cw completion

```sh
cw completion [bash|zsh|fish|powershell]
cw completion --install
```

Prints a completion script (zsh by default), or installs one for the shell in
`$SHELL` (zsh, bash or fish).
