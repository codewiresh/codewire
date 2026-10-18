---
title: cw itself
description: install, update, doctor, config and completion.
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

## cw update

```sh
cw update [--channel stable | --version vX.Y.Z | --from DIR --sha256 HEX]
          [--expect-generation N] [--restart-vms] [--store DIR] [--json]
cw update status [--json]
cw update rollback [--to VERSION] [--expect-generation N] [--restart-vms]
```

| Flag | Meaning |
| --- | --- |
| `--channel stable` | The default: the newest signed stable release; refuses an installed-version regression |
| `--version vX.Y.Z` | An explicit signed release; a downgrade is permitted |
| `--from DIR --sha256 HEX` | A pinned local release directory (`cw` and `cw-runtime.json`) |
| `--expect-generation N` | Refuse unless the selection generation is still `N` |
| `--restart-vms` | Restart local VMs still running on the previous `cw` without asking |
| `rollback --to` | A retained version by SHA-256, a unique 8+ digit prefix, or package version; default the previous one |

See [Update cw](@/guides/update.md).

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
