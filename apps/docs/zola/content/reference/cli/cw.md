---
title: cw itself
description: install, upgrade, doctor, feedback, config and completion.
updated: 2026-11-10
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

## cw feedback

```sh
cw feedback "MESSAGE" [--anonymous] [--environment ID] [--yes] [-o json]
cw feedback                      # at a terminal: type the message
some-command | cw feedback --yes # from a script: the message on stdin
```

Sends a message to the Codewire team. Without `MESSAGE` at a terminal, type
it: Enter starts a new line, Ctrl-D sends, and Escape or Ctrl-C cancels. When
stdin is not a terminal, the message is read from it.

Before sending, `cw` shows who the feedback is from and everything attached,
then asks; `--yes` sends without asking, and is required when there is no
terminal to ask in or with `-o json`.

What is sent, and nothing else:

- the message, at most 10 KB;
- the `cw` version, the operating system and the architecture;
- whether you work locally or in the cloud: `--local` or `--cloud`, else
  where the selected environment runs;
- with `--environment ID`, that environment's ID.

No logs, files, environment contents or settings are sent. Do not paste
secrets into the message.

Signed in, the feedback records your account and your current organization;
signed out, or with `--anonymous`, it records neither. A sign-in that no
longer works is refused rather than sent anonymously: run `cw login`, or send
with `--anonymous`.

Sending is limited to 10 messages an hour for an account, 5 an hour
anonymously from one address, and a ceiling for everyone together. A refusal
says how many seconds to wait. See [Feedback](@/reference/security.md#feedback)
for what is stored and who reads it.

| Flag | Meaning |
| --- | --- |
| `--anonymous` | Send without your account or organization |
| `--environment ID` | An environment the feedback is about; only its ID is sent |
| `-y`, `--yes` | Send without asking |
| `-o json` | Print the stored feedback's ID as JSON |

Example:

```sh
cw feedback "cw ls is slow with 40 environments"   # then choose Continue
```

```text
Feedback for the Codewire team at https://codewire.sh
  From      alice@example.com, organization Acme
  Attached  cw 0.4.3, linux x86_64, cloud
  Message   34 bytes
Feedback sent (5f0c9a2e-0d7b-4c1e-9a43-2b8f6f3d1c11). Thank you.
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
