---
title: Secrets and credentials
description: cw secrets for application secrets and cw credentials for provider credentials and profiles.
updated: 2026-11-07
weight: 5
aliases: ["/cli/secrets-and-credentials"]
---

Use `--local` for protected storage on this computer (Linux and macOS), or
`--cloud` for storage in your Codewire account. At an interactive terminal,
omitting the store opens a menu. It names the actual local protection:
macOS Keychain, the Linux system keyring, or permission-restricted file storage
when configured. An unavailable local store is labeled with its reason; your
Codewire account remains selectable. Credential storage is separate from where
your environment runs.

For a guided addition, start with:

```sh
cw credentials add
cw credentials connect
cw credentials generate
cw credentials set
cw secrets set
cw secrets projects create
```

`cw` asks for missing choices and keeps supplied flags. Use arrows or type to
filter a menu, then Enter to select. Invalid names can be corrected in place.
Escape, Ctrl-C, or Ctrl-D cancels; protected values stay hidden, including when
correcting or canceling them. Prompts and completed answers appear on stderr;
credential and secret values never appear in summaries or arguments.

Scripts and JSON commands never open menus. Supply the store and all required
metadata explicitly before piping a protected value. The full forms below work
for automation as well as interactive use.

## cw secrets

```sh
cw secrets --local|--cloud (--user | --organization | --project NAME) list        # alias: ls
cw secrets --local|--cloud (--user | --organization | --project NAME) set KEY
cw secrets --local|--cloud (--user | --organization | --project NAME) delete KEY
cw secrets --local|--cloud (--user | --organization | --project NAME) rename OLD NEW
cw secrets --cloud projects create NAME
cw secrets --cloud projects list
cw secrets --cloud projects delete NAME [--yes]
cw secrets --local|--cloud preview [--file codewire.yaml] [--output json]
```

| Scope flag | Meaning |
| --- | --- |
| `--user` | Your personal keys |
| `--organization` | The current organization's keys (platform only) |
| `--project NAME` | A named secret project, `local:NAME`, `platform:NAME` or `id:UUID` |

Key operations need one explicit scope; nothing is inferred from `cw use` or
`codewire.yaml`. Guided `set` offers the supported scopes, existing secret
projects, and creation of a project with its first key. It asks for the key
name and confirms replacement of an existing key before reading the new value.
Project creation and key storage are separate writes: if saving the first key
fails after project creation, the error identifies the retained project.

For scripts, pass exactly one scope flag. `set` reads the value from a hidden prompt or
stdin (one trailing newline removed); keys match `[A-Za-z_][A-Za-z0-9_]*` and
values are UTF-8 up to 64 KiB. `projects delete` removes every key in the
project and needs `--yes` when not interactive. `preview` shows which key
would come from which source for `codewire.yaml`, without values.

Example:

```sh
cw secrets --cloud projects create docs-demo
printf 'postgres://app@db.internal/app\n' | cw secrets --cloud --project docs-demo set DATABASE_URL
cw secrets --cloud --project docs-demo rename DATABASE_URL DB_URL
cw secrets --cloud projects delete docs-demo --yes
```

```text
Secret project "docs-demo" created. (id: 8b9c5a2d-ea91-402e-9cff-69b4961960aa)
Secret DATABASE_URL set in project "docs-demo".
Secret DATABASE_URL renamed to DB_URL in project "docs-demo".
Deleting platform secret project "docs-demo" (8b9c5a2d-ea91-402e-9cff-69b4961960aa) in organization ORG_ID and all its keys.
Secret project "docs-demo" deleted.
```

## cw credentials

```sh
cw credentials --local|--cloud [--profile NAME] SUBCOMMAND
```

### Add and connect

```sh
cw credentials --cloud connect codex|github|claude --name NAME [-y]
cw credentials --cloud add openai|anthropic|claude-subscription --name NAME [--expires-at UNIX_SECONDS]
cw credentials --cloud add ssh --name NAME --key-file PATH
cw credentials --cloud generate ssh --name NAME [--expires-at UNIX_SECONDS]
```

| Provider | How |
| --- | --- |
| `codex` | ChatGPT device-code sign-in; enable device code authorization in ChatGPT's Security settings first |
| `github` | Device-code sign-in to the Codewire GitHub App; prints the installation link |
| `claude` | Browser sign-in to Claude, paste the code shown; platform only |
| `openai`, `anthropic` | API key from stdin |
| `claude-subscription` | token from `claude setup-token`, from stdin; platform only; one-year expiry recorded |
| `ssh` | an Ed25519 key `cw` generates (public key printed), or an imported OpenSSH key file |

Guided `add`, `connect`, and `generate` ask for missing provider, name, and
SSH-file choices. Menus offer providers supported by the chosen store. After a
successful guided enrollment, `cw` offers optional profile assignment; choosing
or canceling that later step keeps the saved credential. Assignment binds the
exact saved identity, even if its name changes while the menu is open.

Repeating `connect` with an existing name reconnects after confirmation (`-y`).
Declining the reconnect stops the walkthrough without changing a profile.

### Inspect and change

```sh
cw credentials --cloud list [--output json]            # alias: ls
cw credentials --cloud get NAME|id:UUID
cw credentials --cloud rename NAME NEW_NAME
cw credentials --cloud rotate NAME [--expires-at UNIX_SECONDS]   # replace an API key or token; sets it Active
cw credentials --cloud revoke NAME
cw credentials --cloud delete NAME [--yes]             # on the platform, revoke first
```

### Profiles

```sh
cw credentials --cloud --profile NAME set codex|openai|anthropic|ssh CREDENTIAL   # creates the profile on first set
cw credentials --cloud --profile NAME unset SLOT
cw credentials --cloud --profile NAME get [--revision N]
cw credentials --cloud --profile NAME list
cw credentials --cloud --profile NAME generate ssh --name NAME    # generate and set in one step
cw credentials --cloud --profile NAME delete [--yes]
cw credentials --local --profile NAME revisions                   # local storage
cw credentials --cloud profiles list                               # alias: ls; the default first
cw credentials --cloud profiles default NAME                       # make NAME your default
```

Guided `credentials set` offers an existing profile or a new name, then a
compatible active credential for the selected provider. If none exists, it
offers the supported connection, API-key, or SSH setup route and returns to the
profile selection. Canceling before enrollment leaves the profile unchanged.

A profile names one identity per slot. The `codex` slot takes a Codex sign-in
or an OpenAI API key, `openai` an OpenAI API key, `anthropic` an API key, a
subscription token or a Claude sign-in, and `ssh` an SSH key. There is no
`github` slot: every profile includes your one GitHub connection. Each change
makes a new revision; environments keep the revision they selected.

Profiles are referenced from environments as `local:NAME` or `platform:NAME`
(`cw create --profile`, `cw update ENV --profile`).

Your first cloud profile becomes your default. A cloud `cw create` that names
no profile, in a flag or in `codewire.yaml`, uses it; `--no-profile` creates
without one. The default cannot be deleted: make another profile the default
first.
