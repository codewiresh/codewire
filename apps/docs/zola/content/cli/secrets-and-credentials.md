---
title: Secrets and credentials
description: cw secrets for application secrets and cw credentials for provider credentials and profiles.
weight: 4
---

Both commands name their store before the subcommand: `--local` (the
protected store on your machine; Linux and macOS) or `--cloud` (the
platform). At a terminal `cw` asks when neither is given; scripts and JSON
output must pass one. Values are read from a hidden prompt or standard input,
never from arguments.

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

Key operations need exactly one scope flag; nothing is inferred from
`cw use` or `codewire.yaml`. `set` reads the value from a hidden prompt or
stdin (one trailing newline removed); keys match `[A-Za-z_][A-Za-z0-9_]*` and
values are UTF-8 up to 64 KiB. `projects delete` removes every key in the
project and needs `--yes` when not interactive. `preview` shows which key
would come from which source for a project file, without values.

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

Repeating `connect` with an existing name reconnects after confirmation
(`-y`).

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
cw credentials --cloud profiles list                               # alias: ls
```

A profile names one identity per slot. The `codex` slot takes a Codex sign-in
or an OpenAI API key, `openai` an OpenAI API key, `anthropic` an API key, a
subscription token or a Claude sign-in, and `ssh` an SSH key. There is no
`github` slot: every profile includes your one GitHub connection. Each change
makes a new revision; environments keep the revision they selected.

Profiles are referenced from environments as `local:NAME` or `platform:NAME`
(`cw create --profile`, `cw update ENV --profile`).
