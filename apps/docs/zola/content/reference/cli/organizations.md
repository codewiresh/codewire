---
title: Organizations
description: setup, login, logout, whoami, org, api-keys and cost.
updated: 2026-11-11
weight: 7
aliases: ["/cli/account"]
---

## cw setup

```sh
cw setup [--org ID_OR_SLUG | --create-org NAME [--org-slug SLUG]] [--skip-ssh]
cw setup --local [--from DIR] [--replace]
```

The hosted wizard: choose the server (`--server`, `CODEWIRE_SERVER_URL`, the
saved configuration, or `https://codewire.sh`), sign in through the browser
(the URL and code are printed), save credentials, choose or create the default
organization, and write the OpenSSH integration (as `cw setup ssh` does)
unless `--skip-ssh`. With one organization
it is picked automatically; with several, `--org` or a picker.

`--local` installs and verifies the local VM runtime this release pins
instead of signing in. `--from DIR` installs a runtime directory built from
the same source (development builds), and `--replace` overwrites a different
installed runtime.

Example:

```sh
cw setup --local
```

```text
Downloading the local VM runtime (6 files, 186 MiB)...
Local VM runtime installed (e818b56a224a).
```

## cw login, logout, whoami

```sh
cw login [--org ID_OR_SLUG]
cw logout
cw whoami [--output json]
```

`login` needs a configured server (run `setup` once, or pass `--server`).
`logout` asks the server to end the sign-in, then removes it and the saved
configuration from this machine. It says "Logged out" only when the server
confirmed the sign-in ended. When it could not confirm (the server was
unreachable or refused), the sign-in is still removed from this machine, but
`logout` exits non-zero, names the reason, and says until when the sign-in's
access token stays valid. `logout` never ends an API key: with
`CODEWIRE_API_KEY` set it says so; delete the key with `cw api-keys delete`.

## cw org

```sh
cw org list [--output json]            # alias: ls
cw org current
cw org set [ID_OR_SLUG]                # also: cw org, with one organization
cw org create [NAME] [--slug SLUG]
cw org invite [EMAIL] [--role owner|admin|member] [--org ID_OR_SLUG]   # prints the invitation link once
cw org delete ID_OR_SLUG [--yes]       # owner only; asks you to type the name
```

## cw api-keys

```sh
cw api-keys create [NAME] [--expires DAYS]   # 0 = never; the key is printed once
cw api-keys list
cw api-keys delete KEY_ID
```

Keys act in the current organization. Use one with `CODEWIRE_API_KEY`.

## cw cost

```sh
cw cost [--org SLUG_OR_ID] [--output json]
```

Usage and billing overview for the organization.

At an interactive terminal, omitting the organization name, invitation email,
or API-key name opens a walkthrough. Invitations offer a role menu; API keys
offer expiry choices. The walkthrough shows the owning organization and asks
for confirmation before creating anything. Supplied flags skip their questions.
`cw org set` without a target offers a searchable organization list.
Without a terminal, name these values explicitly; stdin is never consumed as
metadata.
