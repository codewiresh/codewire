---
title: Account and organizations
description: setup, login, logout, whoami, org, api-keys and cost.
weight: 6
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

## cw login, logout, whoami

```sh
cw login [--org ID_OR_SLUG]
cw logout
cw whoami [--output json]
```

`login` needs a configured server (run `setup` once, or pass `--server`).
`logout` revokes the sign-in and removes the saved configuration.

## cw org

```sh
cw org list [--output json]            # alias: ls
cw org current
cw org set [ID_OR_SLUG]                # also: cw org, with one organization
cw org create NAME [--slug SLUG]
cw org invite EMAIL [--role owner|admin|member] [--org ID_OR_SLUG]   # prints the invitation link once
cw org delete ID_OR_SLUG [--yes]       # owner only; asks you to type the name
```

## cw api-keys

```sh
cw api-keys create NAME [--expires DAYS]   # 0 = never; the key is printed once
cw api-keys list
cw api-keys delete KEY_ID
```

Keys act in the current organization. Use one with `CODEWIRE_API_KEY`.

## cw cost

```sh
cw cost [--org SLUG_OR_ID] [--output json]
```

Usage and billing overview for the organization.
