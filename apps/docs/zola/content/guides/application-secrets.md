---
title: Application secrets
description: Store values such as DATABASE_URL in organization, personal or project scope, and select which ones an environment's processes receive.
weight: 7
---

An application secret is a named value your application reads from its
environment. Codewire stores it write-only and delivers it to the processes of
environments that select its scope. It is not the place for provider
credentials; see [Provider credentials](@/guides/credentials.md).

## Store values

Every `cw secrets` command names its store, `--cloud` or `--local`, and
exactly one scope, before the subcommand. `set` reads the value from a hidden
prompt or standard input.

```sh
cw secrets --cloud projects create development          # a named collection
cw secrets --cloud --project development set DATABASE_URL
cw secrets --cloud --project development list
cw secrets --cloud --project development rename DATABASE_URL DB_URL
cw secrets --cloud --project development delete DB_URL
cw secrets --cloud --organization set SENTRY_DSN       # owners and admins
cw secrets --cloud --user set APP_TOKEN                # personal, platform
cw secrets --local --user set APP_TOKEN                # personal, your machine
```

In the dashboard: the organization's **Secrets** page for the organization
scope and secret projects, and **Settings → Secrets** for personal values.
Lists show key names and timestamps only. Keys match
`[A-Za-z_][A-Za-z0-9_]*`; values are UTF-8 up to 64 KiB. Deleting a project
deletes every key in it and asks you to confirm (`--yes` in scripts).

## Select sources for an environment

```sh
cw create --name app --image workspace \
  --secrets development --user-secrets platform --org-secrets
cw update app --secrets development
cw update app --clear-secrets
```

Or in `codewire.yaml`:

```yaml
secrets:
  organization: true
  user: platform
  project: development
```

`cw secrets preview --file codewire.yaml` shows which key comes from which
source, without values. In the dashboard, **Create Sandbox** has
**Organization** and **Personal** checkboxes and a secret project picker.

## What the processes see

At every launch (setup, install and startup commands, shells, `cw run`
commands, managed agents) Codewire assembles the selected values into an
environment projection and passes them under their original names. If several
selected sources set the same key, the environment's own configuration wins,
then personal, then project, then organization. A changed value applies to the
next launch; a running process keeps what it had. Everything in the
environment, including root, can read these values.

Changing an environment's selected sources restarts it after confirmation;
workspace data stays. A hosted sandbox selects platform sources only; a local
VM may select local or platform ones.
