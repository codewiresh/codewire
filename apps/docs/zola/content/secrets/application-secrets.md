---
title: Application secrets
description: Store values such as DATABASE_URL in organization, personal or project scope, and select which ones an environment's processes receive.
updated: 2026-10-26
weight: 2
aliases: ["/guides/application-secrets"]
---

An application secret is a named value your application reads from its
environment. Codewire stores it write-only and delivers it to the processes of
environments that select its scope. It is not the place for provider
credentials; see [Credentials](@/secrets/credentials.md).

## Try it

This run stores one value in a secret project, creates a sandbox that
selects the project, and reads the value inside it. The output is from a
real run; the value is a dummy.

```sh
cw secrets --cloud projects create docs-demo
printf 'postgres://app@db.internal/app\n' | cw secrets --cloud --project docs-demo set DATABASE_URL
cw secrets --cloud --project docs-demo list
```

```text
Secret project "docs-demo" created. (id: 8b9c5a2d-ea91-402e-9cff-69b4961960aa)
Secret DATABASE_URL set in project "docs-demo".
KEY                              CREATED                  UPDATED
DATABASE_URL                     2026-10-25T15:32:21Z     2026-10-25T15:32:21Z
```

Lists never show values. Select the project when creating the sandbox:

```sh
cw create --name app --image workspace --secrets docs-demo
```

```text
  Application-secret project: "platform:id:8b9c5a2d-ea91-402e-9cff-69b4961960aa"
  Organization application secrets: none
  Personal application secrets: none
  Credential profile: none
Application secrets are visible to the managed workload; provider credentials remain behind their supported handlers.
app · cloud VM
  2 vCPU · 8 GiB RAM · 10 GiB disk
  Credentials: none
  Secrets:     platform:docs-demo
```

Every process in the sandbox gets it under its own name:

```sh
cw run --in app --name env --no-tty -- sh -c 'echo "$DATABASE_URL"'
```

```text
✓ Started session app/env · cloud
postgres://app@db.internal/app
```

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

`cw secrets --cloud preview --file codewire.yaml` shows which key comes from
which source, without values:

```text
PLACEMENT  KEY                              SOURCE                   OVERRIDDEN
platform   DATABASE_URL                     project                  -
``` In the dashboard, **Create Sandbox** has
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
