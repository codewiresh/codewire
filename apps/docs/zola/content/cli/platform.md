---
title: Platform Commands
description: CLI commands for codewire.sh integration — sandbox environments, orgs, and billing.
---


Platform mode connects the CLI to codewire.sh for sandbox environment management, org administration, and remote access. All platform commands require authentication via `cw setup` or `cw login`.

## Setup

### setup

Interactive wizard that configures platform mode. Walks you through server URL, login, org selection, and GitHub connection.

```bash
cw setup
```

Run this once to get started. Your configuration is saved to `~/.codewire/platform.json`.

## Authentication

### login

Authenticate with the Codewire platform.

```bash
cw login
```

### logout

Sign out and clear stored credentials.

```bash
cw logout
```

### whoami

Show the currently authenticated user.

```bash
cw whoami
```

## Organizations

### org list

List all organizations you belong to.

```bash
cw org list
```

### org create

Create a new organization.

```bash
cw org create <name> --slug <slug>
```

### org delete

Delete an organization (owner only).

```bash
cw org delete <slug>
```

### org invite

Invite a member to an organization.

```bash
cw org invite <email> [--org <slug>] [--role <role>]
```

## Environments

### env create

Create a sandbox environment from a repository or template.

```bash
cw env create github.com/your-org/your-repo
cw env create --preset python --name fix-auth
```

### env list

List environments in the current org.

```bash
cw env list
cw env list --org <slug>
```

### env info / start / stop / rm

Inspect or change the lifecycle of a sandbox environment.

```bash
cw env info <env>
cw env start <env>
cw env stop <env>
cw env rm <env>
```

### shell / run

Connect to an environment shell or run a durable foreground command.

```bash
cw shell <env>
cw run --no-tty <env> -- <command> [args...]
```

## Running Commands

### run

`cw run` creates a durable session owned by the selected or named environment.

```bash
cw run [ENV] -- <command> [args...]
```

```bash
cw run -- claude "fix the tests"
cw run --no-tty fix-auth -- make test
cw run --detach fix-auth -- codex
```

{% aside(kind="note") %}
  Local Docker/Lima environments use the same session grammar after creation
  with `cw env create --local`. See [Sessions](@/cli/sessions.md).
{% end %}

## Secrets

### secrets

Manage organization secrets from the CLI.

```bash
cw secrets [--org <slug>]
```

## Billing & Cost

### cost

View organization billing and sandbox environment usage.

```bash
cw cost [--org <slug>]
```


## GitHub

### github login

Authenticate with GitHub for private repo access.

```bash
cw github login
```

### github logout

Remove stored GitHub credentials.

```bash
cw github logout
```

### github status

Check GitHub authentication status.

```bash
cw github status
```

## Utilities

### update

Automatic updates are unavailable during the private preview. Update your
authorized source checkout and reinstall from its root:

```bash
make cli-install
```

### completion

Generate shell completions.

```bash
cw completion <bash|zsh|fish>
```

```bash
# Add to your shell profile
eval "$(cw completion zsh)"
```
