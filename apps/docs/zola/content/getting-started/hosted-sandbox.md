---
title: Your first hosted sandbox
description: Sign in, create an environment on the Codewire platform, open a shell and run a managed agent.
weight: 3
---

A hosted sandbox is an environment the Codewire platform runs for your
organization: one VM, persistent storage, SSH and VS Code access, preview URLs
and managed agents. You need an [account and an organization](@/getting-started/account.md).

## 1. Sign in

```sh
cw setup
```

The wizard connects to `https://codewire.sh`, opens a browser sign-in (it
prints the URL and a code if the browser cannot open), saves your credentials
under `~/.config/cw/`, picks your organization (`--org SLUG` or
`--create-org NAME` for scripts) and writes the Codewire block into
`~/.ssh/config` so that `ssh`, `scp` and VS Code work. `--skip-ssh` leaves
your SSH config alone.

```sh
cw whoami
cw org list
```

## 2. Create the sandbox

```sh
cw env create --name my-app --image workspace
```

`workspace` is shorthand for the Codewire workspace image; any OCI image
works. Add repositories with `--repo URL[@branch]` (repeatable), or start from
a preset with `--preset SLUG`. An image, a repository or a preset is required.
Useful flags:

| Flag | Meaning |
| --- | --- |
| `--cpu`, `--memory`, `--disk` | resources, for example `--cpu 2 --memory 8GB --disk 40GB` |
| `--ttl 8h` | delete the sandbox after a lifetime |
| `--profile platform:NAME` | the [credential profile](@/guides/credentials.md) agents and Git use |
| `--secrets NAME`, `--user-secrets platform`, `--org-secrets` | [application secrets](@/guides/application-secrets.md) to deliver |
| `--install`, `--startup` | an install command and a startup script |
| `--no-wait` | return at once instead of watching startup |

The command follows setup until the environment is running. Later:

```sh
cw env list
cw env info my-app
cw env logs my-app        # setup logs
```

The same form is in the dashboard: open your organization and choose
**Create Sandbox**. The dashboard calls a hosted environment a *Sandbox*.

## 3. Use it

```sh
cw shell my-app
cw run my-app --name tests --no-tty -- make test
cw wait my-app tests
cw logs my-app tests
```

`cw vscode my-app` opens it in VS Code over SSH, and `ssh cw-my-app` works
after `cw setup`; see [SSH, VS Code and files](@/guides/ssh-and-vscode.md).

Publish a port as an HTTPS preview URL:

```sh
cw env port add 3000 --label web --access org_members -e my-app
```

## 4. Run an agent

Managed agents need a credential profile with a provider credential for the
agent: the `codex` slot (or an OpenAI API key) for Codex, the `anthropic` slot
for Claude Code. Create one once, then create the sandbox with
`--profile platform:NAME`, or add it later with
`cw env update my-app --profile platform:NAME`.

```sh
cw run my-app --name lead --agent codex --detach --prompt 'Review this repository and list the three riskiest files.'
cw inbox my-app lead                       # the conversation so far
cw wait --message MESSAGE_ID --timeout 10m # the reply to one message
cw msg my-app lead 'Now propose tests for the first one.'
```

See [Orchestrate agents](@/guides/run-agents.md) for workers, steering and
recovery.

## 5. Stop or delete

```sh
cw env stop my-app     # releases compute; workspace storage stays
cw env start my-app
cw env rm my-app       # deletes it at once, no prompt
```

Billing is per second of running compute; see
[Plans and billing](@/reference/subscription-plans.md).
