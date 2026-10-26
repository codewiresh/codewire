---
title: Troubleshooting hosted sandboxes
description: Find out why a hosted sandbox failed to create, start or connect, why a preview or a conversation does not respond, and how to recover.
updated: 2026-10-26
weight: 6
---

Start with the state and the checks `cw` runs itself:

```sh
cw info ENV            # state, and the error code after a failure
cw doctor              # build, platform connection, organization, SSH config
cw logs ENV --setup    # what setup did, step by step
```

The states and what to do in each are in
[Environment statuses](@/reference/environment-statuses.md); the error codes
the platform returns are in [Errors](@/reference/errors.md).

## A create or start is refused

| Message or code | Cause | Fix |
| --- | --- | --- |
| `quota_exceeded` | The organization already runs as many sandboxes as its plan allows | Stop or remove one; stopped sandboxes do not count |
| `resource_limit_exceeded` | The sandbox's CPU or memory would take the organization past its total | Stop a sandbox, or create a smaller one |
| `rate_limited` | More than 10 creates or starts in a minute | Wait, then retry |
| `missing_input` | No repository, image or preset was named | Add `--repo`, `--image` or `--preset` |
| `CPU is in cores, so N means N CPUs` | A millicore value from an old script | Use cores: `--cpu 2`, or `2000m` |

See [Resources and limits](@/environments/resources.md).

## Setup fails or stays in pending

`cw logs ENV --setup --follow` shows each step as it runs: cloning, the
install command and the startup script. A startup script must finish; a
server started there keeps setup waiting. Start servers in a session instead:
`cw run --in ENV --name server --detach -- npm run dev`. A failed clone of a
private repository usually means the GitHub App cannot reach it; see
[Git repositories](@/access/git.md).

## The sandbox is in error

`cw info ENV` names the error code. `cw daemon status ENV` and
`cw daemon repair ENV` inspect and reconcile the daemon inside without
recreating the sandbox; `cw stop ENV` then `cw start ENV` restarts it with
its disk. `cw prune` removes sandboxes stuck in `error`, `creating` or
`pending`.

## cw shell, SSH or VS Code does not connect

```sh
cw doctor tailnet ENV
```

reports which path it found (direct UDP, the UDP relay, DERP or the
WebSocket fallback) and how long each step took. A sandbox must be
`running`; `cw start ENV` first. If `ssh cw-cloud-NAME` fails but
`cw shell NAME` works, run `cw setup ssh` again to refresh the SSH config.
See [SSH and VS Code](@/access/ssh-and-vscode.md).

## A preview URL does not answer

- The sandbox must be running, and something must listen on the port inside
  it: `cw run --in ENV -- ss -ltn` lists the listeners.
- A server that exited does not answer; `cw logs ENV --session server` shows
  why it stopped.
- A `creator` or `org_members` preview asks you to sign in first; open it in
  a browser signed in to the same organization.

See [Ports and preview URLs](@/access/ports.md).

## A conversation does not resume after a start

`cw msg` says why. A conversation cannot resume when the sandbox's
credentials or secret sources changed since it started, its working
directory is gone, its last outcome is unknown, or it is a worker whose lead
must resume first. Start a new one with `cw run --agent`. See
[Run and orchestrate](@/agents/run.md#after-a-hosted-sandbox-stops-and-starts).

## Still stuck

Write to `hello@codewire.sh` with the sandbox's name, what you ran, and the
output of `cw doctor` and `cw info ENV`.
