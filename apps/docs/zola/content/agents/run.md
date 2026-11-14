---
title: Run and orchestrate
description: Launch a lead and workers, send tasks, read results, steer or interrupt a turn, and recover after a disconnect or a stop.
updated: 2026-11-14
weight: 2
aliases: ["/guides/run-agents"]
---

This journey works the same in a hosted sandbox, a local VM and a trusted
host. Set `ENV` to your environment's name.
For a short worked example with the output of every step, see
[Coding agents](@/use-cases/coding-agents.md#several-agents-on-one-task).

## Before you start

- **Hosted sandbox or local VM**: the environment needs a credential profile
  with a provider for each agent: the `codex` slot (or an OpenAI API key) for
  Codex, the `anthropic` slot for Claude Code. See
  [Credentials](@/secrets/credentials.md), then
  `cw create ... --profile platform:NAME` or
  `cw update ENV --profile platform:NAME` (`local:NAME` on a local VM).
- **Trusted host**: install Codex and Claude Code on your `PATH` and sign in
  to them yourself; the host uses your ordinary `HOME`.

## Launch a lead and two workers

```sh
cw run --in "$ENV" --name lead --agent codex --detach --output json \
  --prompt 'Coordinate the assigned change and review worker results.'
cw run --in "$ENV" --name implement --parent lead --agent codex --detach --output json \
  --prompt 'Implement the assigned change and report the result.'
cw run --in "$ENV" --name review --parent lead --agent claude --detach --output json \
  --prompt 'Review the assigned change without editing files.'
cw ls "$ENV"
```

Each launch returns a session ID; a launch with `--prompt` also returns a
message ID. Names are unique within the environment. A worker's parent must be
a running managed conversation in the same environment. `--model` and
`--effort` are optional.

## Talk to them

Send tasks, read results, and steer or interrupt a turn with `cw msg`,
`cw inbox`, `cw wait`, `cw steer` and `cw interrupt`; see
[Messages and inbox](@/agents/messages.md).

## Run commands alongside

```sh
cw run --in "$ENV" --name check --detach --no-tty -- make test
cw wait "$ENV" --session check --timeout 10m
cw logs "$ENV" --session check
cw run --in "$ENV" --name shell --tty --detach -- sh
cw send "$ENV" --session shell 'pwd'
cw attach "$ENV" --session shell   # Ctrl-B, then d detaches
```

`wait` succeeds only after a zero exit, confirmed cleanup and drained output.
Raw input (`send`, `attach`) is refused for managed conversations.

## Reconnect, stop, restart

Closing your terminal changes nothing in the environment:

```sh
cw ls "$ENV"
cw logs "$ENV" --session implement
cw inbox "$ENV" --session implement
```

`cw interrupt` ends an active turn. `cw stop "$ENV" --session NAME` cancels
the whole conversation (at a terminal it asks about running children; `--all`
stops them too), and `cw restart "$ENV" --session NAME` resumes the retained
conversation from its saved session. Without `--session`, `stop` and
`restart` act on the whole environment. An
interrupted turn can remain unknown; restarting does not resubmit it.

### After a hosted sandbox stops and starts

A managed conversation stops with its sandbox. After `cw start`, it is
still listed, and `cw msg` or `cw restart ENV --session NAME` resumes it in the new sandbox with
its earlier turns; a `cw wait --message` for a message sent before the stop
completes once the conversation has resumed. What was in flight is not
replayed. If the environment refuses the resume before anything ran (for
example the launch window expired), `cw msg` says so and sending again
resumes it.

A conversation cannot resume, and `cw msg` says why, when the environment's
selected credentials or secret sources changed since it started, its working
directory is gone, its last outcome is unknown, or it is a child (resume the
parent). Start a new one with `cw run --agent`.

## Clean up

```sh
cw stop "$ENV" --session review
cw stop "$ENV" --session implement
cw stop "$ENV" --session lead --all
cw stop "$ENV"
```

## On a trusted Linux host

A conversation launched on a host by its user sees `CW_ENVIRONMENT` and
`CW_SESSION_ID`, so a lead can launch its own workers with
`cw run --in "$CW_ENVIRONMENT" --parent "$CW_SESSION_ID" --agent codex ...`.
A host also runs `--agent noel --model PROVIDER/ID`.

A host enrolled in Codewire Mesh can be driven from another Linux machine
with `cw --member NAME run|list|logs|wait|stop|restart|msg|steer|interrupt|inbox`,
using canonical `session-UUID` IDs. See
[CLI: networking](@/reference/cli/networking.md).

## FAQ

**Which agents work?** Codewire manages Codex and Claude Code conversations
(`cw run --agent`), and noel on a trusted Linux host. Any tool that runs in a
Linux terminal runs in an environment as an ordinary session.
