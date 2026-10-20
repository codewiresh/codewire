---
title: Sessions and agents
description: Durable sessions, managed Codex and Claude Code conversations, and how leads and workers exchange work.
weight: 3
---

A session is a process inside an environment: a shell, a command, or a managed
agent conversation. The environment owns it, so it keeps running when your
terminal closes, and you reattach, read its output or stop it from anywhere.

## Sessions

```sh
cw run claude --in my-app                            # Claude Code's own terminal UI, in session claude
cw run --in my-app -- cargo test                     # foreground: streams output, exits with the command's status
cw run --in my-app --name dev --detach -- npm run dev # background, named
cw run --in my-app --name shell --tty --detach -- sh  # an interactive shell you attach to later
cw ls my-app                                         # cw ls alone covers every environment
cw attach my-app --session dev                       # Ctrl-B, then D detaches
cw logs my-app --session dev --follow
cw wait my-app --session tests --timeout 10m
cw stop my-app --session dev
cw restart my-app --session dev
```

Names are unique within an environment. A foreground `run` fails when the
command exits unsuccessfully. `cw wait` succeeds only after it has observed a
zero exit, confirmed cleanup and drained the output; a timeout reports
unknown, never success. `cw send` writes input to a terminal or command
session and acknowledges the write; it does not tell you that a command
finished.

`cw stop ENV --session NAME` stops one session and asks at a terminal whether
to stop its running children; `--all` stops every descendant without asking.
`cw stop ENV` without `--session` stops the whole environment. Output is
retained across your disconnects and across an environment's stop and start.

## Managed agents

`cw run --agent codex` or `--agent claude` starts a managed conversation
instead of a command. Codewire drives the agent's own protocol, so you send
tasks and read replies rather than typing at a terminal:

```sh
cw run --in my-app --name lead --agent codex --detach --prompt 'Plan the change.'
cw msg my-app --session lead 'Also cover the migration.'   # a task, follow-up or reply
cw inbox my-app --session lead                   # messages and their results
cw wait --message MESSAGE_ID --timeout 10m       # the reply to one message
cw steer my-app --session lead 'Keep the public API stable.'
cw interrupt my-app --session lead
cw logs my-app --session lead                              # each turn's prompt, tools and reply
```

`--model` and `--effort` (`low`, `medium`, `high`, `xhigh`, `max`) are
optional; each agent otherwise uses its own defaults. Raw terminal input is
refused for a managed session; use `cw msg`, `cw steer` and `cw interrupt`.

| | Codex | Claude Code |
| --- | --- | --- |
| Steering mid-turn | yes | not supported |
| Interrupt | yes | when the client advertises it |
| Resume after stop | saved thread | saved session |

On a trusted Linux host, `--agent noel` runs the noel client with
`--model PROVIDER/ID`.

### Leads and workers

A conversation can launch others under itself with `--parent`. When a worker
finishes a task, a result notification lands in the parent's inbox: an idle
lead starts a turn on it, a busy lead queues it, a stopped lead adopts it after
restart. Notifications have deterministic IDs, so nothing is delivered twice.

```sh
cw run --in my-app --name implement --parent lead --agent codex --detach --prompt '...'
cw run --in my-app --name review --parent lead --agent claude --detach --prompt '...'
```

On a trusted host, a conversation's agent sees `CW_ENVIRONMENT` and
`CW_SESSION_ID`, so a lead can launch a worker under itself with
`cw run --in "$CW_ENVIRONMENT" --parent "$CW_SESSION_ID" --agent ...`.

### Which client runs, and with what permissions

A managed agent runs the first `codex` or `claude` on the environment's
`PATH`: the workspace image's client until you or the client updates it. A
trusted host runs the client you installed. A conversation keeps the client it
was launched with.

| Placement | Codex | Claude Code |
| --- | --- | --- |
| Hosted sandbox, local VM | full access, approvals off, working directory trusted | `--permission-mode auto`, so a headless turn can use tools; your settings and permission rules still apply, and `permissions.disableAutoMode` turns it off |
| Trusted host | full access, approvals off | your own default permission mode |

Codewire never passes an option that hides or skips the agent's permission
rules.

### Credentials

In a hosted sandbox or a local VM a managed agent uses the environment's
credential profile: the `codex` slot (or, without one, an OpenAI API key) for
Codex, the `anthropic` slot for Claude Code. The private material stays
outside the environment. See
[Secrets and credentials](@/concepts/secrets-and-credentials.md). A trusted
host uses the clients' own logins.

### Across a stop and start

A managed conversation in a hosted sandbox stops with the sandbox. After
`cw start`, `cw ls` still shows it, and the next `cw msg` or
`cw restart ENV --session NAME` resumes it: the agent starts again from its saved session with
its earlier turns. Whatever was in flight when the sandbox stopped is not
replayed. A conversation cannot resume when its selected credentials or
secrets changed, its working directory is gone, or its last outcome is
unknown; `cw msg` says why, and `cw run --agent` starts a new one.

See [Orchestrate agents](@/guides/run-agents.md) for a complete journey.
