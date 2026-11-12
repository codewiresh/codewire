---
title: Supported agents
description: The coding agents Codewire runs as managed conversations, how each one signs in, what each supports, and how to run any other agent.
updated: 2026-10-26
weight: 1
---

Codewire runs two kinds of agent session:

- **Managed conversations** (`cw run --agent`): Codewire starts the agent,
  queues your messages, records its replies and the results of its workers,
  and resumes it after a stop. Claude Code and Codex run this way.
- **Terminal sessions** (`cw run claude`, `cw run -- gemini`): the agent's
  own interface in a durable terminal you attach to. Any agent that runs in a
  Linux terminal works.

## Claude Code and Codex

| | Claude Code | Codex |
| --- | --- | --- |
| Managed | `cw run --agent claude` | `cw run --agent codex` |
| Interactive | `cw run claude` | `cw run codex` |
| Signs in with | the `anthropic` slot: an Anthropic API key, a Claude subscription token, or a Claude sign-in | the `codex` slot (a ChatGPT sign-in), or else the `openai` slot (an OpenAI API key) |
| Steer a running turn | no | yes, `cw steer` |
| Interrupt a turn | when its client allows it | yes, `cw interrupt` |
| `--model`, `--effort` | yes | yes |

Both are installed in the [workspace image](@/environments/workspace-image.md).
In a hosted sandbox or a local VM the agent never holds your key: the
environment's credential profile names which credential fills each slot, and
a broker outside the VM adds it to the agent's requests. See
[Credentials](@/secrets/credentials.md). On a local VM you can also sign in
to the agent yourself inside the VM.

A trusted Linux host uses the agents installed on your own `PATH`, signed in
as you, and also runs `--agent noel --model PROVIDER/ID`.

## Other agents

Gemini CLI (`gemini`) and Aider (`aider`) are installed in the workspace image
too, and any other agent can be installed in an environment. They run as
terminal sessions:

```sh
cw run --in ENV --name gemini --tty --detach -- gemini
cw attach ENV --session gemini        # Ctrl-B, then d detaches
```

They keep running when you disconnect, like every session, but Codewire does
not queue messages for them or broker their keys; give them their keys as
[application secrets](@/secrets/application-secrets.md).

## Related

- [Run and orchestrate](@/agents/run.md)
- [Messages and inbox](@/agents/messages.md)
- [Coding agents](@/use-cases/coding-agents.md)
