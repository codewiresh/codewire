---
title: Agents
description: msg, steer, interrupt and inbox for managed Codex and Claude Code conversations.
updated: 2026-10-26
weight: 4
aliases: ["/cli/agents"]
---

A managed conversation is started with `cw run --in ENV --agent codex|claude`;
see [Sessions](@/reference/cli/access.md#cw-run). These commands name the
environment as `ENV` or `--in ENV` (the selected environment when omitted)
and the session with `--session`.

## cw msg

```sh
cw msg [ENV] --session SESSION TEXT [--reply-to MESSAGE_ID] [-o json]
```

One text command for both kinds of session. `cw msg` looks up the session
before writing anything and acts on its recorded mode:

- A managed conversation receives a durable task, follow-up or reply through
  its driver. `cw msg` prints the message ID and its actual state; `cw wait
  --message ID` waits for its result. `--reply-to` threads it under an
  earlier message. After a hosted sandbox was stopped and started, the first
  `msg` resumes the conversation in the new sandbox.
- A normal terminal session, such as Claude Code or Codex in their own
  terminal UI, receives the text and Enter through its terminal input, and
  `cw msg` prints `Sent to terminal ENV/SESSION.` That acknowledges the write
  only: the program may be busy or showing a dialog, and there is no message
  ID to wait for. An unconfirmed write is never sent again automatically.

`--output json` adds a top-level `"delivery"`: `"managed"` beside the
message's fields, or `"terminal"`. A managed failure never falls back to
terminal input. `cw send` stays the raw input command, for keys and partial
text, and refuses managed conversations.

## cw steer

```sh
cw steer [ENV] --session SESSION TEXT [--turn-id TURN_ID] [-o json]
```

Steers the agent's current turn. `--turn-id` names the turn you expect (from
`cw inbox --output json`, `.driver.current_turn_id`); without it the current
turn is used. Codex supports steering; Claude Code does not. The command
returns only after the agent accepts or refuses. A normal terminal session
refuses `steer`; type into it with `cw msg`.

## cw interrupt

```sh
cw interrupt [ENV] --session SESSION [-o json]
```

Interrupts the current turn. Codex supports it natively; Claude Code when its
client advertises it. An idle conversation refuses.

## cw inbox

```sh
cw inbox [ENV] --session SESSION [-o json]
```

Shows the conversation's messages (the latest 100) and their results,
including the driver's current turn and capabilities in JSON. A worker's
completed task appears here, in its parent's inbox, as a result notification.

A normal terminal session has no structured inbox: `cw inbox` says so and
prints the exact `cw logs ENV --session SESSION` and `cw attach ENV --session
SESSION` commands that read and reattach it.

Example:

```sh
cw inbox pr-42 --session coordinator
```

```text
session-c82414ed-1903-4df5-accf-8d4a807939f5	generation 1
1741176a-fd28-8154-a867-051697803ea5	completed
1799dade-af95-4139-8d54-1446aaeb7adc	completed
```

`--output json` adds each message's text, state, result and error. See
[Coding agents](@/use-cases/coding-agents.md#several-agents-on-one-task).

## Message states

`cw inbox --output json` and `cw wait --message --output json` report a
message's `state`. `completed` is the only success; `error`, `interrupted`
and `unknown` are final failures, and `cw wait` exits nonzero for them and
for a timeout. A noel conversation on a trusted host can also report
`paused` while its environment is stopped; treat it like `running`.

## Flags that need --member

`--request-id` and `--expected-launch-generation` appear on these commands
but apply only with the global `--member` option, when controlling an
enrolled trusted host; see [Networking](@/reference/cli/networking.md).
