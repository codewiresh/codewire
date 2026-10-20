---
title: Agents
description: msg, steer, interrupt and inbox for managed Codex and Claude Code conversations.
weight: 3
---

A managed conversation is started with `cw run --in ENV --agent codex|claude`;
see [Sessions](@/cli/sessions.md#cw-run). These commands address it by `ENV`
and `SESSION`; `interrupt` names the session with `--session`.

## cw msg

```sh
cw msg [ENV] SESSION TEXT [--reply-to MESSAGE_ID] [-o json]
```

Sends a task, follow-up or reply to the conversation and returns a message ID.
`--reply-to` threads it under an earlier message. After a hosted sandbox was
stopped and started, the first `msg` resumes the conversation in the new
sandbox.

## cw steer

```sh
cw steer [ENV] SESSION TEXT [--turn-id TURN_ID] [-o json]
```

Steers the agent's current turn. `--turn-id` names the turn you expect (from
`cw inbox --output json`, `.driver.current_turn_id`); without it the current
turn is used. Codex supports steering; Claude Code does not. The command
returns only after the agent accepts or refuses.

## cw interrupt

```sh
cw interrupt [ENV] --session SESSION [-o json]
```

Interrupts the current turn. Codex supports it natively; Claude Code when its
client advertises it. An idle conversation refuses.

## cw inbox

```sh
cw inbox [ENV] SESSION [-o json]
```

Shows the conversation's messages (the latest 100) and their results,
including the driver's current turn and capabilities in JSON. A worker's
completed task appears here, in its parent's inbox, as a result notification.

## Message states

`cw inbox --output json` and `cw wait --message --output json` report a
message's `state`. `completed` is the only success; `error`, `interrupted`
and `unknown` are final failures, and `cw wait` exits nonzero for them and
for a timeout. A noel conversation on a trusted host can also report
`paused` while its environment is stopped; treat it like `running`.

## Flags that need --member

`--request-id` and `--expected-launch-generation` appear on these commands
but apply only with the global `--member` option, when controlling an
enrolled trusted host; see [Networking](@/cli/networking.md).
