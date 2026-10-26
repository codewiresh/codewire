---
title: Messages and inbox
description: Send a managed agent a task, read its inbox, wait for a reply in a script, steer or interrupt a turn, and recover a lost reply.
updated: 2026-10-26
weight: 3
---

A managed conversation, started with `cw run --agent`, takes its work as
messages. Each message gets an ID and an outcome, and the conversation's inbox
keeps the messages, the agent's replies and the results its workers report.
Set `ENV` to your environment's name; for starting the conversations, see
[Run and orchestrate](@/agents/run.md).

## Send a task and read the result

```sh
cw msg "$ENV" --session implement 'Include the failed-start recovery case.' --output json
cw inbox "$ENV" --session implement
cw wait --message "$MESSAGE_ID" --timeout 10m
cw inbox "$ENV" --session lead
```

`msg` sends a task, follow-up or reply and returns a message ID. When the
worker's task completes, a result notification appears in the lead's inbox: an
idle lead starts a turn on it, a busy lead queues it, a stopped lead adopts it
after restart. `cw wait --message` returns the final reply and fails on a
timeout, an error or an unknown outcome. Inspect the message before deciding
what to do next; Codewire never replays a completed or ambiguous task.

## Steer or interrupt

```sh
cw inbox "$ENV" --session implement --output json      # .driver.current_turn_id, capabilities
cw steer "$ENV" --session implement 'Focus on ownership and cleanup.' --turn-id "$TURN_ID"
cw interrupt "$ENV" --session implement
```

Codex accepts steering during a turn (`--turn-id` pins the turn you mean;
without it the current turn is used). Claude Code does not support steering,
and accepts an interrupt when its client advertises it. Both commands return
only after the agent accepts or refuses, so a nonzero exit means nothing
applied.

## Lost replies

If a platform control request loses its reply, observe the original request
instead of resending it:

```sh
cw agent observe "$ENV" --request-id "$ORIGINAL_REQUEST_ID" --output json
cw stop "$ENV" --session implement --cleanup-request-id "$ORIGINAL_REQUEST_ID"
```

## Related

- [Run and orchestrate](@/agents/run.md): launch a lead and workers, and
  recover after a stop.
- [Personal assistants](@/use-cases/personal-assistants.md): one long-running
  conversation you message from anywhere.
- [CLI: agents](@/reference/cli/agents.md)
