---
title: Coding agents
description: Give each coding agent its own VM with your project, run several on one task, and come back to their results later.
updated: 2026-10-26
weight: 3
aliases: ["/use-cases/parallel-agents"]
---

Let Claude Code or Codex work with every permission it asks for, running
installs, tests and Docker, inside a VM that holds only your project. Start
one VM per task, detach, and come back when it is done.

## Interactive: the agent's own terminal

On your machine, with no account:

```sh
cw create --local --name fix-login --path .
cw run claude --in fix-login
```

```text
✓ Started Claude Code in fix-login/claude · local VM
  Detach: Ctrl-B, then d · Reconnect: cw --local attach fix-login --session claude
```

Claude Code opens in the VM, in your project folder, which is mounted live:
you see its edits in your editor as it makes them. Because the VM holds
only your project, you can let it run commands without approving each one.
Press **Ctrl-B**,
then **D**, to leave it working; `cw attach fix-login --session claude`
brings you back. `cw run codex --in fix-login` does the same with Codex.

For a second task, create a second VM. Each has its own processes, ports and
dependency folders, so two agents never fight over `node_modules` or a port.

## Unattended: a managed conversation

A managed conversation takes a task, queues follow-ups and records each
result, so you can hand off work and read the answer later, from a script if
you like. The environment needs a [credential profile](@/secrets/credentials.md)
with a provider for the agent; Codewire keeps the provider key outside the
VM.

This example is from a real run in a hosted sandbox created with
`--profile platform:agents-dev`, a profile with an Anthropic provider. Your
IDs will differ.

```sh
cw run --in pr-42 --name review --agent claude --detach \
  --prompt 'Read /workspace/Hello-World and say in one sentence what the repository contains. Do not edit files.'
```

```text
request 9f403fc3-1977-4580-8dc1-3ce48e24acdd	session session-9f403fc3-1977-4580-8dc1-3ce48e24acdd	message f78df504-2dbb-8f7e-9c2b-3f714849dddc	completed
```

Wait for the reply to that message:

```sh
cw wait --message f78df504-2dbb-8f7e-9c2b-3f714849dddc --timeout 10m
```

```text
The repository contains a single `README` file with the text "Hello World!"
```

Send a follow-up in the same conversation with
`cw msg pr-42 --session review 'Now ...'`, and list its messages with
`cw inbox pr-42 --session review`.

## Several agents on one task

Split a task across agents: a lead that coordinates, and workers that each
do one part. When a worker finishes, Codewire delivers its result to the
lead as a new message, so the lead can act on it while you are away. The
output below is from a real run in the same kind of hosted sandbox.

### Start the lead

```sh
cw run --in pr-42 --name coordinator --agent claude --detach \
  --prompt 'You coordinate workers. When a worker result arrives, reply with one line that starts with SUMMARY: and repeats it.'
```

```text
request c82414ed-1903-4df5-accf-8d4a807939f5	session session-c82414ed-1903-4df5-accf-8d4a807939f5	message 1741176a-fd28-8154-a867-051697803ea5	completed
```

### Start a worker under it

`--parent` makes the new conversation a worker of the lead:

```sh
cw run --in pr-42 --name files --parent coordinator --agent claude --detach \
  --prompt 'Count the files in /workspace/Hello-World, excluding .git, and reply with only the number.'
```

```text
request 5d620929-d43c-4e46-8491-3aa0d0f277ed	session session-5d620929-d43c-4e46-8491-3aa0d0f277ed	message 1f26fd96-3902-80fd-b6e7-e43f9b7b1269	completed
```

Start as many workers as the task needs, each with its own name. A worker
can be Codex or Claude Code regardless of what the lead is.

### Watch the result arrive

```sh
cw wait --message 1f26fd96-3902-80fd-b6e7-e43f9b7b1269 --timeout 5m
```

```text
1
```

That is the worker's reply. Codewire then delivers it to the lead, whose
inbox gains a second message:

```sh
cw inbox pr-42 --session coordinator
```

```text
session-c82414ed-1903-4df5-accf-8d4a807939f5	generation 1
1741176a-fd28-8154-a867-051697803ea5	completed
1799dade-af95-4139-8d54-1446aaeb7adc	completed
```

The second message is the worker's result. The lead's reply to it is that
message's `result`, in the JSON form of the inbox:

```sh
cw inbox pr-42 --session coordinator --output json
```

```text
"result": "SUMMARY: Worker \"files\" (session session-5d620929-d43c-4e46-8491-3aa0d0f277ed) completed message 1f26fd96-3902-80fd-b6e7-e43f9b7b1269 with result: \"1\"."
```

(an excerpt: the second entry of `messages`.)

### See the tree

```sh
cw ls pr-42
```

`cw ls` shows each conversation with `MODE` `managed` and the worker's
`PARENT` (other sessions omitted):

```text
NAME           STATE    MODE     PARENT       SESSION                                       COMMAND
coordinator    Running  managed  -            session-c82414ed-1903-4df5-accf-8d4a807939f5  managed agent
files          Running  managed  coordinator  session-5d620929-d43c-4e46-8491-3aa0d0f277ed  managed agent
```

### What the lead does with results

An idle lead starts a turn on each result as it arrives; a busy lead queues
it; a lead that was stopped picks it up after a restart. Codewire never
replays a task that completed or whose outcome is unknown. Send the lead more
instructions with `cw msg`, or redirect a running Codex turn with `cw steer`.
See [Run and orchestrate](@/agents/run.md).

## Local or hosted

| | Local VM | Hosted sandbox |
| --- | --- | --- |
| Account | none | an organization |
| Agent credentials | your own sign-in inside the VM, or a local credential profile | a platform credential profile |
| Keeps running | while your machine is on | when your laptop sleeps |
| Reach it from | this machine | any device, over SSH or the browser |

## Related

- [Run and orchestrate](@/agents/run.md): steering, interrupting and
  recovering a conversation.
- [Credentials](@/secrets/credentials.md)
