---
title: Personal assistants
description: Keep an agent running in a hosted sandbox with your project, message it from any terminal, and read its answers later; it remembers the conversation.
updated: 2026-11-08
weight: 4
---

Keep an agent running somewhere that is not your laptop, with your project
and tools beside it, and talk to it when you need it: from your desk, from
another machine, or from a script. The conversation lives in the sandbox, so
the agent remembers what you asked, and its answers wait for you.

The output below is from a real run on a Codewire platform. Your IDs will
differ.

## 1. Give it a home

```sh
cw create --name assistant --image workspace \
  --repo https://github.com/octocat/Hello-World --profile platform:agents-dev
```

```text
assistant · cloud VM
  2 vCPU · 8 GiB RAM · 80 GiB disk
  Credentials: platform:agents-dev
  ✓ Cloning repositories  1s
  ✓ Setup complete
✓ Environment assistant created · cloud VM
```

The [credential profile](@/secrets/credentials.md) gives the agent its
provider; the key stays outside the sandbox. A hosted sandbox keeps running
when your laptop sleeps. Leave out `--ttl` so it stays, and consider
`cw protect assistant` so it is not deleted by mistake.

## 2. Start the conversation

```sh
cw run --in assistant --name assistant --agent claude --detach \
  --prompt 'You are my assistant for the repository in /workspace/Hello-World. Answer in one or two sentences. Remember what I ask you across messages.'
```

```text
request 19015f6b-39da-49bf-a64f-6db5d50e59ef	session session-19015f6b-39da-49bf-a64f-6db5d50e59ef	message 10df51b8-1e07-83e7-b12e-f5c1d702787a	completed
```

```sh
cw wait --message 10df51b8-1e07-83e7-b12e-f5c1d702787a --timeout 10m
```

```text
Got it: I'll keep answers to one or two sentences and keep track of what you ask during this conversation. What would you like to know about the Hello-World repo?
```

## 3. Message it from anywhere

From any terminal signed in to your organization, or a script with an
[API key](@/organizations/api-keys.md):

```sh
cw msg assistant --session assistant 'Which files are in the repository, apart from .git?'
```

```text
✓ Message f935ead3-d93c-4ab1-b0b1-588f9ecaad86 running
  Conversation  assistant/assistant (managed)
→ cw wait --message f935ead3-d93c-4ab1-b0b1-588f9ecaad86
```

```sh
cw wait --message f935ead3-d93c-4ab1-b0b1-588f9ecaad86 --timeout 10m
```

```text
Apart from `.git`, the repository has one file: `README`.
```

It is one conversation, so the agent remembers:

```sh
cw msg assistant --session assistant 'What did I ask you a moment ago?'
cw wait --message 1a7c436e-b839-414f-aea6-1ded81f235b9 --timeout 10m
```

```text
You asked which files are in the repository apart from `.git`, and the only one is `README`.
```

Messages queue: send several, close the terminal, and read the answers when
you are back.

## 4. Catch up

```sh
cw inbox assistant --session assistant
```

```text
session-19015f6b-39da-49bf-a64f-6db5d50e59ef	generation 1
10df51b8-1e07-83e7-b12e-f5c1d702787a	completed
f935ead3-d93c-4ab1-b0b1-588f9ecaad86	completed
1a7c436e-b839-414f-aea6-1ded81f235b9	completed
```

`cw inbox ... --output json` includes each message's text and the agent's
reply. If the sandbox stops and starts again, the conversation resumes from
its saved session; see
[Run and orchestrate](@/agents/run.md#after-a-hosted-sandbox-stops-and-starts).

## Related

- [Coding agents](@/use-cases/coding-agents.md): agents that change code,
  one VM per task.
- [Agent skills](@/agents/skills.md): give the assistant the same skills
  every time.
- [Agents](@/agents/_index.md)
