---
title: Terminal sessions
description: Run commands that outlive your terminal, read their output later, type into them, wait for them in a script, and stop or restart them.
updated: 2026-10-26
weight: 1
aliases: ["/guides/sessions"]
---

A session is a process that belongs to the environment, not to your
terminal. It keeps running when you detach, close the laptop or lose the
connection, and its output is saved. Everything in an environment runs in
one: `cw shell`, `cw run claude`, a dev server, a test run. The
[concepts page](@/agents/_index.md) explains the model; this
page shows the commands.

The output below is from a real run in a local VM named `app`. The same
commands work in a hosted sandbox.

## Start a session in the background

```sh
cw run --in app --name dev --detach -- python3 -m http.server 8080
```

```text
✓ Started session app/dev · local VM
→ cw --local attach app --session dev
```

`--name` names the session; without it, the session is named after the
command (`python3`, then `python3-2`). A name is never reused in an
environment, so a script can rely on it.

## Type into a session without attaching

Start a shell as a session, then send it lines:

```sh
cw run --in app --name shell --tty --detach -- bash
cw send app --session shell 'echo hello from send'
cw logs app --session shell
```

```text
Input written to session-a09621a6-d205-4ebb-8a6c-045c7cab5f19
codewire@codewire:/workspace/my-app$ echo hello from send
hello from send
```

`cw send` adds a newline unless you pass `--no-newline`; `--key ctrl-c`
sends a key. Managed agent conversations take `cw msg` instead.

## List and read

```sh
cw ls app
```

```text
NAME   STATE    MODE    PARENT  SESSION                                       COMMAND
dev    Running  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
shell  Running  normal  -       session-a09621a6-d205-4ebb-8a6c-045c7cab5f19  bash
```

`cw logs app --session dev` prints what a session has written so far, also
after it has exited and after the environment was stopped and started;
`--follow` keeps streaming and `--tail N` shows the last lines.

## Attach and detach

```sh
cw attach app --session dev
```

attaches your terminal to a running session. Press **Ctrl-B**, then **d**, to
detach and leave it running.

| Keys | Action |
| --- | --- |
| `Ctrl+B d` | Detach; the session keeps running |
| `Ctrl+B h` / `Ctrl+B l` | Previous / next session in this environment |
| `Ctrl+B k` / `Ctrl+B j` | Previous / next environment |
| `Ctrl+B w` | Show the environment list |
| `Ctrl+B r` | Restart the session once it has exited |
| `Ctrl+B b` | Send a literal Ctrl+B |

## Wait in a script

A foreground `cw run` streams the output and fails when the command fails:

```sh
cw run --in app --no-tty -- sh -c 'echo building; exit 3'
```

```text
✓ Started session app/sh · local VM
building
session exited with code 3
```

and `cw` exits 1. For a detached session, `cw wait` does the same once it
finishes:

```sh
cw run --in app --name tests --no-tty --detach -- sh -c 'sleep 2; echo 12 passed'
cw wait app --session tests --timeout 1m
```

```text
✓ Started session app/tests · local VM
12 passed
```

`cw wait` succeeds only after a zero exit; a non-zero exit, a timeout or an
unknown outcome fails.

## Stop and restart one session

```sh
cw stop app --session dev
cw restart app --session dev
```

```text
NAME  STATE    MODE    PARENT  SESSION                                       COMMAND
dev   Stopped  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
NAME  STATE    MODE    PARENT  SESSION                                       COMMAND
dev   Running  normal  -       session-5c7443a7-2a7e-409f-b684-bd74c8b580b5  python3 -m http.server 8080
```

The session keeps its ID and saved output across a restart, and its
siblings keep running. `cw stop app` without `--session` stops the whole
environment, which ends every session; start them again after
`cw start app`.

## Select an environment once

```sh
cw use app
```

```text
✓ Current environment: app
  local VM · running
  2 vCPU · 4 GiB RAM · 20 GiB disk
  Credentials: none
```

After that, session commands work without the environment name:
`cw run -- npm test`, `cw logs --session dev`. `cw current` shows the
selection.

## Browser terminal

The Sandbox page in the dashboard opens a terminal in the environment: up to
eight tabs that you can rename, disconnect from and reopen, with the recent
output replayed. It is the same daemon session engine `cw shell` uses.

## Related

- [CLI reference: Sessions](@/reference/cli/access.md) for every flag.
- [Run and orchestrate](@/agents/run.md) for managed conversations.
