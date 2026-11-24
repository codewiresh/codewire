---
title: Terminal sessions
description: Run commands that outlive your terminal, read their output later, type into them, wait for them in a script, and stop or restart them.
updated: 2026-11-24
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
environment, so a script can rely on it. When `--name` names a session that
has ended, `cw run` at a terminal asks whether to restart it, under its own
command; in a script, or with `--yes`, it prints the `cw restart` command
and exits non-zero. A session that is still running is never replaced.

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
SESSION  STATE    COMMAND
dev      Running  python3 -m http.server 8080
shell    Running  bash
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
| `Ctrl+B r` | Restart the session once it has exited, in `cw attach` |
| `Ctrl+B b` | Send a literal Ctrl+B |

A foreground `cw run` at a terminal ends when its command does, as
`cw shell` does. It prints one line on how the command ended and how to read
its output again or restart it, and `cw` exits with the command's status:

```text
Exited with status 3 · Output: cw --local logs app --session sh · Restart: cw --local restart app --session sh
```

The session stays listed with its saved output. Attach to it with `cw attach`
to restart it with `Ctrl+B r`.

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
SESSION  STATE    COMMAND
dev      Stopped  python3 -m http.server 8080
SESSION  STATE    COMMAND
dev      Running  python3 -m http.server 8080
```

The session keeps its ID and saved output across a restart, and its
siblings keep running. `cw stop app` without `--session` stops the whole
environment, which stops every session and keeps its name, its ID and its
saved output. Start each one again after `cw start app`:

```sh
cw stop app
cw start app
cw restart app --session dev
```

A stop ends everything the session started: its command, and every
process that command started, background jobs included. It asks them to
exit, waits 2 seconds, then ends whatever is left.

A session also ends when its command exits. Processes the command left
running end with it, even under `nohup` or `disown`, and the session's last
line of output names them. To keep a server running, run it in its own
session, or start it with `setsid`, which gives it a session of its own:

```sh
cw run --in app --name dev --detach -- npm run dev
cw exec --in app sh -c 'setsid my-server > /tmp/my-server.log 2>&1 < /dev/null &'
```

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
