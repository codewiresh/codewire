---
title: Sessions
description: Run, list, attach to, and read durable environment sessions.
---

Every durable session belongs to one Codewire environment. Pass the environment
as the first positional argument or select it with `cw use`.

## Run

```bash
cw run [ENV] [--workdir DIR] [--env KEY=VALUE] [--tty|--no-tty] \
  [--detach] -- COMMAND [ARG...]
```

Examples:

```bash
cw run my-app -- cargo test
cw run --no-tty my-app -- sh -lc 'printf ready'
cw run --detach my-app -- codex
```

A foreground run streams retained output and fails when the durable command
exits unsuccessfully. `--detach` returns after launch.

## List

```bash
cw list my-app
cw list my-app --output json
```

## Attach

```bash
cw attach my-app
cw attach my-app <session-id>
cw attach my-app --session <session-id>
```

When no session is supplied, one session is selected automatically and
multiple sessions open the picker. Detach without stopping the session with
`Ctrl+B d`.

Navigation uses:

- `Ctrl+B h` / `Ctrl+B l` for previous/next session
- `Ctrl+B k` / `Ctrl+B j` for previous/next environment
- `Ctrl+B r` to restart a completed session
- `Ctrl+B w` to show environments

## Logs

```bash
cw logs my-app <session-id>
cw logs --follow my-app <session-id>
cw logs --tail 100 my-app <session-id>
cw logs --raw my-app <session-id>
```

Output is durable across CLI disconnects and supported local environment
stop/start cycles.

## Shell

```bash
cw shell my-app
```

This creates an interactive shell as another environment-owned session.
`cw shell --stdio my-app` is reserved for the OpenSSH and VS Code proxy path.
