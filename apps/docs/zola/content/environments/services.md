---
title: Services after a start
description: Bring a database and a dev server back every time an environment starts, with a startup script that starts them and exits.
updated: 2026-11-19
weight: 6
---

A stop ends every process in an environment. Files under `/workspace` and
`/home/codewire` stay, and so do Docker's containers, images and volumes,
but nothing runs again until something starts it. The startup script does
that: it runs when the environment is created, and again at every
`cw start`.

A start waits for the startup script to finish, so the script starts each
service in the background and exits. Start a server with both of these, or
the start waits for it to end:

- `setsid`, so it runs in a session of its own;
- its own log file and no input: `> /tmp/dev.log 2>&1 < /dev/null`.

`nohup` alone is not enough, as [Terminal sessions](@/access/sessions.md)
explains. A container needs neither: `docker start`, or `docker run -d` the
first time, returns once the container is up.

## Postgres in Docker and a dev server

```yaml
version: 1
image: workspace
working_directory: /workspace/app

repositories:
  - source: https://github.com/owner/app
    destination: app

install_command: pnpm install
startup_script: |
  docker start db 2>/dev/null || docker run -d --name db -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:16
  cd /workspace/app && setsid pnpm dev > /tmp/dev.log 2>&1 < /dev/null &
```

The first boot creates the `db` container, and every later start starts that
same container, with its data. The dev server's output is in `/tmp/dev.log`:

```sh
cw exec --in app tail -f /tmp/dev.log
```

## What keeps a start waiting

- `startup_script: pnpm dev`: the dev server never finishes, so the start
  never does.
- `pnpm dev &` on its own: the server keeps the script's output open, and the
  start waits until the server ends.

`cw logs app --setup --follow` shows the startup script while it runs.

## A server you watch

To see a server's output as it runs, or type into it, run it in a named
session instead of the startup script. A session doesn't start again by
itself after a stop; [Terminal sessions](@/access/sessions.md) shows how to
restart it after `cw start`.
