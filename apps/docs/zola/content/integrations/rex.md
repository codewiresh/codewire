---
title: Rex
description: Run commands, open shells and attach to sessions from Rex's command palette, see each session's state with its pane, and run a Rex server inside an environment.
updated: 2026-11-21
weight: 1
aliases: ["/access/rex"]
---

{{ tool_logo(name="rex") }}

[Rex](https://superlogical.com) is a terminal multiplexer with a command
palette. The Codewire plugin puts environments, commands and persistent
sessions in that palette, beside the terminal where you already work.

## Install the Codewire plugin

With [Codewire installed](@/install.md), run this on the computer running Rex:

```sh
cw setup rex
```

It writes a Lua plugin beside Rex's config (`~/.config/rex/init.lua`, or
`REX_CONFIG`) and a managed block in the config that loads it, checks the
result with `rex config check`, and reloads Rex's config. Open the palette in
Rex and type Codewire. `cw setup rex remove` takes both out again.

## Actions

The actions work in the environment `cw use` selected and name it, for
example Codewire: Open Shell in app. `cw use` and `cw rm` update them in Rex
as the selection changes. Each opens beside the pane you are in.

| Action | Shown | Does |
| --- | --- | --- |
| Codewire: Run Once in ENV… | Always | Asks for a command and runs it once with `cw exec`, in a pane that stays open to show how it ended. No session is left. With nothing selected it opens `cw use` first |
| Codewire: Start in ENV… | Always | Asks for something that keeps running, such as a server or an agent, and starts it as a session with `cw run -- sh -c COMMAND`. `claude` or `codex`, with or without arguments, opens that agent's own terminal UI instead. With nothing selected it opens `cw use` first |
| Codewire: Open Shell in ENV | Always | `cw shell`: a login shell that ends when you leave it, as `ssh` does, or 10 minutes after a lost connection; with nothing selected, `cw use` first |
| Codewire: Choose Environment… | Always | `cw use` in a floating panel: every environment, or an offer to create one when there are none |
| Codewire: List Environments | Always | `cw ls` in a floating panel |
| Codewire: Attach to a Session in ENV… | An environment is selected | `cw attach`: its only session, a choice among them, or a new shell |
| Codewire: Message This Session… | An environment is selected | Asks for text and sends it with `cw msg` to the session attached in the focused pane: typed into a terminal session, or a managed agent's next task |
| Codewire: Ports of ENV | A local VM or cloud environment is selected | `cw ports` in a floating panel |
| Codewire: Open ENV in VS Code | A local VM or cloud environment is selected | `cw vscode` |

Rex can also run them by name with arguments, for example from a key binding
in your own `init.lua` or from a script:

```sh
rex do codewire_exec 'command=npm test' env=my-app
rex do codewire_run 'command=npm run dev' env=my-app
rex do codewire_attach env=my-app session=lead
```

The actions run `cw` on the machine of the Rex server, so they refuse a Rex
session on another host.

## Session state in Rex

A session attached in a Rex pane, by `cw attach` or `cw run`, reports itself
to Rex with an OSC 7501 program status record, `codewire/session`, which Rex
shows with the pane:

| State | Means |
| --- | --- |
| idle, `ENV/SESSION`, `local VM`, `cloud` or `host` | Attached to a running session |
| working, `reconnecting to ENV` | The connection was lost; `cw` is reconnecting |
| done, `exited` | The session exited with status 0 |
| error, `exited with status N` | The session failed or exited with another status |

Detaching withdraws the record. Outside Rex, or when output is not a terminal,
`cw` writes nothing.


## Run a Rex server in an environment

A Rex server can also run inside an environment, so that its sessions run
there and keep running while your computer is disconnected. Rex's own remote
setup, `rex server install ssh://HOST`, works with the hosts `cw setup ssh`
defines: it installs Rex in the environment, and Rex then reaches the server
by [forwarding its Unix socket](@/access/ssh-and-vscode.md#unix-sockets) over
SSH, as it does on any machine.

An environment has no systemd, so nothing starts the server at boot. Rex
starts it the first time it connects, and again the first time after the
environment has stopped and started.

The commands and output below are from a cloud environment named `my-rex`.
For a local VM, create it with `--local` and use the host `cw-local-my-rex`;
everything else is the same. A local VM created before socket forwarding
can't be reached this way until it is recreated.

### Install Rex in the environment

On the computer running Rex:

```sh
cw create --cloud --name my-rex
cw setup ssh
rex server install ssh://cw-cloud-my-rex --label my-rex
```

Rex connects with `ssh cw-cloud-my-rex`, through the block `cw setup ssh`
wrote in your [OpenSSH config](@/access/ssh-and-vscode.md#openssh). It prints
each command it runs in the environment, downloads Rex there, puts `rex` in
`~/.local/bin` without sudo, starts the server, and adds a host labelled
`my-rex` to your Rex hosts. Where it has no terminal to ask on, add `--yes`.
It ends with a warning about systemd, which is expected in an environment:

```text
Installed Rex in ~/.local/bin on cw-cloud-my-rex.
The server on cw-cloud-my-rex answered through ssh.
warning: cw-cloud-my-rex has no systemd, so nothing starts the server at boot. […]
Added my-rex to your hosts. Reach it with: rex -S my-rex
```

### Use it from your computer

```sh
rex -S my-rex server status
```

```text
you: uid 1000 over unix
endpoint: ssh://cw-cloud-my-rex
listener: unix:///home/codewire/.local/state/rex/run/server.sock (unix, peer_credentials, primary)
[…]
```

The server listens only on Rex's own socket in the environment, which admits
only the environment's user. The forward connects as that user, so the server
sees `uid 1000`, and nothing listens on a port. Rex commands given
`-S my-rex` act on that server, and a `rex` command typed inside the
environment reaches the same one:

```sh
rex -S my-rex new work
rex -S my-rex ls
```

```text
session:01a1fe7d-65d3-7233-94e1-c3c6db7af929
LABEL  ID
work   7af929
```

### After a disconnect or a stop

The server runs until the environment stops. Rex opens its forward for each
connection, so there is nothing to keep running on your computer.

| What happened | The server and its sessions | To reconnect |
| --- | --- | --- |
| Your computer disconnected | Keep running | Nothing; the next `rex -S my-rex` reconnects |
| `cw stop my-rex`, then `cw start my-rex` | Stopped with the environment. The next connection starts the server again, and Rex lists its saved sessions, each with a new shell | Nothing; the next `rex -S my-rex` starts it |

While the environment is stopped, a command with `-S my-rex` answers
`host "my-rex" could not be reached`.
