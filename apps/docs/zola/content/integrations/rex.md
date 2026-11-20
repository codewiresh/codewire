---
title: Rex
description: Run commands, open shells and attach to sessions from Rex's command palette, see each session's state with its pane, and run a Rex server inside an environment.
updated: 2026-11-20
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
defines and installs Rex in the environment. Two things then differ from an
ordinary machine:

- An environment has no systemd, so nothing starts the Rex server for you.
  Run it as a [session](@/access/sessions.md).
- Rex reaches an `ssh://` host by forwarding a Unix socket, and an
  environment's SSH server forwards only TCP ports on the environment's own
  loopback. Give the Rex server a loopback port and forward that instead.

The commands and output below are from a cloud environment named `my-rex`.
For a local VM, create it with `--local` and use the host `cw-local-my-rex`;
everything else is the same.

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
`~/.local/bin` without sudo, and adds a host labelled `my-rex` to your Rex
hosts. Where it has no terminal to ask on, add `--yes`. It ends with two
warnings, both expected in an environment:

```text
Installed Rex in ~/.local/bin on cw-cloud-my-rex.
warning: cw-cloud-my-rex has no systemd, so nothing starts the server at boot. […]
warning: could not reach the server on cw-cloud-my-rex through ssh: […]
Added my-rex to your hosts. Reach it with: rex -S my-rex
```

The host it added points at `ssh://cw-cloud-my-rex`, which cannot connect;
the last step changes it.

Rex's connection attempt sometimes leaves a server of its own running in the
environment. Stop it, so that the session in the next step can start:

```sh
cw exec --in my-rex -- rex server stop
```

It answers `Rex server stopped.`, or `Error: rex server is not running` when
there was none.

### Start the server as a session

```sh
cw run --in my-rex --name rex --detach -- \
  rex server run --extra-listen http://127.0.0.1:7350 --allow-anonymous
```

```text
✓ Started session my-rex/rex · cloud
→ cw --cloud attach my-rex --session rex
```

The server keeps Rex's usual socket, so a `rex` command typed inside the
environment reaches it, and it also listens on port 7350 of the environment's
loopback. Another free port works as well; `cw logs my-rex --session rex`
shows `address already in use` when the port is taken, as 7777 is in a cloud
environment.

Rex cannot tell who connects to a TCP port. It refuses to listen on one
without `--allow-anonymous`, and with it every connection to that port has
full access to the Rex server, which runs commands as the environment's user.
The port is on the environment's loopback, so programs inside the environment
can reach it, and you can through the SSH forward below. That includes a
browser running inside the environment, such as an agent's or the desktop's:
Rex turns away a page from another site, but not a page whose own host name
has been pointed at `127.0.0.1`. Don't open untrusted pages in the
environment while this server is listening.

Never publish the port with `cw ports`: that gives it a preview URL and opens
it to every member of the environment's
[Mesh network](@/networking/environment-to-environment.md), whatever access
you choose for the preview.

VS Code is a second way out. Connected to the environment, it
[forwards every port it sees listening](@/access/ssh-and-vscode.md#port-forwarding)
to a TCP port on your computer, where any program could then use the Rex
server. Before opening this environment in VS Code, exclude the port in your
VS Code settings, or turn automatic forwarding off with
`"remote.autoForwardPorts": false`:

```json
"remote.portsAttributes": {
  "7350": { "onAutoForward": "ignore" }
}
```

### Connect from your computer

```sh
ssh -f -N -o ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes \
  -L ~/.ssh/my-rex.sock:127.0.0.1:7350 cw-cloud-my-rex
rex hosts edit my-rex --endpoint "unix://$HOME/.ssh/my-rex.sock"
rex -S my-rex server status
```

```text
you: anonymous over tcp from 127.0.0.1:49978
endpoint: unix:///home/user/.ssh/my-rex.sock
listener: unix:///home/codewire/.local/state/rex/run/server.sock (unix, peer_credentials, primary)
listener: http://127.0.0.1:7350 (tcp, anonymous)
```

`ssh` stays in the background and carries a socket in your `~/.ssh`, which
only your user can open, to the server's port in the environment. Rex
commands given `-S my-rex` now act on that server:

```sh
rex -S my-rex new work
rex -S my-rex ls
```

```text
session:01a1f934-ba34-7c01-a553-629843cb81a8
LABEL  ID
work   cb81a8
```

### After a disconnect or a stop

The session is detached, so the server keeps listening until you stop it or
the environment stops. `cw stop my-rex --session rex` stops it and closes the
port; `cw restart my-rex --session rex` starts it again.

| What happened | The server and its sessions | To reconnect |
| --- | --- | --- |
| The `ssh` forward ended | Keep running | Run the `ssh` command again |
| `cw stop my-rex`, then `cw start my-rex` | Stopped with the environment. Once the server runs again, Rex lists its saved sessions, each with a new shell | `cw restart my-rex --session rex`, then the `ssh` command again |

While the forward is down, a command with `-S my-rex` answers
`host "my-rex" could not be reached`.
