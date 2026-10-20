---
title: SSH, VS Code and files
description: Use OpenSSH, scp, sftp and rsync, open a hosted sandbox in VS Code, copy files with cw cp, and use the browser terminal.
weight: 2
---

Every environment runs an SSH server with SFTP and SCP inside its daemon. For
a hosted sandbox, `cw` reaches it over the Codewire tailnet, and your OpenSSH
config can use `cw` as its proxy.

## OpenSSH

`cw setup ssh`, which `cw setup` also runs, adds a managed block to
`~/.ssh/config`:

```text
# ---- START CODEWIRE ----
Host cw-*
  ProxyCommand cw shell --stdio %n
  KnownHostsCommand cw ssh known-hosts %H
  ...
# ---- END CODEWIRE ----
```

Then any `cw-` host name is an environment, by name or ID:

```sh
ssh cw-my-app
scp ./fixture.json cw-my-app:/workspace/
rsync -av cw-my-app:/workspace/out/ ./out/
sftp cw-my-app
```

`KnownHostsCommand` asks the platform for the host key it recorded when the
environment bound, so there is no trust-on-first-use prompt. Re-run
`cw setup ssh` after changing SSH options (`--ssh-option` adds lines to the
block; `--dry-run` prints the result). `cw doctor` checks the block.

`cw shell --stdio` is for hosted sandboxes. For a local VM or a trusted host,
use `cw shell ENV` and the session commands.

## Port forwarding

Local forwards reach servers listening inside a hosted sandbox:

```sh
ssh -N -L 8080:localhost:3000 cw-my-app     # http://localhost:8080 on your machine
ssh -W localhost:5432 cw-my-app             # stdio, for ProxyCommand chains
ssh -N -D 1080 cw-my-app                    # SOCKS, as VS Code uses it
```

A forward reaches only the sandbox's own loopback: `localhost`, `127.0.0.1`
or `::1`. Any other target, such as another host, the node or a metadata
address, is refused with that reason, and so is a port nothing listens on.
Reverse forwards (`ssh -R`) and agent and X11 forwarding are not available.

## VS Code

```sh
cw vscode my-app                     # opens /workspace
cw vscode my-app --folder /workspace/my-repo
```

This refreshes your SSH config and opens
`vscode://vscode-remote/ssh-remote+cw-<id>/<folder>`, so the Remote-SSH
extension connects through the same proxy. The Sandbox page in the dashboard
has the same **Open in VS Code** action.

## Copy files

```sh
cw cp ./local.txt my-app:/workspace/local.txt
cw cp my-app:/workspace/build.log ./build.log
```

Exactly one side names an environment. This works for hosted sandboxes and
local VMs.

## Browser terminal

The Sandbox page in the dashboard opens a terminal in the environment: up to
eight tabs that you can rename, disconnect from and reopen, with the recent
output replayed. It is the same daemon session engine `cw shell` uses.

## Transport

`cw` tries a direct UDP path to the environment, then the shared UDP relay,
then DERP over TCP, and finally a WebSocket SSH proxy through the platform.
`cw doctor tailnet my-app` reports which path you get and how long each step
took; `--expect direct_udp` makes it fail when a direct path is not reached.
