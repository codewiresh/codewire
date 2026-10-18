---
title: SSH, VS Code and files
description: Use OpenSSH, scp, sftp and rsync, open a hosted sandbox in VS Code, copy files with cw env cp, and use the browser terminal.
weight: 2
---

Every environment runs an SSH server with SFTP and SCP inside its daemon. For
a hosted sandbox, `cw` reaches it over the Codewire tailnet, and your OpenSSH
config can use `cw` as its proxy.

## OpenSSH

`cw setup` runs `cw config-ssh`, which adds a managed block to
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
`cw config-ssh` after changing SSH options (`--ssh-option` adds lines to the
block; `--dry-run` prints the result). `cw doctor` checks the block.

`cw shell --stdio` is for hosted sandboxes. For a local VM or a trusted host,
use `cw shell ENV` and the session commands.

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
cw env cp ./local.txt my-app:/workspace/local.txt
cw env cp my-app:/workspace/build.log ./build.log
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
