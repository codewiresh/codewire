---
title: SSH, VS Code and files
description: Use OpenSSH, scp, sftp and rsync, open a hosted sandbox in VS Code, copy files with cw cp, and use the browser terminal.
weight: 2
---

Every environment runs an SSH server with SFTP and SCP inside its daemon. For
a hosted sandbox, `cw` reaches it over the Codewire tailnet; for a local VM,
through the local supervisor, which serves SSH with the VM's own host key.
Your OpenSSH config can use `cw` as its proxy for both.

## OpenSSH

`cw setup ssh`, which `cw setup` also runs, adds a managed block to the top
of `~/.ssh/config` and reports whether it wrote the block or found it current:

```text
# ---- START CODEWIRE ----
Host cw-local-*
  ProxyCommand cw --local shell --stdio %n
  KnownHostsCommand cw --local ssh known-hosts %H
  ...
Host cw-cloud-*
  ProxyCommand cw --cloud shell --stdio %n
  KnownHostsCommand cw --cloud ssh known-hosts %H
  ...
Host *
# ---- END CODEWIRE ----
```

Then `cw-cloud-` followed by a cloud environment's name or ID is a host, and
`cw-local-` followed by a local VM's name or ID is one too:

```sh
ssh cw-cloud-my-app
scp ./fixture.json cw-cloud-my-app:/workspace/
rsync -av cw-cloud-my-app:/workspace/out/ ./out/
sftp cw-cloud-my-app

ssh cw-local-my-vm
ssh cw-local-my-vm 'make test'
```

The placement in the alias means a local VM and a cloud environment with the
same name never get mixed up: a `cw-local-` name is never sent to the cloud,
and a `cw-cloud-` name never reaches a local VM. A local VM's host key is the
one its supervisor keeps for it, the same for every boot, and
`cw --local ssh known-hosts` hands OpenSSH exactly that key, so there is no
trust-on-first-use prompt either. Commands, interactive sessions, `scp`,
`sftp`, `rsync` and port forwarding work in a local VM created by this `cw`; a
VM on an older runtime refuses forwarding until it is recreated.

There is no bare `cw-NAME` alias: an environment is reached only as
`cw-cloud-NAME` or `cw-local-NAME`. The part after the prefix is the name or
ID as given, so a cloud environment named `cloud-x` is `cw-cloud-cloud-x`.

The block passes the host name to `ProxyCommand` (`%n`) for every `cw-` host,
so use OpenSSH 9.6 or later, or a distribution build that includes the fix for
CVE-2023-51385. Without that fix, a host name from an untrusted source, such as
a git submodule URL, can run commands. Many distributions backported the fix
without changing the version number, so check your distribution's advisory
rather than `ssh -V` alone.

`KnownHostsCommand` asks the platform for the host key it recorded when the
environment bound, so there is no trust-on-first-use prompt. Re-run
`cw setup ssh` after changing SSH options (`--ssh-option` adds lines to the
block) or moving `cw`. `--dry-run` shows how the block would change, without
writing anything. `cw doctor` checks the block.

To take the block out again:

```sh
cw setup ssh remove             # --dry-run shows what would go
```

This removes only the block, from its start marker through its end marker;
your own entries and your environments stay. A file with no block, or no file at all, is left
alone. If one marker line is missing, `cw` changes nothing and asks you to
delete the other.

`cw` never edits the file in place. It writes the new text to a file beside
it and renames that over the old one, so an interrupted run never leaves it
half written. A symlinked config stays a symlink, because `cw` writes the file
it points to. A file `cw` creates is readable only by you, and an existing
one keeps its permissions.

`cw shell --stdio` is the proxy for both placements. For a trusted host, use
`cw shell ENV` and the session commands.

## Port forwarding

Local forwards reach servers listening inside a hosted sandbox:

```sh
ssh -N -L 8080:localhost:3000 cw-cloud-my-app   # http://localhost:8080 on your machine
ssh -W localhost:5432 cw-cloud-my-app           # stdio, for ProxyCommand chains
ssh -N -D 1080 cw-cloud-my-app                  # SOCKS, as VS Code uses it
```

A forward reaches only the sandbox's own loopback: `localhost`, `127.0.0.1`
or `::1`. Any other target, such as another host, the node or a metadata
address, is refused with that reason, and so is a port nothing listens on.
The platform's own listeners in the sandbox are refused too: the credential
bridge on port 38081, which answers provider requests with your credentials,
and the daemon's SSH and API ports. So VS Code, which forwards every port it
sees listening, never publishes them on your machine.
Reverse forwards (`ssh -R`) and agent and X11 forwarding are not available.

## VS Code

```sh
cw vscode my-app                     # opens /workspace
cw vscode my-app --folder /workspace/my-repo
```

This refreshes your SSH config and opens
`vscode://vscode-remote/ssh-remote+cw-cloud-<id>/<folder>`, so the Remote-SSH
extension connects through the same proxy. The Sandbox page in the dashboard
has the same **Open in VS Code** action, with the same `cw-cloud-<id>` link.

For a local VM, `cw --local vscode my-vm`, `cw vscode cw-local-my-vm`, or
`cw --local vscode` for the selected one, opens `ssh-remote+cw-local-<id>` the
same way. Remote-SSH reaches its
server in the VM through port forwarding, so it needs a VM created by this
`cw`; a VM on an older runtime refuses forwarding until it is recreated.

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
