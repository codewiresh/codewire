---
title: SSH, VS Code and files
description: Use OpenSSH, scp, sftp and rsync, open a hosted sandbox in VS Code, copy files with cw cp, and use the browser terminal.
weight: 2
---

Every environment runs an SSH server with SFTP and SCP inside its daemon. For
a hosted sandbox, `cw` reaches it over the Codewire tailnet, and your OpenSSH
config can use `cw` as its proxy.

## OpenSSH

`cw setup ssh`, which `cw setup` also runs, adds a managed block to the top
of `~/.ssh/config` and reports whether it wrote the block or found it current:

```text
# ---- START CODEWIRE ----
Host cw-cloud-*
  ProxyCommand cw --cloud shell --stdio %n
  KnownHostsCommand cw --cloud ssh known-hosts %H
  ...
Host cw-*
  ProxyCommand cw shell --stdio %n
  KnownHostsCommand cw ssh known-hosts %H
  ...
Host *
# ---- END CODEWIRE ----
```

Then `cw-cloud-` followed by a cloud environment's name or ID is a host:

```sh
ssh cw-cloud-my-app
scp ./fixture.json cw-cloud-my-app:/workspace/
rsync -av cw-cloud-my-app:/workspace/out/ ./out/
sftp cw-cloud-my-app
```

The placement in the alias means a local VM and a cloud environment with the
same name never get mixed up. `cw-local-` is reserved for local VMs: SSH
aliases for them are not available yet, so `ssh cw-local-NAME` is refused with
a pointer to `cw shell NAME`, and is never sent to the cloud.

A bare `cw-NAME`, such as one an editor remembers from an earlier `cw`, still
reaches the cloud environment `NAME`, and will through at least v0.5. Before
the aliases were qualified, `cw-cloud-x` meant a cloud environment named
`cloud-x`; it still does when nothing else is named `x`. When both `x` and
`cloud-x` exist, `cw` refuses rather than guess, and names both IDs, so you
can connect with `cw-cloud-<id>`. A cloud environment named `local-x` is
`cw-cloud-local-x`.

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

`cw shell --stdio` is for hosted sandboxes. For a local VM or a trusted host,
use `cw shell ENV` and the session commands.

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
has the same **Open in VS Code** action. Its link uses the bare `cw-<id>`,
which every version of `cw` resolves, until the bare aliases are retired.

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
