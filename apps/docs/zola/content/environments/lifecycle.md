---
title: Lifecycle
description: Stop, start, resize and remove environments; give hosted sandboxes a lifetime, extend it, and protect them from deletion.
updated: 2026-11-08
weight: 5
aliases: ["/guides/lifecycle"]
---

An environment keeps its disks while it is stopped and loses them only when
you remove it. Stopping releases its compute; on the platform, a stopped
sandbox is not billed for compute.

The output below is from real runs: a local VM named `app` and a hosted
sandbox named `web-app`. Your IDs will differ.

## Stop and start

```sh
cw stop app
```

```text
✓ Environment app stopped
  local VM · environment disk retained
```

Stopping gives every process SIGTERM and up to 5 seconds, then powers the VM
off. Every session ends; their saved output stays readable with `cw logs`.
`cw start app` boots it again with the same disks and published ports.

A hosted sandbox stops the same way, and `cw stop` returns once it has, so a
`cw start` can follow it straight away:

```sh
cw stop web-app && cw start web-app
```

`cw stop` waits up to 3 minutes. If the sandbox still hasn't stopped by then, it
says so and exits non-zero; the stop carries on, and `cw info web-app` shows how
far it has come. `cw start` is refused until the state is `stopped`. See
[Environment statuses](@/reference/environment-statuses.md) for every state.

A hosted `cw start` returns once the sandbox is usable: its Git identity is set
and its startup script has run, as after `cw create`, so the next command can
open a session straight away. A long startup script makes the start as long;
start servers in a session instead.

## Resize

```sh
cw resize app --cpu 4 --memory 8GB -y
```

```text
Environment: app (local · Cloud Hypervisor)

              Current   Desired
CPU       2         4
Memory    4 Gi      8 Gi
Disk      20 Gi     20 Gi

Active sessions: none
Codewire will stop the VM, grow the disk offline if requested, and restore its prior running state. Disk growth cannot be reversed.
```

`--disk` grows the disk; disks never shrink. A running local VM restarts to
apply the change, and a hosted sandbox with active sessions needs `--force`.
Without a quantity, `cw resize` asks at a terminal.

## Remove

```sh
cw rm app
```

```text
✓ Environment app removed
  local VM · environment disk removed
```

Removal deletes the VM and its disks at once. A local VM's project folder on
your machine is never touched. Removing a trusted host environment asks
first; `-y` skips the question.

## Hosted sandboxes: lifetime and protection

Give a sandbox a lifetime when you create it, and it deletes itself:

```sh
cw create --name web-app --image workspace --repo https://github.com/octocat/Hello-World --ttl 1h
cw extend web-app --hours 2
```

```text
Environment web-app: ttl_extended (2 hours added).
```

Protect one you cannot afford to lose:

```sh
cw protect web-app
cw rm web-app
```

```text
Environment web-app: protected.
environment web-app is protected, so nothing was removed; remove the protection first with `cw --cloud unprotect web-app`
```

`cw unprotect web-app` lifts it. `cw logs web-app --setup` records each of
these changes:

```text
  ✓ scheduled shutdown after ttl 3600s
  ✓ ttl extended by 7200s
  ✓ environment protected
  ✓ environment unprotected
  ✓ desired state -> stopped
```

`cw prune` deletes the organization's sandboxes stuck in error or creation,
and `cw cancel-delete` cancels a pending deletion. See the
[CLI reference](@/reference/cli/environments.md#cw-extend-protect-unprotect-cancel-delete-prune-nuke-cloud).

## FAQ

**Can I change an environment after creating it?** Resize it
(`cw resize`), change its selected secrets and credential profile
(`cw update ENV`), and publish ports (`cw ports ENV --publish PORT`). For a
different image or repositories, create a new one.

**What happens to my data when I stop an environment?** Workspace storage is
kept and compute is released. Removing it deletes the storage.

**An environment is stuck.** `cw info ENV` shows the state and error
code; `cw daemon status ENV` and `cw daemon repair ENV` inspect and
reconcile the daemon; otherwise stop and start it. For a local VM, see
[Troubleshooting](@/reference/troubleshooting.md).
