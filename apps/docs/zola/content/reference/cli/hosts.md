---
title: Hosts
description: host and hosts, for computers that provide VMs for your organization's environments.
updated: 2026-11-11
weight: 11
aliases: ["/cli/hosts"]
---

A host is a computer, yours or your team's, that runs Codewire VMs for your
organization. It is not a trusted host environment (`--type host`,
`cw member`). A host must be Linux on x86_64 with KVM, or macOS on Apple
silicon.

Enrolling a host grants nothing. Only you may use your host until you offer
VMs from it (`cw host provide`) and grant it to other members
(`cw host grant`). Creating environments on a host is coming; for now a host
enrolls, connects and shows its state.

## cw host enroll

```sh
cw host enroll [--name NAME] [--key-store keyring|file] [-o json]
```

Registers this computer as a host of your current organization, owned by you.
It creates the host's Ed25519 key in the OS keyring (Secret Service on Linux,
the Keychain on macOS), proves to Codewire that this computer holds it, and
records the host. It installs and starts nothing. `--name` defaults to this
computer's name, as a DNS label: lowercase letters, digits and `-`.

A Linux computer with no Secret Service, such as a server or a cloud VM, keeps
the key in a file instead: one file only you can read, in a `host-key`
directory only you can open, beside the enrollment in Codewire's config
directory. Its safety is the filesystem's permissions and the disk's
encryption, as with SSH host keys. The agent then comes back after a reboot
with nobody logged in, which a keyring that only a password login unlocks
cannot do. On Linux, `--key-store file` chooses the file even when a keyring
exists, and `--key-store keyring` refuses to fall back. `cw host status`
shows where the key is.

```text
Enrolled this computer as host `build-box` (0f32162e-a4c5-4ce2-b3ae-9c62d3d69378).
Its key is in the OS keyring. Nothing is running yet, and nothing is offered.
Next:
  cw host run                  run the agent now, in this terminal
  cw host service install      or keep it running in the background
  cw host provide --max-vms 2  offer VMs, with limits
```

## cw host run

```sh
cw host run
```

The host agent, in the foreground. It keeps one outbound connection to
Codewire, so it works behind home routers with no port forwarding, and proves
the host's key when it connects and every 10 minutes after. The host shows
online while the agent runs, and offline 45 seconds after it stops. Ctrl-C
stops it.

Run it however you like: in a terminal, under tmux, in a container, or under
your own init system. `cw host service install` runs it for you.

If the OS keyring is locked, for example after a reboot with nobody logged in,
the agent waits and retries every 30 seconds, and `cw host status` says so. A
key kept in a file needs no login.
If the host is revoked, the agent stops for good.

## cw host service install, uninstall, status

```sh
cw host service install
cw host service uninstall
cw host service status
```

The opt-in that keeps `cw host run` running. On Linux it writes a systemd user
unit, `~/.config/systemd/user/codewire-host.service`, and starts it; logs are
in `journalctl --user -u codewire-host.service`. To keep the agent running
when you are logged out, and start it at boot, it prints the
`loginctl enable-linger` command for you to run. On macOS it writes a
LaunchAgent, `~/Library/LaunchAgents/sh.codewire.host.plist`, logging to
`~/Library/Logs/codewire-host.log`. `uninstall` stops the service and removes
only the file `install` wrote.

## cw host status

```sh
cw host status [-o json]
```

This computer's host: what Codewire sees, what it provides, who may use it,
the agent and the service.

```text
Host:      build-box (0f32162e-a4c5-4ce2-b3ae-9c62d3d69378)
Server:    https://codewire.sh
State:     offline, never seen
Provides:  nothing (`cw host provide` to offer VMs)
Used by:   only you
Agent:     not running (`cw host run`, or `cw host service install`)
Service:   not installed (`cw host service install` to keep the agent running)
```

## cw host provide

```sh
cw host provide --max-vms N [--max-vcpus N] [--max-memory SIZE] [--max-disk SIZE] [-o json]
cw host provide --off
```

Offers VMs from this host, within your limits: at most `--max-vms` VMs
(1 to 1024), and optionally caps on their vCPUs, memory (`8G`, `512M`) and
disk (`200G`, `1T`) together. `--off` stops offering and keeps the limits.

```text
Host `build-box` provides VMs: 2 VMs, 8 GiB memory, 200 GiB disk.
```

## cw host grant, ungrant

```sh
cw host grant [HOST] --user ID | --organization [-o json]
cw host ungrant [HOST] --user ID | --organization [-o json]
```

Lets a member of the organization, or every member, place environments on
your host, or takes that back. Only the host's owner may grant. `HOST` is a
host's name or ID, and defaults to this computer's host.

## cw host revoke

```sh
cw host revoke HOST [--yes]
```

Revokes a host for good: its agent is disconnected at its next message and
can never connect again. The host's owner or an organization owner or admin
may revoke. A revoked host's record stays, so its key can never be enrolled
again; its name may be reused.

## cw host leave

```sh
cw host leave [--yes]
```

Removes this computer's host: its record (unless it was revoked), its key
(from the keyring or its file), its service if installed, and the local
enrollment.

## cw hosts

```sh
cw hosts [-o json]
```

Your organization's hosts, revoked ones included. `(this)` marks this
computer's host.

```text
NAME                     PLATFORM           STATE     PROVIDES                           LAST SEEN
build-box (this)         linux-x86_64-kvm   online    2 VMs, 8 GiB memory, 200 GiB disk  2026-11-11T21:34:36Z
old-laptop               linux-x86_64-kvm   revoked   not providing                      2026-11-11T21:33:40Z
```
