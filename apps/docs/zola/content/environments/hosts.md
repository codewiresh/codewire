---
title: Hosts
description: Computers you own that provide VMs for your organization's environments. How a host connects to Codewire, who may use it, and how to set one up.
updated: 2026-11-25
weight: 9
---

A host is a computer, yours or your team's, that runs Codewire VMs for your
organization: a Mac on your desk, a Linux workstation, or a server in your
own cloud account. You keep the computer. Codewire sees a host that is
online, what it offers, and who may use it.

{% aside(kind="preview") %}
  Hosts are a preview and still being built: some host features don't work
  yet. Today a host enrolls, connects and shows its state, and
  `cw create --on host:NAME` creates an environment with an empty workspace
  on it. Opening a session in that environment comes next.
{% end %}

A host is not a [local VM](@/environments/_index.md#local-vm), which runs
only for you and needs no account, and it is not a
[trusted host session](@/environments/_index.md#trusted-host-session), which
has no VM at all.

## What a host needs

- Linux on x86_64 with KVM, or macOS on Apple silicon.
- `cw`, [installed and signed in](@/install.md) to the organization the host
  will serve.
- A way out to Codewire over HTTPS, directly or through the proxy named in
  `HTTPS_PROXY`.

It does not need a public address, an open port or port forwarding.

## How a host connects

The host agent, `cw host run`, opens one HTTPS connection to Codewire and
keeps it open. That connection is the only way Codewire reaches the host, so
a host works behind a home router or a firewall that allows nothing in.

{% figure(source="hosts-call-out", alt="A Mac and a Linux workstation on a home or office network with no port forwarding, and a cloud server with no inbound rule, each run the host agent. An arrow goes from each host agent up to Codewire, labelled one outbound HTTPS connection from each host. A dashed line from Codewire down toward the hosts ends in a cross, labelled nothing connects in.") %}
  Each arrow points the way its connection is opened: from the host, out to
  Codewire. Nothing connects in to a host.
{% end %}

- **A host proves who it is with a key, not a password.** Enrolling creates
  an Ed25519 key that stays on the host. The agent signs a fresh challenge
  with it when it connects and every 10 minutes after, so a recorded
  answer is no use to anyone else.
- **Online means connected.** A host shows online while its agent runs, and
  offline about 45 seconds after it stops. When the connection drops, the agent
  connects again by itself.
- **Each running environment gets its own tailnet connection.** For direct
  access with `cw shell`, `cw exec` and SSH, the agent also connects out for
  each running VM: to Codewire's coordinator and relay over HTTPS, and over
  UDP where your network allows it, so you reach the VM directly or through
  the relay. Nothing listens on the host for it.
- **Revoking is final.** A revoked host is disconnected at its next message
  and can never connect again.

## Set up a host

On the computer that will be the host:

```sh
cw host enroll --name build-box   # create its key and register it; starts nothing
cw host run                       # connect, in this terminal
```

`cw host run` stays in the foreground, so you can run it however you like: in
a terminal, under a terminal multiplexer or under your own init system. To
keep it running in the background and across restarts instead:

```sh
cw host service install
```

Then check what Codewire sees:

```sh
cw host status   # this computer's host
cw hosts         # every host in the organization
```

## Who may use a host

Enrolling a host grants nothing. Each step below is separate, and each is
yours to take:

1. **Enroll.** The host exists, and only you may use it.
2. **Provide.** You offer VMs from it, within limits you set: how many VMs,
   and optionally their vCPUs, memory and disk together.
3. **Grant.** You let one member, or every member of the organization, place
   environments on it.

```sh
cw host provide --max-vms 2 --max-memory 8G --max-disk 200G
cw host grant --organization
```

`cw host provide --off` stops offering and keeps your limits, and
`cw host ungrant` takes a grant back.

## Where the key lives

On a Mac the host's key is in the Keychain, and on a Linux desktop in the
Secret Service keyring. A Linux computer with no keyring, such as a server or
a cloud VM, keeps the key in a file only you can read, protected like an SSH
host key by the file's permissions. That is also what lets a server's agent
come back after a reboot with nobody logged in. `cw host status` shows where
the key is.

## Remove a host

```sh
cw host leave          # on the host: removes its record, key and service
cw host revoke HOST    # from anywhere: ends its connection for good
```

The host's owner, or an owner or admin of the organization, may revoke it. Use
`revoke` when you no longer trust the computer, for example after it is lost.

## Related

- [CLI: hosts](@/reference/cli/hosts.md)
- [Environments](@/environments/_index.md#where-it-runs)
- [Security model](@/reference/security.md)
