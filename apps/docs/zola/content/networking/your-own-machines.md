---
title: Your own machines
description: Enroll a trusted host on one of your Linux machines in a Mesh network and drive its agents and commands from another of your machines with cw --member.
updated: 2026-10-26
weight: 4
---

A trusted host session runs agents and commands as your own account on a
machine of yours, such as a build box with a GPU or the tools a job needs.
On Linux you can enroll that host in a [Mesh network](@/networking/mesh.md)
and drive it from another of your machines. This is delegated control over
your own machines, not sharing with other people: every grant names the exact
calling machine and the exact target.

{% aside(kind="caution") %}
  A trusted host has no containment. An agent on it can read and change
  anything your account can. See
  [Environments](@/environments/_index.md#trusted-host-session).
{% end %}

## 1. Create the host and grant access

On the machine that will do the work:

```sh
cw create --local --type host --name build-box --path ~/src/project
cw control info --environment build-box
```

On the machine you will drive it from, print that machine's keys:

```sh
cw member identity                        # this machine's control_key and wg_key
```

Back on the host, grant that key what it may do, then join the network:

```sh
cw control grant --environment build-box --grant-id UUID --org ORG --network NET \
  --caller-key HEX --target-key HEX --allow read,launch,input,stop,managed-launch,managed-message \
  --expected-book-revision N --expected-grant-revision 0
cw member up build-box --mesh-url URL --org ORG --network NET --enrollment-stdin
```

`cw control list` shows the grants and `cw control revoke` removes one. The
verbs a grant can allow are `read`, `launch`, `input`, `stop`,
`managed-launch`, `managed-message`, `managed-steer`, `managed-interrupt`,
`managed-stop`, `managed-restart` and `managed-read`.

## 2. Pin it on the controlling machine

```sh
cw member add build-box --mesh-url URL --org ORG --network NET --environment UUID --node NODE \
  --target-key HEX --target-wg-key HEX --grant-id UUID --grant-revision N
cw member info build-box
```

## 3. Drive it

```sh
cw --member build-box run --name worker --agent codex --detach --prompt 'Run the slow integration suite and report failures.'
cw --member build-box ls
cw --member build-box wait --message MESSAGE_ID --timeout 10m
cw --member build-box logs --session session-UUID
```

`--member` works with `run`, `ls`, `send`, `logs`, `wait`, `stop`, `restart`,
`msg`, `steer`, `interrupt` and `inbox`. Sessions are named by their
`session-UUID` IDs, commands need `--no-tty`, and attaching is not available.
After a lost reply, `cw member observe NAME REQUEST_ID` reports what happened
to the request instead of sending it again.

Member control needs Linux on the host. macOS has no public way to find a
session's processes after their parent exits, so on a Mac run the work in a
local VM instead.

## Related

- [Agentic collaboration](@/use-cases/agentic-collaboration.md)
- [CLI: networking](@/reference/cli/networking.md#trusted-host-members-linux)
