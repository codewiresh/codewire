---
title: Troubleshoot local VMs
description: What the local VM messages mean, what cw doctor local reports, and how to recover.
weight: 10
---

`cw info ENV` shows an environment's state and, after a failure, the error
code that names the cause (for example
`environment_sources_guest_start_failed`). `cw daemon status ENV` and
`cw daemon logs ENV` inspect the daemon inside a running VM, and
`cw daemon repair ENV` reconciles it without recreating the environment.

## Messages

**`this host cannot run local VMs yet`**, followed by a list. Fix each item
as described (`usermod -aG kvm`, `modprobe vhost_vsock`, a newer kernel, the
`e2fsprogs` package), then rerun. After `usermod`, log out and back in.

**`this cw needs its local VM runtime (...) install it with cw setup --local`**.
The runtime could not be downloaded when the VM was created or started.
Reconnect and run `cw setup --local`. With an application firewall, allow
`cw` (under `~/.local/share/codewire/cli/versions/`) to reach
`releases.codewire.sh` for the runtime, and `ghcr.io` and
`pkg-containers.githubusercontent.com` for the workspace image.

**`your local VMs ... still run on the cw you updated from`**. Restart them on
this version with `cw upgrade --vms`, or stop them and rerun. See
[Update cw](@/guides/update.md).

**`Local VMs aren't available on Linux arm64 yet`**. Local VMs run on x86_64
Linux and on Apple Silicon Macs. Elsewhere, use hosted sandboxes.

**`managed VM agents require a selected credential profile`**. Select a
profile with a provider for the agent: a `codex` slot (or an `openai` slot)
for Codex, an `anthropic` slot for Claude Code:
`cw update ENV --profile local:NAME` or `--profile platform:NAME`. If the
message says the profile has no Codex or OpenAI (or Anthropic) provider, add
that slot with `cw credentials --local --profile NAME set codex CREDENTIAL`,
then run `cw update ENV` again, because a VM keeps the profile revision it
selected.

**A credential command cannot reach the Secret Service**. Start or unlock
your keyring. Over SSH or on a headless host, make sure a session bus and a
Secret Service run for your user.

**`create_registry_platform`** (macOS). The image has no `linux/arm64`
variant. Pass `--image` with one.

**`create_guest_docker_tooling_missing`**. The image has no Docker tooling.
Create with `--no-docker`.

**`start_direct_share_changed`**, at "Checking mounted folders". A directly
mounted folder was moved, removed or replaced while the VM was stopped. Move
it back and start again. A removed folder cannot come back, even recreated at
the same path: remove the environment with `cw rm --local NAME` and create it
again.

## Stops and leftovers

A stop gives every process SIGTERM and up to 5 seconds, kills what remains,
then unmounts the disks; a process that ignores SIGTERM makes the stop take
about 5 seconds.

A failed create leaves no environment, VM, disk or record behind. `cw`
reports the cause and "No environment was kept" once the environment is
confirmed gone, or names `cw --local rm NAME` when removal could not
finish. The image layers it already downloaded and verified stay cached, so
a retry resumes the download instead of starting over. The cache holds only
the latest pull's image layers, never a repository, and lasts until you
delete a VM or the supervisor restarts; until then `cw doctor local` lists
those layers as unreferenced content.

```sh
cw doctor local                    # VM files and processes no environment owns; changes nothing
cw rm --local NAME --yes       # remove a VM you no longer need
```

## Where things are

| Path | Contents |
| --- | --- |
| `~/.cache/codewire/local-vmm-v1/` | the pinned runtime: hypervisor, guest kernel and root, the in-VM `cw` |
| `~/.codewire/native-v1/` | the supervisor's state and VM disks |
| `~/.codewire/native-v1/logs/` | `supervisor.log` and one `runner-<environment id>.log` per VM, capped at 1 MiB with one previous copy; codes and identifiers only, never secret values or guest output |
