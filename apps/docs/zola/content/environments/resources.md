---
title: Resources and limits
description: What every environment gets, the sizes you can choose, what an organization can run at once, and what each state keeps and costs.
updated: 2026-10-26
weight: 2
---

Every environment starts at a default size, which you can change when you
create it or later. Local VMs are limited only by these sizes and your own
machine; hosted sandboxes also count against their organization's limits.

## What every environment gets

| | Local VM | Hosted sandbox |
| --- | --- | --- |
| vCPU | 2 | 2 |
| Memory | 4 GiB | 8 GiB |
| Disk | 20 GiB | 10 GiB |
| Docker data disk | 8 GiB, separate | — |
| Address | none; ports you publish on `127.0.0.1` | HTTPS preview URLs and SSH from anywhere you are signed in |
| Runs until | you stop it | you stop it, or its `--ttl` ends |

A flag wins over `codewire.yaml` and presets; the default fills in whatever
none of them sets.

## Choosing a size

```sh
cw create --local --name app --path . --cpu 4 --memory 8GB --disk 40GB
cw create --name app --repo https://github.com/octocat/Hello-World --cpu 4 --memory 16GB
cw resize app --cpu 8 --memory 32GB
```

CPU is in cores: `2`, or `0.5` and `500m` for half a core on a hosted
sandbox. Memory and disk take `MB` and `GB` units. In `codewire.yaml` they
are quoted strings; see [codewire.yaml keys](@/reference/codewire-yaml.md).

| | Local VM | Hosted sandbox |
| --- | --- | --- |
| vCPU | 1 to 32, whole cores | 0.1 to 256 |
| Memory | 128 MiB to 64 GiB | 128 MiB to 1 TiB |
| Disk | 1 GiB to 1 TiB | 1 GiB to 16 TiB, whole GiB |

A size outside these ranges is refused, never quietly reduced.

- **Disks only grow.** Asking for a smaller disk fails, locally and hosted.
- **Resizing a local VM** stops it, grows the disk offline and starts it
  again; its sessions end.
- **Resizing a hosted sandbox** applies at its next start if it is stopped. A
  running one grows its disk in place, but needs a restart to take less
  memory, and on some hosts to take more CPU or memory; `cw resize` asks
  first (`--allow-restart` agrees in advance).

## Organization limits

Hosted sandboxes count against their organization while they are active:
starting, running or stopping. Stopped sandboxes do not count.

| Limit | Default |
| --- | --- |
| Active sandboxes | set by the plan; your organization's **Billing** page shows it |
| CPU across active sandboxes | 32 vCPU |
| Memory across active sandboxes | 64 GiB |
| Creates and starts | 10 of each per minute, per person |

At the default 8 GiB each, the memory total allows eight running sandboxes at
once. Going over a limit fails with `quota_exceeded`,
`resource_limit_exceeded` or `rate_limited`; see
[Errors](@/reference/errors.md). `hello@codewire.sh` can raise an
organization's limits.

Up to 256 application secrets reach one environment, each value up to
64 KiB.

## What each state keeps and costs

| State | Keeps | Counts toward limits | Billed |
| --- | --- | --- | --- |
| Running | everything | yes | per second, for vCPU, memory and disk |
| Stopped | its disk, settings and agent conversations | no | nothing |
| Removed | nothing | no | nothing |

Local VMs are never billed. When a hosted sandbox's `--ttl` ends, it is
removed, not stopped, unless it is protected (`cw protect`); `cw extend`
adds up to 24 hours at a time. See [Lifecycle](@/environments/lifecycle.md)
and [Usage and costs](@/organizations/usage.md).
