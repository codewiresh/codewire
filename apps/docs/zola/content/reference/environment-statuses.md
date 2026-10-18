---
title: Environment statuses
description: The states cw env info and the dashboard report for an environment.
weight: 1
---

`cw env info ENV` and `cw env list` show the state; the dashboard shows the
same word in lowercase, with `destroying` as "deleting…" and `destroyed` as
"deleted".

| State | Meaning | What to do |
| --- | --- | --- |
| `pending` | Creation is queued. | Wait; `cw env logs ENV` follows setup on the platform. |
| `pending_build`, `building` | A custom image is being built. | Wait. |
| `build_failed` | The image build failed. | Read the setup logs, fix the image, create again. |
| `pulling_snapshot` | A saved image layer is being fetched. | Wait. |
| `creating` | The VM, storage and daemon are being set up. | Wait; a local create shows its stage on one line. |
| `starting` | A stopped environment is coming back. | Wait. |
| `running` | Sessions, SSH, previews and agents are available. | |
| `stopping` | Processes are being terminated and disks unmounted. | A process that ignores SIGTERM makes this take about 5 s. |
| `stopped` | Compute is released; workspace storage is kept. | `cw env start ENV`. |
| `resizing` | Resources are being changed. | Wait; the environment returns to its previous state. |
| `archiving`, `archived`, `restoring` | Long-term storage states. | `cw env start ENV` restores an archived environment. |
| `destroying`, `destroyed` | Deletion in progress or done. | Protected environments refuse deletion. |
| `error` | The last operation failed; `cw env info` shows the error code. | `cw env daemon status ENV` and `repair`, or stop and start; for a local VM see [Troubleshoot local VMs](@/guides/troubleshoot-local-vms.md). |
| `unknown` | The state could not be read. | Retry; `cw list` reports environments it cannot reach. |

`cw env list --state STATE` filters by state, and `cw env prune` removes
hosted environments stuck in `error`, `creating` or `pending`.
