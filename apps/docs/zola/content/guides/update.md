---
title: Update cw
description: Keep the managed cw current, roll back, and move local VMs that still run on the previous version.
weight: 9
---

```sh
cw update                      # the stable channel; refuses a downgrade
cw update status --json
cw update --version v0.3.400   # an explicit signed release, downgrade allowed
cw update rollback             # the previous version
cw update rollback --to 0.3.39 # a retained version by package version or digest prefix
```

Releases come from `releases.codewire.sh` and are signature-checked. Every
installed version is retained, so a rollback downloads nothing. A `cw` that is
running keeps its bytes: the update only changes which version the
`~/.local/bin/cw` link points to.

## Local VMs across an update

`cw update` never stops your local VMs. The previous version's VM supervisor
keeps serving them, and the new `cw` uses it for everything that does not boot
or reconfigure a VM: listing, `cw run`, `cw shell`, sessions and logs,
stopping, removing and host ports. Creating, starting, restarting or resizing
a VM needs the new supervisor, so while an old VM still runs such a command
says:

```text
your local VMs dev, web still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw env --local stop NAME`)
cw: restart them with `cw env --local upgrade`
```

Once none of your VMs runs, the next such command switches over by itself and
installs the new runtime. To move running VMs now:

```sh
cw env --local upgrade          # names them and asks; a restart ends the work in them
cw env --local upgrade --yes
cw update --restart-vms         # update and restart them without asking
```

Each VM stops the ordinary way, the supervisors hand over, and it starts again
on the new `cw`. Without a terminal these commands only list the VMs. After a
rollback, `cw setup --local` reinstalls the previous runtime from the copy it
kept beside the current one.

`cw` works with VM supervisors back to v0.3.388's; an older one is refused
with a message that names it.

## Runtime inside the VM

The `cw` that runs inside a local VM, for sessions and managed agents, comes
from the runtime `cw setup --local` installed; a VM keeps the runtime it
started with until it restarts.
