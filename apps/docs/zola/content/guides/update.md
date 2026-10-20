---
title: Update cw
description: Keep the managed cw current, roll back, and move local VMs that still run on the previous version.
weight: 9
---

```sh
cw upgrade                       # at a terminal: choose the newer CLI and VM restarts
cw upgrade --cli                 # the stable channel without asking; refuses a downgrade
cw upgrade status --json
cw upgrade --version v0.3.400    # an explicit signed release, downgrade allowed
cw upgrade rollback              # the previous version
cw upgrade rollback --to 0.3.39  # a retained version by package version or digest prefix
```

Releases come from `releases.codewire.sh` and are signature-checked. Every
installed version is retained, so a rollback downloads nothing. A `cw` that is
running keeps its bytes: the upgrade only changes which version the
`~/.local/bin/cw` link points to.

At a terminal, bare `cw upgrade` checks for a newer stable `cw` and for local
VMs that would be left on an older one, and offers what applies as a
checklist: the CLI checked, the VM restart unchecked. Space toggles, Enter
applies, Escape or Ctrl-C changes nothing. In a script, bare `cw upgrade`
upgrades the CLI only. `cw upgrade` never changes an environment; that is
`cw update ENV`.

## Local VMs across an upgrade

`cw upgrade` never stops your local VMs unless you choose the restart. The
previous version's VM supervisor keeps serving them, and the new `cw` uses it
for everything that does not boot or reconfigure a VM: listing, `cw run`,
`cw shell`, sessions and logs, stopping, removing and host ports. Creating,
starting, restarting or resizing a VM needs the new supervisor, so while an
old VM still runs such a command says:

```text
your local VMs dev, web still run on the cw you updated from; this cw starts and changes local VMs once they stop (`cw --local stop NAME`)
cw: restart them with `cw upgrade --vms`
```

Once none of your VMs runs, the next such command switches over by itself and
installs the new runtime. To move running VMs now:

```sh
cw upgrade --vms          # restart them onto this cw; a restart ends the work in them
cw upgrade --cli --vms    # upgrade the CLI, then restart them
```

Each VM stops the ordinary way, the supervisors hand over, and it starts again
on the new `cw`. Without `--vms` (or the checked checklist item) an upgrade
only lists the VMs left on an older `cw`. After a rollback, `cw setup --local`
reinstalls the previous runtime from the copy it kept beside the current one.

`cw` works with VM supervisors back to v0.3.388's; an older one is refused
with a message that names it.

## Runtime inside the VM

The `cw` that runs inside a local VM, for sessions and managed agents, comes
from the runtime `cw setup --local` installed; a VM keeps the runtime it
started with until it restarts.
