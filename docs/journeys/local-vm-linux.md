# Local VMs on Linux

Local VMs on a Linux host run under Cloud Hypervisor (`docs/dev/LINUX-LOCAL-VMS.md`).
This file holds the Linux steps that differ from the Mac's
([local-vm-mac.md](local-vm-mac.md)). The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-15.

| ID | Linux |
| --- | --- |
| `linux-vm-image-disk` | not yet observed (#4646 trial branch) |

## `linux-vm-image-disk`: one shared image disk per image (#4646)

On the #4646 trial branch only: a built `cw` from `feat/image-disk-4646`.
The design is `private-docs: designs/2026-11-14-local-shared-image-disk.md`.
Here the builder guest runs under Cloud Hypervisor; the Mac's twin is
`mac-vm-image-disk`.

- **Entry points:** `cw create --local`.
- **States to exercise:**
  - the first create from an image never used on this host, which builds the image disk;
  - a second create from the same image, which builds nothing;
  - a builder killed mid-build, after which the next create builds again;
  - the staged disk swapped before the builder exits, after which nothing is promoted;
  - an image disk removed by hand, and the error a start then gives;
  - a VM from before the change;
  - collection once nothing names the disk.
- **Driving it:** no command yet beyond `cw create --local`. Each step is in
  the design's acceptance journey (section 10).
- **Proof:**
  - the first create names "Preparing the image" and the build;
  - the second create's time is recorded with no build;
  - a file written under `/usr` in A is absent in B;
  - S0's `guest_stages` and `vm_started` lines give the times.
- **Observed:** not yet observed.
