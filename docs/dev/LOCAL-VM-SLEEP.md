# Local VM sleep

A local VM on Linux can **suspend** in memory and **hibernate** to disk, either
by hand or after an idle timeout, and wake automatically when used with its
processes still running. This page is the contract for `#5529`, written before
the local implementation, and its acceptance journey is
[`docs/journeys/local-vm-sleep.md`](../journeys/local-vm-sleep.md). It matches
the CLI verbs, flags, states, and fallback contract shipped for cloud
`standard` Sandboxes ([`IDLE-STOP.md`](IDLE-STOP.md), "Suspend";
[`SANDBOX-SLEEP.md`](SANDBOX-SLEEP.md)).

Local VMs on macOS (`#4654`) and enrolled hosts (`#3609`) are out of scope for
`#5529`.

## The two sleep states

| State | What it is | What the host gets back | Waking |
| --- | --- | --- | --- |
| `suspended` | The VM's workload is frozen and its vCPUs are paused in memory. Processes, memory, open files, and sockets stay as they were. | CPU | `cw resume`, `cw start`, or the first connection (`cw shell`, `cw run`, `cw exec`, `ssh`, host port) resumes it in milliseconds. |
| `hibernated` | The VM's memory and device state are written to its private state directory on disk and the VMM and helper processes exit. | CPU and memory | `cw start`, `cw resume`, or the first connection restores it in a few seconds with processes and clock intact. |

A sleeping VM runs nothing. Timers and scheduled jobs inside it do not fire
while it sleeps. `stopped` is unchanged: a stop ends the VM's processes and
keeps its disks.

## Commands and settings

All commands and flags match cloud `standard` Sandboxes (`#6650`, `#6647`):

| Command / setting | Default | Meaning |
| --- | --- | --- |
| `cw [--local] suspend NAME` | manual | Freezes the guest workload and pauses the VM (`state = suspended`). Idempotent if already `suspended`. Refused if `stopped` or `hibernated`. |
| `cw [--local] resume NAME` | manual | Resumes a `suspended` VM (or restores a `hibernated` VM). Idempotent if already `running`. Refused if `stopped`. |
| `cw [--local] hibernate NAME` | manual | Saves guest memory and device state to disk and exits the VMM (`state = hibernated`). Accepts `running` or `suspended` VMs. Idempotent if already `hibernated`. Refused if `stopped`. |
| `cw [--local] start NAME` | manual | Wakes a `suspended` or `hibernated` VM, or cold-boots a `stopped` VM. |
| `--idle-suspend 15m\|on\|off` | `off` (`on` = `15m`) | Automatically suspends the VM after this much idle time (`5m` to `7d`, or `off`). |
| `--idle-hibernate 6h\|on\|off` | `off` (`on` = `6h`) | Automatically hibernates the VM after this much idle time (`5m` to `7d`, or `off`). |

- **`codewire.yaml`:** `idle_suspend` and `idle_hibernate` use the exact
  grammar already shared with cloud (`5m` to `7d`; `on`/`true` = `15m` for
  suspend and `6h` for hibernate; `off`/`false`/`0` disables).
- **`cw create --local --idle-suspend … --idle-hibernate …`** overrides
  `codewire.yaml`.
- **`cw update NAME --idle-suspend … --idle-hibernate …`** updates either
  setting on an existing local Linux VM in any state without restarting or
  waking it.
- **Ordering rule:** when both `idle_suspend` and `idle_hibernate` are enabled,
  `idle_hibernate` must be strictly longer than `idle_suspend`; otherwise
  create/update is refused, naming both values. With `idle_suspend` off and
  `idle_hibernate` on, an idle VM transitions directly from `running` to
  `hibernated`.
- **Non-Linux local VMs:** Macs (`#4654`) refuse `cw suspend`, `cw resume`,
  `cw hibernate`, `--idle-suspend`, and `--idle-hibernate` with a message
  stating that local VM sleep is supported only on Linux.

## What counts as activity

The rule matches cloud idle stop and suspend (`#3384`,
[`IDLE-STOP.md`](IDLE-STOP.md)), measured on the host by the supervisor without
waking a sleeping VM:

- **CPU:** the VM process used at least 10% of one CPU (6 seconds of CPU time
  in the last minute, covering everything in the guest including Docker
  containers).
- **Terminal or session activity:** input or output on a `cw` session, shell,
  or SSH connection, including a managed agent turn in flight (whose driver
  emits periodic turn heartbeats while waiting on its model) and active
  `cw exec`, `cw run`, `cw cp`, or checkpoint operations.
- **Inbound traffic:** connections or data on published host ports, local HTTPS
  hostnames, SSH, or admitted Mesh streams.
- **A start or wake:** a VM never sleeps within its idle timeout of starting or
  waking.

These do not count: an idle attached terminal with no input/output, `cw ls`,
`cw info`, `cw ports` (read-only), `cw doctor`, or outbound-only traffic from
the guest.

While a VM is `suspended`, its idle clock keeps advancing toward
`idle_hibernate` without waking the VM.

## Going to sleep

- **Suspend:** the runner freezes the guest workload through PID 1's checkpoint
  hook and pauses Cloud Hypervisor (`vm.pause`). The supervisor records
  `suspended` (with timestamp and reason: `user` or `idle`). The VM process,
  its helper processes, and its published host ports stay alive. On a host
  reboot or supervisor exit, a `suspended` VM lands in `stopped`, like a
  `running` VM.
- **Hibernate:** if `suspended`, the runner snapshots the already-paused VM (or
  freezes and pauses a `running` VM), writes Cloud Hypervisor's memory and
  device state into `vms/<id>/checkpoints/in` (mode `0400` inside `0700`),
  writes sibling hibernate metadata (`hibernate/record.json` and one-shot
  `hibernate/generation`, mode `0600` inside `0700`) outside the VMM's write
  directory, and terminates the VMM and helper processes so the host gets CPU
  and RAM back. No disk is copied, so no reflink filesystem is required.
- **Memory file custody:** the hibernate image belongs to the environment, is
  readable only by the owning user, is never listed as a `cw checkpoint`, is
  never exported or forked, and is excluded from `cw snapshot`. It is restored
  at most once (guarded by the external generation file consumed before restore
  starts) and deleted immediately after restore succeeds, on `cw stop`, on cold
  fallback, or on `cw rm`.
- **Disk space:** before writing a hibernate image, the supervisor checks free
  space on the state root for the VM's memory plus 2 GiB headroom. If space is
  insufficient, manual `cw hibernate` fails clearly leaving the VM running (or
  suspended), and idle hibernate skips the transition and records why.
- **Open connections:** hibernate closes active host-to-guest connections
  (attached terminals and SSH), while durable sessions keep running inside the
  guest and can be reattached after wake.

## Waking

- **What wakes a sleeping VM:** `cw start`, `cw resume`, `cw shell`, `cw run`,
  `cw exec`, `cw attach`, `cw cp`, `cw logs`, `cw msg`, `cw checkpoint create`,
  SSH (`cw-local-<name>`), and connections to published host ports.
- **What does not wake a sleeping VM:** `cw ls`, `cw info`, read-only
  `cw ports`, `cw doctor`, and `cw rm` (which deletes the VM and any hibernate
  memory file without waking it).
- **From `suspended`:** the runner calls Cloud Hypervisor `vm.resume` and thaws
  the guest workload. Concurrent wake requests coalesce onto one resume.
- **From `hibernated`:** the supervisor starts a fresh runner restoring from
  `checkpoints/in` over the VM's existing disks, keeping guest processes,
  sessions, workspace files, and SSH host key intact, reseeding the guest RNG,
  and aligning the guest clock with the host. Concurrent wake requests wait on
  the same restore.
- **`cw stop` and `cw restart`:** on a `suspended` VM, resume first so the
  guest shuts down cleanly. On a `hibernated` VM, `cw stop` discards the
  hibernate memory file and transitions directly to `stopped` (ending saved
  processes while keeping disks); `cw restart` discards the memory file and
  cold-boots the VM.

## When a hibernated VM cannot be restored (fallback)

Matching the cloud `standard` hibernate contract
([`SANDBOX-SLEEP.md`](SANDBOX-SLEEP.md), "When a restore cannot happen"): if a
hibernated local VM's memory image cannot be restored — because files are
missing or damaged, checksums fail, the VMM binary `sha256` or guest runtime
ABI changed after an upgrade, the VM configuration changed, or the one-shot
restore generation was already consumed:

1. The supervisor deletes the unusable hibernate memory files and metadata.
2. The supervisor boots the VM cleanly from its existing persistent disks
   (`/workspace`, `/home/codewire`, root disk, and Docker disk intact).
3. The supervisor records `hibernate_fallback_reason` on the environment and
   clears its `hibernated` state (cleared again on the next start or stop).
4. `cw start`, `cw resume`, wake-on-access (`cw shell`/`cw run`/`cw exec`), and
   `cw info` surface a clear fallback notice stating why restore failed, that
   the VM booted cleanly from disks, and that running processes were lost while
   workspace files were kept.

Workspace files are never lost and a user is never stranded in an unbootable
state.

## What a person sees

- **`cw ls`:** `STATE` reads `suspended` (or `suspended (idle)`) and
  `hibernated` (or `hibernated (idle)`). JSON `state` carries `"suspended"` or
  `"hibernated"`.
- **`cw info`:** shows `State: suspended` or `State: hibernated`, when and why
  it slept, `IdleSuspend` and `IdleHibernate` settings, memory file size when
  hibernated, last wake duration, and any `hibernate_fallback_reason` notice
  after a fallback cold boot.
- **`cw doctor`:** treats `suspended` and `hibernated` local VMs as healthy.
