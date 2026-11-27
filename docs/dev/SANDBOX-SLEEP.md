# Sandbox sleep on `standard`

Target, not shipped (`#6647`). A cloud Sandbox on the `standard` runtime
profile that nobody is using can **suspend** in memory and **hibernate** to
its encrypted volume, then wake or restore with its processes still running.
This page is the contract for `standard` hibernate and restore, written before
the code (`#6647`; design and owner decisions on `#5484`, `#5602`, `#5529`).

- **Suspend** (`idle_suspend`, pausing the VM inside its Pod and waking on
  use) is specified in [`IDLE-STOP.md`](IDLE-STOP.md), "Suspend".
- **Activity rules** ("any traffic counts") are specified in
  [`IDLE-STOP.md`](IDLE-STOP.md), "What counts as activity".
- **Re-bind after restore** is summarized in
  [`SANDBOX-DAEMON.md`](SANDBOX-DAEMON.md), "Claim-time workspace binding",
  and specified in full in ["After a restore"](#after-a-restore) below.
- **Billing** is specified in [`BILLING.md`](BILLING.md), "A hibernated
  stretch".
- **Admission and volume headroom** are specified in
  [`CODEWIRE-GUARD-RUNTIME-PROFILES.md`](CODEWIRE-GUARD-RUNTIME-PROFILES.md),
  "The `standard` profile".
- **Acceptance journeys** are `standard-hibernate` and
  `standard-hibernate-fallback` in
  [`docs/journeys/standard-runtime.md`](../journeys/standard-runtime.md).

Sandboxes on `commodity` and `confidential` never suspend or hibernate: they
stop when idle ([`IDLE-STOP.md`](IDLE-STOP.md)). Local VMs on Linux are
tracked separately (`#5529`).

## The two sleep states

| State | What it is | What the node gets back | Waking |
| --- | --- | --- | --- |
| `suspended` | The VM is paused in its Pod. Its processes, memory, open files and connections stay as they were. | CPU | Any connection on the Pod's published ports or a wake from orchestration resumes it ([`IDLE-STOP.md`](IDLE-STOP.md), "Suspend"). |
| `hibernated` | The VM's memory and device state are written to the Sandbox's LUKS-encrypted volume outside guest reach, and the Pod is deleted. | CPU and memory | A start restores the VM on the same volume, with its processes, sessions, files, name, preview URL and tailnet identity intact. |

A sleeping Sandbox runs nothing. A timer or scheduled job inside it fires when
it wakes. On waking or restoring, the VM's clock matches the node's.

`stopped` is unchanged: a stop ends the Sandbox's processes and keeps its
disk.

### State representation

`hibernated` is a mark on a stopped Sandbox, matching how `suspended` is a
mark on a running Sandbox ([`IDLE-STOP.md`](IDLE-STOP.md), "The suspend"):

- The stored lifecycle state is `stopped` (`desired_state = 'stopped'`), and
  the Sandbox carries `hibernated_at`, `hibernate_reason` (`idle` or `user`),
  and its hibernate metadata record (runtime image digest, image disk
  reference, image disk id, build id, VMM sha256, and restore generation).
- Every existing stop-safe invariant (Pod deleted, workspace binding released,
  running/paused billing session closed, stop/destroy fencing) applies without
  a new lifecycle state machine branch, and clients older than hibernate see
  `stopped` and can still start the Sandbox with `cw start`.
- The API exposes `Environment.hibernated_at`, `Environment.hibernate_reason`,
  and `Environment.hibernate_fallback_reason` (set when a start had to fall
  back to a cold disk boot, cleared on the next start or stop). `cw ls`,
  `cw info` and the dashboard's state pill display `hibernated` while
  `hibernated_at` is set.
- Stopping a `hibernated` Sandbox (`cw stop NAME`) clears `hibernated_at` and
  its hibernate record so it becomes an ordinary `stopped` Sandbox; the next
  start boots cold from the disks and discards any memory file left on the
  volume.

## The settings and commands

| Setting / command | Default | Meaning |
| --- | --- | --- |
| `idle_suspend` | off; `on` is 15 minutes | Pauses the VM in its Pod once idle this long ([`IDLE-STOP.md`](IDLE-STOP.md)). |
| `idle_hibernate` | off; `on` is 6 hours | Hibernates the Sandbox once idle this long (`5m` to `7d`, or `off`). |
| `cw hibernate NAME` | manual | Hibernates a `running` or `suspended` `standard` Sandbox now. |

- **`codewire.yaml`:** `idle_hibernate: 6h`, using the same duration grammar
  as `idle_stop` and `idle_suspend` (`45m`, `6h`, `1h30m`, `7d`; `on` or
  `true` is 6 hours; `off`, `false` or `0` turns it off). Stored in its own
  request field and column, never in the project spec.
- **`cw create --idle-hibernate 6h|on|off`** overrides `codewire.yaml`, and
  **`cw update NAME --idle-hibernate 6h|on|off`** changes an existing Sandbox
  (`running`, `suspended`, `stopped` or `hibernated`) without waking or
  restarting it.
- **API:** `CreateEnvironmentRequest.idle_hibernate_seconds`,
  `SetEnvironmentIdleHibernate`, and `HibernateEnvironment`, with the same
  operator access and range validation (`5m` to `7d`, or `0` for off) as
  `idle_stop` and `idle_suspend`.
- **Runtime profile check:** setting `idle_hibernate` or calling
  `cw hibernate NAME` / `HibernateEnvironment` on a Sandbox whose recorded
  runtime profile is not `standard` (such as `commodity` or `confidential`) is
  refused with `failed_precondition`, naming the Sandbox's runtime profile.
- **Relationship to `idle_suspend`:** when both `idle_suspend` and
  `idle_hibernate` are on, `idle_hibernate` must be strictly greater than
  `idle_suspend`; otherwise the create or update is refused with
  `invalid_argument`, naming both settings.
- **Relationship to `idle_stop`:** on `standard`, `idle_hibernate` takes
  `idle_stop`'s place. When `idle_hibernate` is on for a `standard` Sandbox,
  the idle worker hibernates it instead of stopping it; when `idle_hibernate`
  is off, `idle_stop` behaves unchanged.
- **Manual `cw hibernate NAME`:**
  - On a `running` or `suspended` `standard` Sandbox, triggers hibernate now
    with `hibernate_reason = 'user'`.
  - On an already `hibernated` Sandbox, succeeds as a no-op and says it is
    already hibernated.
  - On a `stopped` Sandbox, refuses with `failed_precondition` explaining that
    a stopped Sandbox has no running VM to hibernate.
- **A fork** (`cw --cloud create --snapshot`) takes the `idle_hibernate`
  setting its source had when the snapshot was captured (on `standard`);
  `--idle-hibernate` at fork overrides it.

## What counts as activity

Exactly idle stop's rule ([`IDLE-STOP.md`](IDLE-STOP.md), "What counts as
activity"): CPU, terminal input or output, an agent turn or `cw` runtime
request in flight, and inbound traffic ("any traffic counts"). Orchestration's
idle worker decides on the same 30-second loop, and time spent `suspended`
counts toward `idle_hibernate` without waking the VM to poll activity until
the hibernate timeout is reached.

## Hibernating a Sandbox

1. **The ask.** When a `standard` Sandbox reaches its `idle_hibernate` timeout
   (with no open agent or `cw` runtime request) or receives
   `HibernateEnvironment` (`cw hibernate`), orchestration calls the daemon's
   `Hibernate` RPC (`DaemonService`, under the bound Pod's daemon credential).
   - If the Sandbox is `suspended`, that call on port `7777` wakes the VM
     briefly so the daemon can execute the hibernate handoff uniformly with no
     new host-to-Pod port.
   - A daemon whose runtime does not support hibernate answers unimplemented;
     the idle worker remembers that Pod and stops asking it (and manual
     `cw hibernate` returns `failed_precondition` saying this Sandbox's
     runtime cannot hibernate).
   - Otherwise, the daemon quiets its platform connections (tailnet and mesh
     coordinator sessions, DERP, and credential relay epoch — held closed so
     nothing reconnects before the freeze), sends `hibernate\n` to the
     supervisor on host vsock port `7784`, waits for `ok\n`, and answers
     `accepted`.
2. **Arming in the supervisor.** On `hibernate\n`, `cw __pod-runtime` arms
   hibernate-on-SIGTERM, answers `ok\n` (or `no\n` if the VM cannot
   hibernate), and writes a host-observed arming line to the Pod log.
3. **Pod stop and SIGTERM.** Once the daemon accepts, orchestration marks the
   Sandbox's desired stop as a hibernate stop and deletes/scales down the Pod,
   sending SIGTERM.
4. **Memory write inside the Pod grace period.** On SIGTERM with hibernate
   armed, `cw __pod-runtime`:
   - freezes the workload through PID 1's checkpoint hook (`Freeze`);
   - pauses every vCPU;
   - has Cloud Hypervisor write guest memory and device state into a private
     staging directory on the Sandbox's LUKS-encrypted volume (`/state/runtime/`),
     outside every path the guest can reach; no disk is copied;
   - writes a sibling hibernate metadata record naming:
     - the VMM binary's `sha256`;
     - the runtime image digest (`CODEWIRE_STANDARD_RUNTIME_IMAGE_DIGEST` or
       the runtime's baked digest);
     - the workspace image disk's `image_disk_id` and `build_id`;
     - the restore generation counter (matched against a generation file kept
       outside the memory image directory);
     - the runner's `RestoreBoot` bindings;
   - atomically commits the staging directory into the active hibernate slot
     and syncs it to the volume;
   - writes one host-observed Pod log line:
     `standard runtime: vm-hibernate-record {"event":"hibernated","generation":G,"vmm_sha256":"...","image_disk_id":"...","build_id":"...","at_unix_ms":T}`;
   - ends Cloud Hypervisor without a guest power-off and exits `0`, fitting
     within the Pod's 60-second termination grace period.
   - If freezing, pausing, or writing fails or exceeds its write budget inside
     the grace period, the supervisor discards the incomplete staging files,
     powers the guest off cleanly, writes no `hibernated` record, and exits.
     The next start then boots cleanly from the disks.
5. **Host-observed state transition.** Orchestration reads the Pod's log
   before completing the stop. Only when orchestration **itself** requested
   the hibernate **and** observes the runtime's `vm-hibernate-record`
   `"event":"hibernated"` line (which no guest output can forge because guest
   output is always prefixed `guest-daemon: `) does orchestration set
   `hibernated_at`, `hibernate_reason`, and the hibernate record on the
   environment. If no `hibernated` record was written (for example, a write
   timeout or a crash), the Sandbox lands in plain `stopped` (not
   `hibernated`).
   - Because orchestration only enters `hibernated` when orchestration
     requested it, an unsolicited `hibernate\n` sent by a guest process on
     vsock `7784` can never cause orchestration to treat a stop as a hibernate
     or restore an unrequested memory image.
6. **Volume space.** A `standard` Sandbox's PVC includes unbilled headroom
   for its memory file (the VM's memory plus device-state overhead). The
   cluster volumes are thin LVM with discards, so real blocks are consumed
   only while a memory file is present.

## Restoring a hibernated Sandbox

- **Triggers:** `cw start NAME`, the dashboard's **Start**, or
  start-on-access (`cw shell`, `cw exec`, `cw attach`, `cw run`, `ssh`, and
  signed-in preview visits that wake a hibernated Sandbox).
- **Rendering the restoring Pod:**
  - Orchestration checks whether the hibernate record's runtime image digest
    and workspace image-disk digest are still within the 30-day admission
    allow window
    ([`CODEWIRE-GUARD-RUNTIME-PROFILES.md`](CODEWIRE-GUARD-RUNTIME-PROFILES.md)).
  - If they are allowed, orchestration renders the new Pod with the hibernate
    record's runtime image digest and workspace image-disk reference/ids and
    sets `CODEWIRE_VM_RESTORE_GENERATION=<G>` on the `workspace` container.
    The Pod mounts the Sandbox's existing node-local volume (scheduling onto
    the same node).
  - If the 30-day window has elapsed or the digests are no longer admitted,
    orchestration clears the hibernate record, records the fallback reason
    (`runtime_image_expired`), and renders a normal cold-boot Pod on the
    current release digests (without `CODEWIRE_VM_RESTORE_GENERATION`).
- **In `cw __pod-runtime` at boot:**
  - When `CODEWIRE_VM_RESTORE_GENERATION` is unset (ordinary cold start, or
    start after `cw stop` of a hibernated Sandbox), the runtime deletes any
    leftover hibernate directory and record on the volume before booting cold.
  - When `CODEWIRE_VM_RESTORE_GENERATION=<G>` is set, the runtime checks:
    1. the active hibernate slot and sibling metadata record exist and are
       intact (checksums / required VMM files present);
    2. the generation recorded **outside** the memory directory equals `G`
       and has not already been consumed (**restore-once**);
    3. the VMM binary's `sha256`, the runtime image digest, and the mounted
       image disk's `image_disk_id` and `build_id` all match the metadata
       record.
  - Before starting the restore, the runtime advances/marks the external
    generation as consumed so the same memory image can never be restored a
    second time even if the Pod crashes mid-restore.
  - If every check passes, the runtime restores Cloud Hypervisor from the
    hibernate slot over the same disks, keeping `7777` and `2222` closed
    until the restored daemon completes its new bind (see ["After a
    restore"](#after-a-restore)).
  - **Kept across restore:** running processes, durable sessions, files,
    Sandbox name, preview URL, and tailnet name and address.
  - **Lost at hibernate:** open network connections through the old Pod's
    address, both ways.

## After a restore

Agreed with `cw-security` (2026-11-21, `#5484`). A restored guest holds its
pre-hibernate memory, so nothing from the old Pod is trusted:

> **A running daemon never re-binds; a restored daemon binds again, as the new
> Pod's daemon, before it serves.**

### Every old Pod authority ends on the server

Each item below is verified by an automated test that presents the old value
after restore and observes it refused:

| Authority in restored memory | Where it ends |
| --- | --- |
| Daemon credential (HMAC over environment, Pod UID, purpose) | Refused by the new Pod UID |
| Projected ServiceAccount tokens (`binding`, `credential`, `egress`) | Bound to the deleted Pod object; Kubernetes / API refuses them |
| Workspace binding row | Released once the old Pod is gone |
| Credential bridge epochs, front-door registrations, and broker leases for the old Pod | Refused once the old binding is released (test presents an old epoch handle after the new bind) |
| Tailnet node key (and disco key / any node or pre-auth secret) | Re-bind generates a fresh WireGuard node key and disco key in memory; the coordinator drops the old node key in the same bind while keeping the Sandbox's tailnet name and address |

### Strict thaw order

Before the frozen workload (including the hosted daemon) thaws, the
supervisor and guest init execute these steps in strict order:

1. **Reseed RNG and move boot secrets.** Guest init's resume step (PID 1,
   outside `/workload`) reseeds the guest kernel RNG from fresh host entropy,
   steps the guest clock to the host's wall clock, and rotates boot-scoped
   control secrets to the new boot generation.
2. **Deliver the new Pod's settings and tokens.** Over the authenticated
   hosted control channel, the supervisor delivers the new Pod's settings
   (`CODEWIRE_POD_UID`, platform peers, TLS roots) and projected tokens
   (`binding`, `credential`, and `egress` in broker mode), replacing every
   checkpointed copy whole.
3. **Delete the old daemon credential.** Guest init removes
   `/codewire/run/daemon/credential` (and signals the daemon that this wake
   is a restore requiring a fresh bind) **before** thawing `/workload`.

### Ports and tailnet stay closed until re-bind succeeds

- The supervisor does **not** bind or forward Pod TCP ports `7777` or `2222`
  until the restored daemon completes its new `BindWorkspace` and reports
  re-bind completion. A connection attempt to `7777` between restore and bind
  is refused (verified by test).
- Inside the guest, the restored daemon clears its in-memory old credential,
  keeps `7777`, `2222`, and tailnet closed/refusing, reloads the new Pod's
  settings and projected tokens, calls `BindWorkspace` on `8087` with the new
  Pod UID and token, writes the new credential (`0400`), starts a fresh
  tailnet connection with a newly generated WireGuard node key and disco key
  (dropping the old node key at the coordinator), re-records its SSH host key
  if required by the new binding generation, and only then re-opens `7777`
  (accepting only the new daemon credential), `2222`, and tailnet.
- Once the restored daemon confirms the new bind, the supervisor opens `7777`
  and `2222`, writes a host-observed `standard runtime: vm-hibernate-record
  {"event":"restored",...}` log line, and **deletes the hibernate memory file
  and its metadata record** from the volume.

### Memory file custody

1. **Unreachable by the guest.** The memory file and its metadata live under
   `/state/runtime/` on the Sandbox's LUKS-encrypted volume, mode `0700`
   (files `0600`), owned by the container's non-root user. No virtio-fs
   share, guest disk, or workspace path exposes it: Cloud Hypervisor parses
   it at restore, so the guest must never be able to write or corrupt it.
2. **Restored at most once.** Checked against a generation counter stored
   outside the memory directory, consumed before restore starts.
3. **Deleted on completion, stop, or destroy.** Deleted immediately after the
   restored daemon binds, discarded on any non-restore start (such as after
   `cw stop` or a fallback), and deleted with the PVC on `cw rm`.
4. **Never a VM checkpoint; excluded from snapshots and forks.** Never listed
   by `cw checkpoint` and cannot be forked. Disk snapshot clearing
   (`cw __snapshot-clear --standard-vm`) removes any hibernate memory file
   and record from the snapshot volume so product snapshots and forks never
   carry it. Encrypted infrastructure volume backups may still hold a copy;
   an old copy is harmless because every credential inside it is dead on the
   server (table above).

## When a restore cannot happen (fallback)

When restore is impossible — because the memory file is missing, incomplete,
or damaged, the workspace image disk was rebuilt (`image_disk_id` or
`build_id` mismatch), the VMM binary `sha256` or runtime image digest does
not match, the generation was already consumed, or the runtime image is past
its 30-day admission allow window:

1. The runtime (or orchestration, for an expired 30-day allow window) deletes
   the unusable memory file and metadata record.
2. The Sandbox boots cleanly from its persistent disks (`/workspace`,
   `/home/codewire`, and root disk intact).
3. The runtime emits a host-observed Pod log line:
   `standard runtime: vm-hibernate-record {"event":"fallback","reason":"...","at_unix_ms":T}`.
4. Orchestration records `hibernate_fallback_reason` on the environment and
   clears `hibernated_at`.
5. `cw start` and `cw info` clearly inform the user that the Sandbox could
   not restore from hibernate, so its running processes were lost while its
   files were kept, naming the reason.

## Billing

A hibernated `standard` Sandbox closes its running or paused billing session
at the host-observed hibernate stop and opens a `hibernated` session that
draws only its allocated disk (`disk_gib`, excluding the unbilled memory-file
headroom) at the organization rate card's storage rate
(`parked_storage_per_gib_hour`, `0` until set on the admin Pricing page,
`#5782`). No rate is hardcoded in code, and nothing the guest says moves a
second between billing rates. See [`BILLING.md`](BILLING.md), "A hibernated
stretch".

## What a person sees

- **`cw ls`:** `STATE` reads `hibernated` (or `hibernated (idle)` when
  hibernated by `idle_hibernate`).
- **`cw info`:** shows `State: hibernated`, `IdleHibernate: 6h` or `off`,
  when and why it hibernated, and how to wake it (`cw start NAME`). After a
  restore, shows how long the restore took; after a fallback cold boot,
  prints the fallback notice that processes were lost and files were kept.
- **Dashboard:** the state pill reads **Hibernated**, and the Sandbox page
  shows when and why it hibernated beside **Start** (and shows the fallback
  notice after a fallback start).
- **`cw hibernate NAME`:** on `standard`, hibernates the Sandbox and reports
  when it is `hibernated`. On `commodity` or `confidential`, refuses and
  names the Sandbox's runtime profile.
