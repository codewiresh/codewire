# The cw runtime journal

`UpdateEnvironmentCwRuntime` and `RollbackEnvironmentCwRuntime` change which
`cw` a hosted sandbox runs. They change the version Store inside the sandbox
(`crates/codewire-cw-release`, the same Store `cw upgrade` uses; see
[CLI-MANAGED-INSTALL.md](CLI-MANAGED-INSTALL.md)). Every request is recorded
in `environment_cw_runtime_requests`, the journal. This page says what the
journal promises and how a request that loses its owner is settled. The code
is `crates/codewire-orchestration/src/api/cw_runtime/`.

## A request and its effects

A request is admitted with the selection its client expects the Store to
hold: a generation, the current version and the previous one. It then runs a
fixed sequence of effects in the sandbox, each one a single command of the
platform role (`cw __platform-cw-runtime`):

| Action | Effects |
| --- | --- |
| Update into an empty Store | Bootstrap, Staging, Update, Cleanup |
| Update | Staging, Update, Cleanup |
| Rollback | Rollback, Cleanup |

Bootstrap, Update and Rollback select a version; Staging and Cleanup only add
or remove the request's own staged files. Each effect is **issued** in the
journal before it is dispatched, and **acknowledged** with its receipt after.
A request ends `succeeded`, `failed`, or `unknown` when an effect was
dispatched but no receipt came back. A terminal row never changes, except to
add a resolution once (below).

Each request also holds its environment's runtime lease
(`organization_mutation_leases`, class `environment_runtime_dispatch`) from
admission until it settles. While that lease is active, the sandbox is not
replaced by liveness, and the environment's destroy waits. A request that
ends `unknown` leaves its lease `resolution_required`. An environment has at
most one unresolved request, and a new one is refused while it does.

## Bounds

Everything acting for a request stops on its own:

- admission and each settlement are one transaction of at most 20 s;
- the owner, a task detached from the client's call, stops at 600 s, and
  waits at most 130 s for any one effect;
- the role in the sandbox dies at its own alarm, 121 s after it starts.

So nothing can act for a request 15 minutes after its admission
(`ABANDONED_AFTER`).

## Where an upload is staged (#5508)

An update's `cw` arrives in chunks, at most 512 MiB in all, and is kept on
disk until it is checked and handed to the sandbox. It is staged under one
directory the server makes for itself, so the server can run with a
read-only root filesystem.

The public edge in front of the API resets a request body over about 100 MB
(observed on Dev, #5566), well under the server's 512 MiB, so no real `cw`
can be delivered this way yet. Until a hosted update stops carrying the
upload (#5566), `cw --cloud runtime update` refuses a release over 100 MB
before it sends anything. The refusal names the release's size and the
limit, and says how to pick up the current release instead: stop and start
the sandbox, which re-pins `/codewire/bin/cw` to the current release. A `cw`
an earlier update or rollback selected still comes first
([SANDBOX-DAEMON.md](SANDBOX-DAEMON.md), "Which `cw` a sandbox runs").

- **The mount.** Orchestration's Pod mounts an `emptyDir` at
  `/var/lib/codewire-orchestration/staging`, on disk, not in memory, with
  `sizeLimit: 2Gi`. The path is fixed, and `CODEWIRE_CW_RUNTIME_STAGING`
  overrides it only for tests and local runs. `fsGroup` makes the mount's
  root root-owned and group-writable (2777), so the server never uses the
  mount's root for an upload.
- **The private directory.** At startup, before it serves, the server
  creates `<mount>/cw-runtime` with mode 0700 if it is absent. It opens it
  with `O_DIRECTORY | O_NOFOLLOW` and requires it to be owned by the
  server's own uid, with mode exactly 0700. One exception is corrected
  instead of refused: the server's own directory at 02700 and empty. That
  is what a crash between making the directory and setting its mode leaves
  below the setgid mount root, and since the `emptyDir` survives a container
  restart, refusing it would refuse every restart until the Pod is replaced
  (#5548 review).
- **Refusal to start.** The server exits with
  `cw runtime staging unavailable` when:
  - the mount is absent;
  - the private directory can't be created or opened;
  - it is a symlink;
  - it isn't owned by the server;
  - its mode isn't exactly 0700.

  It never falls back to `std::env::temp_dir()` or `/tmp`.
- **The intake's walk** starts at that private directory. The server already
  holds it open and has checked it, so the walk doesn't follow or check the
  mount above it. Below it nothing changes:
  - each upload gets its own `codewire-cw-runtime-<uuid>` directory, 0700 and
    owned by the server;
  - the upload file is created exclusively (`O_EXCL`, `O_NOFOLLOW`), mode
    0600;
  - every directory the walk holds is still checked by `owner_directory`.

  The ownership rule itself doesn't change: there is no exception for a
  group-writable parent.
- **Space.**
  - **The rule:** an upload holds one of three slots for as long as it runs.
    The server counts uploads in flight in-process; each replica has its own
    `emptyDir`, so a per-process count is exact for its mount. The slot is
    taken before the first chunk is written. A fourth concurrent upload gets
    `unavailable`, and nothing is recorded.
  - **A second check:** with a slot held, the upload is also refused unless
    the staging filesystem has at least 512 MiB free (`statvfs`).
  - **Why:** three uploads of at most 512 MiB each stay inside the 2 GiB
    limit, which would make the kubelet evict the Pod. A free-space check
    alone races: uploads that start together all see the same free space.
  - **Release:** the slot is a guard released however the upload ends:
    success, refusal, error, timeout, drain or a dropped connection.
  - **Cleanup:** an upload's directory is removed when it ends, however it
    ends.
  - **After a restart:** only a new Pod starts with an empty mount. An
    `emptyDir` survives a container restart (a crash, an OOM kill, a failed
    liveness probe), so leftovers can remain. So at startup, after validating
    `cw-runtime` and before serving, the server removes every entry inside
    it. It works relative to the held directory descriptor (`unlinkat`, and
    `openat` with `O_NOFOLLOW` for each subdirectory it empties), never by
    path, and never follows a symlink out of it.
- **Tests.**
  - **Startup:** refuses a missing mount, a symlinked private directory, the
    wrong owner and a mode other than 0700, and makes the directory when
    it's absent.
  - **Leftovers:** startup empties a `cw-runtime` left holding an old upload
    directory, a stray file and a symlink pointing outside. It removes the
    symlink itself without following it, and leaves its target untouched.
  - **Intake:** stages under the private directory, even when the mount's
    root is 2777 with setgid, and refuses an upload when less than 512 MiB
    is free.
  - **Concurrency:** with three uploads in flight, a fourth gets
    `unavailable`. Once one of the three ends, however it ends, a new one is
    admitted.
  - **Never `temp_dir`:** a test proves no upload path calls it.
- **Deployment.** Orchestration's container then sets
  `readOnlyRootFilesystem: true`, like the other services (#5505–#5510). Its
  Kind overlays mount the same `emptyDir`.

## Rollouts (#4460)

A replica that a rollout is replacing drains for 270 s from SIGTERM.

- **New requests.** Once its drain has begun, it admits no update or
  rollback. The client gets `unavailable`, with nothing recorded, and sends
  the request again to the next replica.
- **Uploads.** An update still receiving its `cw` at the drain deadline ends
  with `unavailable` and discards what it received; nothing was admitted.
- **Admitted requests.** Once admitted, a request is not stopped by the
  drain, because a stop would leave its outcome unknown. One admitted just
  before SIGTERM with long effects can still be cut by the kill.

## Abandoned requests (#4518)

The owner can die mid-request: a rollout's kill, a node failure or an OOM
kill. Its request then stays open, and its lease stays active. The
`abandoned-leases` worker loop runs on the leader every 5 minutes and
settles every request open longer than `ABANDONED_AFTER`. It settles each one
into a state the journal already has:

- `admitted` or `acknowledged`: no effect is in flight, so the request fails
  as `cw_runtime_cancelled_before_dispatch`, and its lease is released;
- `issued`: the effect may or may not have run, so the request ends
  `unknown`, and its lease becomes `resolution_required`, exactly as a lost
  receipt leaves it.

The loop touches only the database. Either way the lease is no longer
active, so the sandbox can be replaced and the environment destroyed.

## Resolving an unknown request (#4518)

An `unknown` request still blocks its environment's next update or rollback.
That next request resolves it. Before admission, every update and rollback
reads the Store's selection through its own caller's capture of the Pod.

The Store can only say what an unknown effect did once nothing can still make
it: a request ends `unknown` as soon as its dispatch fails or times out, but
the role it started can still select until its alarm. So a request is
resolvable only `RESOLVABLE_AFTER` (130 s, the owner's wait for a role, longer
than the role's 121 s alarm) after it ended, checked under its row lock.

If the environment's unresolved request ended `unknown` that long ago, and
the selection is consistent, not pending, and one of these two, the admission
records a resolution:

- **`unchanged`:** the selection before the unknown effect, the last
  acknowledged one or else the one the request was admitted against;
- **`applied`:** exactly the selection that effect makes. The generation
  rises by one, the target becomes current and the old current becomes
  previous, as the role's own check of a selection has it.

The resolution, the observed selection and the resolving request's ID are
added to the unknown row, and its lease is resolved, in the transaction that
admits the new request. Any other observation, a pending selection or an
inconsistent Store resolves nothing, and the new request is refused as
before. Nothing ever guesses an outcome; the Store decides it, under the
authority of the user asking for the next change.

The database enforces this: a trigger lets an `unknown` row gain a
resolution once and change nothing else, and the one-unresolved-request index
counts only rows without one (migration `0028_cw_runtime_resolution.sql`).

## Lease owners (#4523)

Three other features hold an environment's runtime lease with no journal: the
dashboard terminal, for its whole session, because the lease covers the
terminal's child process; an SSH port-forward, until it opens; and a daemon
repair, until its replacement Pod is up (120 s, or 30 minutes for a
confidential sandbox). Their lease rows are alike, and a terminal's can be
hours old, so a lease's age cannot tell whether its owner is still there.
Instead the lease records which process took it, and that process says it is
alive.

- **Incarnations and heartbeats.** Each orchestration process picks a random
  incarnation at start, and records it on every runtime lease it admits
  (`owner_incarnation`). It writes a heartbeat for it, `last_seen`, into
  `lease_owner_heartbeats` every `INCARNATION_CHECK` (5 s) on a connection of
  its own (migration `0049_lease_owner_incarnation.sql`). Every time involved is
  the database's own clock, as the leases' own times are.
- **A failed heartbeat.** A write that fails, or takes longer than 5 s, is
  tried again every `INCARNATION_RETRY` (2 s) on a new connection. Failures for
  less than `INCARNATION_FENCE` (60 s) change nothing. That is long enough to
  ride out a database failover or a network blip without ending anyone's
  session.
- **Fencing.** A process with no successful heartbeat for `INCARNATION_FENCE`
  fences, up to about 77 s after its last successful heartbeat: one interval,
  one write timed out, the fence and a retry. It stops acting for the runtime
  leases it holds and admits no new ones until its next successful heartbeat.
  Its open dashboard terminals close with WebSocket code 1012, "server
  restarting", so the browser can reconnect to another replica; a
  port-forward still opening or a daemon repair still waiting stops, and
  leaves its lease `resolution_required`. Everything that holds no lease keeps
  working, and the process never exits for this: one Postgres outage must not
  stop every replica at once.
- **A frozen process.** A process stopped for a while, by SIGSTOP or a paused
  VM, fails no write while it is stopped, and its first write after resuming
  may succeed. So before every write, and after a successful one, it fences if
  its last success is older than `INCARNATION_FENCE`: holders that acted
  through the freeze stop before acting again, since the sweep may have
  settled their leases meanwhile. The fence then lifts with that successful
  write, for new work.
- **The sweep.** Every 30 s the `abandoned-leases` loop settles an active
  runtime lease that no journal holds when its owner has written no heartbeat
  for `INCARNATION_GRACE` (5 minutes) and the lease itself is that old, since
  its owner was alive when it admitted it. Such a lease becomes
  `resolution_required` with `environment_runtime_dispatch_owner_lost`. Five
  minutes is well past the latest fence, so a lease is settled only after its
  owner has died or stopped acting for it. The decision is one query over the
  database's own times, so a failed pass, a skipped one or a change of leader
  carries nothing over. Destroy and organization deletion resolve those leases
  as they resolve any ambiguous runtime dispatch, and liveness no longer
  waits on them. A heartbeat a day old whose owner holds no active lease is
  deleted.
- **Not covered here.** A lease admitted before owners were recorded carries
  none, and is left to organization deletion as before. The cw runtime journal
  settles its own leases, above.
- **Managed platform agents.** Their journal holds its own leases, so the
  sweep applies the same rule to the leases of their open requests, an owner
  with no heartbeat for the grace, and settles each through the journal's own
  states: an admitted request is
  rejected as cancelled before dispatch, its lease released; an issued one
  ends unknown with its lease `resolution_required`, which a later known-clean
  Stop resolves exactly as it resolves a lost receipt. A fenced process
  admits no agent request. Its owner takes the fence before admission, so a
  fence raised before issue rejects the request as cancelled before dispatch,
  and one raised while the dispatch is out ends it unknown without waiting
  for the daemon. A request whose settlement keeps failing is passed over for
  ten minutes at a time, so it cannot take every pass's turn from the rest.
- **Every holder takes its fence before its admission check,** so a fence
  raised after the check is seen, and one raised before it is refused by it.
