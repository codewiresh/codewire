# Snapshots and forks

A disk snapshot saves a stopped environment's disks so that new environments,
called forks, can start from it, each with its own identity. A cloud snapshot
is a hosted sandbox's workspace disk; a local snapshot is a stopped local VM's
disks on a Linux host. `SPEC.md` "Saved state vocabulary" (section 2) defines
a snapshot, but still says disk snapshots are not implemented; that sentence
is out of date (#4007). What users are told is in the docs' CLI reference,
"Cloud snapshots" (`apps/docs/zola/content/reference/cli/environments.md`),
and in `docs/dev/LINUX-LOCAL-VMS.md`, "Disk snapshots". The work is Program
#3046. Launch step 10 (`launch-snapshot-fork` in [launch.md](launch.md))
walks `snap-capture` and `snap-fork` on Production as a new account. The
format is in [README.md](README.md).

## Where it stands

Updated 2026-11-13. Cloud capture, management and a three-way fork are
observed on Dev and on Production, as the smoke identities. The launch walk by
a new account, the fork while the snapshot's node is down and the dashboard
are not observed.

| ID | What | Dev | Production |
| --- | --- | --- | --- |
| `snap-capture` | a snapshot of a stopped cloud sandbox, and its refusals | observed 2026-11-13 with `v0.4.17` (#4370); the zero-credit refusal observed 2026-11-13 (#4379) | observed 2026-11-13 with `v0.4.18`, as the smoke identity (#4370); the refusals not yet observed |
| `snap-manage` | `cw --cloud snapshot ls`, `inspect` and `rm` | observed 2026-11-13 with `v0.4.17` (#4370) | observed 2026-11-13 with `v0.4.18`, as the smoke identity (#4370) |
| `snap-fork` | `cw --cloud create --snapshot`, one fork and `--count N` | `--count 3` observed 2026-11-13 with `v0.4.17` (#4370); one fork on its own not yet observed | `--count 3` observed 2026-11-13 with `v0.4.18`, as the smoke identity (#4370) |
| `snap-fork-node-down` | a fork while the snapshot's node is unavailable | not yet observed (#4371) | not yet observed |
| `snap-local` | `cw snapshot create`, `ls`, `inspect` and `rm` on a local VM (Linux) | does not apply; a local VM observed on a pre-merge build (#3525) | does not apply |
| `snap-local-fork` | `cw create --local --snapshot`, one fork and `--count N` | does not apply; a local VM observed on a pre-merge build (#3525) | does not apply |
| `snap-dashboard` | the organization's Snapshots page | hidden for launch (#4582) | hidden for launch (#4582) |

## Before any of these

- A cloud snapshot is the caller's own. Only the environment's creator can
  snapshot it; an organization admin is refused with "only the
  environment's creator can snapshot it". `cw --cloud snapshot ls` lists only
  the caller's snapshots.
- Rehearse on Dev first. `scripts/runtime/dev/with-dev-smoke-auth.sh --
  COMMAND` runs one command as the synthetic Dev identity; `--openbao-path`
  selects another, such as the billing rehearsal one, which the zero-credit
  state needs. On Production, `scripts/runtime/prod/with-prod-smoke-auth.sh
  -- COMMAND` may create, inspect and remove only its own environments and
  snapshots.
- Record `cw version` with every observation. An observation on Dev counts
  only for the source Dev had rolled out.
- Local snapshots need a Linux host. On macOS, `cw snapshot create ENV`
  without `--cloud`, `cw snapshot ls` without `--cloud` and `cw create --local
  --snapshot` refuse with "local disk snapshots need a Linux host for now"
  (#3803).

## `snap-capture`: a snapshot of a stopped cloud sandbox

Issues: #4370 (hosted snapshots on Production; forks landed in #3754), #4379
(the credit gate), #4387 (the node-local line).

- **Entry points:** `cw --cloud snapshot create ENV [--name NAME]`; `cw
  snapshot create` with no environment at a terminal, which asks where the
  environment is and which stopped one to use. The dashboard has none
  (`snap-dashboard`).
- **States to exercise:**
  - a stopped sandbox: captured;
  - a running sandbox: refused with "environment must be stopped to snapshot
    it";
  - zero credit, where credit is enforced: refused (#4379), and admitted once
    credit is restored;
  - a name the caller already uses: "you already have a snapshot with this
    name"; a name that is not one token: refused with the rule;
  - the organization's limit: an organization holds at most 32 snapshots,
    failed ones included ("this organization holds the most snapshots it can;
    remove one first"), and captures at most four at a time ("this
    organization has too many snapshots being captured; try again shortly");
  - an API restart while `cw` waits: `cw` keeps waiting and reports the
    result (#3752);
  - a confidential sandbox: refused with "confidential environments do not
    support snapshots".
- **Driving it:** on the walk's sandbox:

  ```sh
  cw exec --in launch-walk sh -c 'date > /workspace/snapshot-marker'
  cw --cloud stop launch-walk
  cw --cloud snapshot create launch-walk --name launch-walk-snap
  ```

  `snapshot create` waits for the capture, up to 20 minutes, and prints
  "Created snapshot launch-walk-snap." and then "It is kept on the storage
  node that holds this environment's disk and is not backed up: if that node
  is lost, so is the snapshot." For the running state, run `snapshot create`
  before the stop. For zero credit, run it as the billing rehearsal identity
  at a balance of zero or below.
- **Proof:** `cw --cloud snapshot inspect launch-walk-snap` shows `State:
  ready` and a size. A refusal exits 1 and `cw --cloud snapshot ls` shows no
  new snapshot; at zero credit `--output json` carries `"code":
  "credit_exhausted"`.
- **Gotchas:**
  - Limits accepted for launch (#4370, 2026-11-12): a snapshot stays on one
    storage node and is not backed up, so it is lost with that node;
    snapshots are not billed; an organization can hold 32.
  - Codewire's delivered sign-ins are cleared from a snapshot. Anything
    else on the disk, such as a `.env` file, is kept.
  - Snapshot creates share the rate limit that sandbox creates and starts use
    (#4465): by default 10 a minute per user, which an admin can change.
  - The zero-credit refusal says "This organization has no compute credit,
    so it can't run cloud sandboxes." It does not name the organization or
    link its billing page, as `cw create` does (a follow-up noted on #4370).
  - Reaching the limit of 32 takes 32 captures; a walk removes them after.
- **Observed:**
  - Dev, 2026-10-31, source `cdf056c97`, `cw` built from it, as the Dev smoke
    identity (#3046, "Hosted snapshots H1, product journey on Dev"): a
    running environment refused with "environment must be stopped"; an
    invalid name and a name already taken refused, each with its reason; a
    stopped environment's capture `ready` in 13.0 s.
  - Dev, 2026-10-31, source `483c1d45e`, `cw` built from it (#3046, "Hosted
    snapshots H2, product journey on Dev"): the API was restarted while a
    capture was clearing, and `cw snapshot create` waited through it and
    exited 0 after 21.7 s.
  - Dev, 2026-11-12, `cw` built from #4387's branch (`ac9e265e6`): `cw
    --cloud snapshot create` printed both lines above, after 15 s (#4387).
  - Dev, 2026-11-13, source `3a6203ffd`, `cw` `v0.4.15`, as the billing
    rehearsal identity (#4370, "Step 10, prerequisite 3"; #4379): the
    capture was refused at a balance of −€0.06 with exit 1 and `"code":
    "credit_exhausted"`, and no snapshot was kept; after credit was restored,
    the same capture was admitted and `ready` in 18 s.
  - Dev, 2026-11-13, source `1e0f58773`, `cw` built from `v0.4.17`, as the
    Dev smoke identity (#4370, "Step 10: the Production capture-and-fork
    walk, rehearsed on Dev"): `cw --cloud snapshot create` on a stopped
    sandbox printed both lines above in 18 s.
  - Production, 2026-11-12, storage only (#4370): a volume snapshot was
    taken and restored, including when the scheduler first chose another
    node. That is a prerequisite, not this step.
  - Production, 2026-11-13, release `v0.4.18` (source `a9dd8b270`), `cw`
    built from `v0.4.18`, as the Production smoke identity (#4370, "Step 10:
    a snapshot of a sandbox on Production, forked three times"): `cw --cloud
    snapshot create` printed both lines above in 20.2 s.
  - Production: the running, zero-credit, name and limit refusals are not
    yet observed. The zero-credit refusal was not repeated there (#4370).
  - The limits of 32 snapshots and four captures at a time: not yet observed
    on any surface.

## `snap-manage`: list, inspect and remove cloud snapshots

- **Entry points:** `cw --cloud snapshot ls` (alias `list`), `cw --cloud
  snapshot inspect SNAPSHOT` and `cw --cloud snapshot rm SNAPSHOT`, by name
  or ID, each with `--output json`.
- **States to exercise:**
  - no snapshots: "No snapshots. Create one with: cw --cloud snapshot create
    ENV";
  - a ready snapshot and a failed one (`inspect` names the reason, such as
    "its delivered sign-ins could not be cleared");
  - `rm` while the snapshot is still being captured: "this snapshot is still
    being captured";
  - `rm` while an environment is being created from it: "an environment is
    being created from this snapshot; try again when it has started";
  - `rm` with forks running: the forks keep working;
  - the source sandbox removed: the snapshot stays `ready`.
- **Driving it:**

  ```sh
  cw --cloud snapshot ls
  cw --cloud snapshot inspect launch-walk-snap
  cw --cloud snapshot rm launch-walk-snap
  cw --cloud snapshot ls
  ```

  `ls` prints ID, STATE, SIZE and NAME. `rm` prints "Removing snapshot
  launch-walk-snap; environments made from it are unaffected."
- **Proof:** after `rm`, `ls` no longer lists the snapshot, and a fork made
  from it still answers `cw exec`.
- **Gotchas:**
  - `rm` starts a deletion and returns; the snapshot shows `deleting` until
    it is gone.
  - A name is the caller's own; another member's snapshot of the same name is
    not visible and cannot be removed.
- **Observed:**
  - Dev, 2026-10-31, source `cdf056c97` (#3046, "Hosted snapshots H1,
    product journey on Dev"): the empty message above; a capture that failed
    `clearing_failed`, with `inspect` showing the reason; the source
    destroyed and the snapshot still `ready`; `rm` of each snapshot, and the
    empty message again.
  - Dev, 2026-10-31, source `483c1d45e` (#3046, "Hosted snapshots H2,
    product journey on Dev"): delete during a create refused; both snapshots
    deleted and the forks kept working.
  - Dev, 2026-11-12, `cw` built from `ac9e265e6` (#4387): `cw --cloud
    snapshot rm`, and a later `cw --cloud snapshot ls` showed nothing left.
  - Dev, 2026-11-13, `cw` built from `v0.4.17` (#4370, "Step 10: the
    Production capture-and-fork walk, rehearsed on Dev"): `snapshot inspect`
    showed `ready` and 85899345920 bytes; `cw --cloud snapshot rm` by ID left
    no snapshots.
  - Production, 2026-11-13, release `v0.4.18`, as the Production smoke
    identity (#4370, "Step 10: a snapshot of a sandbox on Production, forked
    three times"): the same `inspect` result, and `cw --cloud snapshot rm` by
    ID left no snapshots.
  - Production: the empty, failed and in-use states are not yet observed.

## `snap-fork`: create cloud sandboxes from a snapshot

- **Entry points:** `cw --cloud create --snapshot NAME`, with `--name NAME`
  for one fork, or `--count N` (1 to 16) with an optional `--name-prefix
  PREFIX` for several.
- **States to exercise:**
  - one fork;
  - several with `--count`;
  - a snapshot that is not `ready`: "snapshot NAME is not ready";
  - `--snapshot` with a repository, `--branch`, `--file` or
    `--share-mounts`: refused;
  - a disk smaller than the snapshot's, or a snapshot that does not exist:
    refused, each with its reason;
  - zero credit: a fork is a create, so the create's credit refusal applies
    (#4379);
  - one create in a `--count` series fails: `cw` names the forks it already
    made ("Already created: …").
- **Driving it:**

  ```sh
  cw --cloud create --snapshot launch-walk-snap --name launch-walk-fork
  cw exec --in launch-walk-fork cat /workspace/snapshot-marker
  cw --cloud create --snapshot launch-walk-snap --count 3 --yes
  cw --cloud ls
  ```

  With `--count 3` and no prefix, the forks are named `launch-walk-snap-1`
  to `-3`.
- **Proof:** the fork's marker file has the same content as the source's,
  and `cw ls` lists the fork as its own sandbox. With `--count`, each fork
  has its own environment ID, and a file written in one is not seen in
  another or in the source.
- **Gotchas:**
  - A snapshot holds a disk and no image, so a fork starts on the workspace
    image unless `--image` names another.
  - A fork starts on the snapshot's node. While that node is unavailable, a
    fork waits (#4371; `snap-fork-node-down`).
  - On Production the scheduler can first choose another node. The fork is
    then moved to the snapshot's node in about 2 s; that is expected, not a
    failure (#4370).
  - Each fork counts against the create rate limit.
- **Observed:**
  - Dev, 2026-10-31, source `483c1d45e`, `cw` built from it (#3046, "Hosted
    snapshots H2, product journey on Dev"): `--count 5` in 45.0 s; in each
    fork the sign-ins were absent and the marker present; environment ID,
    hostname and SSH host key distinct in all six; a write in one fork not
    seen in another; a fork of a fork kept its parent's write; a repository,
    a disk too small and a missing snapshot each refused with its reason.
  - Dev, 2026-11-13, `cw` built from `v0.4.17`, as the Dev smoke identity
    (#4370, "Step 10: the Production capture-and-fork walk, rehearsed on
    Dev"): `cw --cloud create --snapshot` with `--count 3` created three
    forks in 29 s, each running on the snapshot's node with the marker file
    intact. Everything was removed afterwards.
  - Production, 2026-11-13, release `v0.4.18`, `cw` built from `v0.4.18`, as
    the Production smoke identity (#4370, "Step 10: a snapshot of a sandbox
    on Production, forked three times"): `--count 3 --name-prefix` created
    three forks in 44.3 s, all running on the snapshot's node with the
    marker intact. For each, the scheduler first chose another node and was
    refused once; it was scheduled on the snapshot's node 1.3–1.5 s later.
    Everything was removed afterwards.
  - One fork with `--name`, the not-ready refusal and the credit refusal
    for a fork: not yet observed on any surface.
  - The launch walk's own step 10, by a new account on Production: not yet
    observed. deploy#242, which turns snapshots on, reached Production with
    the `v0.4.18` promotion (#4370).

## `snap-fork-node-down`: a fork while the snapshot's node is unavailable

- **Entry points:** `cw --cloud create --snapshot NAME`.
- **States to exercise:** the node holding the snapshot not ready; the node
  back.
- **Driving it:** no command yet. A user cannot take a node away, and the
  refusal this step should see is not built (#4371).
- **Proof:** today, the fork waits and ends at the create's readiness
  timeout. Once #4371 lands, the fork is refused within seconds with a clear
  reason.
- **Gotchas:** a node that is down also takes the source sandbox down, so
  #4371 is not a launch gate.
- **Observed:** not yet observed. The 2026-11-12 Production storage check
  (#4370, "Step 10, prerequisite 1") inferred the wait from the scheduler's
  message; it did not take a node down.

## `snap-local`: snapshots of a stopped local VM (Linux)

- **Entry points:** `cw snapshot create ENV [--name NAME]`, `cw snapshot ls`,
  `cw snapshot inspect SNAPSHOT` and `cw snapshot rm SNAPSHOT`, without
  `--cloud`, on a Linux host. `--local` selects the same.
- **States to exercise:**
  - a stopped VM: captured; the name defaults to `ENV-YYYYMMDD-HHMMSS`;
  - a running VM: "ENV is running; stop it first (`cw stop ENV`), or snapshot
    it later with a VM checkpoint";
  - a name already used: "a snapshot named NAME already exists; …";
  - the host limit: "this host already keeps 256 snapshots; remove one first
    (`cw snapshot rm NAME`)";
  - `inspect` and `rm` of an unknown name: refused;
  - `rm` while environments made from it run: they are unaffected.
- **Driving it:**

  ```sh
  cw stop app
  cw snapshot create app --name good-toolchain
  cw snapshot ls
  cw snapshot inspect good-toolchain
  cw snapshot rm good-toolchain
  ```

  `create` prints "Snapshot good-toolchain of app: mode=… consistency=…
  disks=… apparent=… in … s" and how many delivered sign-ins it removed.
  `rm` prints "Removed snapshot good-toolchain; environments made from it
  are unaffected."
- **Proof:** `inspect` names the source, `Consistency:  clean` and each
  disk's allocated bytes; after `rm`, `ls` says "No snapshots. Make one from a
  stopped local VM with `cw snapshot create ENV`."
- **Gotchas:**
  - Where the host's filesystem shares blocks (btrfs, XFS) a capture takes
    about a second; elsewhere it is a sparse copy that needs the free space
    first.
  - A forced stop records `consistency: crash`.
- **Observed:**
  - A local VM on Linux, `cw` and runtime built from #3525's branch at
    `48d109251` and `243d350bb`, in an isolated home with synthetic tokens
    (#3525, "Review-3 journey" and "Journey"): `cw snapshot create app --name
    s1` in 0.24–0.30 s, `mode=reflink`, clean, 3 disks, sign-ins removed; a
    running source, an unknown name and a duplicate each refused with cause
    and fix; `cw snapshot ls` listed the snapshots again after their store
    was removed; `cw snapshot rm` of each left no snapshots. The pull request
    records no run date; it merged on 2026-10-26.
  - A local VM with a released `cw`: not yet observed.

## `snap-local-fork`: local VMs from a snapshot (Linux)

- **Entry points:** `cw create --local --snapshot NAME`, with `--name`, or
  `--count N` (1 to 16) and `--name-prefix`; `--share-mounts` for a snapshot
  of a VM that mounts host folders directly.
- **States to exercise:**
  - one fork, and several with `--count`;
  - a snapshot whose source mounts host folders directly: refused without
    `--share-mounts`;
  - `--cpu` and `--memory` overrides;
  - the source removed: forks still start from the snapshot.
- **Driving it:**

  ```sh
  cw create --local --snapshot good-toolchain --name app2
  cw create --local --snapshot good-toolchain --count 3
  cw ls
  ```

- **Proof:** each fork has the source's files and packages, its own
  environment ID, machine ID and SSH host key, and no delivered sign-ins.
- **Gotchas:** forks publish no host ports, so a fork beside a source that
  publishes one does not collide.
- **Observed:**
  - A local VM on Linux, `cw` and runtime built from #3525's branch at
    `243d350bb` (#3525, "Journey"): one fork in 6.07 s with the marker,
    package and image present; `--count 3` in 13.13 s, with distinct IDs,
    machine IDs and SSH host keys and no sign-ins; the direct-mount refusal
    and `--share-mounts`; a fork after the source was removed; `--cpu 1
    --memory 2GB`. The pull request records no run date; it merged on
    2026-10-26.
  - A local VM with a released `cw`: not yet observed.

## `snap-dashboard`: the Snapshots page

- **Entry points:** none for launch. The owner decided on 2026-11-13: "The
  snapshots aren't done yet we don't need to show them." The dashboard hides
  the Snapshots link and its placeholder page, and snapshots stay in `cw`
  (#4582, recorded on #3013). A page that lists, forks and deletes snapshots
  moves after launch (#4582).
- **States to exercise:** the organization's settings navigation has no
  Snapshots link, and `/{slug}/snapshots/` answers 404.
- **Driving it:** open the organization's settings while signed in, and
  request `/{slug}/snapshots/`.
- **Proof:** no Snapshots link, and a 404. Until the hide lands, the link
  shows "Soon" and the page says "Snapshots are not available yet."
- **Gotchas:** a user who took a snapshot with `cw` sees none in the
  dashboard. Use `cw --cloud snapshot ls`.
- **Observed:** not yet observed. `apps/dashboard/e2e/ssr-dashboard.routes.ssr.ts`
  covers the page on Kind today; the hide changes that spec to expect the
  404.
