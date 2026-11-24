# Orchestration fencing

This document describes how `codewire-orchestration` stops a stale Temporal
workflow run or activity attempt from writing to an environment after a
newer run has taken over. The `temporal`, `worker::activity_authority` and
`worker::setup_lease` modules implement it. Read it before changing any
environment lifecycle activity or any durable write an activity makes.

## The problem

One workflow run per environment processes lifecycle commands one at a
time. That serializes work inside a live run only. An activity can outlive
its run: the run is terminated, a replacement run starts, and the old
activity is still executing. The workflow id is therefore not a write
fence. Without one, a stale activity could move a `destroyed` environment
to `error` or run setup commands in a workspace that the replacement run
is also changing.

## Operation generation

Each environment row has a monotonically increasing
`environment_operation_generation`. One generation belongs to one workflow
run, or to a chain of runs each of which took it over from a closed run
(below), not to one activity attempt. Retries of an activity in the same run keep
the generation. A replacement run claims a higher one, which fences the old
run.

A run claims its generation before any environment activity does work,
through `EnvironmentClaimAuthorityActivity`, or
`EnvironmentClaimAndCreateActivity` when the first command is a create. The
generation returns to the workflow and is recorded in its history. Every
environment activity command carries it as a required positive
`operation_generation`. No command form omits the generation. The external
signal that starts a command does not carry it.

### A run's history is bounded

A Sandbox's one workflow lives as long as the Sandbox, and every command it
handles adds about ten events, a periodic reconcile included. A worker that
does not have the workflow cached, as after every orchestration restart,
replays the whole history before it can handle the next command. A history
of about 20,000 events took more memory than orchestration's limit and
longer than the 10 s workflow-task timeout (#5856), so the replay never
finished and was retried.

So a run ends once it is past 2,000 events, or once Temporal suggests it:
after finishing a command, with no command queued and no handler running,
the run continues as new with no command of its own. The workflow id stays
the same, so the next signal reaches the new run.

The continuation check runs only while the workflow is not replaying. A run
ends at the end of its history, and an open run's history never holds that
end, so replaying an open run never reaches a point where it continued. This
also lets a run that predates the bound end at its next command. A patch
could not do that: replay records the patch's answer as absent at the first
check and keeps it. A query that replays a run which has continued as new
cannot replay its end, so it fails; the open run answers queries.

The new run keeps the generation (#5950), by the takeover below.

### A new run takes over a closed run's generation

A credentialed Sandbox's daemon opens its credential bridge with the
generation its binding captured, and the broker refuses one that differs
from the environment's. A new generation therefore makes every running
credentialed Sandbox's bootstrap stale, and the reconcile restarts it. No
restart is wanted when the run that held the generation has closed: it
continued as new, or it failed after its activity's attempts ran out and
the next command started a fresh run (#6103).

So a run's first claim takes over the current generation's claim row, once,
and keeps the generation, when all of these hold (step 3 of the claim,
below):

- the row names another run, the holder, under the same workflow id,
  `environment/<environment id>`;
- Temporal describes the holder as closed, with any close status:
  `ContinuedAsNew`, `Completed`, `Failed`, `Terminated`, `TimedOut` or
  `Canceled`. The holder comes from the claim row and its status from
  Temporal, never from a command or an activity input;
- the holder's claim was scheduled earlier than the new run's.

Only an explicit close counts. A holder that Temporal describes as running,
with no status it knows, or has no record of (`NotFound`, as once its
retention has passed) is not taken over: the new run claims a new
generation as a replacement run does, and a credentialed Sandbox restarts
once. That restart is intended: when Temporal cannot say the holder closed,
the fail-safe is a new generation, never a takeover.

A Temporal read that fails claims nothing. The claim activity returns the
error and is retried; when its attempts run out the run fails, and the next
run reads again. A blip never moves the generation.

A worker from before #5971 does not take over at all, so during the first
rollout of a release that carries #5971 an old worker can still claim a new
generation for a run that continued as new. Once no such worker runs, that
cannot happen again.

What this means for fencing:

1. A run that takes over keeps the holder's generation number.
2. Temporal closes a terminated, timed-out or canceled run without waiting
   for its activities, so one may still be executing (see "The problem").
   It is fenced by the claim row's run id, not by the generation: every
   authority check also requires the generation's claim row to name the run
   the authority was captured for (below), and the takeover renamed it.
3. A new claim by the holder is refused (`AuthorityLost`), because the claim
   row now names the run that took it over.
4. A replacement whose holder is running or unknown to Temporal still claims
   +1 and fences everything older.

### Claim

`ActivityAuthority::claim` records claims in
`environment_operation_generation_claims`: `environment_id`,
`workflow_run_id`, `generation`, `scheduled_at_unix_nanos`, `created_at`.
The table is unique on `(environment_id, workflow_run_id)` and on
`(environment_id, generation)`, and its rows are deleted with the
environment. `scheduled_at_unix_nanos` is the activity's original scheduled
time as Temporal reports it, never a worker clock.

Before its transaction, the claim reads the run named by the current
generation's claim row, when that is another run, and asks Temporal for its
status. A failed read returns the error and claims nothing.
`EnvironmentClaimAndCreateActivity` claims without reading the holder,
because a create runs only for a Sandbox that is not running. The claim is
then one transaction:

1. When the holder is closed, lock its claim row, then lock the environment
   row. A missing environment row is `AuthorityLost`.
2. If this run already has a claim row, return its generation only when it
   is still the current generation and the scheduled time matches.
   Otherwise return `AuthorityLost`. A retry after a lost response is
   idempotent, and a superseded run cannot increment again.
3. When the holder is closed (above), take over the current generation's
   claim row: one `UPDATE` on the row for this environment, the current
   generation and the holder's run id, with an earlier scheduled time, sets
   its run id and scheduled time to the new run's, and the claim returns
   the current generation unchanged. The same transaction clears the setup
   owner held at that generation (see "Setup lease"). The row then names
   the new run, so the takeover happens once, and the holder's own retried
   claim is `AuthorityLost` by step 2. A row that changed since the holder
   was read matches nothing, and the claim goes on.
4. A run without a row may claim only when its scheduled time is strictly
   later than that of the current generation's row. An equal or earlier
   time is `AuthorityLost`. A positive current generation with no claim row
   is `AuthorityLost`.
5. Increment the generation, update the environment and insert the claim
   row.

A missing run id or scheduled time is `AuthorityLost`, never replaced by a
default. Step 4 stops a delayed retry from an older run taking authority
back after a newer run has claimed it.

## Authority-checked writes

`ActivityAuthority` captures the generation, the committed `desired_state`
and the run that the generation's claim row names when an activity starts.
An activity's capture requires that run to be the activity's own
(`workflow_run_id`); a caller outside a workflow run, such as a loop or an
API handler, pins whichever run holds the row. Every durable write locks
the claim row (`FOR SHARE`), then the environment row, and checks that the
claim row still names the captured run, the generation, the desired state
and the lifecycle states valid for that operation, in the same transaction
as the write. The unlocked `ensure` checks read the same. This covers
lifecycle transitions, error writes, backend rows, and every log and
checkpoint row. A stale write is a no-op.

A takeover renames the claim row under `FOR UPDATE`, taking the claim row
before the environment row as every fenced write does, so a write either
commits before the takeover or is refused after it. Activities of the run
whose generation was taken over keep the generation number and lose
authority at their next check.

`AuthorityLost` is control flow, not a failure. A hard-deleted environment
is `AuthorityLost`, never a retryable missing-row error. An activity that
loses authority ends cleanly and records no error on the environment.

## Heartbeat and cancellation

- Environment activities heartbeat every 5 seconds and run with a 15 second
  heartbeat timeout.
- They use cancellation type `WaitCancellationCompleted`. Cancellation
  reaches the underlying wait and means the activity has lost authority.
  It is not an environment failure.
- Waits for readiness and deletion recheck authority while pending, so a
  delete interrupts create, start or reconcile work promptly.

## External mutations

Kubernetes and other external providers cannot join the database
transaction. `ActivityAuthority::begin_external_mutation` holds the
environment row lock across one external request and its matching
bookkeeping. A replacement command either commits before the guard, and
the guard refuses to run, or after it, and then sees the side effect it
must reconcile. The guard gives ordering, not atomicity, so provider calls
stay idempotent.

## Setup lease

Setup runs commands inside the workspace while the environment is already
`running`, so generation, state and intent cannot separate two overlapping
setup runs. Setup also holds a lease on the `sandbox_environment_backend`
row: `setup_owner_generation`, `setup_owner_activity_id`,
`setup_owner_attempt`, `setup_owner_phase`, `setup_owner_status` and
`setup_owner_pod_uid`. The fields are all absent or form one coherent
lease. Any partial or unknown combination fails closed.

| `setup_owner_status` | Meaning | Pod UID |
|---|---|---|
| `claimed` | The setup phase is owned and no process has been launched. | absent |
| `running` | A workspace process may be running in the recorded Pod. | required |
| `reaping` | The owner's processes are being proven gone. | required |

Rules:

- Every setup transaction locks the generation's claim row (`FOR SHARE`),
  then `environments`, then `sandbox_environment_backend`. It requires the
  claim row to name the run its activity authority was captured for, the
  current generation, `desired_state = 'started'`, `state = 'running'`, the
  expected setup phase and the exact lease owner (generation, activity id,
  attempt). Activity ids are a per-run sequence, so after a takeover two
  runs' setups can share a lease identity; the claim row's run id tells
  them apart.
- A setup phase first takes the lease as `claimed`. Before the first exec
  it records the Pod UID and moves to `running`. Before every exec or
  parallel launch group it revalidates the lease and holds the lock through
  the bounded attach handshake.
- Completing a setup phase writes its log and checkpoint, advances
  `setup_phase` and clears the owner in one transaction.
- A failed setup phase records `setup_error`, keeps `setup_phase` on the
  failed step and clears the owner in one transaction. Terminal sessions are
  admitted only while no owner holds the lease, so a failed setup opens them
  and a setup that takes the lease again closes new ones (#4767).
- Retry setup (`EnvironmentService.RetryEnvironmentSetup`) runs the setup
  activity again through the environment workflow's `retry_setup` command,
  on a running Sandbox with a recorded failure and no owner. The run resumes
  from the recorded checkpoint, so no completed step runs again.
  - Only a resumable setup run's claim clears `setup_error`, in the claiming
    write, so a retry whose command is lost leaves the failure recorded. The
    post-start mutation that every start runs claims the lease without
    clearing it, so a stop and start keeps the failure and its terminals.
  - A retry that would run the clone step is refused (`reclone_unconfirmed`)
    until the caller confirms it, because the clone deletes each repository's
    directory first.
  - It takes the same access as Start: the creator, an organization owner or
    admin, or an `operator` grant. Operators can already run commands in the
    Sandbox, so the clone's deletion gives them nothing they lacked.
  - The command sits behind the `retry-setup-4767` workflow patch. The SDK
    records a patch's answer once per workflow, so a workflow that skipped a
    `retry_setup` before the patch ignores every later one while the RPC
    returns Ok. That lasts until the run continues as new (see "A run's
    history is bounded"). It affects only a Sandbox whose Retry was
    signalled during the rollout.
- `AuthorityLost` propagates through every setup path. It is never turned
  into a warning or followed by advancing to the next setup phase.

### Takeover

A run that takes over a closed holder's generation clears the setup owner
held at that generation in the takeover's transaction, so its setup starts
as a fresh owner and the closed run's next setup step is refused. A
`running` owner cleared this way is not reaped first.

A `claimed` lease has launched nothing. The current generation and attempt
may take it over directly. A `running` lease may hide a live process, so
the current generation, or a higher attempt of the same generation and
activity, first moves it to `reaping`. Worker death, cancellation and an
ambiguous exec launch or exit take the same path. The stale owner keeps
teardown-only authority over its own lease. It may never scale up, launch
or change the workspace.

Reaping scales the sandbox to zero, observes that the recorded Pod UID is
gone and that no workspace Pod remains, then waits a quiescence interval
longer than the exec attach timeout. A Pod that is already absent counts as
exited. Before scaling back up, recovery requires the current generation
with `desired_state = 'started'` and `state = 'running'`. Otherwise the
environment stays down. After scale-up it requires a different Pod UID and
then takes the lease as `claimed`.

A setup activity that is cancelled or loses authority establishes `reaping`
and completes this no-Pod check before it reports cancellation. Dropping an
exec future is never treated as process exit. Parallel clones share one
lease and one launch group: an early error observes every sibling complete
or enters the reaping path.

### A claimed owner left behind

An activity can end with its `claimed` post-start lease still recorded,
for example when an ordinary error returns between taking the lease and
releasing it. A later attempt of the same activity that finds the Sandbox
already running never asks for the lease, and a later activity of the same
run does not outrank it. Nothing would release it, and while it is recorded
runtime reads and terminal sessions are refused (#6251).

So the running path releases it. When a reconcile finds the Sandbox
`running` with intent `started`, or a start finds it already running, the
activity releases the setup owner when all of these hold:

- setup is complete (`setup_complete`);
- the owner is `claimed`;
- the owner's generation, activity id and attempt are not the activity's
  own.

It checks them in one transaction under the setup lock order above (the
claim row `FOR SHARE`, then `environments`, then
`sandbox_environment_backend`), with the same current-authority checks as
every setup write. It clears only the exact owner tuple it read under those
locks, so an owner that changed in between is left alone. Each release is
logged with the environment, the released tuple and the releasing activity,
and counted in `codewire_setup_claimed_owner_releases_total`.

It is safe because a `claimed` owner has launched nothing. To launch, the
owner first moves its own lease to `running` with a compare-and-set on its
tuple. After a release that fails with `AuthorityLost`; if it commits
first, the owner is `running` and the release leaves it. The owner is also
done: a run handles one command at a time and awaits each activity before
the next, and only the run the claim row names passes the authority check.
A claimed owner that is not the activity's own is therefore an earlier
activity of the run, an earlier attempt of the same activity, or an
activity of a closed run.

It leaves alone a `running` or `reaping` owner, which may hide a live exec
and keeps the reap path above; any owner while setup is incomplete, which
keeps the setup phase rules; and the activity's own claim. A Sandbox
already left with such an owner is released by its next `running bootstrap
check` reconcile.
