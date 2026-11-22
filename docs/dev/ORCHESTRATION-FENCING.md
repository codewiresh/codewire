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
run, or to a chain of runs that continued as new from one another (below),
not to one activity attempt. Retries of an activity in the same run keep
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

The new run keeps the generation (#5950). A credentialed Sandbox's daemon
opens its credential bridge with the generation its binding captured, and
the broker refuses one that differs from the environment's, so a new
generation would make every running credentialed Sandbox's bootstrap stale
and the reconcile would restart it. So the new run's first claim takes over
its predecessor's claim row, once, and keeps the generation, when all of
these hold (step 3 of the claim, below):

- Temporal reports, in the new run's own `WorkflowExecutionStarted` event,
  the run it continued from, and describes that run as
  `ContinuedAsNew`. Neither comes from a command or an activity input;
- that run holds the current generation's claim row;
- that run's claim was scheduled earlier than the new run's.

Otherwise, a Temporal error included, the new run claims a new generation as
a replacement run does, and a credentialed Sandbox restarts once.

What this means for fencing:

1. A continued run keeps its predecessor's generation.
2. The predecessor's in-flight activities keep the authority they had, as
   within one run: `ensure`, `ensure_for_states` and the locked checks
   compare the generation, the desired state and the lifecycle state, never
   the run id. That is the exposure before runs continued as new, and it is
   small because a run continues as new only at an idle point, after its
   command finished, with no command queued and no handler running. The
   setup lease's attempt takeover (below) still governs any setup attempt.
3. A new claim by the predecessor is refused (`AuthorityLost`), because the
   claim row now names the successor.
4. A replacement that isn't a continuation (a reset, a duplicate run, an
   operator's start, or a predecessor in any status other than
   `ContinuedAsNew`) still claims +1 and fences everything older.

The continuation check runs only while the workflow is not replaying. A run
ends at the end of its history, and an open run's history never holds that
end, so replaying an open run never reaches a point where it continued. This
also lets a run that predates the bound end at its next command. A patch
could not do that: replay records the patch's answer as absent at the first
check and keeps it. A query that replays a run which has continued as new
cannot replay its end, so it fails; the open run answers queries.

### Claim

`ActivityAuthority::claim` records claims in
`environment_operation_generation_claims`: `environment_id`,
`workflow_run_id`, `generation`, `scheduled_at_unix_nanos`, `created_at`.
The table is unique on `(environment_id, workflow_run_id)` and on
`(environment_id, generation)`, and its rows are deleted with the
environment. `scheduled_at_unix_nanos` is the activity's original scheduled
time as Temporal reports it, never a worker clock.

The claim is one transaction:

1. Lock the environment row. A missing row is `AuthorityLost`.
2. If this run already has a claim row, return its generation only when it
   is still the current generation and the scheduled time matches.
   Otherwise return `AuthorityLost`. A retry after a lost response is
   idempotent, and a superseded run cannot increment again.
3. A run that continued as new (above) takes over the current
   generation's claim row when that row names its predecessor and an
   earlier scheduled time: one `UPDATE` sets the row's run id and
   scheduled time to the new run's, and the claim returns the current
   generation unchanged. The row then names the new run, so the takeover
   happens once, and the predecessor's own retried claim is
   `AuthorityLost` by step 2. Otherwise the claim goes on.
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

`ActivityAuthority` captures the generation and the committed
`desired_state` when an activity starts. Every durable write locks the
environment row and checks the generation, the desired state and the
lifecycle states valid for that operation, in the same transaction as the
write. This covers lifecycle transitions, error writes, backend rows, and
every log and checkpoint row. A stale write is a no-op.

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

- Every setup transaction locks `environments` before
  `sandbox_environment_backend`. It requires the current generation,
  `desired_state = 'started'`, `state = 'running'`, the expected setup
  phase and the exact lease owner (generation, activity id, attempt).
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
