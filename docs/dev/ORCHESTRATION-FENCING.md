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
run, not to one activity attempt. Retries of an activity in the same run
keep the generation. A replacement run claims a higher one, which fences
the old run.

A run claims its generation before any environment activity does work,
through `EnvironmentClaimAuthorityActivity`, or
`EnvironmentClaimAndCreateActivity` when the first command is a create. The
generation returns to the workflow and is recorded in its history. Every
environment activity command carries it as a required positive
`operation_generation`. No command form omits the generation. The external
signal that starts a command does not carry it.

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
3. A run without a row may claim only when its scheduled time is strictly
   later than that of the current generation's row. An equal or earlier
   time is `AuthorityLost`. A positive current generation with no claim row
   is `AuthorityLost`.
4. Increment the generation, update the environment and insert the claim
   row.

A missing run id or scheduled time is `AuthorityLost`, never replaced by a
default. Step 3 stops a delayed retry from an older run taking authority
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
