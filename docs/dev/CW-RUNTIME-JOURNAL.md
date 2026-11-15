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

Daemon repair and managed platform agents hold the same lease from detached
owners. They join the same loop as their own kinds (#4523).
