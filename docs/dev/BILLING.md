# Billing sessions

A cloud Sandbox is charged for the time it runs, at its allocated size. This
page is the contract for when that time starts and ends. The writer is the
billing-session loop in `crates/codewire-orchestration/src/worker/billing_sessions.rs`;
the charge is drawn by `crates/codewire-billing/src/credit.rs`. The journey is
[`docs/journeys/billing-and-credits.md`](../journeys/billing-and-credits.md).

## A session

Each stretch of time a Sandbox runs for an environment is one row in
`sandbox_running_sessions`: its start, its last observation, its end and
the reason it ended, and the vCPU, memory and disk allocated to it.

- **It opens** when the environment's binding names this Sandbox, at the
  binding's time, for a cold Sandbox and a warm-pool one alike. An unclaimed
  warm-pool member has no binding and is never charged. A session never
  starts before the same Sandbox's previous session ended.
- **While it runs**, the orchestration leader lists the Sandbox objects every
  60 seconds and records each running one's last observation and current
  size. A Pod replaced while its Sandbox runs keeps the same session, with
  no gap.
- **It closes** when its Sandbox object stops running, is deleted or is
  gone, at the time below. A session never ends before its last
  observation.

## When it ends, and why

The billing loop reads Sandbox objects, never Pods or VMs. So the charge
ends when the product stops or deletes the Sandbox, not when its Pod or VM
finally goes.

| `end_reason` | What happened | `ended_at` |
| --- | --- | --- |
| `suspended` | The Sandbox was stopped: by a person (`cw stop`, the dashboard), for running out of credit, or for being idle ([IDLE-STOP.md](IDLE-STOP.md)). Its disk is kept. | When its Ready condition turned off; if that isn't recorded yet, the poll that saw the stop. |
| `deleting` | `cw rm`: the Sandbox object has a deletion time, and may still be listed while its Pod ends. | The earlier of its deletion time and when its Ready condition turned off. |
| `controller_lost_track` | The Sandbox object is gone. | Its last observation, at most one 60-second poll before. |
| `Failed`, `Error`, `Evicted`, `Expired`, `DeadlineExceeded`, `SandboxFailed`, `PodFailed`, `NodeLost` | The Sandbox's Ready condition gives a reason it can't recover from. | When its Ready condition turned off. |
| `environment_destroyed` | `cw rm` finished, its Pod gone, before the billing loop's next poll saw the delete. This is the usual end of a quick delete. | The time the destroy finished. |

A session the billing loop closed keeps its end; the destroy never moves
it. When a Pod outlives its delete, the next poll closes the session as
`deleting`, at the delete, before the destroy can finish. The charge runs
to the Pod's end only if the billing loop isn't running then, for example
with no leader.

## What is charged

Every 60 seconds, `codewire-billing`'s metering draws each session's
allocated vCPU, memory and disk, per second, from its organization's credit
at the organization's rate card. One draw writes one `usage` ledger entry
per organization, for all its due sessions. An open session is drawn only
through its last observation, so a Sandbox whose observations stop is never
charged past them; a closed one is drawn through its end, which for
`environment_destroyed` can be up to one poll past its last observation. An
organization on the Unlimited card is never charged.

A stopped Sandbox has no open session and draws nothing, its kept disk
included. A start opens a new session.
