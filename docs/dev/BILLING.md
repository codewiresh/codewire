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
| `environment_destroyed` | `cw rm` finished, its Pod gone, before the billing loop's next poll saw the delete. This is the usual end of a quick delete. | Its last observation, at most one 60-second poll before. |

A session the billing loop closed keeps its end; the destroy never moves
it. When a Pod outlives its delete, the next poll closes the session as
`deleting`, at the delete, before the destroy can finish. If no poll ran
meanwhile, for example with no leader, the destroy still ends it at its
last observation, so the charge never runs to the Pod's end (#5675).

## What is charged

Every 60 seconds, `codewire-billing`'s metering draws each session's
allocated vCPU, memory and disk, per second, from its organization's credit
at the organization's rate card. One draw writes one `usage` ledger entry
per organization, for all its due sessions. An open session is drawn only
through its last observation, so a Sandbox whose observations stop is never
charged past them; a closed one is drawn through its end. An organization
on the Unlimited card is never charged.

A stopped Sandbox has no open session and draws nothing, its kept disk
included. A start opens a new session.

## Prices

**Partly built (#5782).** The storage rate, the admin-only call
(`UpdateRateCard` on the admin `BillingCatalogService`) and its audit entry
exist. There's no Pricing page yet, and `pricing.html` and the usage
documentation still copy the numbers (€0.0438 a vCPU-hour, €0.0141 a GiB-hour
of memory, €0.000087 a GiB-hour of disk). What follows is the rule #5782
builds.

Every price is a row of `billing_rate_cards`, one per rate card: Regular,
Discounted and Unlimited (#5782).

- **What a card holds:** a vCPU-hour, a GiB-hour of memory and a GiB-hour of
  disk while a Sandbox runs, and a GiB-hour of storage while it is suspended
  or hibernated (#5484), in nano-euros. The storage rate starts at 0 on
  every card. Unlimited's rates are all 0 and stay 0. No rate is negative or
  above €10 a unit-hour; the call and the database both refuse one, so a
  price typed with extra zeros can't reach every organization.
- **Who changes them:** a platform administrator, on the admin panel's
  Pricing page, through an admin-only call. A change made from a stale read
  of the card is refused, never applied over a newer one. Nothing else
  writes a price. A migration creates the rows and never sets a price again,
  and no template or document repeats a number.
- **When a change applies:** each metering draw reads its organization's
  card when it runs, so a change applies from the next draw, within a
  minute. That draw prices the time since each session's last draw, which
  can include up to one draw interval before the change. Usage already in
  the ledger keeps its amount; nothing is re-priced.
- **What it records:** each change writes one audit entry, with the
  administrator, the card, the rate, and its old and new value.
- **What shows a price:** the public pricing page, home, the Billing page
  and the Sandboxes menu's estimate read the live cards (the public pages
  show Regular). The public pages read Regular's rates through billing's
  unauthenticated `GetPublicRates`, which answers only those four rates.
  The usage documentation points to the pricing page.

