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

## A suspended stretch (`standard`, #5529)

**Built (#5529), not yet observed.** Nothing suspends a Sandbox until its
`idle_suspend` is set, and the split hasn't been walked on Dev. A
`standard` Sandbox whose VM is paused inside its
Pod ([IDLE-STOP.md](IDLE-STOP.md), "Suspend") is charged as suspended,
only for the seconds between its runtime's own record of a pause and its
record of the resume. Nothing the guest says moves a second between rates.

- **A session has a kind,** `running` or `paused`. The loop reads each
  `standard` Sandbox's new pause records at every poll, through its Pod's
  log, and splits its session at each one: a `paused` record closes the
  running session at the record's time, with `end_reason` `vm_paused`, and
  opens a `paused` one at the same instant and size; a `resumed` record
  closes it (`vm_resumed`) and opens a running one. A split never ends a
  session before its last observation.
- **Where the loop is:** each session carries the last pause record's
  generation and sequence the loop applied, carried over at each split, so
  a record is never applied twice. A poll that can't read the records
  doesn't move a `standard` session's last observation, so no second past
  an unread record is drawn at either rate. A paused session is observed
  only up to its latest record; the next record, or the session's end,
  settles the time after it.
- **A paused session draws only its disk,** at the rate card's storage
  rate, which is 0 until an administrator sets one ("Prices"). Its vCPU and
  memory draw nothing.
- **A gap** (IDLE-STOP.md, "A gap"): one of 60 seconds or less is billed as
  paused. A longer one closes the paused session at the last state record
  before it, with `end_reason` `pause_records_gap`, and opens a running
  session there marked for review; a record that says paused again after
  it opens a paused session from that record. A gap while the session is
  running changes nothing: it stays running. The loop logs the Sandbox, the
  generation and the missing sequence numbers, and counts it in
  `codewire_billing_pause_record_gaps_total`. An operator reviews every
  marked session and refunds it when the Sandbox was in fact paused.
- **A stop** of a suspended Sandbox wakes its VM: the runtime resumes it at
  the Pod's SIGTERM and records the resume. When the loop sees the Sandbox
  stopped, it reads the Pod's last lines before it closes the session, so
  the last record says running and the session ends as a running one does,
  at the Sandbox's stop ("When it ends, and why"). If those lines can't be
  read, the time from the last record seen to the stop is a gap.
- **A boot that ends paused** (an eviction or a lost node, not
  orchestration's stop) is paused at most up to the next boot's first
  record, or the session's end when that comes first. The time from the
  last record seen to there is a gap, settled as above. A Sandbox that
  carries on in a new Pod turns running where the new boot starts, with
  `end_reason` `vm_boot_ended`, and the new boot's records, a new
  generation, split it from there.

## When it ends, and why

A session opens and ends from the Sandbox object, never from its Pod or
VM. So the charge ends when the product stops or deletes the Sandbox, not
when its Pod or VM finally goes. Only a `standard` Sandbox's split between
running and paused comes from its runtime's Pod log ("A suspended
stretch").

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
included. A start opens a new session. A paused session draws only its
disk, at the storage rate ("A suspended stretch").

## Prices

**Built (#5782), not yet observed.** The `billing-admin-prices` journey
hasn't been walked on Dev.

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
- **What shows a price:** the public pricing page, the Billing page and
  the Sandboxes menu's estimate read the live cards (the public pricing page
  shows Regular). The public pages read Regular's rates through billing's
  unauthenticated `GetPublicRates`, which answers only those four rates.
  The pricing page asks at most once a minute. When billing doesn't answer
  it shows the last rates it read, and no prices if it has read none since
  it started; it never shows a copied number. The usage documentation points
  to the pricing page.

