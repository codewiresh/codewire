---
title: Usage and costs
description: Organization plans, per-second metering of hosted sandboxes, reading your usage with cw cost, and the Billing page.
updated: 2026-10-26
weight: 4
aliases: ["/reference/subscription-plans"]
---

Hosted sandboxes are billed to the organization that owns them. Local VMs and
trusted host sessions cost nothing.

## Plans

| Plan | Price |
| --- | --- |
| Starter | $49 per month |
| Pro | $199 per month |
| Team | $499 per month |
| Enterprise | contact us |

Each plan includes a monthly allowance of CPU, memory and disk hours for
running sandboxes and a number of concurrent sandboxes; the current allowances
and overage rates are shown on your organization's **Billing** page. Human
developer seats are $18 per developer per month; agents are not seats.

## Metering

Compute is metered per second while a sandbox is running, from its resources
(vCPU, memory and disk), and added up for the month. A stopped sandbox keeps
its disk and is not billed. Local VMs and trusted hosts are never billed.

## See your usage

```sh
cw cost
```

From a real run on a Codewire platform, for an organization without a plan:

```text
# {organization}

  Plan             Status       Seats $/mo     CPU hrs Mem GB·hrs Storage GB·hrs
  No plan          none         0     $0.00    37.9    134.6      155.9

  Included developers: 0
  Active subscriptions: 0
```

`CPU hrs`, `Mem GB·hrs` and `Storage GB·hrs` are the month's metered use so
far. `--org SLUG` picks an organization when you belong to several, and
`--output json` gives the same numbers to a script. What counts toward the
organization's limits is in [Resources and limits](@/environments/resources.md).

## The Billing page

Owners and admins open the organization's **Billing** page to add a payment
method or manage the subscription and invoices in the payment portal.
`hello@codewire.sh` answers questions about plans and invoices.
