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

From a real run on a Codewire platform, for an organization that has run out
of compute credit:

```text
# {organization}

  Balance      This month   CPU hrs Mem GB·hrs Storage GB·hrs
  -€0.270793   €0.270793    0.2     0.8        8.0

  Rates: €0.0438 per vCPU-hour, €0.0141 per GiB-hour of memory, €0.000087 per GiB-hour of disk
  Automatic top-up: off
  Credit ran out at 2026-10-31T15:24:55Z: creates and starts are refused, and running sandboxes stop 24 hours later.
```

`Balance` is the organization's prepaid compute credit, and `This month` is
what running sandboxes have drawn from it so far. `CPU hrs`, `Mem GB·hrs` and
`Storage GB·hrs` are the month's metered use so far. `--org SLUG` picks an organization when you belong to several, and
`--output json` gives the same numbers to a script. What counts toward the
organization's limits is in [Resources and limits](@/environments/resources.md).

## The Billing page

Owners and admins open the organization's **Billing** page to see the credit
balance and rates, add a payment method, and set automatic top-up. Invoices and
their receipts are listed there, and the payment portal manages the card.
`hello@codewire.sh` answers questions about credit and invoices.
