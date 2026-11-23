---
title: Usage and costs
description: Prices, per-second metering of hosted sandboxes, reading your usage with cw cost, and the Billing page.
updated: 2026-11-23
weight: 4
aliases: ["/reference/subscription-plans"]
---

Hosted sandboxes are billed to the organization that owns them. Local VMs and
trusted host sessions cost nothing.

## Prices

There are no plans, seats or minimums. Each organization keeps a prepaid
compute credit, and its running cloud sandboxes draw it down per second at the
organization's rates. Members and agents cost nothing. The standard rates are
on the [pricing page](https://codewire.sh/pricing), and an organization's own
are on its **Billing** page.

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

  Rates: {rates}
  Automatic top-up: off
  Credit ran out at 2026-10-31T15:24:55Z: creates and starts are refused, and running sandboxes stop 24 hours later.
```

`Balance` is the organization's prepaid compute credit, and `This month` is
what running sandboxes have drawn from it so far. `Rates` are the
organization's prices per vCPU-hour and per GiB-hour of memory and disk; the
standard ones are on the [pricing page](https://codewire.sh/pricing). `CPU hrs`, `Mem GB·hrs` and
`Storage GB·hrs` are the month's metered use so far. `--org SLUG` picks an organization when you belong to several, and
`--output json` gives the same numbers to a script. What counts toward the
organization's limits is in [Resources and limits](@/environments/resources.md).

## When credit runs out

An organization with no compute credit can't create, start or snapshot
cloud sandboxes. `cw create`, `cw start`, `cw --cloud snapshot create` and any
other command that creates, starts or snapshots one exit with status 1 and say
so:

```text
{organization} has no compute credit, so it can't run cloud sandboxes.
Add a card or credit on its billing page: {server}/{slug}/billing/
Local sandboxes stay free: cw create --local
```

With `--output json` the command also prints the refusal on stdout, with the
stable code `credit_exhausted`:

```json
{
  "error": {
    "code": "credit_exhausted",
    "message": "{organization} has no compute credit, so it can't run cloud sandboxes.",
    "organization": { "id": "{id}", "name": "{organization}", "slug": "{slug}" },
    "billing_url": "{server}/{slug}/billing/",
    "local_create": "cw create --local"
  }
}
```

`organization` and `billing_url` are `null` when `cw` could not look the
organization up.

## The Billing page

Owners and admins open the organization's **Billing** page to see the credit
balance and rates, add a payment method, add credit once, and set automatic
top-up. **Add credit** charges €50, €100, €250, €500 or another amount from €5
to €1,000 to the saved card at once. When the bank asks to approve the payment,
or there is no card yet, Stripe's payment page finishes it, and a card entered
there is saved for later top-ups. Invoices and their receipts are listed there,
and the payment portal manages the card.
`hello@codewire.sh` answers questions about credit and invoices.
