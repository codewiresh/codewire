---
title: Plans and billing
description: Organization plans, per-second metering of hosted sandboxes, and the billing page.
weight: 2
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
(vCPU, memory, disk), and added up for the month. A stopped sandbox keeps its
storage and uses no compute. `cw cost` shows the organization's usage.

## The Billing page

Owners and admins open the organization's **Billing** page to add a payment
method or manage the subscription and invoices in the payment portal.
`hello@codewire.sh` answers questions about plans and invoices.
