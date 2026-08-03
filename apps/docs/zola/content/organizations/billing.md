---
title: Billing
description: Manage subscriptions, plans, and usage for your organization
---


Codewire bills at the organization level for seats, environment capacity, and usage.

## Plans

| Plan | Price | Included |
|------|-------|----------|
| **Starter** | $49/mo | Basic sandbox capacity |
| **Pro** | $199/mo | More concurrent environments and support |
| **Team** | $499/mo | Team features with higher limits |
| **Enterprise** | Custom | Dedicated support and SLAs |

Plans include a **14-day free trial**.

## Seat pricing

Organizations are charged **$18 per developer per month** for human developer seats.

## Environment usage and overages

Codewire tracks CPU, memory, and storage usage for running environments. If you exceed your plan's included capacity, overage charges apply:

| Usage | Overage Rate |
|----------|-------------|
| **CPU** | $0.03 per core-hour |
| **Memory** | $0.01 per GB-hour |
| **Disk** | $0.05 per GB-hour |

Usage is tracked in real time and reported to your billing dashboard.

## Free trial

Your first organization plan includes a **14-day free trial**. During the trial:

- Full access to all plan features
- No credit card required to start
- Usage tracking is active (so you can see your patterns)

{% aside(kind="caution") %}
  When the trial expires, environments may be **suspended**. Add a payment method and subscribe to resume.
{% end %}

## Managing your subscription

### View billing

1. Navigate to your organization
2. Click **Billing** in the organization header
3. View active subscriptions, usage, and invoice history

### Add or change payment method

1. Go to **Billing** → **Manage Payment**
2. You'll be redirected to the Stripe customer portal
3. Update your card or payment method

### View invoices

1. Go to **Billing** → **Invoices**
2. View and download past invoices

### Cancel a subscription

1. Open organization billing
2. Open the Stripe customer portal
3. Cancel the subscription

{% aside(kind="caution") %}
  Cancelling a subscription may suspend environment access. Retention rules depend on the active plan and organization policy.
{% end %}

## Related

{{ card_grid(
  titles=["Subscription plans", "Environment usage"],
  hrefs=["/docs/reference/subscription-plans", "/docs/environments/manage-environments"],
  descriptions=["Detailed plan comparison and features.", "View usage from environment details."]
) }}
