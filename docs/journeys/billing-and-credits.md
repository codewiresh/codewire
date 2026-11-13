# Billing and compute credit

An organization pays for cloud Sandboxes from a prepaid compute balance: a
card tops it up, running Sandboxes draw it down per second at the
organization's rate card, and an empty balance refuses new work. The model
and its owner decisions are #3381; Stripe delivery is proven by #3263; the
launch walk's step 6 (`launch-buy-credit`, [launch.md](launch.md)) walks the
same steps on Production. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-13. Production does not enforce credit yet: it starts with
the first Production release after codewire/deploy#245.

| ID | Dev | Production |
| --- | --- | --- |
| `billing-card` | observed 2026-11-11 (#3381) | not yet observed |
| `billing-auto-top-up` | observed 2026-11-11 (#3381) | not yet observed |
| `billing-add-credit` | not yet observed | not yet observed |
| `billing-receipt` | not yet observed | not yet observed |
| `billing-costs` | observed 2026-11-13 (#3954) | not yet observed |
| `billing-zero-refusal` | observed 2026-11-11 and 2026-11-13 (#3381) | not yet observed |
| `billing-notice` | sent once observed 2026-11-13 (#4087); failure backoff not observed | not yet observed |
| `billing-stripe-delivery` | observed 2026-10-24 (#3263) | endpoint created 2026-10-24; delivery not yet observed |

## Before the walk

- Walk as an organization on the Regular rate card. Unlimited is never
  charged and never refused, so it proves nothing here.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh --openbao-path
  apps/codewire/dev/ci-billing-rehearsal -- COMMAND` runs one command as the
  synthetic billing-rehearsal identity (Regular card). A fresh identity
  comes from `scripts/runtime/dev/provision-dev-smoke-user.sh --rate-card
  regular --create-document --openbao-path apps/codewire/dev/<slug>`; it
  starts at €0 and is never funded.
- Dev's Stripe is in test mode: use Stripe's test cards, such as `4242 4242
  4242 4242` (succeeds) and `4000 0000 0000 0341` (attaches, then declines
  every charge). Production takes real cards.
- Only a platform admin can move a balance by hand (the admin organization
  page, **Rate card and credit**). A walk that needs a low or empty balance
  asks for that adjustment and records both the change and the restore.
- The balance, the month's draw and the rates are readable without the
  dashboard: `cw cost` prints `Balance`; `GetBillingOverview` and
  `GetEnvironmentUsage` on `codewire.console.v1.BillingService` return the
  exact nano-euro figures the Billing page shows.

## 1. `billing-card`: add a card

- **Entry points:** the Billing page (`/<org>/billing/`), **Add payment
  method**; the "Add a card or credit" link that `cw create --cloud` prints
  at €0.
- **States to exercise:** no card yet; a card added at an empty balance; a
  second card the same day; a card that declines.
- **Driving it:**
  1. At €0 with no card, choose **Add payment method**. Stripe's page
     offers cards only.
  2. Enter the card and save. Stripe returns to the Billing page.
  3. Add a card again: a fresh Stripe session opens, not "You're all done
     here".
- **Proof:** **Payment methods** shows the card. At an empty balance, adding
  it charges whole €20 top-ups until the balance is above zero, as one
  charge (owner, 2026-11-11). One paid invoice appears under **Invoices**,
  and the balance moves by the amount paid.
- **Gotchas:** the headless browser could not complete Stripe's declined-card
  flow (Stripe answered "Your internet connection is unstable"); walk the
  declined card in a real browser.
- **Observed:**
  - Dev, v0.4.14 candidate `b30889111`, 2026-11-11 (#3381): test card 4242
    added; balance €0 → €20.00 with one paid €20.00 invoice.
  - Dev, `e7f3c85c6`, 2026-11-11 (#3381): Stripe offers cards only, and a
    second add-card opens a fresh session.
  - Production: not yet observed.

## 2. `billing-auto-top-up`: automatic top-up

- **Entry points:** the Billing page, **Automatic top-up** (on at €20 by
  default; €5 to €1,000, or off).
- **States to exercise:** a balance that runs out with a working card; a
  card that declines; a balance still below zero after one top-up.
- **Driving it:** with a card on file and top-up on, let the balance reach
  zero (by use, or by an admin adjustment), then wait one minute for the
  settlement sweep.
- **Proof:** one top-up charge of whole €20 amounts takes the balance above
  zero; the out-of-credit mark clears and creates are allowed again.
- **Gotchas:** with top-up off, the same balance marks the organization out
  of credit instead; a walk of `billing-zero-refusal` must turn it off first.
- **Observed:**
  - Dev, accepted `91d8c52e2`, 2026-11-11 (#3381, #4167): an organization
    stuck at −€7.14 was charged one €20 top-up at 21:25:18Z and reached
    +€12.86, with creates allowed again.
  - Production: not yet observed.

## 3. `billing-add-credit`: add credit once

- **Entry points:** the Billing page, **Add credit**: €50, €100, €250, €500
  or **Custom** (€5 to €1,000) (#4288).
- **States to exercise:** a saved card; a bank that asks for confirmation
  (SCA), which goes to Stripe's page; no card yet, where Stripe's page takes
  the card and the payment together.
- **Driving it:** choose an amount and confirm.
- **Proof:** the balance rises by exactly that amount, and one paid invoice
  for it appears under **Invoices**.
- **Observed:** not yet observed.

## 4. `billing-receipt`: the receipt email

- **Entry points:** the organization owner's inbox. Billing sends the
  receipt itself on Stripe's `invoice.paid`, with links to Stripe's invoice
  and PDF; Stripe sends none from a test-mode account.
- **States to exercise:** a top-up receipt and an Add credit receipt; a send
  that fails, which makes billing fail the webhook so Stripe delivers it
  again.
- **Proof:** the email arrives once per invoice, and its amount and invoice
  number match **Invoices**.
- **Gotchas:** Dev's SES delivers only to addresses it is allowed to send
  to, so most Dev owners never see the email. Production email is #2053.
- **Observed:** not yet observed.

## 5. `billing-costs`: the Billing page shows costs in credits

- **Entry points:** the Billing page's **Current Month**, **Usage by
  Sandbox** and hourly chart; Account Home's hourly chart.
- **States to exercise:** a Sandbox while it runs and after it stops; a run
  shorter than a cent; Regular, Discounted and Unlimited.
- **Driving it:**
  1. `cw create --cloud --name usage-walk`, wait about five minutes, then
     `cw rm --yes usage-walk`.
  2. Two minutes after the stop, read the Billing page (or
     `GetBillingOverview` and `GetEnvironmentUsage`).
- **Proof:** after the stop, the Sandbox's cost under **Usage by Sandbox**
  and the hourly chart's total equal **Current Month**, the credit actually
  drawn, to within a few billionths of a euro of rounding; the balance fell
  by the same amount. While it runs, the per-Sandbox figure leads the draw
  by up to a minute. Unlimited shows time but no cost.
- **Observed:**
  - Dev, `e0841e760`, 2026-11-13 (#3954): `usage-3954` ran 366 s; drawn
    €0.063186774, per Sandbox and per hour €0.063186776; balance €20.00 →
    €19.936813226.
  - Production: not yet observed.

## 6. `billing-zero-refusal`: an empty balance refuses new work

- **Entry points:** `cw create --cloud`, `cw start` of a stopped cloud
  Sandbox, a snapshot capture (#4379), the dashboard's create and start.
- **States to exercise:** a never-funded organization; one that ran out
  (top-up off, or a card that declined); credit restored.
- **Driving it:** at a balance of zero or below:

  ```sh
  cw create --cloud
  cw create --cloud --output json
  ```

- **Proof:** `cw create --cloud` exits 1 with "… has no compute credit, so
  it can't run cloud sandboxes. Add a card or credit on its billing page:
  …/billing/ … Local sandboxes stay free: cw create --local". The JSON form
  carries `"code": "credit_exhausted"`. The Billing page says "This
  organization ran out of compute credit on …". After credit is restored,
  the same create succeeds.
- **Gotchas:** running Sandboxes are stopped 24 hours after credit runs out,
  not at once; their storage is kept.
- **Observed:**
  - Dev, v0.4.14 candidate `b30889111`, 2026-11-11 (#3381): €0 refused,
    then `cw create --cloud` succeeded in 2.1 s once funded.
  - Dev, `cw` at `5aee6e65c`, 2026-11-11 (#3381, #4096): the wording and
    JSON above.
  - Dev, 2026-11-13 (#3381, #4379): a capture refused at 12:56:11Z at
    −€0.06 and admitted at 13:07:21Z after credit was restored.
  - Production: not yet observed.

## 7. `billing-notice`: the low and out-of-credit emails

- **Entry points:** the organization owner's inbox.
- **States to exercise:** running low with top-up off; running out; a send
  the mail service rejects.
- **Proof:** each notice is sent once per spell (once per running-out, once
  per running-low since credit last came in). A rejected send is retried
  after 1, 2, 4 … minutes, at most a day apart, and is logged once per
  attempt (#4087).
- **Observed:**
  - Dev, `e0841e760`, 2026-11-13 (#4087): marked out of credit at
    12:56:10.556Z, one notice sent at 12:56:10.812Z, none again through
    13:04Z.
  - The failure backoff: not yet observed on any surface; no Dev address is
    rejected by its mail service.
  - Production: not yet observed.

## 8. `billing-stripe-delivery`: Stripe reaches billing

- **Entry points:** Stripe's webhook endpoint for the environment's
  `/api/webhooks/stripe`; billing's `/healthz/stripe-webhook-endpoint`.
- **Proof:** the health check reports `ok` with the endpoint's ID, and a
  Stripe-sent event is accepted with its signature verified and recorded.
- **Gotchas:** billing signs nothing itself in this walk; an event billing
  signed with a known secret cannot catch a missing endpoint or a wrong
  secret (#3263).
- **Observed:**
  - Dev, 2026-10-24 (#3263): health `ok`; a Stripe-delivered `invoice.paid`
    accepted with no signature failure.
  - Production: endpoint created 2026-10-24 (#3263); a delivered event not
    yet observed.
  - Continuous proof on Dev and Production (#3263 items 3 and 4): no
    command yet.
