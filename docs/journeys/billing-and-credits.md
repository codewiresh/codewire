# Billing and compute credit

An organization pays for cloud Sandboxes from a prepaid compute balance: a
card tops it up, running Sandboxes draw it down per second at the
organization's rate card, and an empty balance refuses new work. The model
and its owner decisions are #3381; Stripe delivery is proven by #3263; the
launch walk's step 6 (`launch-buy-credit`, [launch.md](launch.md)) walks the
same steps on Production. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-22. Production does not enforce credit yet: it starts with
the first Production release after codewire/deploy#245.

| ID | Dev | Production |
| --- | --- | --- |
| `billing-card` | observed 2026-11-11 (#3381) | not yet observed |
| `billing-auto-top-up` | observed 2026-11-11 (#3381) | not yet observed |
| `billing-add-credit` | not yet observed | not yet observed |
| `billing-receipt` | billing's skip observed 2026-11-18 (#4816) | Stripe's receipt observed 2026-11-21 (#4816) |
| `billing-costs` | observed 2026-11-13 (#3954) | not yet observed |
| `billing-zero-refusal` | observed 2026-11-11 and 2026-11-13 (#3381) | not yet observed |
| `billing-admin-adjust` | not yet observed | not yet observed |
| `billing-banner` | not yet observed | not yet observed |
| `billing-admin-prices` | not yet observed | not yet observed |
| `billing-operator-notice` | not yet observed (#5358) | not yet observed |
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

- **Entry points:** the Billing page (`/<org>/billing/`), **Add card**, the
  page's first action; the "Add a card or credit" link that `cw create
  --cloud` prints at €0.
- **States to exercise:** no card yet; a card added at an empty balance; a
  second card, made the default from its menu; removing the default; a card
  that declines (`4000 0000 0000 0002`); a card that saves but declines
  the charge saving makes (`4000 0000 0000 0341`, #6502); a bank that asks
  to confirm (`4000 0025 0000 3155`); too many tries (#4874); a return link
  the page didn't start.
- **Driving it** (design v4, #4750; the card form stays in the page):
  1. At €0 with no card, choose **Add card**. A dialog opens with Stripe's
     card field, and **Automatic top-up** on at €20 beside it. Its button
     reads **Save card and pay €20**, because saving at an empty balance
     charges the top-up (owner, 2026-11-14). With top-up off, it reads
     **Save card**.
  2. Enter the card and save. A bank's check opens over the dialog. On
     success the dialog closes, and a notice names the card and any charge.
  3. From a card's **⋯** menu, **Make default**, or **Remove card…**. The
     Remove dialog says what happens to the default and to top-up.
- **Proof:** **Payment methods** lists the card, marked **Default**. At an
  empty balance with top-up on, saving it charges whole €20 top-ups until the
  balance is above zero, as one charge (owner, 2026-11-11). A declined card
  or a cancelled bank check says so at the field, and nothing is saved or
  charged. One paid invoice appears under **Invoices**,
  and the balance moves by the amount paid.
- **Saved, but its charge declined** (#6502): at an empty balance with
  top-up on, or with credit chosen under Add credit, a card can save and
  then decline the charge. The dialog stays open and says so: "Your card is
  saved, but its automatic top-up was declined, so no credit was added. Try
  another card." (for a purchase: "…but the payment was declined…", or
  "…declined for insufficient funds…"). Its button becomes **Done**, which
  goes to Billing. There the card is listed as the default, the notice says
  the top-up was declined, and the banner says the organization is out of
  credit. The notice and any error sit outside the part of the page that
  refreshes on a credit change, so the refresh that follows the declined
  charge no longer erases them, as it did before. Observed on Kind (below).
- **Too many tries** (#4874, against card testing): an organization starts at
  most 10 card setups an hour, and a user at most 20 a day across all their
  organizations. One client address starts at most 60 an hour, across every
  account and organization on it (`card_setup_address`, #4901): enough for a
  class or an office on one network to each save a card, not enough for one
  machine with many accounts to test cards. Every save counts, accepted or
  not, and opening the form counts nothing. The next try is refused
  before Stripe is called, so nothing is saved or charged; the dashboard
  says there were too many tries and to try again later, and the form opens
  again once the hour (or the day) has passed. Billing counts the refusal in
  `codewire_rate_limit_refusals_total` and logs the organization and user.
  Not yet observed on Dev or Production.
- **A return link the page didn't start** (#4750): a bank's check that needs
  a full redirect returns to Billing with Stripe's SetupIntent in the
  address. What the card is for (top-up, credit) is what was chosen when it
  was saved, kept by billing, never read from the address; a SetupIntent
  finishes once, within an hour. So a crafted or replayed link buys nothing
  and changes no setting; the page says Codewire couldn't finish adding the
  card.
  Not yet observed on Kind, Dev or Production.
- **Gotchas:** the headless browser could not complete Stripe's declined-card
  flow (Stripe answered "Your internet connection is unstable"); walk the
  declined card in a real browser.
- **Observed:**
  - Dev, v0.4.14 candidate `b30889111`, 2026-11-11 (#3381): test card 4242
    added; balance €0 → €20.00 with one paid €20.00 invoice.
  - Dev, `e7f3c85c6`, 2026-11-11 (#3381): Stripe offers cards only, and a
    second add-card opens a fresh session.
  - Kind, the in-page card form (#4750), 2026-11-18. Dev was impractical:
    its agent identities sign in with API keys only, and a fresh browser
    identity needs a provisioning path agents don't use. The cluster ran
    #4874 and #4941 as merged (the card code differs from `c50de4a78` only
    in a doc comment), with Dev's Stripe test keys. Two fresh
    organizations at €0, each with test card 4242, in headless Chromium at
    1440:
    - Top-up switched off in the dialog: the button read **Save card**. The
      notice was "Visa •••• 4242 saved as your default card." Nothing was
      charged and the balance stayed €0.00. The Automatic top-up switch
      showed off beside "Charge Visa •••• 4242 when the balance reaches €0".
      The organization's `auto_top_up_enabled` was false, with no top-up or
      ledger row.
    - Top-up left on: the button read **Save card and pay €20**. The notice
      was "…saved as your default card. Automatic top-up added credit; the
      receipt is on its way." The balance went €0 → €20.00, the switch
      showed on, and there was one `billing_top_ups` row, 2,000 cents,
      `paid`, with a Stripe test-mode invoice, and one €20 `top_up` ledger
      entry.
    - Not observed on Kind: the invoice under **Invoices**, which billing
      lists only after Stripe's `invoice.paid` webhook. Kind receives no
      Stripe webhooks.
    - Recorded on #4750, comments 115389 and 115402.
  - Kind, a card saved whose charge declined (#6502), 2026-11-25, with Dev's
    Stripe test keys. The dashboard ran main `e9e43f9843` merged into
    #5688's user token branch, whose billing code is main's. At €0 with
    top-up on, test card 4000 0000 0000 0341, at 1280 and at 390:
    - the dialog stayed open with "Your card is saved, but its automatic
      top-up was declined, so no credit was added. Try another card.";
      Cancel went away and the button became **Done**;
    - Done went to Billing, whose notice read "Visa •••• 0341 saved as your
      default card. Its automatic top-up was declined, so no credit was
      added." and was still there 15 s later, after the live refresh; the
      banner said the organization is out of credit;
    - recorded on #6502, comment 144350.
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
  or **Other €** (€5 to €1,000) (#4288), and **Pay €N**.
- **States to exercise:** a saved card; a bank that asks to confirm a charge
  on a saved card, which goes on to Stripe's invoice page; no card yet,
  where **Pay** first opens Stripe's card field under Add credit, then saves
  the card and buys the credit with it, with no top-up on top (#4750). The
  purchase also sets off settlement, which finds it pending; only one of
  the two pays it, and the buyer sees it paid, never "could not be
  confirmed" (#5365).
- **Driving it:** choose an amount and **Pay**.
- **Proof:** the balance rises by exactly that amount, and one paid invoice
  for it appears under **Invoices**.
- **Observed:** not yet observed.

## 4. `billing-receipt`: the receipt email

- **Entry points:** the organization owner's inbox. On Dev and Production,
  Stripe sends the receipt, with the invoice and receipt PDFs, and billing
  sends none (`CODEWIRE_BILLING_RECEIPTS=stripe`, #4816). Billing keeps the
  Stripe customer's email on the organization's current owner before each
  purchase. With the setting unset, billing sends its own receipt on
  `invoice.paid`, with links to Stripe's invoice and PDF. Stripe sends no
  automatic receipt for a test-mode payment.
- **States to exercise:** a top-up receipt and an Add credit receipt; a send
  that fails, which makes billing fail the webhook so Stripe delivers it
  again.
- **Proof:** the email arrives once per invoice, and its amount and invoice
  number match **Invoices**. An automatic top-up's receipt says why the card
  was charged: "Compute credit, added by automatic top-up when the balance
  reached €0" (#4754), whether billing or Stripe sends it.
- **Gotchas:** on Dev, a test-mode payment gets no automatic receipt from
  Stripe, so a Dev walk proves billing's skip line, not the email.
- **Observed:**
  - Dev, 2026-11-18 (#4816): billing logged "Stripe sends this invoice's
    receipt; billing sends none" for a test-mode **Add credit** of €5, and
    sent no email.
  - Production, 2026-11-21 (#4816): Stripe's receipt for the owner's €5
    purchase arrived, later than expected. Billing logged the skip 0.4 s
    after the payment.

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
- **States to exercise:** running low with top-up off, and with top-up on
  and a card (#4754); running out; a send the mail service rejects; an owner
  who owns a second organization (#5298).
- **Proof:** each notice is sent once per spell (once per running-out, once
  per running-low since credit last came in). A rejected send is retried
  after 1, 2, 4 … minutes, at most a day apart, and is logged once per
  attempt (#4087). Running low with top-up on says what top-up charges to
  the saved card at €0, and still offers Add credit.
- **Which organization** (#5298): the low, out-of-credit and payment-failed
  emails name the organization in the subject, the heading and the first
  sentence, for example "Acme has run out of compute credit". An owner of
  two organizations can tell which one it is without opening the link. A
  name with a line break reads as one line; a name that can't be read keeps
  the general words ("Your compute credit has run out"), and the email is
  still sent.
- **Observed:**
  - Dev, `e0841e760`, 2026-11-13 (#4087): marked out of credit at
    12:56:10.556Z, one notice sent at 12:56:10.812Z, none again through
    13:04Z.
  - The failure backoff: not yet observed on any surface; no Dev address is
    rejected by its mail service.
  - Production: not yet observed.

## 8. `billing-stripe-delivery`: Stripe reaches billing

- **Entry points:** Stripe's webhook endpoint for the environment's
  `/api/webhooks/stripe`; billing's `/healthz/stripe-webhook-endpoint` and
  `/healthz/stripe-webhook-delivery` (the daily delivery check, `disabled`
  until a sentinel customer exists).
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
  - Continuous proof on Dev and Production (#3263 items 3 and 4): Dev
    acceptance runs `scripts/runtime/dev/smoke-dev-billing-roundtrip.sh`
    after each promotion; billing's daily delivery check runs wherever a
    sentinel customer exists, which infra's
    `openbao-codewire-prod-stripe-delivery-sentinel apply` creates for
    Production. Not yet observed.

## 9. `billing-admin-adjust`: an adjustment that would leave a negative balance asks first

Issue: #4754.

- **Entry points:** the admin organization page, **Rate card and credit**,
  **Adjust credit**; `AdjustOrganizationCredit` on the admin API.
- **States to exercise:**
  - a grant, and a removal that leaves the balance at €0 or above: applied at
    once, as today;
  - a removal that would leave the balance below €0, with automatic top-up on
    and a card: nothing changes yet. The page asks, naming the result, the
    card and the charge: "This leaves the balance at -€1.14. Automatic
    top-up is on, so Visa •••• 4242 is charged €20.00 within seconds." The
    card is read from billing for platform administrators only (#5094);
  - the same with top-up off, or with no card: "This leaves the balance at
    -€1.14. New Sandboxes and starts are refused, and running Sandboxes
    stop after 24 hours; their storage is kept.";
  - billing can't say whether there is a card: the question names both
    outcomes, "…Automatic top-up is on at €20.00, so a saved card is charged
    within seconds; without one, new Sandboxes and starts are refused.";
  - on Unlimited, which is never charged or refused, the question names no
    charge and no refusal (#6503): "This leaves the balance at -€11.00. The
    organization is on Unlimited, so nothing is charged or refused."
    Observed on Kind;
  - confirming applies it, once; going back changes nothing;
  - the balance moving between the question and the answer: the answer
    confirms the result it was shown, and a different result asks again.
- **Driving it:** on Kind (`make kind-seed-login`), as a platform admin, open
  the e2e owner's organization page. Grant €5, then remove €6 with top-up on
  and with it off.
- **Proof:**
  - nothing is written until a negative result is confirmed: the credit
    entries table and the audit log gain one entry, with its reason, only
    after **Confirm**;
  - the API refuses an unconfirmed negative result
    (`FailedPrecondition`), so no client can skip the question;
  - after a confirmed negative result with top-up on, the card is charged
    within seconds (#4777), and the Billing page shows the charge.
- **Observed:** Kind, 2026-11-25, main `867dabfdba` with Dev's Stripe test
  keys (#4754 comment 143367):
  - a €5 grant applied at once with one ledger and one audit entry;
  - a removal past €0 with top-up on and no card asked, naming no charge,
    and Go back wrote nothing;
  - the API without a confirmed balance answered `FailedPrecondition`
    (`NEGATIVE_BALANCE_UNCONFIRMED`) and wrote nothing;
  - a grant that landed between the question and Confirm made Confirm ask
    again with the new result, and the second Confirm applied it once;
  - with card 4242 and top-up on, the question named "Visa •••• 4242 is
    charged €20.00 within seconds" (#5094), and Stripe test mode charged it
    about 5 s after Confirm.
  - Not seen on Kind: the charge under **Invoices**, which needs Stripe's
    webhooks.
  - On Unlimited, with Visa •••• 0341 saved and top-up on, 2026-11-25, on
    the same tree as the declined card under `billing-card`: "This leaves the balance at -€20.00. The
    organization is on Unlimited, so nothing is charged or refused." The
    same removal on Regular named "Visa •••• 0341 is charged €20.00 within
    seconds". Recorded on #6503, comment 144357.

## 10. `billing-banner`: every page says where credit stands

Issue: #4754. Design: private-docs `designs/billing-compute-credits.md`,
"What the console says about credit".

- **Entry points:** the banner across the top of every page of a metered
  organization, and Create Sandbox's drawer.
- **States to exercise:**
  - low with top-up off: under €5, and under 24 hours at current use;
  - low with top-up on and a card;
  - €0 or below while automatic top-up charges the card;
  - €0 or below with no card, top-up off, or a declined charge, with and
    without Sandboxes running;
  - back above €0, and Unlimited;
  - each as an owner and as a member.
- **Driving it:** with credit enforced, set the balance through the admin
  organization page's credit adjustment (`billing-admin-adjust`). Turn
  top-up on and off on the Billing page; Stripe's test card
  `4000 0000 0000 0341` saves and then declines its charges. Keep a
  Sandbox running for the "at current use" states.
- **Proof:**
  - each state's banner reads as the design says: its tone, its words, the
    charge and the card;
  - an owner or admin sees the card's brand and last four, and the action
    (Add credit, or Add a card) where one applies; a member reads "the saved
    card" and sees no action;
  - in both €0 states Create Sandbox's drawer says why instead of failing on
    submit, and while top-up charges it offers no Add credit;
  - each change shows within a few seconds without a reload
    (`codewire:live:credit`), and a balance back above €0 clears the banner
    and the refusal.
- **Gotchas:** where credit isn't enforced (`CODEWIRE_CREDIT_ENFORCEMENT`
  unset), there is no banner at all: nothing would be refused or charged.
- **Observed:** Kind, 2026-11-25, main `867dabfdba`, as owner and member,
  credit enforced, Dev's Stripe test keys (#4754 comments 143367 and
  143585):
  - every state above reads as the design says, with the card for the owner
    and "the saved card" and no action for a member;
  - with a Sandbox running, the low states add "about 14 hours at current
    use", and out of credit names when running Sandboxes stop, in #6505's
    sentences;
  - the charging banner appeared 0.7 s after an admin's adjustment and
    cleared 5.6 s later when the charge settled, without a reload;
  - Create Sandbox's drawer, once settled, said why at €0 with top-up off,
    with the owner's and the member's own next step.
  - Dev and Production: not yet observed.

## 12. `billing-admin-prices`: an administrator sets the prices

Issue: #5782. The rule is [`docs/dev/BILLING.md`](../dev/BILLING.md),
"Prices".

- **Entry points:** the admin panel's Pricing page, the public pricing page,
  the Billing page and the Sandboxes menu's estimate.
- **States to exercise:**
  - a rate changed, its old and new value shown before it saves;
  - the suspended or hibernated storage rate at 0;
  - Unlimited, which can't be changed;
  - a non-administrator, who can't open the page or make the call;
  - billing down: the public pricing page keeps the last rates it read, or
    says "Prices can't be shown right now." if it has read none.
- **Driving it:** on Dev, as a platform administrator, raise Regular's vCPU
  price by a cent an hour. Keep a Sandbox of a metered test organization
  running across the change, then set the price back.
- **Proof:**
  - the page shows the old and new value before saving, and one audit
    entry records the administrator, the card, the rate and both values;
  - the public pricing page, the Billing page and the Sandboxes estimate
    show the new price without a release, the pricing page within a minute;
  - the first draw after the change uses the new price, and the draws
    before it keep their amounts in the ledger;
  - setting it back does the same in reverse.
- **Observed:** not yet observed.

## 11. `billing-operator-notice`: the operator is told when credit is bought

Issue: #5358 (owner, 2026-11-18: "I would like to get a duplicate receipt
myself if it's possible or at least a notice that somebody signed up.").
The rules are in `docs/CONFIGURATION.md`, "Operator notices".

- **Entry points:** **Add credit** on the Billing page (saved card, and no
  card yet), an automatic top-up, and the operator's inbox
  (`CODEWIRE_OPERATOR_EMAIL` on billing).
- **States to exercise:**
  - each of the three purchases, paid;
  - a declined charge, and one the bank holds for approval and the customer
    then pays on Stripe's page;
  - an organization name holding HTML, line breaks and lines that look like
    email headers;
  - more than 10 purchases in an hour;
  - the email provider failing, and `CODEWIRE_OPERATOR_EMAIL` unset.
- **Driving it:** on Dev, as in `billing-add-credit` and
  `billing-auto-top-up`, with `CODEWIRE_OPERATOR_EMAIL` set to an inbox the
  walker reads. The burst, the failing provider and the hostile names are
  for tests.
- **Proof:**
  - one "Codewire: credit bought, <amount>" email per paid purchase. It
    names the organization, the amount, Add credit or automatic top-up, and
    the time, and links to the organization's admin page. It holds no card,
    payment method, invoice number or link, Stripe ID or buyer;
  - a declined charge sends none, and a held one sends one when it is paid;
  - a second delivery of the same `invoice.paid` sends no second notice;
  - the 11th in an hour sends one "More credit purchases" email, and later
    ones none;
  - a failed send, or the address unset, changes nothing for the buyer: the
    purchase is credited, and Stripe isn't asked to redeliver.
- **Gotchas:** Stripe's receipt to the buyer (#4816) is separate: this
  notice goes only to the operator, and never to the buyer.
- **Observed:** not yet observed.
