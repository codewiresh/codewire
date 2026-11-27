# First-run onboarding

How a new account goes from verification to a working Cloud organization and
connected credentials: the 5-step full-screen onboarding overlay laid over the
Codewire interface (#6659). Each step shares the full Codewire wordmark above
the card, 5 circle-to-pill progress dots below it, and a bottom corner bar with
account escape actions on the left and the signed-in email on the right. The
format is in [README.md](README.md).

## Where it stands

Updated 2026-11-27. Written first (#6659); every step is **not yet observed**.

| ID | Kind | Dev | Production |
| --- | --- | --- | --- |
| `onboarding-workspace` | not yet observed | not yet observed | not yet observed |
| `onboarding-plan` | not yet observed | not yet observed | not yet observed |
| `onboarding-2fa` | not yet observed | not yet observed | not yet observed |
| `onboarding-code` | not yet observed | not yet observed | not yet observed |
| `onboarding-ai` | not yet observed | not yet observed | not yet observed |
| `onboarding-resume-and-bypass` | not yet observed | not yet observed | not yet observed |

## Before the walk

- Start with a fresh verified account that belongs to no organization and has
  not enabled two-factor authentication.
- For hosted Cloud plan checks, run with Stripe test keys configured; for
  self-hosted bypass checks, run with billing disabled.
- Remove scratch organizations and accounts after the walk.

## 1. `onboarding-workspace`: name your organization

- **Entry points:** first sign-in after verification (redirects to
  `/onboarding/workspace`); `/dashboard/` with zero organizations.
- **States to exercise:** auto-filled URL slug from the organization name;
  manually editing the `Organization URL` field directly (which stops
  auto-overwriting); duplicate or invalid slug error; empty submission; an
  account with a pending invitation seeing the link to view invitations.
- **Driving it:**
  1. Sign in as the new account. Confirm the full-screen overlay opens over the
     blurred Codewire interface with the full Codewire wordmark above the card,
     5 progress dots below (first dot active pill, rest circles), `Sign out`
     and `Delete account` at bottom-left, and `Signed in as <email>` at
     bottom-right.
  2. Type an organization name and verify the `codewire.sh/` URL input updates
     live. Edit the URL input directly, then press **Continue**.
- **Proof:** the organization is created with the exact chosen slug, `Delete
  organization` now appears in the bottom-left escape bar, and the browser
  advances to `/{slug}/onboarding/plan` (or `/{slug}/onboarding/2fa` when
  billing is disabled).
- **Gotchas:** no separate "Edit URL" toggle button; the slug field is editable
  inline.
- **Observed:** not yet observed.

## 2. `onboarding-plan`: choose a plan to unlock Cloud

- **Entry points:** Step 2 of onboarding (`/{slug}/onboarding/plan`), and any
  direct visit to `/{slug}/` sandbox routes while the organization has no
  active plan.
- **States to exercise:** the 3 vertically stacked plan cards (**Pro** $40/mo
  with $100 compute, up to 10 sandboxes, 8 vCPU / 16 GB RAM, up to 5 teammates;
  **Max** $100/mo Recommended in green with $250 compute, unlimited sandboxes,
  16 vCPU / 32 GB RAM, unlimited teammates; **Pay as you go** $0/mo with up to
  3 sandboxes, card required); Stripe Hosted Checkout return for Pro or Max;
  cancelling Checkout returns to Step 2 without activating a plan; Pay as you
  go completing through the in-page Stripe card setup modal; `Delete
  organization` from the bottom-left escape bar.
- **Driving it:**
  1. On Step 2, confirm all 3 plan cards stack vertically with aligned 2×2
     non-wrapping spec grids and normal sans numerals (`tabular-nums`).
  2. Choose **Pro** or **Max**, complete Stripe test Checkout, and return to
     `/{slug}/onboarding/plan/return`; or choose **Pay as you go** and save a
     Stripe test card in the modal.
- **Proof:** the organization's plan is active (`pro`, `max`, or `payg`) in
  billing and the browser advances immediately to `/{slug}/onboarding/2fa`
  without waiting for a webhook retry.
- **Gotchas:** local VMs (`cw create --local`) remain unaffected regardless of
  plan state.
- **Observed:** not yet observed.

## 3. `onboarding-2fa`: secure your account

- **Entry points:** Step 3 of onboarding (`/{slug}/onboarding/2fa`).
- **States to exercise:** top-aligned QR cutout with Steps 1 and 2 aligned down
  the right column; setup key partially masked by default; clicking the eye
  icon reveals/hides the full key; clicking the copy icon copies the full key
  and swaps to a green checkmark; wrong 6-digit code error; valid 6-digit code
  enabling 2FA; **Set up later** skipping to Step 4.
- **Driving it:**
  1. Confirm the setup key starts masked (e.g. `ABCD •••• •••• WXYZ`), toggle
     visibility with the eye icon, and click the copy icon.
  2. Either enter a valid 6-digit TOTP code and submit **Enable two-factor
     authentication**, or click **Set up later**.
- **Proof:** enabling 2FA activates TOTP on the account and shows recovery
  codes before Step 4; **Set up later** marks the session skip and advances to
  `/{slug}/onboarding/code`. An account that already enabled 2FA skips Step 3.
- **Gotchas:** onboarding workspace and plan routes allow pre-2FA sessions so
  users reach 2FA at Step 3 rather than before organization creation.
- **Observed:** not yet observed.

## 4. `onboarding-code`: connect your code

- **Entry points:** Step 4 of onboarding (`/{slug}/onboarding/code`).
- **States to exercise:** GitHub App OAuth connect returning to Step 4 with a
  connected badge; generating or importing an SSH key inline; **Continue**
  enabling once at least one code provider is connected; **Skip for now**
  advancing to Step 5.
- **Driving it:**
  1. Confirm GitHub (`icon-github`) and SSH key (`icon-key`) appear with
     single-line action buttons (`Connect`, `Add key`).
  2. Connect GitHub or add an SSH key (or click **Skip for now**).
- **Proof:** connected credentials appear in Settings → Credentials and
  **Continue** advances to `/{slug}/onboarding/ai`.
- **Gotchas:** real GitHub OAuth requires a human sign-in; SSH key generation
  can be walked without external provider credentials.
- **Observed:** not yet observed.

## 5. `onboarding-ai`: bring your AI subscription

- **Entry points:** Step 5 of onboarding (`/{slug}/onboarding/ai`).
- **States to exercise:** provider brand icons inside each button left of the
  label (**Claude**, **ChatGPT Codex**, **Antigravity**, **API key**); single
  borderless credential-proxy trust line with green dot and no em dash;
  streamlined Claude code-paste modal (no separate credential name prompt);
  Codex device-code modal; API key modal; **Finish setup** and **Skip for
  now**.
- **Driving it:**
  1. Connect a synthetic API key (or real Claude/Codex/Antigravity sign-in) and
     press **Finish setup**, or press **Skip for now**.
- **Proof:** any credential connected in Step 5 is automatically bound to the
  user's `default` credential profile, `users.onboarding_completed_at` is set,
  and the browser lands on `/{slug}/` without the onboarding overlay.
- **Gotchas:** real Claude, Codex, and Antigravity sign-ins require a human
  account; API key enrollment proves the modal and auto-profile binding path
  with a synthetic key.
- **Observed:** not yet observed.

## 6. `onboarding-resume-and-bypass`: resume, second org, invitations and self-hosted

- **Entry points:** reloading mid-onboarding; visiting `/{slug}/` before
  choosing a plan; creating a second organization; accepting an invitation to
  an existing organization; running with billing disabled or on the `unlimited`
  rate card.
- **States to exercise:**
  - reloading after Step 1 lands back on Step 2 (plan);
  - direct navigation to `/{slug}/` without a plan redirects to
    `/{slug}/onboarding/plan`, while `/settings/` and `/{slug}/billing/` stay
    reachable;
  - creating a second organization runs Steps 1–2 and skips personal 2FA/Git/AI
    steps;
  - accepting an organization invitation skips Steps 1–2 and enters the personal
    steps (2FA if needed, code, AI);
  - self-hosted (`STRIPE_SECRET_KEY` unset) or `unlimited` organizations skip
    Step 2 automatically.
- **Driving it:** exercise each entry state in a browser and check the target
  route and progress dot count.
- **Proof:** each state lands on the exact route in the route table and never
  traps a user who wants to sign out or delete their organization/account.
- **Gotchas:** existing accounts migrated from before #6659 have
  `onboarding_completed_at` backfilled and are not forced back through
  onboarding.
- **Observed:** not yet observed.
