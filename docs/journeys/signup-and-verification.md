# Sign-up and verification

How a person gets an account and proves the address it belongs to: email and
password sign-up with and without an invite code, the verification link,
sign-in with GitHub or Google, and the abuse gates in front of them. The
rules are in [`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md); the issues are
#4481 (a password proves only who chose it), #4062 (sign in with GitHub or
Google), #3297 (abuse resistance) and #2053 (account email). Launch step 1
([launch.md](launch.md), `launch-signup`) walks the provider part of this on
Production. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-13.

| ID | Dev | Production |
| --- | --- | --- |
| `signup-email-invite` | not yet observed | not yet observed |
| `signup-email-review` | not yet observed | not yet observed |
| `signup-unverified-stranger` | failure observed 2026-11-13 before #4489 (#4481) | not yet observed |
| `signup-resend` | not yet observed | not yet observed |
| `signup-provider` | not yet observed | not yet observed |
| `signup-gates` | not yet observed | not yet observed |
| `account-password-reset` | not yet observed | not yet observed |
| `account-receipt-email` | not yet observed | not yet observed |

## Before the walk

- Every email step needs an inbox the walker can read, at an address used for
  nothing else. A synthetic smoke identity
  (`scripts/runtime/dev/with-dev-smoke-auth.sh`) is created already verified,
  so it cannot stand in for any step here.
- Sign-up asks for a Turnstile challenge, so it is walked in a browser; a
  script cannot sign up. Sign-in has no challenge, and a step may check it
  from a terminal with the JSON API the sign-in page uses:

  ```sh
  curl -sS -X POST "$CODEWIRE_ORIGIN/api/auth/sign-in" \
    -H 'Content-Type: application/json' \
    -d '{"email":"ADDRESS","password":"PASSWORD"}'
  ```

- Record the source commit Dev or Production was running with every
  observation, and remove each walk account afterwards.

## `signup-email-invite`: email and password, with an invite code

Issue: #4481.

- **Entry points:** the sign-up page; the sign-in page.
- **States to exercise:**
  - a valid invite code: the account is enabled but signs in only after its
    address is verified;
  - sign-in with the right password before verification;
  - sign-in after verification;
  - the verification link opened on another device than the sign-up.
- **Driving it:**
  1. On the sign-up page enter a name, the walk address, a password and a
     valid invite code, and pass the challenge. The page reads **Check your
     email**: "We sent a verification link to your email address. Open it,
     then sign in with the password you chose." No session cookie is set.
  2. Sign in with that password. The sign-in page shows "Check your email to
     verify your address." with a **Resend verification email** button, and
     no session starts. The curl above answers `403` with
     `"code":"email_unverified"`.
  3. Open the emailed link. The page reads **Email verified**: "Your email
     address is verified. Sign in with the password you chose." with a
     **Sign in** button.
  4. Sign in. It continues to two-factor setup, then the dashboard.
- **Proof:** step 2's sign-in starts no session and step 4's does: a session
  cookie is set only in step 4.
- **Gotchas:**
  - Without mail delivery the sign-up answers 503 and creates no account.
  - Before #4489 an invite-code sign-up signed in at once; a walk on a surface
    without it proves nothing about this step.
- **Observed:** not yet observed.

## `signup-email-review`: email and password, waiting for review

Issue: #4481, and #3297 item 8 (the access review is Production's gate).

- **Entry points:** the sign-up page; the sign-in page; the admin accounts
  page, where an admin enables an account.
- **States to exercise:**
  - no invite code, or a wrong one: the sign-up is an access request and asks
    what the person wants to build;
  - sign-in before verification, after verification but before review, and
    after an admin enables the account.
- **Driving it:**
  1. Sign up with no invite code. The page reads **Verify your email**: once
     verified, the person is on the list.
  2. Sign in before opening the link: "Check your email to verify your
     address." with the resend button.
  3. Open the link. The page reads **You're on the list**.
  4. Sign in: "You're on the list." and no session.
  5. An admin enables the account on the admin accounts page. Sign in: it
     continues to two-factor setup.
- **Proof:** no session cookie until step 5.
- **Gotchas:** sign-in checks the password first, so only the right password
  learns why it was refused; a wrong one gets the same answer as an unknown
  address.
- **Observed:** not yet observed.

## `signup-unverified-stranger`: a sign-up at someone else's address

Issue: #4481.

- **Entry points:** the sign-up page; the sign-in page.
- **States to exercise:**
  - someone signs up at an address they cannot read, with a password they
    chose, with and without an invite code;
  - the address's owner never opens the link.
- **Driving it:**
  1. Sign up at a second walk address, as the stranger, and do not open the
     link.
  2. As the stranger, sign in with that password, from the page and with the
     curl above.
  3. Read the verification email in the second address's inbox: it says
     someone created an account with this address, and to ignore it if that
     wasn't them.
- **Proof:** step 2 answers `403` `email_unverified` and sets no session
  cookie, invite code or not. The stranger holds nothing that signs in.
- **Gotchas:** if the address's owner does open the link, the stranger's
  password then works. The email's wording is the guard for that case (owner,
  2026-11-13, #4481): "Someone created a Codewire account with this address.
  If it was you, verify your email to finish setting it up." and "If it wasn't
  you, ignore this email. Nobody can sign in to the account unless this link
  is opened."
- **Observed:**
  - Dev, 2026-11-13, before #4489: failure. With an invite code, the
    stranger's password signed in before verification and kept working after
    the owner verified. Stand-in: the account's sign-up rows were written
    directly because Turnstile blocks scripted sign-up, and the owner's link
    was a token only the check knew; verification and sign-in used Dev's
    public API (#4481).

## `signup-resend`: a new verification link

Issue: #4481.

- **Entry points:** the **Resend verification email** button on the sign-in
  page.
- **States to exercise:** a first resend; a second within five minutes; the
  button's token after ten minutes.
- **Driving it:**
  1. Sign in to an unverified account and press **Resend verification
     email**. The page says "Sent. Check your email; the link works for 24
     hours." and one email arrives.
  2. Sign in again and press it again within five minutes. No second email
     arrives.
- **Proof:** the number of emails received: one per address in any five
  minutes.
- **Gotchas:** the button carries a single-use, ten-minute token, never in a
  URL; nobody can ask for a link by typing an address.
- **Observed:** not yet observed.

## `signup-provider`: sign in with GitHub or Google

Issue: #4062. Launch step 1 (`launch-signup`) walks this on Production.

- **Entry points:** **Continue with GitHub** and **Continue with Google** on
  the sign-up and sign-in pages, and on the page `cw login` opens; linking
  and unlinking in Settings.
- **States to exercise:**
  - a new identity, through the same review as an email sign-up;
  - a second sign-in with the same identity reaches the same account;
  - an identity whose email matches an existing account links only after
    that account proves itself, never by the email alone;
  - unlinking keeps at least one way to sign in;
  - cancelling at the provider.
- **Driving it:** launch step 1, then link and unlink in Settings.
- **Proof:** `cw whoami` names the same account after the second sign-in.
- **Gotchas:** only a real GitHub or Google account proves this step.
- **Observed:** not yet observed.

## `signup-gates`: the abuse gates in front of sign-up and sign-in

Issue: #3297 (items 7, 8, 11 and 14).

- **Entry points:** the sign-up, sign-in and forgotten-password pages.
- **States to exercise:**
  - sign-up on a surface with no Turnstile secret: refused, no account;
  - five wrong passwords lock the account for fifteen minutes;
  - the edge rate limits on the sign-up and sign-in routes.
- **Driving it:**
  1. Five sign-ins with a wrong password for a walk account, then one with
     the right password: the sixth answers `429`.
- **Proof:** the `429` on the right password, and no session.
- **Gotchas:** the lockout is per account. The edge rate limits have no
  command yet (#3297).
- **Observed:** not yet observed.

## `account-password-reset`: a forgotten password

Issues: #2053, #4481. What the reset ends is fixed by #4488: the transaction
that replaces the password also ends the account's browser sessions, pending
second-factor challenges and OAuth grants and tokens; API keys stay (owner,
2026-11-13, #4481). #4507 adds that a sign-in racing the reset gets no
session; until it merges, leave that state out.

- **Entry points:** **Forgot password?** on the sign-in page, which opens
  `/forgot-password`; the link in the email, which opens `/reset-password`.
- **States to exercise:**
  - an address with a password account: one email, subject "Reset your
    Codewire password";
  - an address with no account: the same page, and no email;
  - the link used a second time, and a link more than an hour old;
  - a new password that fails the rules (at least 12 characters, with an
    upper-case letter, a lower-case letter, a digit and a symbol);
  - a browser, and a `cw` sign-in, that were signed in before the reset.
- **Driving it:**
  1. Sign in to the walk account in a second browser, and with `cw login`.
  2. In the first browser, open **Forgot password?**, enter the address and
     press **Send reset link**. The page says "If an account exists for that
     address, a password reset link has been sent." One email arrives, with
     a **Reset Password** link that "expires in 1 hour".
  3. Open the link. The page asks for the new password twice. Enter it and
     press **Reset password**: "Your password has been reset. You can now
     sign in with the new password."
  4. Open the link again and submit a valid new password. The form opens,
     because opening checks nothing, and the submit answers "The reset link
     is invalid or expired, or the password does not meet the
     requirements."
  5. Sign in with the old password, then with the new one.
  6. Reload the second browser, and run `cw ls`.
- **Proof:**
  - the old password is refused and the new one signs in;
  - the second browser is back at the sign-in page, and `cw ls` asks to sign
    in again;
  - an API key the organization made before the reset still works;
  - an address with no account received nothing;
  - the audit log has one `user.password.reset` event, whose
    `signed_out_sessions` counts the browser sessions it ended. The `cw`
    sign-in ends too, but is not in that count.
- **Gotchas:**
  - opening the link only moves its token into a cookie scoped to
    `/reset-password`, so a mail scanner that fetches it uses nothing up;
    only the reset itself spends the token;
  - an account that signs in only with GitHub or Google still gets the email,
    and the reset page reports success, but no password is set and nothing is
    signed out (#4528). Walk this step with a password account;
  - each request sends an email; the throttle on account mail is #3297's.
- **Observed:** not yet observed.

## `account-receipt-email`: the receipt after a top-up

Issue: #2053. The receipt is walked as `billing-receipt` in
[billing-and-credits.md](billing-and-credits.md); this step is that walk on
Production, which #2053 needs before Resend is retired.

- **Entry points:** **Add credit** on the Billing page, or an automatic
  top-up; the receipt goes to the organization's first owner, whoever paid.
- **States to exercise:** one real payment on Production. Dev's Stripe is in
  test mode, and Dev's SES sends only to verified addresses, so Dev cannot
  stand in for it.
- **Driving it:** the owner adds the smallest credit (€5, **Custom**), or the
  walk waits for the next real top-up. Either is a real charge, so the owner
  chooses which (#2053).
- **Proof:** one "Payment Receipt — Codewire" email for the invoice, whose
  invoice number and amount match **Invoices** and whose **View Invoice** and
  **Download PDF** links open Stripe's copies; a second delivery of the same
  `invoice.paid` sends no second email.
- **Gotchas:** a receipt that fails to send fails the webhook, so Stripe
  delivers it again; one late email is a retry, not a duplicate.
- **Observed:** not yet observed.
