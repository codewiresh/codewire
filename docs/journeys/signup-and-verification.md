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

Updated 2026-11-20.

| ID | Dev | Production |
| --- | --- | --- |
| `signup-email-invite` | not yet observed | not yet observed |
| `signup-email-review` | not yet observed | not yet observed |
| `signup-unverified-stranger` | observed 2026-11-16 at b183980df, stand-in (#4481) | not yet observed |
| `signup-resend` | not yet observed | not yet observed |
| `signup-provider` | buttons, start, cancel and state refusals observed 2026-11-17 at `5c6631406` (#4062); a real provider sign-in reported working by the owner 2026-11-14, not walked | buttons, start, cancel and state refusals observed 2026-11-17 at v0.4.22 (#4062); a real provider sign-in reported working by the owner 2026-11-14, not walked |
| `signup-gates` | not yet observed | not yet observed |
| `account-password-reset` | not yet observed | not yet observed |
| `account-admin-delete` | observed 2026-11-18 on Kind at `a4a3c815d`, stand-in (#4541) | not yet observed |
| `signup-unverified-purge` | observed 2026-11-15 at b183980df, a seeded account and a one-hour lifetime | enforce passes observed 2026-11-18 at v0.4.22, nothing old enough yet; the first deletion is due after 2026-11-20 18:05Z |
| `account-receipt-email` | not yet observed | not yet observed |
| `account-fresh-sign-in` | partly observed on Kind 2026-11-18, main 4199fd0f6 (server side; redirect delivery not yet observed since #5364's fix); not on Dev | not yet observed |

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
The operator's notice is #5358; its rules are in AUTH-POLICY's "The
operator's sign-up notice".

- **Entry points:** the sign-up page; the sign-in page; the admin accounts
  page, where an admin enables an account; the operator's inbox.
- **States to exercise:**
  - no invite code, or a wrong one: the sign-up is an access request and asks
    what the person wants to build;
  - sign-in before verification, after verification but before review, and
    after an admin enables the account;
  - `CODEWIRE_OPERATOR_EMAIL` set to an inbox the walker reads, and unset;
  - more than 10 access requests in an hour: the 11th sends one "more people
    are waiting" notice, and the rest send none.
- **Driving it:**
  1. Sign up with no invite code. The page reads **Verify your email**: once
     verified, the person is on the list.
  2. Sign in before opening the link: "Check your email to verify your
     address." with the resend button.
  3. Open the link. The page reads **You're on the list**. The operator's
     inbox gets "Codewire: access request from <address>".
  4. Sign in: "You're on the list." and no session.
  5. An admin enables the account on the admin accounts page. Sign in: it
     continues to two-factor setup.
- **Proof:**
  - no session cookie until step 5;
  - with the operator address set, exactly one notice arrives, after step 3
    and not after step 1. It names the address, "email", the time and that
    the person waits for review, and links to Admin → Manage account access.
    It holds no reason, name, client address or token. Step 5 sends no
    second notice. With the address unset, nothing is sent and the sign-up
    reads the same.
- **Gotchas:**
  - sign-in checks the password first, so only the right password learns why
    it was refused; a wrong one gets the same answer as an unknown address;
  - a GitHub or Google access request notifies at sign-up, not at a
    verification, because the provider verified the address;
  - the notice limit is site-wide, so other sign-ups in the same hour count
    against the walker's.
- **Observed:** not yet observed.

## `signup-unverified-stranger`: a sign-up at someone else's address

Issue: #4481.

- **Entry points:** the sign-up page; the sign-in page.
- **States to exercise:**
  - someone signs up at an address they cannot read, with a password they
    chose, with and without an invite code;
  - the address's owner never opens the link;
  - the address's owner opens the link anyway: the stranger's password then
    signs in until the owner resets it, the residual accepted by design
    (owner, 2026-11-13, #4481);
  - the owner's reset ends the stranger's sessions, and the old password
    grants nothing (#4507).
- **Driving it:**
  1. Sign up at a second walk address, as the stranger, and do not open the
     link.
  2. As the stranger, sign in with that password, from the page and with the
     curl above.
  3. Read the verification email in the second address's inbox: it says
     someone created an account with this address, and to ignore it if that
     wasn't them.
  4. As the address's owner, open the link anyway. As the stranger, sign in
     with the password again: it now works, in a second browser.
  5. As the address's owner, choose **Forgot password**, set a new password
     from the reset email, and sign in.
  6. As the stranger, reload the dashboard in the second browser, then sign
     in with the old password.
- **Proof:** step 2 answers `403` `email_unverified` and sets no session
  cookie, invite code or not. The stranger holds nothing that signs in. In
  step 6 the stranger's session is signed out, and the old password answers
  `401` "Invalid email or password".
- **Gotchas:**
  - Only a person can walk this. Sign-up meets Turnstile, and Dev exempts no
    address since codewire/deploy#254. Each email step needs an inbox the
    walker reads. e2e@codewire.sh is already an account (`codewire-dev-e2e`),
    so it can't be the second address. Use two throwaway addresses the walker
    reads, and delete both accounts afterwards (Settings → Delete account).
  - If the address's owner does open the link, the stranger's
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
  - Dev, 2026-11-16, at b183980df (with #4489 and #4507): working, by a
    stand-in walk (cw-selfhost, the orchestrator's choice on #4481).
    - **Stood in:** the browser sign-up, by two seeded accounts: one enabled,
      as an invite code leaves it, and one in review. The owner's
      verification link and reset email were stood in by tokens the check
      created itself, never emailed ones. Everything else used Dev's public
      API.
    - **Step 2:** `403` `email_unverified` with no session cookie, invited and
      in review.
    - **Step 4:** after the stand-in link, the stranger's password signed in,
      the accepted residual.
    - **Step 5:** the owner's reset, then the owner's sign-in.
    - **Step 6:** the stranger's old password answered `401` "Invalid email
      or password". The stranger's session was read from the database: the
      reset had deleted its row, and no row matched its cookie. The HTTP
      check couldn't be used, because Dev's edge cache answered
      `/api/auth/get-session` whatever the cookie (reported 2026-11-16).
    - **Step 3, the email's wording, wasn't observed.** #4489's test pins it.
      The stranger holding nothing that signs in is pinned by
      `a_stranger_who_signed_up_at_another_address_holds_nothing_that_signs_in`.
    - Both accounts were removed by id.

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
  minutes, and at most three verification emails to one address in an hour,
  however they were asked for (#3297). A fourth is not sent; the page says
  what it says when one is, and Admin → Audit Log shows `mail.throttled` for
  the account.
- **Gotchas:** the button carries a single-use, ten-minute token, never in a
  URL; nobody can ask for a link by typing an address. Repeating the same
  sign-up also resends the link, and counts toward the three.
- **Observed:** not yet observed.

## `signup-provider`: sign in with GitHub or Google

Issue: #4062. Launch step 1 (`launch-signup`) walks this on Production.

- **Entry points:** **Continue with GitHub** and **Continue with Google** on
  the sign-up and sign-in pages, and on the page `cw login` opens; linking
  and unlinking in Settings.
- **States to exercise:**
  - a new identity, through the same review as an email sign-up, or, with
    `IDP_SIGNUP=open`, signed in at once with no invite and no reason
    (#4121);
  - a second sign-in with the same identity reaches the same account;
  - an identity whose email matches an existing account links only after
    that account proves itself, never by the email alone;
  - unlinking keeps at least one way to sign in;
  - cancelling at the provider.
- **Driving it:** launch step 1, then link and unlink in Settings.
- **Proof:** `cw whoami` names the same account after the second sign-in.
- **Gotchas:** only a real GitHub or Google account proves this step.
- **Observed:**
  - Dev, 2026-11-17, at `5c6631406`, and Production, 2026-11-17, at
    v0.4.22 (`df5ceafd0`), both after #4996 (#4062). These states were
    observed, with HTTP requests only and no provider sign-in:
    - the sign-in and sign-up pages, and the page `cw login` opens, show
      both buttons;
    - each start redirects to its provider and writes no `oauth_states`
      row;
    - the provider's cancel answer (`error=access_denied`) sent to the
      callback returns to the login page with "Sign-in was cancelled." and
      creates no account;
    - a missing, tampered, mismatched or other provider's state cookie is
      refused as expired before any provider call.

    The states that need a real provider account aren't observed yet: a
    first sign-up through a provider, a second sign-in, a completed
    `cw login` through one, the email-match link, linking and unlinking in
    Settings, and a replayed state after a completed exchange.
  - The owner reported on 2026-11-13 that signing in with GitHub and with
    Google works ("GitHub and Google both work for me", #4062), and on
    2026-11-14 that this was on Dev and on Production ("it works on both").
    The record names no release and none of the states above, so on both
    surfaces it is a report, not an observation. The launch walk observes
    the states.
  - Dev, 2026-11-11, at `91d8c52e2` (#4062): both provider buttons were
    shown, each redirected to its provider, and a cancelled sign-in
    returned to the login page with its message. No account was created.

## `signup-gates`: the abuse gates in front of sign-up and sign-in

Issue: #3297 (items 7, 8, 11 and 14); the unavailable page's words are
#4723's.

- **Entry points:** the sign-up, sign-in and forgotten-password pages.
- **States to exercise:**
  - sign-up on a surface with no Turnstile secret or no mail: refused, no
    account, and the page says "Sign-up is temporarily unavailable. Try
    again in a few minutes.", never that the request was saved;
  - a sign-up whose account was saved but whose verification email couldn't
    be sent: the page says the request was saved and to submit again, which
    sends a new link;
  - five wrong passwords lock the account for fifteen minutes;
  - the edge rate limits on the sign-up and sign-in routes;
  - the IdP's sign-up limits: thirty sign-ups an hour from one client address
    (`signup_address`) and a hundred across the site (`signup`), each an
    admin's global value when one is set. A sign-up counts once it has
    passed its own checks, Turnstile included, and before its account is
    looked up, so one for an address that already has an account counts too.
- **Driving it:**
  1. Five sign-ins with a wrong password for a walk account, then one with
     the right password: the sixth answers `429`.
  2. From one address, thirty-one sign-ups on the sign-up page with a walk
     account's own email, each passing Turnstile: the first thirty say the
     account already exists, and the thirty-first is refused with "Too many
     sign-ups right now. Try again in N minutes." (#4695). No account is
     created and no mail is sent.
  3. On a surface with no Turnstile secret (the local Kind cluster), sign up
     with an address that has no account and isn't the e2e bypass address:
     the page says "Sign-up is temporarily unavailable. Try again in a few
     minutes.", and the address still has no account.
- **Proof:** the `429` on the right password, and no session. For the
  sign-ups:
  - the IdP's `sign-up refused by its rate limit` warning with
    `limit=signup_address`;
  - in `rate_limit`, one `signup_address:` key at 31 while `signup:all` rose
    by 30, so the address count refused and the server-wide one had room;
  - no other `signup_address:` key changed during the walk, so the count was
    the walker's alone.
  - for step 3, no `users` row for the address. A walk can't make mail fail,
    so the saved state's words are proven by the dashboard's sign-up tests
    and the IdP's test of the code it sends for it.
- **Gotchas:** the lockout is per account. The edge rate limits have no
  command yet (#3297). Step 2 refuses every sign-up from the walking
  machine's address for the rest of the hour, so walk it where no one else
  signs up from that address. Keep its sign-ups under ten in any ten
  seconds, or the edge's own limit blocks them before the IdP counts them.
- **Observed:** step 3 on the local Kind cluster, 2026-11-17, in a browser
  through the cluster's ingress. With main's dashboard and IdP (2a8adbc94),
  a sign-up for `walk4723-base-2116@example.test` answered `503` with "Your
  request was saved, but verification email delivery is temporarily
  unavailable. Complete the challenge and submit again shortly.", though no
  `users` row existed: the #4723 symptom. With #4723's dashboard and IdP
  deployed, `walk4723-fixed-0905@example.test` answered `503` with "Sign-up
  is temporarily unavailable. Try again in a few minutes.", and again no
  `users` row. Steps 1 and 2 are not yet observed.

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
  - a fourth request for one address within an hour: the same page, and no
    email (#3297); Admin → Audit Log shows `mail.throttled` for the account;
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

## `account-fresh-sign-in`: a client asks for a fresh sign-in

Issue: #4785 (pentest#13 T14). The rule is in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Credential rules".

- **Entry points:** an OIDC client's authorization request,
  `/api/oauth/authorize`, with `prompt=login` or `max_age`.
- **States to exercise:**
  - a browser already signed in, with `prompt=login`;
  - a browser signed in more than `max_age` seconds ago;
  - the same request with neither value, for comparison;
  - the browser's old session presented at the resumed request directly,
    without signing in again.
- **Driving it:**
  1. Sign in to the walk account in a browser.
  2. In that browser, open the authorization URL of a registered client
     (`response_type=code`, `scope=openid`, its redirect URI) with
     `prompt=login`. The sign-in page appears although the browser is
     signed in. Sign in: the client's redirect URI receives a code.
  3. Open it again without `prompt`, and with `max_age=1` after waiting a
     few seconds. Without either value the code comes back at once; with
     `max_age=1` the sign-in page appears first.
- **Proof:** a code only after the fresh sign-in in steps 2 and 3, and the
  database flow test `prompt_login_and_max_age_need_a_fresh_sign_in_through_the_round_trip`
  for the old session refused at the resumed request.
- **Observed:** on a local Kind cluster, 2026-11-18, IdP at main 4199fd0f6
  (with #5104), in Chromium, as the seeded `e2e-owner`, with the
  `codewire-desktop` client (PKCE S256), recorded on #4785. Server side
  only: with neither value `/api/oauth/authorize` answered with the code at
  once; with `prompt=login`, signed in, the sign-in page appeared, and after
  signing in the IdP's database showed the code issued, bound to the new
  sign-in's session; with `max_age=1` and a session minutes old, the sign-in
  page again. The code reaching the client's redirect URI after a sign-in
  form is not yet observed: on 2026-11-18 the form's `form-action` blocked
  the native redirect (#5364, since fixed). The old session refused at the resumed request is the
  database test
  `prompt_login_and_max_age_need_a_fresh_sign_in_through_the_round_trip`. Not on Dev:
  no agent can sign in to a Dev account in a browser (scratch accounts keep no
  password, sign-up has the bot check, and the smoke identities' passwords are
  secrets), so the Dev and Production cells wait for a person's sign-in.

## `account-admin-delete`: an admin deletes someone else's account

Issue: #4541. The rules are in AUTH-POLICY's "Account deletion by an admin or
the purge". The page names no money (owner, 2026-11-15, #3013).

- **Entry points:** Admin → **Manage account access**, the **Delete account**
  link on an account's row, which opens `/admin/accounts/<id>/delete`.
- **States to exercise:**
  - the list: the walker's own row says "Your account. Delete it in
    Settings." and another admin's row says "An admin. Demote them first.";
    neither has the link;
  - an account with a personal organization and a sandbox, and a membership
    in someone else's organization: the plan lists both;
  - an account that is the only owner of an organization others belong to:
    "Transfer or delete these organizations first", with the form disabled;
  - a wrong address typed, a wrong password or code, and the hourly limit:
    each says "Nothing was deleted.";
  - an account whose deletion is already running.
- **Driving it:** as a platform admin with an authenticator:
  1. Create the scratch account to delete with
     `scripts/runtime/dev/provision-dev-scratch-account.sh --verified --label <label>`
     (Dev only, through Infra's kube-access wrapper).
  2. Open Admin → Manage account access and choose **Delete account** on its
     row. Read the plan: what is deleted with the account, the memberships
     that end, and "Everything listed is removed permanently. This can't be
     undone."
  3. Type a different address, your password and a current code, and press
     **Delete account**.
  4. Type the account's address, a wrong code, and press it again.
  5. Type the account's address, your password and a current code, and press
     it.
- **Proof:**
  - in step 3 the browser refuses the form, because the address field must
    match the account's address; a client that skips that check gets "The
    address you typed is not this account's. Nothing was deleted." Step 4
    says "Your password or code is incorrect. Nothing was deleted." The
    account still signs in after both;
  - step 5 returns to the list with "Deletion started for <address>.";
  - the account can no longer sign in, and its sandboxes and personal
    organizations are gone;
  - the deletion operation records `initiator = admin` and the walker as its
    actor; the "account deleted" email goes only to a verified address.
- **Gotchas:**
  - an admin's own account and other admins' accounts are deleted another
    way: Settings → Delete account, after a demotion;
  - each admin may start 10 deletions an hour, a count no setting raises.
- **Observed:**
  - Kind, 2026-11-18, at `a4a3c815d`: working, as a stand-in for Dev
    (cw-accounts). The list rows, the refused only-owner case, the plan
    (a personal organization and a shared membership), steps 3 to 5 and the
    already-running page read as above. The operation completed in about 38
    seconds with `initiator = admin`, the walker as actor and `notify_email`
    set. The account, its personal organization and its membership were
    gone, and its sign-in failed. Kind differs from Dev here: the accounts
    were seeded in the database instead of by the scratch-account script,
    nothing sent the email, the personal organization had no sandbox, and
    the hourly limit was not walked. Recorded on #4541, comment 114759.

## `signup-unverified-purge`: an unverified sign-up is deleted after 7 days

Issue: #4541. The rules are in AUTH-POLICY's "Account deletion by an admin or
the purge": an email sign-up still unverified 7 days after it was created is
deleted, which frees its address (owner, 2026-11-13, #4541).

- **Entry points:** none a user takes. The orchestration leader runs it at
  most once an hour; `UNVERIFIED_SIGNUP_PURGE` is `off`, `report` (the
  default) or `enforce`. Dev and Production set `enforce`.
- **States to exercise:**
  - an unverified sign-up older than the lifetime, holding nothing: deleted;
  - one younger than the lifetime: left;
  - one that holds something (a membership, a sandbox, an API key, a user
    secret, a GitHub or Google sign-in): kept, and counted as kept;
  - an address verified between the selection and the deletion: kept,
    because each condition is checked again with the account's row locked;
  - `report`: every check runs and nothing is deleted.
- **Driving it:**
  1. On Dev, seed an unverified email sign-up that holds nothing with
     `scripts/runtime/dev/provision-dev-scratch-account.sh --unverified --label <label>`
     (through Infra's kube-access wrapper; Turnstile refuses a scripted
     browser sign-up).
  2. Count the purge's candidates read-only, with its own conditions and no
     age filter: the seeded account is the one.
  3. Shorten the lifetime on Dev with `UNVERIFIED_SIGNUP_LIFETIME_SECS`
     (never below an hour, never set in Production) through a reviewed deploy
     PR, and wait for the first hourly pass after the rollout.
  4. Restore the 7-day lifetime through the deploy PR prepared before step 3.
  On Production, read the leader's hourly pass lines and, after an account
  turns 7 days old, check it is gone.
- **Proof:**
  - the leader logs `reconciler: unverified sign-up purge` with
    `setting=Enforce` and its counts (`deleted`, `would_delete`, `kept`,
    `failed`, `held`), and `reconciler: unverified sign-up deletion begun`
    with the operation id. It logs no addresses;
  - `account_deletion_operations` has the operation with
    `initiator = unverified_purge`, no actor and `state = completed`;
  - `users` has no row for the account's id or its address, so the address
    can sign up again;
  - no mail goes to the address.
- **Gotchas:**
  - a repeated sign-up of a pending address doesn't move `created_at`, so the
    7 days count from the first sign-up;
  - GitHub and Google sign-ups are created verified and never match;
  - a self-hosted server without mail keeps `report` (AUTH-POLICY).
- **Observed:**
  - Dev, 2026-11-15, at b183980df: working (cw-accounts). The account was
    seeded at 15:49:52Z, `enforce` with a one-hour lifetime came from
    codewire/deploy#278, and the leader's first pass at 19:45:04Z logged
    `deleted=1 would_delete=0 kept=0 failed=0 held=0`. The operation read
    `initiator = unverified_purge`, `state = completed`, no actor, and `users`
    had no row for the id or the address. codewire/deploy#280 restored the
    7-day lifetime and kept `enforce`. Recorded on #4541,
    comment 104943.
  - Production, 2026-11-18, at v0.4.22: `enforce` passes running. Six hourly
    passes from 06:08Z to 11:09Z logged `setting=Enforce lifetime_secs=604800
    deleted=0 would_delete=0 kept=0 failed=0 held=0`. Nothing is old enough
    yet: the three unverified accounts are #2053's simulator sign-ups from
    2026-11-13 18:04Z to 18:56Z, due after 2026-11-20 18:05Z. The pass lines
    and the read-only replica count are recorded on #4541,
    comment 114161.

## `account-receipt-email`: the receipt after a top-up

Issue: #2053. The receipt is walked as `billing-receipt` in
[billing-and-credits.md](billing-and-credits.md); this step is that walk on
Production.

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
