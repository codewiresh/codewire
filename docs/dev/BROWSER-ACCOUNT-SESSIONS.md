# Browser account session controls

The IdP exposes cookie-only session inventory and revocation for the Account
screen. These routes never accept API keys, OAuth tokens, or bearer session
tokens. The actor must be an enabled account with two-factor authentication
enabled. They do not change the existing factor enrollment flow.
These two exact routes are registered in the permanent raw identity policy.
The dashboard calls the internal IdP origin; this change adds no public ingress
path or wildcard raw control-plane exception.

`GET /api/auth/sessions?account_id=<expected-account>&cursor=<optional-id>`
returns `account_id`, `current_session` (`id`, `expires_at`), `sessions`
(`id`, nullable `created_at`, `expires_at`), and nullable `next_cursor`.
Pages contain at most 50 active sessions, ordered by session ID using bytewise
`COLLATE "C"` in both the cursor predicate and ordering. The ordering is
independent of the database or column's default collation. Follow every
cursor to enumerate the inventory; the current session is reported separately
even if it is outside the current page. The inventory can change between pages.
Session IDs identify rows; they are not authentication capabilities.

`POST /api/auth/sessions/revoke` accepts exactly `account_id` and `session_id`.
It requires exactly one Origin equal to the configured public frontend origin.
A dashboard BFF must validate its browser Origin and CSRF token, then forward
that validated Origin deliberately. A successful committed deletion returns
`revoked: true` and `current_session_revoked`; revoking the current session also
clears its HttpOnly cookie. Foreign, absent, and expired targets return the same
404. Account mismatch returns 403 without deleting anything.

Both routes require exactly one session cookie, reject mixed bearer authority,
return no-store responses, have a five-second HTTP operation budget, and serialize
no token, digest, user agent or IP address. Revocation locks the account before
revalidating and locking the exact actor session, using wall-clock expiry after
lock waits, and deletes only rows owned by that account. Database or timeout
failures are errors, never best-effort success. Server-side statement and idle
transaction timeouts are capped at four seconds without increasing stricter
configured limits; HTTP cancellation alone is not treated as database cleanup.

Revocation denies subsequent cookie authentication. It does not claim to close
already-established streams, stop sandbox shells, revoke OAuth grants or revoke
API keys. These are distinct lifetimes and controls.

Focused proof is `cargo test -p codewire-idp --lib session_inventory` and the
seven synthetic PostgreSQL tests in `tests/session_inventory.rs`. The checked-in
service verification requires all seven tests and rejects missing-database skips.
The collation regression uses a test-owned copy of the migrated session table
with ICU collation and60 mixed-case/punctuation IDs across the50-row boundary;
public/migrated tables are unchanged. Its old query fails byte-order equality,
and the explicit C-collation query preserves both ordering and cursor progress.

## Sign in with GitHub or Google

The sign-in and sign-up pages ask the IdP's `GET /api/auth/oauth/providers`
which providers are configured, keep the answer for a minute, and show a
"Continue with …" link for each; when the IdP does not answer there are no
links and the password form works as before. The links are plain `GET`s to
`/api/auth/oauth/{github|google}/start` carrying the page's `authRequestID` or
`return_to`, so the pages' `form-action 'self'` policy is unchanged and
`cw login`'s device page, which sends a signed-out browser to `/login` with a
return target, resumes after a provider sign-in too. The rules are in
[AUTH-POLICY.md](AUTH-POLICY.md#sign-in-with-github-or-google).

Every browser step of the round trip is a top-level `GET` that began on the
provider's site, so each cookie the IdP sets on the way is HttpOnly,
`SameSite=Lax`, `Secure` on HTTPS and scoped to the one path that reads it:

| Cookie | Path | Life | Set when |
|---|---|---|---|
| `codewire_oauth_state` | `/api/auth/oauth/` | 10 minutes, cleared by the callback | Start |
| `codewire.session_token` | `/` | 8 hours | The callback signs an account in |
| `codewire_2fa_challenge` | `/two-factor` | 10 minutes | The account has a second factor: the dashboard's `/two-factor` page finishes the sign-in, as after a password |
| `codewire_oauth_signup` | `/signup/complete` | 30 minutes, cleared on completion | The email has no account |

A signed-in browser goes to `/setup-2fa` and then its return target, as after
a password. A failed or cancelled round trip goes to
`/login?oauth_error=<code>`, carrying the return target, and the page shows a
fixed message for the code.

`/signup/complete` reads the pending sign-up through
`POST /api/auth/oauth/signup/pending` (`token` in, `provider` and `email` out)
and submits it with the dashboard's CSRF and same-origin checks to
`POST /api/auth/oauth/signup/complete` (`token`, `reason`, `invite_code`,
`turnstile_token`). That answers 200 with a session cookie for an invited
account, 202 `accessPending` for one waiting for review, 400 for a missing
reason or failed challenge, 404 for a used or expired sign-up and 409 when the
email or identity now belongs to an account.

When an unlinked identity's email matches an account that must confirm the
link by email, the callback lands on
`/login?oauth_notice=link_sent&provider=<github|google>`, which says a link
was emailed, and sets `codewire_oauth_link_requester` (HttpOnly,
`SameSite=Lax`, scoped to `/login/link`, 30 minutes) on that browser. The
emailed link is `/login/link?token=…`. Opening it only moves the token into an
HttpOnly `SameSite=Lax` cookie `codewire_oauth_link` scoped to `/login/link`
for 30 minutes and shows a "Connect the GitHub account octocat" page read
through `POST /api/auth/oauth/link/pending` (`token` in, `provider` and
`account` out), so a mail scanner that fetches the link uses nothing up. Its
button is a CSRF-checked, same-origin `POST` that calls
`POST /api/auth/oauth/link/confirm` (`token`, and `requester` from the
browser's cookie): 200 when connected (no session cookie; the page says to
sign in with the provider), 412 from a browser without the matching requester
secret (nothing changes, the link stays usable, and the page says to open it
where the sign-in started), 404 for an expired, used or unknown link, 403 when
the account is disabled, locked out or no longer has that address, and 409
when the identity belongs to another account.

### Sign-in methods in Settings

The Account page's "Sign-in methods" card lists the password (set or not)
and each provider the IdP has configured, connected as its GitHub login or
Google email or not connected. Three cookie-only IdP routes serve it, with the
session controls' boundary: exactly one session cookie and no bearer, the
account the request names, an enabled account that is not locked out, and the
dashboard's two-factor boundary (an enrolled factor, or setup skipped by this
browser session). The two writes also need exactly one Origin equal to the
public frontend origin, which the dashboard forwards after its own Origin and
CSRF checks.

- `GET /api/auth/oauth/identities?account_id=` returns `account_id`, the
  configured `providers`, `password` and `identities` (`provider`, nullable
  `account`, `linked_at`). No column holds the provider account; it is read
  from the latest audit row that linked the identity, and an identity linked
  before that was recorded shows as connected without a name.
- `POST /api/auth/oauth/identities/link` (`account_id`, `provider`) writes a
  single-use `link` row bound to the account (one per account and provider; a
  new start replaces the old) and answers 200 with the provider's authorize
  `location` and the `codewire_oauth_state` cookie. The dashboard's Connect
  action, a CSRF-checked `POST`, forwards only that cookie and answers 303 to
  that location, which must be on `https://github.com` or
  `https://accounts.google.com`. Chromium applies a page's `form-action` to a
  POST's redirects, so the Account page, and no other, adds exactly those two
  origins to it. No `GET` starts a link, so another site cannot start one. It
  answers 404 for a provider that is not configured and 409 when the account
  already has one of that provider.
- The provider returns to the same callback as a sign-in. For a `link` row it
  links the identity only if this browser's session cookie still belongs to
  the row's account and that account is still enabled, not locked out and past
  the two-factor boundary, and only if the identity belongs to no one else.
  It creates no session, audits `user.oauth.linked` (`confirmed_by:
  "session"`), emails the account's address, and lands on
  `/settings/?sign_in_method=<code>&provider=<github|google>#sign-in-methods`,
  where the page shows a fixed message: `connected`, `cancelled`, `expired`,
  `unverified_email`, `unavailable`, `taken` (connected to another Codewire
  account), `already_connected`, `session_changed` or `failed`.
- `POST /api/auth/oauth/identities/unlink` (`account_id`, `provider`) removes
  the account's identity of that provider only when a password or an identity
  of another configured provider remains (409 otherwise; the card disables
  Disconnect and says "Add a password or connect another provider first."),
  audits `user.oauth.unlinked`, and emails the account's address. It answers
  404 when that provider is not connected. The account row stays locked to
  the commit, so two disconnects cannot each leave the other as the last way
  in.

The Account Access admin page lists each account's linked identities:
provider, account when known, subject and when it was linked.

Focused proof is `cargo test -p codewire-idp --lib oauth`, the twenty-five
PostgreSQL tests in `crates/codewire-idp/tests/oauth_sign_in.rs` against an
in-process fake of both providers and a recording mailer (the `idp-sessions`
service lane requires all twenty-five), the dashboard's `oauth_sign_in_tests`
and `sign_in_methods` tests, and the 0016 upgrade test in
`codewire-server-core`'s `migrate::` suite.

## Authenticator replacement and recovery codes

Three more cookie-only IdP routes change an enrolled factor. They share the
session controls' boundary: exactly one Origin equal to the public frontend
origin, exactly one session cookie and no `Authorization` header, an
`account_id` echo that must name the session's own account, closed JSON
bodies of at most 2 KiB, a five-second budget, bounded server-side
transactions and `no-store` responses. They are registered individually in
the permanent raw identity policy.

| Route | Request | Success |
|---|---|---|
| `POST /api/auth/two-factor/replace/start` | `account_id`, `password`, `proof` | `replacement_id`, `totp_uri`, `secret`, `expires_at` |
| `POST /api/auth/two-factor/replace/confirm` | `account_id`, `replacement_id`, `code` | `backup_codes` (10), `signed_out_sessions`, and a new session cookie |
| `POST /api/auth/two-factor/recovery-codes/regenerate` | `account_id`, `password`, `proof` | `backup_codes` (10) |

**Fresh proof.** `start` and `regenerate` share one check, which needs the
password **and** either a code from the enrolled authenticator or an unused
recovery code. The authenticator code must come from a later TOTP time step
than `two_factor.last_totp_step`; sign-in, enrollment and earlier proofs
record the steps they accept, so a code already used cannot be replayed. A
recovery code used as proof is consumed.

The check verifies the password hash before opening the transaction, then
works in this order:

1. Lock the account, then the session, then the factor row.
2. Refuse a locked account with 429 without checking or counting anything.
3. Re-read the password hash; it must still match the one verified.

Every wrong password or code counts against the lockout that sign-in uses and
returns one generic 422. The fifth failure locks the account for 15 minutes
and returns 429. A complete proof resets the counter.

**Replacement.** `start` stores an encrypted pending secret bound to this
browser session, replacing any older pending replacement for the account.
It expires after ten minutes. The secret is returned only in that response;
no route reads it again. The enrolled factor keeps working throughout.

`confirm` behaves as follows:

- Another session, an old `replacement_id` or no pending replacement gets the
  same 404.
- A wrong code returns 422 and counts against the replacement. The fifth wrong
  code ends it, and expiry also ends it, both with 410. Neither affects the
  account lockout.
- A matching code, in one transaction:
  1. swaps the secret and ten new recovery codes into `two_factor` in place;
  2. deletes the pending row and every unfinished sign-in challenge;
  3. deletes **every** session of the account;
  4. issues a new session for this browser.

`signed_out_sessions` counts the other browsers. The request budget covers
every check, but the commit runs outside it, so a late timeout cannot hide a
committed swap.

**Regeneration** replaces only the recovery codes; the authenticator and
sessions are unchanged. Direct `disable` stays closed.

**Audit and notices.** The IdP writes these audit events after commit, with
no secret, code, URI or password in them:

- `user.2fa.proof_failed`, with the operation, the reason and whether the
  account is locked;
- `user.2fa.replace_started`;
- `user.2fa.replaced`, with the number of browsers signed out;
- `user.2fa.recovery_codes_regenerated`.

A configured mail transport also sends a best-effort notice in the background
after a replacement or regeneration. The notice carries no code and only a
password-reset link.

API keys and OAuth grants survive a replacement. The factor encryption key is
still derived from the shared session secret. Both are known limits outside
this change.

Each audit event is written in the same transaction as its change, and the
commit and the notice run in their own task, so a client that disconnects
cannot cancel either one part-way. Sign-in issues its session in the same
transaction that consumes its challenge, while it holds the account lock. A
sign-in that completes during a replacement is therefore either revoked with
every other session, or finds its challenge already gone.

Focused proof is `cargo test -p codewire-idp --lib two_factor` and the eleven
synthetic PostgreSQL tests in `tests/two_factor_replacement.rs`. They cover:

- bearer, Origin and account rejection without side effects;
- the shared lockout, and replay of a sign-in code;
- recovery-code consumption, and pending-secret isolation;
- the old factor working while a replacement is pending;
- attempts, expiry and newer starts;
- the swap, with session revocation and cookie rotation;
- a sign-in completing during a replacement, which keeps no session;
- concurrent confirmations, and concurrent proofs with one code;
- audit hygiene.

The checked-in service verification requires all eleven tests and rejects
missing-database skips.

## Dashboard Account screen

`/settings/` contains account details, security, and paginated active sessions.
The legacy Security and Sessions URLs authenticate and validate selected
organization membership before redirecting to the matching Account section.
Personal navigation has only Account and Credentials, including organization
settings pages. Git commit attribution lives separately on Credentials; the
legacy Git identity POST uses the same mutation handler, not a POST redirect.

The dashboard session adapter has a six-second request budget, disables
redirects, and enforces a streamed64 KiB response limit. It accepts only closed,
account-bound metadata with at most50 rows per page and advancing keyset cursors.
It rejects bearer or duplicate-cookie authority before cookie normalization.
The native confirmation form carries expected account/session IDs and CSRF;
the BFF checks exact Origin, fresh identity, factor state and organization
membership before forwarding the canonical cookie and validated public Origin.
Only a validated committed acknowledgement yields success. Cookie clearing is
driven by the server's current-session acknowledgement, never a browser flag.
Unknown outcomes require refreshed inventory rather than an optimistic retry.

Account identity and sign-out remain available when session controls are
unavailable. A synthetic dashboard factor-setup exemption does not waive the
IdP's actual enabled-factor requirement. This screen promises neither password
reset delivery nor closure of established streams or Sandbox shells.

Focused UI proof includes dashboard library tests (closed DTOs, cumulative
stream bounds, redirect rejection, acknowledgement projection and signed-out
`get-session:null`), desktop/mobile native-dialog fixture tests, and the managed
`ssr-dashboard.account-sessions.ssr.ts` journey. The managed journey enumerates
53 synthetic sessions across pages, checks auth/CSRF/Origin/account/foreign
scope rejection, and proves other/current-session revocation separately.
Fixture request interception proves only presentation/submit shape; it does
not substitute for the real IdP/database journey.

### Security: replacing the authenticator

For an enrolled account, the Security card offers **Replace authenticator** and
**Regenerate recovery codes**. Each opens a focused dialog through a native GET
launcher (`/settings/?dialog=…`), which also works without scripting; scripting
opens the same dialog in place. Only these two proof dialogs open from a URL.
The proof fields are labelled and required, are never prefilled, and are
cleared when a dialog closes.

The three POST actions are:

- `/settings/_actions/two-factor/replace/start`
- `/settings/_actions/two-factor/replace/confirm`
- `/settings/_actions/two-factor/recovery-codes/regenerate`

Each takes a closed form with a 2 KiB limit. Each action:

1. requires one session cookie, no `Authorization` header, exactly one Origin
   and the page CSRF token;
2. requires fresh identity, an enrolled factor, and the form's `account_id`
   to match that identity;
3. reads every piece of page data before the IdP mutation, because a
   confirmed replacement revokes the session the request arrived with;
4. forwards the canonical cookie, the validated public Origin and the
   browser's own User-Agent (one value of at most 512 bytes) through the
   bounded, redirect-free account client, with a 10-second per-request
   timeout. That timeout is above the IdP's 5-second budget, so a slow commit
   is still reported; only a genuine timeout reads as an unknown outcome.

The browser's X-Forwarded-For is not forwarded. The IdP takes the first hop
of that header without a trusted-proxy list, and no other dashboard call to
the IdP forwards it, so relaying it would let a browser choose the address
the IdP records. Like dashboard sign-in, these audit rows and the rotated
session record no client address until a trusted-proxy rule exists.

The response is rendered directly as a private `no-store` page; no secret ever
appears in a redirect or URL:

- The setup key and QR code appear only in the `start` response.
- The new recovery codes appear only in the `confirm` or `regenerate`
  response.
- A rejected code reopens confirmation without the key.
- `confirm` forwards exactly one well-formed rotated session cookie. The
  page then withholds the session list it read before the change, since every
  one of those sessions is gone.

Error messages say what still works:

| Outcome | Dialog | Message |
|---|---|---|
| Wrong password or code | proof | "The password or code didn't match. Nothing changed: …" |
| Account locked | proof | "Too many incorrect attempts. Wait 15 minutes, then try again. Your current authenticator and recovery codes still work." |
| New code rejected | confirm | "That code doesn't match the new authenticator. … Your current authenticator still works." |
| Five wrong codes or ten minutes | replace | "This replacement ended after five incorrect codes or ten minutes. Start again. …" |
| Superseded or foreign replacement | replace | "This replacement is no longer available … Start again. …" |
| IdP without these routes or unreachable before a change | proof | "… unavailable right now. Nothing changed: …" |
| Lost confirmation or regeneration response | Security card or regenerate | Says the outcome is unknown and how to recover |

An account mismatch redirects to `/settings/?security=account-changed#security`
with no change.

Focused proof includes:

- adapter tests for closed results, rotated-cookie admission, redirect refusal
  and the failure mapping;
- registered-route tests against a synthetic identity service, proving
  read-before-mutation, exact Origin, CSRF, account, bearer and unknown-field
  rejection, and that no password or proof is echoed;
- template tests;
- the editable fixtures `settings-account.html`,
  `settings-account-replace-authenticator.html` and
  `settings-account-authenticator-replaced.html`, with their desktop, mobile
  and no-JavaScript specs in `ssr-dashboard.account-dialogs.ssr.ts`.

The managed journey `ssr-dashboard.account-two-factor.ssr.ts` enrolls a
synthetic owner, then on the real IdP, dashboard and database:

1. proves a wrong proof says what still works and counts one failure;
2. regenerates codes with a recovery code;
3. replaces the authenticator, rejecting a wrong new code first;
4. proves both old cookies are refused, the rotated cookie opens Account with
   one session, and sign-in accepts only the new authenticator and its codes.

Account management goldens use an isolated synthetic owner with exactly two
sessions, fixed creation/expiry dates, and the byte-lowest session as the current
browser. The owner joins the selected organization only after its Members
visual test. Screenshots mask only per-run public session IDs and the unique
test email; metadata, row ordering, native actions and organization context
remain real assertions. The Git attribution journey restores its original
values in `finally` through the retained legacy POST and verifies that the
Credentials feedback preserves the selected organization.
