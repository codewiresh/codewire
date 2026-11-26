# Authentication policy

This is Codewire's canonical authentication policy. Product and client code
should link here instead of restating or extending the credential model.

Codewire issues four authentication credential flavors: three user-facing and
one platform-internal. Kubernetes supplies the separate Pod-bound identity a
workspace daemon uses to fetch its binding.

| # | Flavor | Presenter | Acquisition and boundary |
|---|---|---|---|
| 1 | Session cookie | Browsers | The IDP login page issues the HttpOnly, SameSite session cookie. Browsers use it for same-origin product calls and identity pages. |
| 2 | OAuth user bearer | Native apps | PKCE authorization code where a system browser exists; OAuth device grant where none does. Both yield the same opaque access/refresh token species and use one `TokenProvider`. Product access requires exact `codewire.api`. |
| 3 | `cw_` API key | Machines, SDKs, CI, and agents | `ApiKeyService` creates a revocable key bound to exactly one organization. It is not a user token or an OAuth client-credentials grant. |
| 4 | HMAC sidecar token | Coordinator and daemon service hops | The control plane mints a scope-bound service credential for the internal hot path. It never becomes a user credential. |

## Credential rules

- Passwords, 2FA, and passkeys belong only to the browser-owned IDP login
  page. Native apps and the CLI never accept or store a Codewire password.
- Session cookies are browser credentials. A session token in
  `Authorization: Bearer` is invalid and must not be reinterpreted as another
  flavor.
- Every IdP response under `/api/` depends on the caller's cookie or
  `Authorization` header, so it carries `Cache-Control: no-store, private`
  and no `ETag` or `Last-Modified`: no shared cache may store one caller's
  answer for another. This covers `/api/auth/*` (including
  `get-session`), `/api/admin/*`, and every `/api/oauth/*` and
  `/api/oidc/*` response: redirects that carry a code
  (`GET /api/oauth/authorize`, `GET /api/oidc/callback`),
  `GET /api/oauth/userinfo` (the bearer's claims at a fixed URL), and
  every error. Public, caller-independent documents (`/.well-known/*`, including
  the JWKS) keep their own caching. The edge also bypasses its cache for
  these paths; the origin rule holds without it (P0 found by cw-selfhost,
  2026-11-16: the edge cache served one caller's `/api/auth/get-session`
  to others; edge fix by cw-security; routes on #5054).
- Native OAuth credentials are opaque and authoritative in the IDP token
  store. `TokenProvider` supplies the current access token; a
  `CredentialStore` persists the access/refresh pair atomically and saves a
  refreshed pair as one unit.
- Mesh's Connect API and orchestration's raw browser routes answer every
  request with `Cache-Control: no-store, private` and no `ETag` or
  `Last-Modified`, errors included, so no shared cache stores one caller's
  answer for another. For Mesh this is every method, including the
  idempotent GETs, which are mounted without the auth layer that adds
  `private`. For orchestration it is
  `GET /api/v1/organizations/{org}/environments/{env}/ssh-proxy/check`, the
  terminal and SSH-proxy upgrades, and the preview authorization page
  (#5054).
- The shared Connect auth layer (`ConnectAuthLayer`,
  `crates/codewire-server-core/src/connect.rs`) answers every request it
  handles with `Cache-Control: no-store, private`, whatever the method or
  outcome: authenticated calls, public and anonymous-allowed methods, and
  its own 401, 403 and 504 rejections. A handler's `no-store` directive is
  kept; any other directive it sets, such as `public` or `max-age`, is
  replaced, and the edge-only directives that CDNs obey over
  `Cache-Control` (`Cloudflare-CDN-Cache-Control`, `CDN-Cache-Control`,
  `Surrogate-Control`) are removed. A cache decides by the response, not by intent, so storing is
  never the default (cw-security ruling, 2026-11-18, #5054). The public and
  anonymous-allowed methods today are `GetInvitationByToken` (keyed by a
  secret token; it returns the invitee's address), `SubmitFeedback`
  (varies by caller when one signs in), `GetSignupCredit` and
  `GetPublicRates` (both the same for every caller). None is cached. A
  method whose answer is the same for every caller may be cached only
  through an explicit per-method allowlist in the
  layer, added in a reviewed change that names its directive and tests that
  the response does not depend on credentials.
- An OAuth credential without exact `codewire.api` may use the identity
  endpoints its scopes permit, but product calls fail with REST `403` /
  Connect `permission_denied`.
- An OIDC authorization request with `prompt=login`, or with a `max_age`
  shorter than the age of the browser session's sign-in, gets a code only
  after a fresh sign-in (OIDC Core, "Authentication Request"). The provider
  sends the user to sign in and keeps both values on the stored request
  through that round trip, so the resumed request accepts only a session
  signed in to after it (or within `max_age`), never an older one presented
  at the callback (pentest#13 T14, #4785).
- A `cw_` API key is authorized only inside its one bound organization. It
  cannot inherit its owner's global-admin authority or perform account-global
  operations. Creating an organization is one: `CreateOrganization` refuses
  an API key with `permission_denied`, "organizations are made from a
  sign-in", before anything is written. A key's scope never grows to cover
  what it would create, and each new organization brings its own sign-up
  credit (#5863).
- HMAC sidecar tokens stay inside their platform trust domain. They are not a
  fallback for session, OAuth, or API-key authentication.
- Invitation and enrollment codes are one-use capabilities, not
  authentication flavors. Redeeming one may create or bind a resource, but it
  must not mint a new steady-state bearer. In particular, Mesh enrollment
  returns non-secret node/enrollment metadata; persistent node bearers,
  `cwrt1` runtime credentials, verifier bundles, and sender-delegation
  credentials are not approved flavors.
- A Mesh peer coordinate stream starts only by consuming its fixed-name,
  one-use enrollment capability. It never falls back to a persistent node or
  environment bearer. A hosted environment's capability (`cw_eenr_`) is
  issued by orchestration to the environment's live bound Pod. It is valid
  for 60 seconds and redeemed by Mesh through orchestration's
  `EnvironmentMeshService`, which consumes it only while that Pod and its
  operation generation are still the live binding. Mesh rechecks those
  members at least every 60 seconds.
- A trusted service hop may transport the caller's existing credential for a
  canonical authorization decision without creating a new flavor. The WS18
  Mesh boundary authenticates the hop with flavor 4, carries exactly one
  flavor-1/2/3 credential in reserved sensitive binary Connect metadata,
  removes it before handler dispatch, and exposes only a typed authorization
  context. Credential values never belong in protobuf fields, logs, traces,
  metrics, errors, retries, persistence, or response metadata.

## Sign-in with GitHub or Google

GitHub and Google are ways to prove who signs in to the browser login page,
not credential flavors: a successful provider sign-in ends in the same
session cookie (flavor 1) as a password, and Codewire keeps no provider access,
refresh or ID token. The IdP is the OAuth client and owns the whole round
trip; the configuration is in [../CONFIGURATION.md](../CONFIGURATION.md).

- A provider identity is an `accounts` row with `provider_id` `github` or
  `google` and the provider's stable subject (GitHub's numeric user id,
  Google's `sub`) as `account_id`. A unique index gives each identity one
  owner.
- Each round trip has a random `state`, which the provider returns, and lives
  10 minutes in an HttpOnly `SameSite=Lax` cookie, `codewire_oauth_state`,
  scoped to `/api/auth/oauth/`. The code is exchanged server-side with the
  PKCE (S256) verifier.
- **A sign-in start writes nothing** (#4166). It is an unauthenticated `GET`,
  so a row per start would let any client grow the table, and a global cap
  would let one client refuse everyone. cw-security agreed this design on
  2026-11-15: "A start that writes nothing removes the table growth without
  the lock-everyone-out risk of a global cap. [...] Login CSRF stays closed,
  because a callback without this browser's sealed cookie is refused."
  - The start checks the return target against the allowed targets (an OIDC
    auth request id, or a same-origin path), then seals the SHA-256 of the
    state, the verifier, Google's nonce, the return target and an expiry 10
    minutes ahead into the cookie. A second start, in another tab, replaces
    the cookie, so the first tab's callback is refused and `/login` says the
    attempt expired or was started elsewhere: start again.
  - The cookie is sealed with AES-256-GCM under a key derived by HKDF-SHA256
    from the IdP's session secret with the label `codewire-idp-oauth-state-v1`,
    which keys nothing else; the session secret never keys it directly. Each
    seal starts with a version byte and has its own random 96-bit nonce, and
    the associated data binds the label, the version and the provider.
    Rotating the session secret therefore ends every sign-in in flight, which
    costs at most 10 minutes of restarted sign-ins.
  - The callback opens the cookie first. Before any exchange with the
    provider it refuses a missing cookie, one that fails authentication
    (changed, sealed under another key, or sealed for the other provider), an
    unknown version, an expired one, and a `state` whose SHA-256 is not the
    sealed one. It checks the sealed return target against the allowed
    targets again, since sealing proves only that the IdP wrote it. Google's
    ID token `nonce` must equal the sealed one. Every outcome clears the
    cookie.
  - Only after the provider accepts the code does the callback write one
    `sign_in` row, keyed by the state's SHA-256 and living 10 minutes, and a
    callback that finds that row already written is refused as a replay. The
    provider accepts a code once, so this marker is defence in depth; written
    after the exchange, only a real round trip can add one (cw-security: "a
    valid cookie costs nothing: one unauthenticated start mints it").
  - A sign-in started on the release before this one holds a raw state, not a
    sealed one, so its callback is refused once, at that deploy; the person
    starts again.
- A link from Settings keeps a row: its signed-in, CSRF-checked start writes a
  single-use `link` row holding the SHA-256 of the state, the verifier and a
  Google nonce, and the cookie holds the raw state. The callback tells the two
  apart by the cookie's form, requires the `state` parameter to equal a raw
  cookie, deletes the `link` row in the statement that reads it and refuses a
  row that is expired or for another provider.
- The IdP deletes expired `oauth_states` rows every 5 minutes, in bounded
  batches, whatever the traffic.
- Only a verified email counts: GitHub's primary email marked `verified`, or
  Google's ID token with `email_verified`. The ID token comes straight from
  Google's token endpoint over TLS, and its `iss`, `aud`, `exp` and `nonce`
  are checked.
- An identity already linked signs in to its account with the gates password
  sign-in applies after the password: lockout, then `enabled`, then the
  account's second factor when enrolled. A provider sign-in never skips
  Codewire two-factor authentication.
- An unlinked identity whose email belongs to an account that verified that
  email (matched without regard to case) is linked to it only in two ways
  (owner, 2026-11-11, #4062), and never before the account's second factor
  could be asked:
  - **At once**, only when Google vouches for the whole address (a
    `@gmail.com` address, or its domain is the ID token's `hd`, the Google
    Workspace domain that manages the account) and the account has no second
    factor. The link is audited (`user.oauth.linked`, `confirmed_by:
    "provider"`), the account's address is told, and the sign-in continues as
    a linked one.
  - **From the account's own email** in every other case: every GitHub
    match, Google without a vouched domain, and any account with a second
    factor. Nothing is linked and no session is made; the account's address
    gets a single-use link valid for 30 minutes (stored only as a hash, one per
    account and provider, a new one replacing the old) naming the provider
    account (GitHub login or Google email), and `/login` says so. The browser
    that started the sign-in also gets a second random secret in an HttpOnly
    cookie for `/login/link`, stored only as a hash. The emailed link proves
    only that someone reads the account's mail, so it completes only in that
    browser: from any other, nothing changes and the link stays usable. This
    keeps a stranger whose provider account carries a stale copy of the
    address from having the owner click the stranger's identity in. Opening
    the link changes nothing; confirming it on that page links the identity
    if the account is still enabled, not locked out, still has that address
    and the identity belongs to no one else, audits it (`confirmed_by:
    "email"`) and tells the account's address, but signs no one in. The
    person then signs in with the provider through every gate.
  A disabled or locked-out account is refused as its sign-in would be, and
  nothing is linked or sent.
- An unlinked identity whose email belongs to an account that never verified
  it is refused, so whoever registered the address first cannot take over the
  account. The person signs in to that account and links the provider from
  Settings.
- An email with no account becomes a sign-up: the same access-request reason,
  invite policy and Turnstile as email sign-up, on the dashboard's
  `/signup/complete` page. The account starts with `email_verified` true and no
  password; `enabled` follows the invite policy.
- Every refusal lands on `/login` with a fixed code the dashboard turns into a
  fixed message; provider error text is never shown.
- A signed-in account links and unlinks a provider from Settings
  ([BROWSER-ACCOUNT-SESSIONS.md](BROWSER-ACCOUNT-SESSIONS.md#sign-in-methods-in-settings)).
  Only a session past the two-factor boundary starts a link, with a
  CSRF-checked `POST` and never a `GET`; the callback links only while the
  browser's session still belongs to that account, which must still be enabled
  and not locked out, and only an identity that belongs to no one else. The
  emails need not match, since the person proved both. An unlink needs a
  password or another configured provider to remain. Both are audited
  (`user.oauth.linked`, `user.oauth.unlinked`) and the account's address is
  told.
- An account with no password asked to reset one gets no reset link: the
  email says how it signs in and that it can add a password in Settings once
  signed in (#4528). A reset link proves only that someone reads the mailbox,
  so it never adds a password.
- A signed-in account with no password may add one from Settings
  (`POST /api/auth/password/add`, owner 2026-11-13 on #4528), under the
  account controls' boundary (session cookie only, exact Origin, an
  `account_id` echo). Its address must be verified, the browser session must
  have signed in within the last 10 minutes (else `reauthentication_required`),
  and an account with a second factor gives a fresh authenticator code or an
  unused recovery code, whose failures count toward the lockout. The password
  row and its audit (`user.password.added`, with the proof) commit together;
  sessions stay, and the account's address is told. Changing an existing
  password stays the reset flow.

## Sign-up by invitation link

On every server, a sign-up that presents an organization invitation's link
token in `invitation_token` is admitted at exactly the invited address, at
once and without Turnstile (owner, 2026-11-13, #4121).
`auth_session/sign_up_invitation.rs`
reads the invitation in the sign-up's transaction, `FOR SHARE`. It must be
pending, unexpired and addressed to the sign-up's address, compared with
`lower()`. Anything else gets one answer, `403 invitation_invalid` ("This
invitation is no longer valid. Ask for a new one."), or `403 invite_only` on
an invite-only server. Only a token that names a live invitation for the
address skips Turnstile, so on a server with Turnstile's keys any other token
fails the challenge first: `400 human_verification_failed`, the code every
failed challenge carries.

The dashboard's sign-up from an invitation asks for no reason, invite code or
challenge, on every server (#5908). It shows `invitation_invalid`, and
`human_verification_failed` on a form that carries a token, as "This
invitation is no longer valid. Ask for a new one."; every other refusal keeps
its own words.

The link carries one of two tokens:

- **The CreateInvitation token**, the one-time link an admin copies. Only
  its SHA-256 is stored, in `org_invitations.token_hash`.
- **The invitation email's token** (`invitation_link`, #3840). The
  invitation sender mints it when it sends the email
  (`invitation_link::mint_invitation_link`). Only its purpose-bound hash is
  stored, in `verifications` with the invitation id as its identifier.
  - There is one live token per invitation: a new email replaces it, so an
    older forwarded email stops working. It expires with the invitation, and
    migration 0036's trigger deletes it when the invitation is accepted,
    revoked, expired or deleted.
  - The invitation page resolves it again after the sign-up, so the sign-up
    does not consume it.
  - It admits one account: once that account exists, a second sign-up at the
    address is refused as taken.

Neither token accepts the invitation, signs anyone in or links a provider.
With mail the new account is unverified until its owner opens the
verification email. Accepting still needs a signed-in session whose verified
address matches, and provider auto-linking still needs a verified address.

## Invite-only sign-up

Email sign-up is one path for every `IDP_SIGNUP` mode
([../CONFIGURATION.md](../CONFIGURATION.md#sign-up));
`auth_session/email_sign_up.rs` decides admission from the mode. With
`IDP_SIGNUP=invite-only` (#4121), the self-hosted mode:

- **Admission.** Nothing is taken before setup has made the admin. A sign-up
  presents an organization invitation's link token. The invitation is read in the sign-up's own
  transaction, `FOR SHARE`: it must be pending and unexpired, addressed to
  the sign-up's address (compared with `lower()`), and, on a server with no
  mail, issued within the last 24 hours. No account may exist at the address
  in any case; that person signs in. A missing, wrong, used, revoked or
  expired link and one for another address all get the same `403
  invite_only`. Sign-up only reads the invitation; accepting it is still
  AcceptInvitation's. The audit names the invitation id, never its token.
- **The admin** is made by setup, `codewire-idp create-admin`, with the
  password on stdin; an advisory lock lets only one run make it, and a second
  run changes nothing.
- **Vouching, on a server with no mail.** Nothing can prove who owns an
  address, so the admin's approval stands in for proof, by the owner's rule:
  the admin issued the invite link, setup created the admin, or the admin
  enabled a waiting account. The account records it in `email_vouched_by`
  (`invitation`, `bootstrap` or `admin`) and keeps `email_verified` false, so
  every check that needs a verified address, such as provider auto-linking
  and ListMyInvitations, still refuses it. A database check keeps the two
  apart: a mailbox verification, the proof #4481 settled on, replaces the
  vouch. So a server that adds mail later asks its vouched accounts, the
  setup admin included, to verify their addresses, and they sign in again
  once they have.
- **Sign-in** needs a verified or vouched address. A waiting account is told
  it is disabled, not asked to verify an email that cannot be sent.
- **Sending an invitation** needs the same proof as sign-in, a verified or
  vouched address (#4805).
- **Provider sign-up** is refused (`oauth_error=invite_only`). A provider is
  connected from Settings after signing up.
- **The admin's account list** shows each address's vouch and, for a sign-up
  through an invitation, the invitation, its organization, the inviter and the
  time, so an admin who gave a link to the wrong person can disable the
  account there.

## Accounts waiting for access

Every email sign-up verifies its address before it signs in, invite code or
not (owner, 2026-11-13, #4481). A password proves only who chose it, so the
sign-up starts no session; it answers `202` with `verificationPending` and
emails a 24-hour link. A valid invite code only enables the account, so it
signs in once verified; without one, the sign-up is an access request.

An access request is a disabled account. Sign-in checks the password before
access, so only the right password learns why it was refused: `403
email_unverified` while the email is unverified, whether or not the account is
enabled, otherwise `403 account_disabled`. The dashboard shows "You're on the
list" for the second.

With `email_unverified` the IdP returns `resendToken`, a 10-minute,
single-use token bound to the user id and stored hashed as a
`resend_verification` verification. The dashboard puts it only in the hidden
field of a "Resend verification email" button on the sign-in notice, never in
a URL. `POST /api/auth/resend-verification` claims the token and sends a new
24-hour verification link, at most one per address every five minutes, and
writes `user.verification.resent` to the audit log. Nobody can ask for a link
by typing an email address.

## An address SES won't deliver to

SES keeps an account-level suppression list, on for bounces and complaints on
Codewire's servers: once an address hard-bounces or its owner marks our mail as
spam, SES drops every later send to it. The IdP asks that list about an
address before it would send nothing useful, and tells the person and the
admin (#4548).

- **When it asks.** Only about an address the IdP already holds for its own
  account, never one a request names:
  - before **Resend verification email** on the sign-in page sends, about
    the account that resend token belongs to;
  - before an admin's **Resend verification email** sends, about that
    account;
  - for the accounts Admin → Manage account access lists, four at a time,
    within one 3-second budget for the page.
- **What it hears.** `ses:GetSuppressedDestination` for that one address. The
  answer is suppressed for a bounce, suppressed for a complaint, not
  suppressed (SES answers 404), or unknown: any other answer, a throttled one
  (SES publishes no request rate for this call; 429 is unknown), no answer in 3
  seconds, or a server without SES. Unknown never blocks a send or sign-in and
  is never shown as a mark. Nothing else from SES's record is read out: no
  time, feedback id or message.
- **What the person sees.** A suppressed resend sends nothing, and the sign-in
  page says "Email to that address can't be delivered. Check it, or sign up
  with a different address." It is the same for a bounce and a complaint: the
  fix is the same, and it doesn't tell anyone their complaint is on record. A
  skipped resend isn't counted against the address's three verification emails
  an hour.
- **What the admin sees.** In the Email column, **Bounced** or **Marked as
  spam** beside Verified or Unverified. The admin's own Resend says "Email to
  that address bounced." or "Email to that address was marked as spam." and
  sends nothing. Clearing a suppression stays in SES; Codewire doesn't remove
  one.
- **What a stranger learns.** Anyone can sign up with an address and press
  Resend to learn that it can't be delivered to. That is accepted: it is
  only "can't be delivered", what the sign-up's own verification email
  bouncing would show, never why or when.
- **What is recorded.** `codewire_idp_mail_suppressed_total{reason}`, with
  `bounce` or `complaint`, counts each skip. No log line or metric names the
  address.
- **Not covered:**
  - Password reset. It is asked for anonymously, so it must answer the same
    for every address. When its sends check the list later, a skip stays
    silent: no message, only the count.
  - Organization invitations.
  - Changing an unverified account's address: the person signs up again
    with the right one.
  - Being told the moment SES records a bounce (SNS events).

## The operator's sign-up notice

A server with mail can tell its operator about each new person
(`crates/codewire-idp/src/operator_notice.rs`), so an access request in
review mode never waits unannounced (owner, 2026-11-18, #5358:
"Yes, I would like an email notice."). `CODEWIRE_OPERATOR_EMAIL` names one
address. Unset or empty, the default for a self-hosted server, sends nothing.
A value that isn't one email address stops the IdP at startup, as
`CODEWIRE_SUPPORT_EMAIL` does for the dashboard.

- **When.** Once per person, at the moment the account first becomes real:
  - an email sign-up, when its address is verified for the first time. In
    review mode with no code, that is an access request waiting for review;
    otherwise the account can now sign in. Before verification nothing is
    sent, so an address nobody owns, which the purge deletes after 7 days,
    never reaches the operator.
  - a GitHub or Google sign-up, when the account is created (the provider
    verified the address): an access request in review mode, otherwise a
    sign-up that has signed in.

  Nothing is sent for an account setup or an admin creates, a vouched
  account that verifies later (#4121), a second verification of an address
  already verified, or an admin enabling an account.
- **What.** The subject is "Codewire: access request from <address>" or
  "Codewire: new sign-up, <address>". The body gives the address, how the
  person signed up (email, GitHub or Google), the time in UTC, whether they
  wait for review, and a link to Admin → Manage account access
  (`<frontend>/admin/accounts/`). Nothing else: not the reason, the name or
  the client address, which the person wrote or the operator doesn't need
  in an inbox, and no token of any kind. The address is escaped in the HTML
  body, and a subject is cut at its first control character.
- **How many.** The notices share one site-wide limit, `operator_notice`,
  10 an hour, counted in the shared `rate_limit` table like the sign-up
  limits, so every IdP replica counts against the same 10. The 11th in an
  hour sends one notice instead, "Codewire: more people are waiting". It gives
  the number of accounts waiting for review at that moment, when notices
  start again, and the same link. Past the 11th, nothing is sent until the
  hour ends. No setting changes the count: it bounds an inbox, not a person,
  so it isn't among the limits an admin sets.
- **Never in the way.** The notice is sent after the sign-up or the
  verification has committed and its response is decided, in its own task.
  A failed send, a full limit or a database error is logged and changes
  nothing for the person signing up.

## Account deletion by an admin or the purge

An account is deleted only through the account deletion that Settings
starts (`server-core/src/account_deletion.rs`), whoever asks (#4541):

- **The purge of unverified sign-ups.** An email and password sign-up still
  unverified 7 days after it was created is deleted (owner, 2026-11-13,
  #4541), which frees its address. The orchestration leader runs it at most
  once an hour, up to 100 accounts a run. `UNVERIFIED_SIGNUP_PURGE` is
  `off`, `report` (the default: every check runs and nothing changes) or
  `enforce`. Only a server with mail sets `enforce`: without mail no account
  can verify, so an unverified account there is an access request waiting
  for the admin, not an abandoned sign-up, and the self-hosted setup leaves
  the purge in `report`. `UNVERIFIED_SIGNUP_LIFETIME_SECS` shortens the 7 days, never
  below an hour, and is for proving the purge on Dev. It never deletes an
  admin, an account whose address an admin vouched for on a server with no
  mail (`email_vouched_by`, #4121), or an account that holds anything: an organization membership, a
  sandbox it created, an API key, a user secret, or a GitHub or Google
  sign-in. It keeps such an account and logs why. Each condition is checked
  again in the deletion transaction with the account's row locked, so an
  address verified meanwhile keeps its account. No mail is sent.
- **An admin.** `POST /api/admin/accounts/{user_id}/delete` takes the
  account's address and the admin's password with a fresh second factor:
  the same check as replacing an authenticator. The proof locks the admin's
  row, then the deletion locks the account's, and in that transaction the
  actor must still be an admin and the account must not be one. An admin
  deletes their own account from Settings, and demotes another admin before
  deleting them. Each admin may ask for 10 deletions an hour, a count no
  setting raises. The operation records the admin as its actor, and the
  "account deleted" mail goes only to a verified address. Before confirming,
  the admin reads `GET /api/admin/accounts/{user_id}/deletion-plan`: the
  account's personal organizations and their sandboxes, the memberships that
  end, the organizations in the way and whether a deletion already runs.
  Admin → Manage account access offers "Delete account" on every row except
  the admin's own and other admins'.

## Account access revocation

`users.enabled = false` is a security revocation boundary. The disabling
transaction deletes Codewire-issued browser sessions, authorization codes,
opaque OAuth access and refresh tokens, bound device approvals, and pending
2FA challenges. It retires API keys by setting `disabled_at` and clamping their
expiry; their rows remain only as disabled, expired records. Six targeted
`user_id` indexes keep those revocation predicates bounded to the affected
account. Database guards also reject issuance for a disabled subject from a
predecessor-shaped writer during a rolling deployment. A predecessor ownership
transition that already holds its capability row fails promptly while a
disablement holds the account row, rather than allowing a lock cycle to choose
the winner.
Re-enabling an account requires fresh authentication and cannot revive any of
those prior bearer capabilities. An older service binary cannot start against
the version-24 SQLx ledger; its supported rollback boundary is the disposable
application-schema rebuild documented in `DATABASE-MIGRATIONS.md`.

A password reset proves only that someone reads the account's mail, and may be
the address's owner taking the account back from whoever chose the old password
(#4481). The transaction that replaces the password also deletes what signing
in with the old one minted: browser sessions, pending 2FA challenges, and OAuth
authorization requests, access and refresh tokens and device authorizations.
A device sign-in that the old password's session approved pays out nothing
after the reset. API keys stay: a key ends when it is disabled, deleted or
expires, or when its account is disabled, never through a reset (owner,
2026-11-13, #4481). A sign-in that verified the old password
just before the reset committed gets nothing either: it issues its session or
second-factor challenge only while the account's credential row, locked
`FOR SHARE`, still holds the hash it verified.

The boundary does not erase account identity factors or user-owned
configuration. A pending device request with no user bound to it has no subject
to revoke; it can only be approved after a newly authenticated enabled account
action. A previously bound approval is deleted on disablement.

An ID token is a signed, self-contained assertion. Built-in public clients
issue one-hour ID tokens, and a third party that validates one offline cannot be
notified retroactively of an account disable. Codewire product APIs do not
accept ID tokens as user credentials; they validate the revocable opaque access
token store. Relying parties that need live account status must use token
introspection instead of offline ID-token validation.

Disablement is checked when Codewire authenticates a new request or begins a
new stream. A stream already admitted ends when the authority that admitted it
is lost (#3586). An exec, file, attach or log-follow stream, and the
dashboard's terminal, the SSH proxy's WebSocket or the desktop viewer's, ends
in seven cases:

- its user is disabled, which covers suspension and account deletion;
- the browser session that admitted it is deleted before it expired: a
  sign-out, signing out one session, a password reset or a 2FA replacement;
- the OAuth access token that admitted it is deleted before it expired, by
  revocation or a password reset, or refresh-token reuse revokes its grant
  (the user and the client). Revoking any token of a sign-in deletes them
  all: each access and refresh token carries the sign-in it came from, from
  the `cw login` (or other code or device exchange) through every refresh, so
  revoking one ends the sign-in, as `cw logout` means (#5688). A token issued
  before tokens carried their sign-in ends alone, and its next refresh starts
  one;
- the API key that admitted it is disabled or deleted;
- the user token that admitted it is deleted, by any of the ways that end
  one, or the `cw` client's grant is revoked for its user (#5688);
- its user leaves, or is removed from, the organization its environment
  belongs to: the `membership` kind;
- that organization's deletion starts: the `organization` kind, which ends
  every member's streams into it at once.

Such a stream ends within seconds normally, and within 30 seconds at most.
Expiry never ends a stream (#3827): one whose credential expired runs on until
one of the seven cases applies to its user, grant, key, token or organization. A sign-out ends only
the streams its own session admitted, so another machine's stream keeps
running.

An organization whose deletion has started, or has failed, admits no new
stream or connection into its environments (#3586). The refusal comes after
the caller's own access check, which answers as it does today, so only a
caller who would otherwise be admitted learns why: they are told the
organization is being deleted. A failed deletion refuses the same way, with
the same words, until it is retried to the end. Every way into an
environment, and whether it is refused:
- **Refused:** exec, file, attach and log-follow streams; the dashboard's
  terminal; the SSH proxy; the tailnet client session; the port proxy and
  the preview of a port shared with the organization; and the operations
  that reach a running Sandbox through its daemon (a repair, a runtime
  update).
- **Also refused:** every request to a public port's preview, from anyone,
  since it has no caller to check: it gets the preview's unavailable page;
  a new Mesh Dial into the organization's networks; and the desktop
  viewer's WebSocket.

A stream already open into the organization ends when its deletion starts,
through the `organization` kind above. A tailnet client session also ends at
the coordinator's next re-check, within 60 seconds, as before. **Not yet:** a
Mesh Dial session already open, which ends with the Mesh relay step
(`private-docs: designs/stream-revocation.md`, "Mesh sessions"); and a
request already being proxied to a public port, such as a WebSocket opened
through a public preview, which has no caller to end and runs until the
deletion stops its environment.

A member's per-environment grants (`cw share grant`) end with their
membership. Leaving, being removed and deleting the account each delete the
member's grants on that organization's environments, in the transaction that
deletes the membership. One `environment.access.removed_with_membership`
audit row, by whoever ended the membership, names those environments by id.
A member invited back starts with their role's defaults only, and an owner who
wants a grant back makes it again. A grant can mean terminal access, which
reaches the creator's delivered sign-ins, so a stale one must not wait for a
re-invite (#3586).

Some changes to access end no open stream yet; each is checked again at the
next admission:
- a lowered role in the organization, such as an admin made a member;
- a removed per-environment grant, a direct loss of access, which is the next
  kind, `grant`.

An environment moved to another organization is not built: no Sandbox changes
owner. If it is ever built, it comes to cw-security first.

The database records each loss in `credential_revocations`:
- **Writers:** only database code. Triggers on `users`, `sessions`,
  `oidc_access_tokens` and `api_keys` write it, and the refresh-token reuse
  path calls `codewire_revoke_oauth_grant` inside its own transaction. A
  trigger on deleting an `org_members` row writes the `membership` kind
  (the user and the organization), whatever removed it: a removal, leaving,
  an account deletion or the end of an organization's deletion. A trigger on
  `organizations` writes one `organization` row, naming only the
  organization, when its `deletion_state` becomes `deleting`; that one row
  matches every member's streams into it. A
  repository policy check refuses service code that inserts, updates or
  deletes log rows. A new way of ending a credential adds its trigger, or
  calls the log's function, in the same change.
- **Contents:** a row holds ids and token hashes, never a credential. The
  organization has its own column; a check on the table says which columns
  each kind sets. The existing columns stay required, so both organization
  kinds repeat the organization as the credential, and an `organization`
  row names no user. The writing function removes rows older than an
  hour.
- **Threat:** a forged row can only end streams, never grant access. Whoever
  holds the services' database role can already delete sessions or disable
  users, so the check guards against a bug in service code, not against
  that role. The services run as the database owner (#5166).
- **Delivery:** each row wakes every service process. Each process also reads
  the log by its sequence every 30 seconds, so a missed wake-up costs at most
  that.
- **Admission:** a stream registers first, then re-reads the same check that
  admitted it, so a revocation and a new admission can't race. A stream into
  an organization's environment registers under that organization too, and
  its re-read, on the primary, also checks again that its user is a member
  and that the organization admits streams, so a removal or a deletion
  between admission and registration refuses it. A carried admission (a
  tailnet session moving between replicas) carries the organization as
  well. A revocation
  committed before the re-read refuses the stream, and one after it ends the
  stream. A row the re-read already saw never ends the stream, so an account
  disabled and enabled again, or signed in again after a revoked grant, opens
  streams at once. A re-read that fails refuses the stream with
  `unavailable`.

A revoked Connect stream ends with `permission_denied`, "access revoked". A
WebSocket closes with code 1008, "access revoked", or with 1008, "membership
ended", when the `membership` kind ended it: signing in again can't restore a
membership, so the dashboard's terminal says its user is no longer a member
instead of asking them to sign in (#6407). A stream the `organization`
kind ends says why as a new stream's refusal does: a Connect stream ends with
the same error, "organization is being deleted", and a WebSocket closes with
1008 and that reason, so the dashboard's terminal shows its organization line
(#5677) rather than the revoked one. Each writes a
`stream.revoked` audit event naming the user, the kind of loss, the surface
and the environment, never a credential or the stream's contents. The kind
of loss is the key that matched: when several land in one transaction, as a
disabled account's own row and its sessions' rows do, it is whichever the
stream matched first, usually the session's after a disable.

A WebSocket is admitted by the credential its handshake carried, and that is
the credential whose loss ends it:
- **The dashboard's terminal:** a terminal ticket names the browser session
  that minted it, so the ticket's session admits the socket; a durable
  terminal's own session cookie admits it. The surface is `terminal`.
- **The SSH proxy:** the API key or OAuth access token that `cw shell
  --stdio` sends as its bearer token admits it, or a terminal ticket's
  session. The surface is `ssh_proxy`.
- **The check it re-reads:** once, when the socket registers, the same
  authentication that admitted it; for a ticket, which can be redeemed once
  only, the ticket's session still live and its user still enabled. After
  that the registration holds only the credential's id or hash and its
  user, never the bearer token or the cookie.
- **What ending a durable terminal ends:** the socket and the viewer close;
  the durable session's processes run on in the Sandbox, and the revoked
  credential cannot attach to it again. A one-off terminal's shell ends with
  its socket, as it does on any close.

`cw shell` and `cw exec` reach a hosted environment over its tailnet by
default. The client's `Coordinate` session with the coordinator carries that
connection, and it ends in the same four cases (#3586):
- **Admission:** the coordinator admits the session into the same fence when
  it authenticates the hello. A rejoin with a revoked credential is refused at
  its hello, as any new request is.
- **Ending:** a revocation ends the session with `permission_denied`, "access
  revoked", writes `stream.revoked` with the surface `tailnet`, and removes the
  client from the environment's peers. From then on no packet passes between
  them, and `cw` ends the shell or exec with "Access revoked". The removal
  happens within seconds normally and within 30 seconds at most. The
  `organization` kind ends it instead with the refusal a new stream gets,
  `failed_precondition` with the reason `ORGANIZATION_DELETING`, and `cw`
  ends with "Organization is being deleted" (#6422). `cw` takes only these
  ends, and `unauthenticated`, as final; any other end of the session is
  joined again.
- **The environment's replica:** the coordinator replica that serves the
  environment enforces the removal itself. The client's node, published to the
  other replicas over NATS, carries its admission's ids and hashes, never a
  credential, within a size bound, and the log position its replica's fence
  has processed. The environment's replica admits the peer into its own
  fence, which reads revocations from the database, and refuses it if the log
  holds a row for its keys after that position. It also refuses a position
  beyond the log's head or older than the log's oldest retained row, and it
  keeps fencing the peer for as long as it serves it. The data can only take
  access away, never grant or widen it. Once every replica sends it, a remote
  client node without it is refused. Who may publish those subjects is
  limited by the NATS accounts (infra#2620).
- **Addresses** (#5561): a client chooses its own tailnet address, and the
  coordinator checks it. A client node must carry exactly one address, an
  IPv6 host address (`/128`) under Codewire's prefix `fd7a:115c:a1e0::/48`
  that is not its environment's own; an environment's own node must carry
  the address derived from the environment's id. Every `cw` release, from
  the first (v0.3.391), announces one such address derived from a fresh
  id, so the rule needs no version gate. Any other node is refused and its
  session ends with `invalid_argument`. A client keeps the address of its
  first node for its session's life: a later node with another address
  ends the session the same way. The environment's session forwards an
  address to the environment from one client node at a time: the first
  live holder keeps it; a node with the same node key replaces it (a
  reconnect, whose new node can arrive before the old one's removal); a
  node with another key announcing it is not forwarded while the holder is
  there. A node key is public, and the coordinator sees no proof that a
  session holds its private half, so the same key means the same user only
  through its binding: a key is bound to the first user and environment
  that announced it, and another user's session announcing it is refused
  before its node reaches any peer (`docs/dev/DERP-STUN.md`, "Coordinator
  sessions and node keys"). Each refused or unforwarded node is counted
  and logged with the environment and both peer ids, never a credential.
  The daemon's own rule stays behind this: an address two nodes claim
  belongs to neither.
- **The environment's side:** an address one client held can be announced
  by a different client once the first leaves the peer set, so the
  environment's daemon records each tailnet SSH connection, before its
  session runs anything, with the node key of the peer that held the
  connection's address in the peer set it last applied; a connection from
  an address no peer holds is closed at once. When the daemon applies a
  peer set in which another key holds that address, IPv4 or IPv6, it closes
  the connection at once; when no key has held it for 20 seconds, it closes
  it then. It closes none from any other peer. The shell or exec on it ends
  with its processes, as for a client that vanished, rather than when SSH's
  keepalive gives up (up to 60 seconds). The wait grants nothing, since no
  packet reaches a client while its key does not hold its address. It
  keeps two ordinary moments from ending a live shell: a client's
  reconnect, whose old node's removal can reach the daemon before its new
  node (#5120), and the daemon's own coordinator session starting again,
  whose first sets hold only the peers replayed so far. A client announced
  again under a new session keeps its node key and addresses, so its
  connections stay.
- **Not yet:** after an environment's session moves to another replica, it
  learns the clients on other replicas as they announce again, so the first
  of them to announce an address holds it. That lets one admitted client
  keep another off the environment until it leaves; it grants nothing.
  Coordinator-assigned addresses would close it (#5563).

An open Mesh session doesn't end a stream yet. Expiry ends no tailnet
connection either (#3827).

## Account suspension

Suspension is an administrator's one-step response to abuse (#3297), through
the admin API's `SuspendAccount`. In one transaction it:
- disables the account, crossing the revocation boundary above;
- marks each organization the account is the only owner of;
- narrows those organizations' public and organization-wide ports to their
  creator;
- audits the account and each organization with the administrator's reason.

A suspended organization refuses creates, starts and snapshots with
`403 organization_suspended`, and the worker stops its running environments,
keeping their storage. Stopping a Sandbox ends the streams into it, which
disabling the account alone does not. An organization with another owner is
not suspended; it is returned for the administrator to take up with that
owner.

`UnsuspendAccount` re-enables the account and clears the marks. It revives
nothing suspension revoked or stopped: the person signs in again and creates
new API keys, environments stay stopped until started, and ports stay with
their creator. The ordinary enable on Manage account access refuses a suspended account,
so only unsuspension brings it back.

## Client use

- The server-rendered dashboard is the existing Rust backend-for-frontend
  (BFF). Its generated Connect clients forward the canonical browser session
  to the owning product service. Credential forms also require same-origin
  and CSRF checks; their mutations use the shared credential service, not a
  separate dashboard OAuth client. Browser-side product calls remain on the
  same origin; browser JavaScript does not store a user bearer token and Mesh
  does not own another login/session cookie.
- The CLI and rewritten native apps use the shared Rust
  `codewire-client` OAuth implementation and `TokenProvider`. The CLI uses the
  OAuth device grant; clients with a system browser use PKCE.
- Public SDKs and non-interactive agents use an organization-scoped `cw_` API
  key, or a person's user token with the organization named, through their
  generated Connect client wrapper. Each client finds them in code, the
  environment or a `.env` file, as
  [Signing in from the environment](#signing-in-from-the-environment)
  specifies. Personal access profiles require the person's own bearer;
  supplying an organization API key cannot act as its owning user.
  [API key permissions and expiry](#api-key-permissions-and-expiry-approved-not-yet-shipped)
  and [User tokens and the CLI](#user-tokens-and-the-cli-approved-not-yet-shipped)
  are the approved changes to these rules.
- Workspace binding uses an exact-audience, Pod-bound Kubernetes token.
  Coordinator and daemon calls use distinct environment-scoped HMAC
  capabilities; the retired environment bearer is unsupported.
- Public repositories enter environment creation as explicit URL, revision,
  and destination data. Environment creation may resolve an already-saved
  canonical repository configuration, but the dashboard does not fetch or
  analyze repository contents. An unknown repository-only request fails
  closed. Private platform repository access requires an explicit access
  profile and typed platform repository executor; Codewire does not persist,
  inject, or fall back to a raw forge token. Protected local GitHub credential
  enrollment remains a local credential-broker capability and does not create
  a platform credential.

## API key permissions and expiry (approved, not yet shipped)

The owner decided this on 2026-11-21 (#5688). Until each part ships, the
rules above describe what runs. The change that ships a part rewrites the
rule it replaces in the same change. The journey is
[`docs/journeys/api-keys.md`](../journeys/api-keys.md).

**What is true today.** A `cw_` key belongs to one organization and acts as
the person who made it, with their role there (`ApiKey.user_id`).
Authentication joins `org_members`, so the key stops working when its creator
leaves, and leaving also disables it. Its `scopes` are stored but not
enforced. Its expiry is optional, from 1 to 3650 days. Nothing writes an
audit row when a key is made, refused or revoked. A key can make further
keys in its organization.

**What changes:**
- **One organization, as today.** A key never binds a personal credential
  profile. A person's own profiles are reached with a user token
  ([User tokens and the CLI](#user-tokens-and-the-cli-approved-not-yet-shipped)).
  Organization-owned credentials for keys are #5685.
- **Permissions.** Each key carries a set of permissions, chosen when it is
  made, and they are enforced. A key acts with the smaller of its
  permissions and its creator's role at that moment. A key can't be made
  with a permission its creator's role lacks: such a request is refused
  whole, never trimmed. Existing keys get every permission, so nothing they
  do today stops working.
- **Expiry.** Chosen when the key is made: a date up to 3650 days ahead, or
  never. `cw api-keys create NAME --expires DAYS` or `--expires never`, and
  the dashboard asks. A key that never expires lives until it is revoked, so
  its last use is always shown.
- **Made only from a sign-in.** Keys are made only with a browser session or
  a `cw login` sign-in. The power a key has today to make keys ends.
- **Last use.** `cw api-keys list` and Settings → API keys show each key's
  last use, its permissions and its expiry.

**The permissions:**

| Permission | Allows |
| --- | --- |
| `write:environments` | create, update, start, stop and resize environments; change their TTL, idle stop and protection; grant and revoke access to one |
| `delete:environments` | delete environments |
| `write:snapshots`, `delete:snapshots` | make and change snapshots; delete them |
| `write:presets`, `delete:presets` | make and change presets; delete them |
| `write:network_policies`, `delete:network_policies` | make and change network policies; delete them |
| `manage:secrets` | the organization's application secrets and secret projects |
| `manage:mesh` | Mesh networks, groups, invites, nodes and their key-value store |
| `manage:hosts` | enroll, rename and revoke hosts |
| `manage:members` | invite and remove members and change their roles |

Every key, whatever its permissions, may:
- read the organization's environments, snapshots, presets, network
  policies, Mesh networks and hosts;
- use the environments its creator can reach: exec, files, sessions,
  terminals, ports, previews, the desktop and agents.

Using what runs is not a permission. A key exists to reach environments,
so there is no read-only key (owner, 2026-11-21, #5688). `cw api-keys
create`, the dashboard's create form and the API keys docs page say so
plainly: every key can run commands, use files and run agents in the
environments its creator can reach. Account services (credential profiles,
credentials, delegation) and making keys stay refused to every key.

Each public method is classified in one table in code: a permission, "every
key" or "never a key". A repository policy check fails on a public method
missing from the table, and a key calling a method the table lacks is
refused. A refusal names the missing permission.

**Audit.** Each of these writes a row naming the key's id, never its secret:
`api_key.created`, with its permissions and expiry; `api_key.disabled`,
`api_key.enabled` and `api_key.deleted`, with the actor; and
`api_key.refused`, with the method and the missing permission, at most one a
minute per key and method.

**Revocation**, together with
[Account access revocation](#account-access-revocation), is unchanged:
- disabling or deleting a key ends what it can start, and its live streams
  within 30 seconds;
- disabling the account retires all of the person's keys;
- leaving the organization disables the person's keys there;
- a password reset leaves every key alone;
- an organization's owner or admin can disable or delete any key in the
  organization.

## Signing in from the environment

The owner decided this on 2026-11-21 (#5687, #5688). The TypeScript, Python
and Go SDKs ship the configuration below; issuing a user token, binding a
profile with one and the CLI's part are in
[User tokens and the CLI](#user-tokens-and-the-cli-approved-not-yet-shipped),
approved and not yet shipped. The journey is
[`docs/journeys/sdk-sign-in.md`](../journeys/sdk-sign-in.md).

An SDK program, or a script, authenticates in one of two ways:
- **an API key**, belonging to one organization;
- **a user token**, acting as a person, with the organization named.

**The sources**, highest first:
1. code (the client's options);
2. the process environment;
3. `.env.local`, then `.env`, in the working directory (Python and
   TypeScript only; Go reads no file);
4. the defaults.

| Field | Variable | Option |
| --- | --- | --- |
| API key | `CODEWIRE_API_KEY` | `api_key` |
| user token | `CODEWIRE_JWT_TOKEN` | `jwt_token` |
| organization | `CODEWIRE_ORGANIZATION_ID`, or the older `CODEWIRE_ORG_ID` | `organization_id` |
| server | `CODEWIRE_API_URL`, or `CODEWIRE_SERVER_URL`; default `https://codewire.sh` | `api_url` |

The options take each language's own case (`apiKey`, `jwtToken`,
`organizationId`, `apiUrl`); in Go they are `New`'s key argument or
`WithAPIKey`, `WithJWTToken`, `WithOrganizationID` and `WithAPIURL`. The
older option names still work: `orgId` and `baseUrl` in TypeScript,
`org_id` and `base_url` in Python, `WithOrgID` and `WithBaseURL` in Go. An
empty value counts as unset.
- **The server is never read from a `.env` file.** One there is ignored and
  reported once, as a Node process warning or a Python `UserWarning`, so a
  file in a checkout can't send a key or a token to another server. The
  Python SDK keeps `CODEWIRE_BASE_URL` as an alias for one release.
- **The `.env` files** are read with a small parser in each SDK, which takes
  `KEY=VALUE` lines, `#` comments, an optional `export ` and single or double
  quotes, and only the variables above. It never changes the process
  environment. A missing file is fine; one that can't be read is an error
  naming its path.
- **The credential comes as a unit** from the highest source that sets a
  key or a user token; within that source, the key wins. A key or token in
  a lower source is ignored and reported once, by its variable and its
  source, never its value: as a Node process warning (code
  `CODEWIRE_SETTINGS`), a Python `UserWarning`, or in Go one line through
  the standard `log` package, which writes to stderr by default. So a
  `CODEWIRE_API_KEY` in a cloned repository's `.env` can't replace a token
  the program passed in code and act in an organization someone else
  controls.
- **The organization** (`CODEWIRE_ORGANIZATION_ID` or `CODEWIRE_ORG_ID`,
  or the option in code) comes from the highest source that sets one among
  the credential's own source and every source above it. Only when none of
  those sets one does it come from the highest source below the
  credential's, and that is reported once, by its variable and its source,
  never its value, through the same channel as an ignored key. So an
  organization in code always wins, the environment beats a `.env` file,
  and a `.env` file supplies the organization only for a credential with
  none, and only with a report.
- **The server** comes from code, then the environment, then the default.
- **With no key or token anywhere,** the client refuses and names both
  variables.
- **A user token with no organization** is refused, naming
  `CODEWIRE_ORGANIZATION_ID`.
- **Each refusal comes before any request.** The TypeScript and Python
  clients refuse when they are built. Go's `New` returns no error, so each
  call of such a client returns `ErrNoCredentials` or
  `ErrUserTokenWithoutOrganization` without sending anything.
- **Each request names its organization** in its request fields, as the API
  already does. The SDK fills them from the organization setting; there is
  no organization header. A call that needs an organization, made with a key
  and none set, is refused naming `CODEWIRE_ORGANIZATION_ID`.
- **The key and the token are bearer values only.** The SDKs never log
  them, and they appear in no error message and in no printed form of a
  client.

## User tokens and the CLI (approved, not yet shipped)

The owner decided this on 2026-11-21 (#5687, #5688). Until each part ships,
nothing issues a user token for `CODEWIRE_JWT_TOKEN` (the SDKs send whatever
token they are given as the bearer), an SDK binds no profile with one, and
`cw` changes only as "What runs now" says. The change that ships a part moves
it into [Signing in from the environment](#signing-in-from-the-environment).

**What runs now (#5688):** the IdP issues user tokens, the product API
admits them, and `cw auth token` asks for one through the token exchange, as
below. Against a server from before the exchange, the command says that the
server doesn't issue user tokens yet. Binding a profile with one is not yet
shipped.
- **Settings → API keys → User tokens** lists them and revokes one, through
  the routes below.
- **Settings' routes:** `GET /api/auth/user-tokens?account_id=…` lists the
  account's live user tokens with their creation, expiry (none for one that
  never expires) and last use, never a value. `POST
  /api/auth/user-tokens/revoke` with `account_id` and `token_id` revokes one.
  They take only the browser-session cookie, as the session list does, so a
  user token can't list or revoke tokens. The revoke needs the exact Origin,
  and another account's, an expired and a missing token all answer 404.
- **Storage:** a user token is stored by digest in its own table,
  `oidc_user_tokens`, never with `cw`'s own access tokens. A server from
  before the change never reads that table, so after a rollback every user
  token is refused.
- **The exchange:** `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
  at the token endpoint, for the `codewire-cli` client only.
  - `subject_token` must be a live `cw` access token that names its sign-in,
    with `subject_token_type=urn:ietf:params:oauth:token-type:access_token`.
  - `codewire_expires_in_days` is 1 to 3650 or `never`; it defaults to 1.
  - Every refusal of the subject answers the same `invalid_grant`. A token
    from before tokens carried their sign-in is refused until its next
    refresh.
  - A user may exchange 30 an hour; past that the answer is `slow_down`.
  - Each one issued writes `user_token.issued` to the audit log, naming the
    token's id, its sign-in and its expiry.
- **What it may do:** it acts as its user, as `cw` does, but never as a
  platform administrator. It holds no bearer authority, so the routes that
  publish credentials refuse it. `CreateApiKey` and `DeleteAccount` refuse
  it with `user_token_not_allowed`. Sign-in methods, passwords and second
  factors are browser-session routes, which never admit a bearer.
- **What ends it,** each at once, with its streams:
  - ending its sign-in: `cw logout`, or revoking any token of the sign-in;
  - presenting the user token itself to the revocation endpoint, which ends
    only that token;
  - a password reset, account deletion, or refresh-token reuse on any of the
    user's sign-ins, each of which deletes all of the user's user tokens;
  - revoking the `cw` client's grant for the user;
  - an account disable, which refuses them.

  Each live token that ends, by any of these, writes `user_token.revoked` to
  the audit log with its id and sign-in, from the table's delete trigger. A
  repository check (`user-token-deletes`) refuses code that deletes a user's
  access tokens without their user tokens.

**The CLI.** With `CODEWIRE_API_KEY` set, and `CODEWIRE_API_URL` or
`CODEWIRE_SERVER_URL` naming the server, `cw` uses them instead of the saved
sign-in for that command, as `CODEWIRE_API_KEY` does today.

**The user token.** `cw auth token [--expires DAYS|never]`, after
`cw login`, issues one and writes it only when its output is not a terminal:
`export CODEWIRE_JWT_TOKEN=$(cw auth token --expires 30)`.
- **What it is:** an OAuth access token (flavor 2) for the product API,
  opaque and checked against the token store on every call, so revoking it
  takes effect at once. The variable keeps its conventional name; the token
  is not a JWT.
- **Issued by:** the IdP, through one grant (a token exchange) that takes
  only a live access token of the same user and the `cw` client. The new
  token has at most that token's scope.
  - A user token can't be exchanged again.
  - The grant never issues or accepts a refresh token.
  - It is never `cw`'s own token, which `cw` refreshes and can't be given a
    lifetime.
- **Lifetime:** chosen when it is issued, a number of days or never. The
  default is 1 day.
- **What ends it:** signing out or revoking the sign-in it came from, a
  password reset, an account disable, or revoking the token itself on the
  API keys page. A token that never expires lives until one of those, so the
  API keys page lists each live token with its creation, expiry and last
  use, and marks the ones that never expire. A stream it admitted ends as an
  OAuth token's does under
  [Account access revocation](#account-access-revocation).
- **What it can't do:** make API keys, change sign-in methods or second
  factors, or delete the account. It is refused for those by its kind.
- **Audit:** each one issued writes a row naming its parent sign-in, and so
  does each revocation. Neither names the token. The SDKs never log it and
  remove it from errors.

**Credential profiles.** A user token is an account credential, so it binds
the person's own profiles as `cw` does, with one difference. A binding made
with a user token gets none of the direct delivery exceptions
([SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md#direct-delivery-exceptions)):
its credentials stay behind the proxy. A user token is made to be copied
into environment variables and `.env` files, and can live forever, so a
leaked one must never put a real Codex or Claude login into a Sandbox. Direct
delivery stays for `cw`'s own sign-in and the dashboard. An SDK binds one in a single call:
the program names the profile and states the confirmation, and the SDK reads
the profile's revision itself. Before creating anything, the SDK refuses an
API key asked for a profile, or a missing confirmation, and names the user
token as the way.

## Native sign-in lifetimes (approved, not yet shipped)

These are the numbers set on #4786 for the three native clients,
`codewire-cli`, `codewire-desktop` and `codewire-ios`; #6145 builds them.
Until it ships, each client is registered with a 720-hour access token. `cw`
and the desktop app refresh as below, in their last 10 minutes, once after the
auth layer's `BEARER_REFUSED`, and the desktop under its lock file; the iOS app
does the same while it is open. The auth layer's `BEARER_REFUSED` and its
repository check have shipped. The change that ships the lifetimes moves this
section into [Client use](#client-use).

**Lifetimes.** The IdP registers each native client on startup, so a release
changes them for tokens issued after it.
- **Access token: 1 hour.** It bounds how long a leaked access token works
  when nothing revokes it. A sign-out, a password reset, an account disable
  or refresh-token reuse still ends it at once
  ([Account access revocation](#account-access-revocation)).
- **Refresh token: 2160 hours (90 days), unchanged.** It carries the sign-in.
  Every refresh consumes it and issues a new pair, whose refresh token has 90
  days of its own, so a sign-in ends after 90 days unused. A rotated refresh
  token presented again is refused and, with `IDP_REFRESH_REUSE_REVOKES` on,
  revokes the grant ([OIDC-PROVIDER-THREAT-MODEL.md](OIDC-PROVIDER-THREAT-MODEL.md), T4).
- **ID token: 1 hour, unchanged.**
- **Tokens already issued** keep the expiry they were issued with, up to 30
  days. Nothing deletes them unless the owner chooses that on #6145.

**Refreshing.** `cw` and the desktop app share this through
`codewire-client`, and the iOS app does the same:
- **Ahead of expiry.** Before a request, a client refreshes when less than
  10 minutes of its access token remain, measured from the `expires_in` it
  was given.
- **One refresh at a time.** Every client refreshes under a lock shared by
  everything that uses its credential store: `cw`'s credentials file, and
  the desktop app's keyring entry through a lock file beside it. A provider
  that finds a newer saved pair adopts it instead of refreshing. Two
  refreshes of one refresh token would be a reuse, and with
  `IDP_REFRESH_REUSE_REVOKES` on, a reuse signs the user out. The desktop
  app builds a provider per call, across threads and instances, and its
  keyring entry's lock file, `codewire/desktop-credentials.lock` in the
  configuration directory, is what they share.
- **Once on a refused bearer.** The shared Connect auth layer
  (`ConnectAuthLayer`) marks its own refusal of a bearer it doesn't accept
  (unknown, expired or revoked) with a `google.rpc.ErrorInfo` of domain
  `codewire.sh` and reason `BEARER_REFUSED`. It refuses before any handler
  runs. Nothing else produces that reason: a repository check refuses it
  anywhere outside the auth layer and tests.
  - A unary call refused `Unauthenticated` with that reason gets one more
    try. Holding the same locks, the client adopts a saved token that differs
    from the refused one, or else refreshes once, then sends the call once
    more with the new token.
  - Any other `Unauthenticated`, without the reason, is never retried. A
    handler may return one after it has acted, so sending the call again
    could repeat a write.
  - A second refusal, or a refresh the IdP refuses, ends there: `cw` says it
    is not signed in and to run `cw login`, as it does today, and the apps
    ask the user to sign in again.
  - A streaming call is never sent twice. It starts with a token at least 10
    minutes from expiry.
- **The iOS app** refreshes on the same rules while it is open, not only at
  launch.
- **API keys** and user tokens are never refreshed. A client given one sends
  it as it is.

**Streams.** Expiry never ends an admitted stream (#3827): a `cw logs
--follow` started before its access token expired keeps running.

**Order.** The client change ships first, or in the same release as the IdP
change. A `cw` or desktop app from before it already refreshes within 60
seconds of the `expires_in` it is given, so it keeps working with a 1-hour
token. The iOS app from before it refreshes only at launch, so the IdP
change waits for the iOS change to be what people run. If no build of the
app has gone out to users, nobody runs the old one and nothing waits.
A client retries only on `BEARER_REFUSED`, so against a server from before
the reason it never retries, and only refreshes ahead of expiry.

## Protocol and error boundaries

### Long-running credential publication

The isolated credential-mutation mount accepts either the existing OAuth user
bearer or the signed-in browser session through
`ConnectAuthLayer::credential_mutation`. A session request additionally
requires one unambiguous session cookie, no simultaneous Authorization
credential, and the exact configured public Origin; dashboard form actions retain
their existing identity, 2FA, same-Origin and CSRF checks. Organization API
keys are rejected before lookup. Delegation remains on the separate
OAuth-bearer-only mount.

Shared authentication retains an opaque, process-local exact original
authority: OAuth digest/user/client/expiry or session row/digest/user/expiry,
never either raw credential. This reference is not a new credential flavor.

Before saving a provider credential, recheck that exact original authority and
hold its locks through the same credential transaction. OAuth retains the
user/client/token checks. Session authority locks the user and exact live
session row; later browser validation may slide the stored row but cannot
extend an already admitted operation. Logout deletes the row and therefore
fences publication. Absolute and monotonic deadlines remain pinned to initial
authentication and the operation's original duration.
Prepare protected material before taking locks, not during the transaction.

Transaction-local PostgreSQL deadlines bound blocked statements and idle lock
ownership without extending an already-shorter configured timeout. The Rust
timer still bounds admission; neither timer guarantees a rollback acknowledgement
across network loss. Recheck original deadlines before committing. If COMMIT
may have been issued, a missing reply is an unknown outcome: inspect saved
metadata before retrying and never automatically revoke possibly stored tokens.

### Local use of platform sources

`CredentialDelegationService` uses that same original owner-OAuth boundary,
not a new credential flavor. Its first frame selects exact platform sources
and a profile revision for one native environment operation. The authenticated
host asserts the native identity; Codewire does not claim independent VM
attestation. Cookies, organization API keys and purported Pod identities are
not substitutes for the original OAuth authority.

Each admission rechecks that original token plus current owner, organization,
membership, source and profile authority. Provider operations remain inside the
platform broker. Application values leave only as recipient-bound ciphertext.
No platform environment row, stored delegation or provider credential copy is
created for the local VM. Connection expiry cannot extend the original token;
reconnection requires fresh admission and never replays an old operation.
The public TLS leg uses native gRPC and the direct h2c leg uses Connect under
the same OAuth-only mount. Both share the existing broker capacity and drain.

An admitted stream that carries no operation for 25 seconds sends one empty
keepalive, which the server answers on the same stream, so the edge's idle
limits never end it: ingress-nginx ends a request body silent for 60 seconds,
and Cloudflare a response silent for 125. A keepalive grants nothing,
never reaches the broker and is accepted only after admission, with at most one
awaiting its answer. The server offers keepalives in its admission response
(`accepts_keepalive`), and a client sends none to a server that did not, since
an older server ends a stream that carries one.
The host sends Open and the matching Ready, then waits within one bounded setup
deadline for the exact admitted-selection reply. A successful send or HTTP 200
is not admission. Subsequent admission replies are protocol errors.

### Kubernetes Pod identity

The optional `codewire-server-core/kubernetes-identity` verifier has fixed
purposes: credential relay, credential workspace, workspace binding, egress,
egress node and credential service. Their audiences are distinct. A caller
cannot choose an arbitrary audience or substitute a token issued for another
purpose. They are `codewire.internal.credential-relay.v1`,
`codewire.internal.credential-workspace.v1`,
`codewire.internal.workspace-binding.v1`, `codewire.internal.egress.v1`,
`codewire.internal.egress-node.v1` and
`codewire.internal.credential-service.v1`. These are Kubernetes projected Pod
tokens, not another Codewire user bearer flavor.

Credential use reports (#6189): the credential service presents its
credential-service token to orchestration's `SandboxAuditService` on the
internal listener. Only the `codewire-credential-service` ServiceAccount may
present that audience, and orchestration also requires the Pod to be in its
own namespace. The report names a workspace Pod; orchestration files its uses
under that Pod's own binding, never an environment the report names.

Egress (#4000): a broker-mode workspace Pod presents its egress token, for
the sandbox ServiceAccount, to cw-egress on its node, which forwards it to
orchestration's `EgressService`. cw-egress itself authenticates with the
egress-node audience, which only the `codewire-egress` ServiceAccount may
present; orchestration also requires that Pod to be in its own namespace and
reads cw-egress's node from its live Pod, never from a request field. A guest
Pod is admitted only on that node.

The credential relay is orchestration: only the
`codewire-orchestration` ServiceAccount may present the relay audience, and the
broker additionally requires the relay Pod to be in its own namespace. The
broker takes the environment from the workspace Pod's live binding, never from
a label, and reviews the workspace Pod's token as before.

The shared verifier requires one bounded canonical bearer, a successful
exact-audience TokenReview, the expected ServiceAccount and singular reviewed
Pod coordinates. It then reads a strictly typed, future expiry from those exact
reviewed JWT bytes. An echoed response token, an unverified payload, or the
configured projection lifetime cannot supply or extend expiry. Timestamp and
monotonic-conversion bounds fail closed. Owned token-bearing request/response
models and decoded payload buffers are cleared on success, error, timeout and
cancellation; errors retain no token or upstream message.

Verified identity is not a credential grant. Runtime authority must additionally
check live Pod UIDs/deletion, controller association, current environment
generation, owner/membership, pinned profile and explicit personal consent.
The verifier alone installs no listener, TLS, role or deployment and does not
activate platform credential delivery. Codewire OAuth access tokens remain
opaque and use the separate canonical OAuth token-store validation path.

### Host keys

A host, a computer a member enrolls to provide VMs (#3609), authenticates as
itself with an Ed25519 key it holds in the operating system's protected store.
This is proof of possession, not a bearer: nothing the host sends can be
replayed as a credential. It is not another flavor, and it authenticates
exactly two methods, `HostAgentService.AttachHost` and
`HostAgentService.OpenHostTunnel`, which accept no flavor 1 to 4. No product
method accepts a host key.

- **Enrollment** binds the key to one host record. It runs under the member's
  own flavor 1 to 3 credential, with a signature by the key over a
  domain-separated statement naming the organization, the member and the key.
  A key belongs to one host record for good: removing a revoked host's record
  is refused, so its key cannot enroll again.
- **The session** starts with a fresh 32-byte server nonce, which the host
  signs under a separate domain (`codewire-host-attach-v1`) together with its
  host ID. It signs a new nonce every 10 minutes. An unknown host and a wrong
  key get the same `unauthenticated` answer.
- **Only the newest session** of a host takes operations. Each attach takes
  the next session generation; an older session is told it was superseded
  and ended.
- **A tunnel** to one of the host's environments is opened only when the
  host's session asks for it, with a fresh 32-byte nonce in that request. The
  host signs it under its own domain (`codewire-host-tunnel-v1`) with its
  host ID and the tunnel ID, within 10 seconds, once. A daemon tunnel's
  `ready` carries the running generation's daemon capability, which the
  control plane holds in memory for that tunnel only and never records.
  `ready` is accepted only after a verified `open`, once, for a daemon
  tunnel, at most 512 bytes; until then no byte flows. A tunnel ends with
  the session that asked for it, for any reason (superseded, revoked or
  gone), and its capability is dropped with it. The capability never enters
  the database, Temporal, control events, metadata, metrics, errors or audit,
  and is never kept across tunnels. Only a host session on the same replica
  can carry a tunnel today (#4511).
- **Operations** go only to a host that reports capability version 2 or
  later, and only on its current session: claiming them and checking the
  session generation are one statement. A host's answer to an operation is
  recorded once, from any session of that host, and a malformed report ends
  the session.
- **Revocation** by the owner or an organization owner or admin is final. It
  refuses the next attach, and ends a live session at the host's next
  message.
- **Access calls** (capability version 3; not shipped: the server answers
  them from slice 3's PR 2, and hosts make them from its PR 4, #3609). The
  host's tailnet peer for one running VM asks its session for an access
  grant, records the VM's SSH host key, and asks for a peer relay, as a
  hosted daemon does over its Pod binding. A call is admitted only on the
  host's current session, for an environment placed on that host, whose VM
  the host last reported RUNNING with the local ID and boot generation the
  call names.
  - **The peer token** in a grant is the one a hosted daemon gets
    (`codewire-server-core` `peer_token`): an HMAC over the environment, scope
    `peer`, an expiry 10 minutes out and the environment's operation
    generation, signed with a key derived from the session secret for peer
    tokens only. It lets the peer act as that environment's node at the
    coordinator, and nothing else: no product method, binding,
    credential-broker or workspace authority. The host keeps it in memory.
  - **The operation generation** is the one orchestration assigns, never one
    the host names. A host's own report of a new boot generation changes
    nothing: the token and the write-once host-key slot stay at the
    operation generation, and a different key there is refused.
  - **What ends it:** revoking the host, moving or deleting the environment,
    or a new operation generation refuses the next refresh, and the
    coordinator ends the node's session once the record that admitted it is
    gone. The token's 10 minutes is the outer bound.

The stream mount takes no user credential at the HTTP layer
(`with_connect_routes_and_protocol_policy`). Its public leg is native gRPC, on
the same isolated edge as `EnvironmentSessionService`. A caller that never
proves a key costs one lookup and at most 10 seconds.

### Product protocols

OAuth/OIDC endpoints and the browser login/consent pages are permanent raw IDP
protocol. `POST /api/oauth/device_verification` is the session-cookie-only
browser approval bridge for the standard device grant; it is not a product
REST API. Product capability is proto-first and served through the shared
Connect authentication layer.

Terminal tickets are 30-second, single-use derivatives of a signed-in browser
session, for the terminal's WebSocket handshake, which a browser cannot send a
header with. A ticket names the session that minted it, and its redemption
requires that session still live and its user still enabled, so a sign-out or
a disable before redemption refuses it (#3586). Only a session gets a ticket:
an API key or OAuth client sends its own credential with the handshake. Stripe
webhook signatures are a third-party protocol mechanism, not an additional
Codewire credential flavor.

Missing or invalid credentials map to REST `401` / Connect
`unauthenticated`. An authenticated principal without required scope, role,
organization authority, or method authority maps to REST `403` / Connect
`permission_denied`. Handlers return the shared server error and its canonical
`google.rpc` details; they do not construct auth-specific wire errors or log
credential values. See
`docs/dev/PROTO-STYLE.md#error-model` for the complete error contract.
