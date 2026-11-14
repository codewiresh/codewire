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
- Native OAuth credentials are opaque and authoritative in the IDP token
  store. `TokenProvider` supplies the current access token; a
  `CredentialStore` persists the access/refresh pair atomically and saves a
  refreshed pair as one unit.
- An OAuth credential without exact `codewire.api` may use the identity
  endpoints its scopes permit, but product calls fail with REST `403` /
  Connect `permission_denied`.
- A `cw_` API key is authorized only inside its one bound organization. It
  cannot inherit its owner's global-admin authority or perform account-global
  operations.
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
- Each round trip has a single-use `oauth_states` row holding a SHA-256 of a
  random state, the PKCE (S256) verifier, a Google nonce and the return
  target, valid for 10 minutes; the browser holds the raw state in an HttpOnly
  `SameSite=Lax` cookie scoped to `/api/auth/oauth/`. The callback requires
  the `state` parameter to equal that cookie, deletes the row in the statement
  that reads it and refuses a row that is expired or for another provider.
  The code is exchanged server-side with the verifier.
- Only a verified email counts: GitHub's primary email marked `verified`, or
  Google's ID token with `email_verified`. The ID token comes straight from
  Google's token endpoint over TLS, and its `iss`, `aud`, `exp` and `nonce`
  are checked.
- An identity already linked signs in to its account with the gates password
  sign-in applies after the password: lockout, then `enabled`, then the
  account's second factor when enrolled. A provider sign-in never skips
  Codewire two-factor authentication.
- A start is an unauthenticated `GET` that writes a row, so each client
  address (an IPv4 address or IPv6 /64, stored only as an HMAC under a key
  derived from the session secret) may hold at most 30 unfinished sign-ins;
  past that, `/login` says to wait. A finished or abandoned round trip frees
  its place within ten minutes.
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
after the reset. API keys stay; they are an organization's automation, not a
sign-in (owner, 2026-11-13, #4481). A sign-in that verified the old password
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
new stream. This migration does not forcibly terminate an already admitted
terminal, exec, file, or other long-lived stream; that residual authority lasts
only until the stream's existing closure or reauthorization boundary. A future
active-stream revocation feature must explicitly close those connections rather
than claiming that database token revocation does so.

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
  key through their generated Connect client wrapper for organization APIs.
  Personal access profiles instead require the existing user OAuth bearer;
  supplying an organization API key cannot act as its owning user.
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
purposes: credential relay, credential workspace and workspace binding. Their
audiences are distinct. A caller cannot choose an arbitrary audience or
substitute a token issued for another purpose. They are
`codewire.internal.credential-relay.v1`,
`codewire.internal.credential-workspace.v1` and
`codewire.internal.workspace-binding.v1`. These are Kubernetes projected Pod
tokens, not another Codewire user bearer flavor.

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
  Until slice 2's handlers land, no session sends an operation or asks for a
  tunnel, and every tunnel is refused.
- **Revocation** by the owner or an organization owner or admin is final. It
  refuses the next attach, and ends a live session at the host's next
  message.

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

Terminal tickets are short-lived derivatives of an already authenticated user
credential for a WebSocket handshake. Stripe webhook signatures are a
third-party protocol mechanism, not an additional Codewire credential flavor.

Missing or invalid credentials map to REST `401` / Connect
`unauthenticated`. An authenticated principal without required scope, role,
organization authority, or method authority maps to REST `403` / Connect
`permission_denied`. Handlers return the shared server error and its canonical
`google.rpc` details; they do not construct auth-specific wire errors or log
credential values. See
`docs/dev/PROTO-STYLE.md#error-model` for the complete error contract.
