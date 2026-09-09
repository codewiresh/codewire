# Authentication policy

This is Codewire's canonical authentication policy. The architectural decision
and migration evidence live in
`docs/plans/connect-rpc/15-auth-policy.md`; product and client code should link
here instead of restating or extending the credential model.

Codewire issues four authentication credential flavors: three user-facing and
one platform-internal. Kubernetes supplies the separate Pod-bound identity used
to bootstrap gateway binding.

| # | Flavor | Presenter | Acquisition and boundary |
|---|---|---|---|
| 1 | Session cookie | Browsers | The IDP login page issues the HttpOnly, SameSite session cookie. Browsers use it for same-origin product calls and identity pages. |
| 2 | OAuth user bearer | Native apps | PKCE authorization code where a system browser exists; OAuth device grant where none does. Both yield the same opaque access/refresh token species and use one `TokenProvider`. Product access requires exact `codewire.api`. |
| 3 | `cw_` API key | Machines, SDKs, CI, and agents | `ApiKeyService` creates a revocable key bound to exactly one organization. It is not a user token or an OAuth client-credentials grant. |
| 4 | HMAC sidecar token | Gateway, coordinator, and daemon service hops | The control plane mints a scope-bound service credential for the internal hot path. It never becomes a user credential. |

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
  environment bearer.
- A trusted service hop may transport the caller's existing credential for a
  canonical authorization decision without creating a new flavor. The WS18
  Mesh boundary authenticates the hop with flavor 4, carries exactly one
  flavor-1/2/3 credential in reserved sensitive binary Connect metadata,
  removes it before handler dispatch, and exposes only a typed authorization
  context. Credential values never belong in protobuf fields, logs, traces,
  metrics, errors, retries, persistence, or response metadata.

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

- The dashboard uses connect-es/connect-query with the same-origin session
  cookie. Generated Mesh product service paths are routed from that same
  product origin to Mesh; browser JavaScript does not store a user bearer token
  and Mesh does not own another login/session cookie.
- The CLI and rewritten native apps use the shared Rust
  `codewire-client` OAuth implementation and `TokenProvider`. The CLI uses the
  OAuth device grant; clients with a system browser use PKCE.
- Public SDKs and non-interactive agents use an organization-scoped `cw_` API
  key through their generated Connect client wrapper for organization APIs.
  Personal access profiles instead require the existing user OAuth bearer;
  supplying an organization API key cannot act as its owning user.
- Gateway binding bootstrap uses an exact-audience, Pod-bound Kubernetes token.
  Coordinator and daemon calls use distinct environment-scoped HMAC
  capabilities; the retired environment bearer is unsupported.
- Public repositories enter environment creation as explicit URL, revision,
  and destination data. Environment creation may resolve an already-saved
  canonical repository configuration, but the dashboard does not fetch or
  analyze repository contents. An unknown repository-only request fails
  closed. Private platform repository access waits for an explicit access
  profile and typed platform repository executor; Codewire does not persist,
  inject, or fall back to a raw forge token. Protected local GitHub credential
  enrollment remains a local credential-broker capability and does not create
  a platform credential.

## Protocol and error boundaries

### Long-running OAuth-authorized publication

An isolated enrollment mount accepts only the existing OAuth user bearer through
`ConnectAuthLayer::oauth_bearer_only`. Cookies and organization API keys cannot
substitute for it. Shared authentication can retain an opaque, process-local
`OAuthBearerAuthority` containing the original token's digest, user, client and
expiry, never its raw value. This reference is not a new credential flavor.

Before saving a provider credential, recheck that exact original authority and
hold its user/client/token locks through the same credential transaction. The
live token must retain `codewire.api`, its exact identity and original expiry;
its user/client must still exist and the client must remain enabled. A renewed
login cannot rescue the original operation. Absolute and monotonic deadlines
remain pinned to initial authentication and the enrollment's original duration.
Prepare protected material before taking locks, not during the transaction.

Transaction-local PostgreSQL deadlines bound blocked statements and idle lock
ownership without extending an already-shorter configured timeout. The Rust
timer still bounds admission; neither timer guarantees a rollback acknowledgement
across network loss. Recheck original deadlines before committing. If COMMIT
may have been issued, a missing reply is an unknown outcome: inspect saved
metadata before retrying and never automatically revoke possibly stored tokens.

### Kubernetes Pod identity

The optional `codewire-server-core/kubernetes-identity` verifier has three
fixed purposes: gateway binding, credential gateway, and credential workspace.
Their audiences are distinct. A caller cannot choose an arbitrary audience or
substitute a token issued for another purpose. Existing gateway binding retains
`codewire.internal.gateway-binding.v1`; credential purposes use
`codewire.internal.credential-gateway.v1` and
`codewire.internal.credential-workspace.v1`. These are Kubernetes projected Pod
tokens, not another Codewire user bearer flavor.

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
