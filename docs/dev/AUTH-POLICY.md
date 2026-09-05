# Authentication policy

This is Codewire's canonical authentication policy. The architectural decision
and migration evidence live in
`docs/plans/connect-rpc/15-auth-policy.md`; product and client code should link
here instead of restating or extending the credential model.

Codewire has exactly four credential flavors: three user-facing and one
platform-internal.

| # | Flavor | Presenter | Acquisition and boundary |
|---|---|---|---|
| 1 | Session cookie | Browsers | The IDP login page issues the HttpOnly, SameSite session cookie. Browsers use it for same-origin product calls and identity pages. |
| 2 | OAuth user bearer | Native apps | PKCE authorization code where a system browser exists; OAuth device grant where none does. Both yield the same opaque access/refresh token species and use one `TokenProvider`. Product access requires exact `codewire.api`. |
| 3 | `cw_` API key | Machines, SDKs, CI, and agents | `ApiKeyService` creates a revocable key bound to exactly one organization. It is not a user token or an OAuth client-credentials grant. |
| 4 | HMAC sidecar token | Gateway/coordinator service hops | The control plane mints a short-lived service credential for the internal hot path. It never becomes a user credential. |

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

## Client use

- The dashboard uses connect-es/connect-query with the same-origin session
  cookie. Generated Mesh product service paths are routed from that same
  product origin to Mesh; browser JavaScript does not store a user bearer token
  and Mesh does not own another login/session cookie.
- The CLI and rewritten native apps use the shared Rust
  `codewire-client` OAuth implementation and `TokenProvider`. The CLI uses the
  OAuth device grant; clients with a system browser use PKCE.
- Public SDKs and non-interactive agents use an organization-scoped `cw_` API
  key through their generated Connect client wrapper.
- Platform sidecars use only a scoped HMAC sidecar token; raw environment
  bearer credentials are unsupported.
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
