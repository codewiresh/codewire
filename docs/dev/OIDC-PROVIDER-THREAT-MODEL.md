# OIDC provider threat model

This document lists the threats the Codewire OpenID Connect provider is
designed against and the mitigation for each. Comments in `codewire-oidc`
cite threats by id. Read it before changing the
authorization, token, logout or key-handling code.

## Architecture

The provider has two layers.

| Crate | Role |
|---|---|
| `codewire-oidc` | Protocol library. Request parsing and validation, PKCE, the authorization code, refresh and device grants, id_token signing, discovery, JWKS, userinfo, introspection, revocation and RP-initiated logout. It has no Codewire-internal dependencies and never touches a database. |
| `codewire-idp` | Service. Implements the library's store traits on Postgres, bridges to the Codewire session and login pages, and serves the routes. |

The library reaches all state through traits in its `store` module:
`AuthorizationStore`, `TokenStore`, `ClientStore`, `KeyStore`,
`UserAuthenticator`, `DeviceAuthorizationStore` and `TokenCustomizer`.

Facts needed to read the table:

- **Tokens.** Only the id_token is a JWT. It is signed with EdDSA
  (Ed25519). Access tokens, refresh tokens and authorization codes are
  opaque random handles. Userinfo and introspection resolve an access token
  through `TokenStore`, and revocation is a store delete.
- **Storage.** The service stores only the SHA-256 digest of each code,
  access token and refresh token. The raw value exists in memory and in the
  one response that returns it.
- **Subjects.** `sub` is the user id, the same for every client
  (`subject_types_supported` is `public`).
- **Clients.** Clients are registered by the service. There is no dynamic
  client registration. Confidential clients authenticate at the token
  endpoint with `client_secret_basic` or `client_secret_post`. Public
  clients use no secret and rely on PKCE.
- **Login.** The library does not authenticate users. It asks
  `UserAuthenticator`, which resolves the `codewire.session_token` cookie
  to a live session of an enabled user, or returns the login page URL.
  After login, the service callback `/api/oidc/callback` reloads the stored
  request and drives the authorization again with the session present.

Endpoints (the library defaults):

| Endpoint | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/api/oauth/authorize` |
| Token | `/api/oauth/token` |
| UserInfo | `/api/oauth/userinfo` |
| Revocation | `/api/oauth/revoke` |
| Introspection | `/api/oauth/introspect` |
| End session | `/api/oauth/end_session` |
| Device authorization | `/api/oauth/device_authorization` |

## Threats and mitigations

| Id | Threat | Mitigation |
|---|---|---|
| T1 | Open redirect, redirect URI manipulation | `redirect_uri` must match one of the client's registered URIs exactly. No prefix, substring or port wildcard. Validation is staged: until `client_id` and `redirect_uri` are proven, an error is rendered directly and never redirected to a caller-supplied URI. |
| T2 | Authorization code interception | PKCE is required for every client. Only `S256` is allowed; `plain` and a missing method are rejected. A code is single-use, lives 60 seconds, and is bound to the client, the redirect URI and the PKCE challenge. |
| T3 | Authorization code replay | `TokenStore::consume_code` is atomic. The service implements it as `DELETE ... RETURNING` by digest. A second exchange finds nothing and fails with `invalid_grant`. |
| T4 | Refresh token replay or theft | Refresh tokens rotate: the presented token is consumed atomically and a new one is issued. A rotated token presented again is refused with `invalid_grant` and logged with its age. A token presented by a different client is refused. Handles are stored as SHA-256 digests only. Revoking every refresh and access token the user holds for that client on such a replay is built and off by default (`IDP_REFRESH_REUSE_REVOKES`); turning it on is #4786. |
| T5 | CSRF on the login bridge | `state` is returned to the relying party unchanged. Resuming an authorization needs both the opaque authorization request id and the session cookie, which is `HttpOnly; SameSite=Lax`. |
| T6 | Token substitution, audience confusion | The id_token carries `aud` set to the client id, `iss` set to the configured issuer, and the request's `nonce`. Access tokens are opaque and carry no claims to confuse. A client can introspect only its own tokens. |
| T7 | Key compromise, weak keys, algorithm confusion | Signing is EdDSA only. The JOSE header pins `alg` to `EdDSA`, and verification uses Ed25519 against the published keys and never an algorithm chosen by the token header. Private key seeds are stored encrypted, bound to the key id and public key. The JWKS can publish several keys, so a key can be replaced without breaking verification of tokens signed by the previous one. |
| T8 | Mix-up, provider confusion | One static issuer, set in configuration. The discovery document's `issuer`, its endpoints and the id_token `iss` come from that value. No request header, `Host` and `X-Forwarded-Host` included, changes them. |
| T9 | Client secret exposure | Client secrets are stored as bcrypt hashes and verified with bcrypt. A disabled client never authenticates. |
| T10 | Scope or privilege escalation | The requested scopes must include `openid` and be a subset of the client's registered scopes. A refresh request may only narrow the scopes of the original grant. A client may use only the grant types registered for it. No client belongs to an organization, so a token says who the user is, not what they may reach: access to an organization is checked on every API call. |
| T11 | Insecure issuer | The issuer is static deployment configuration and is never derived from a request. The service refuses to start with an issuer that is not `https://`, unless its host is loopback, which is how local development runs; a host that only looks like loopback is refused. The session cookie is marked `Secure` when the front end URL is `https`. |
| T12 | Resource exhaustion through unbounded requests and codes | Every stored item expires: authorization requests after 10 minutes, codes after 60 seconds, device codes after 10 minutes. Expired rows are rejected on read, and expired authorization requests, codes, tokens and device authorizations are deleted as new ones are written. Device polling is told a 5 second interval. The provider itself does not limit request rates; that is left to the deployment's edge, and the limits for the hosted service are written but not in place yet. |
| T13 | Information leak through errors | Errors use the fixed OAuth and OIDC error codes (`invalid_request`, `invalid_client`, `invalid_grant`, `access_denied` and the rest of `ErrorCode`). Store errors are opaque, and responses do not reflect internal detail. One exception is known: a failure to serialize an id_token's header or claims passes the serializer's text into a `server_error`. Those values are built by the provider and no input is known to make them fail. |
| T14 | Silent authentication abuse, stale authentication | `prompt=none` never shows a login page: without a live session the request fails with `login_required`. The id_token carries `auth_time`, taken from the session. `prompt=login` and `max_age` are parsed but not enforced yet (#4785), so a relying party cannot force a fresh sign-in today. |
| T15 | Open redirect at logout | `post_logout_redirect_uri` must match one of the client's registered logout URIs exactly, and requires a `client_id` or an `id_token_hint`. The hint's signature is verified, and a `client_id` that disagrees with the hint's audience is refused. `state` is returned unchanged. |
| T16 | Token caching, browser cross-origin access | Token, introspection, revocation and device authorization responses, and OAuth error responses, carry `Cache-Control: no-store` and `Pragma: no-cache`. The service sends no CORS headers unless an origin is configured ([CONNECT-SERVER.md](CONNECT-SERVER.md), D6). |
| T17 | Disabled or deleted client | An unknown or disabled client is rejected with `invalid_client` at the authorization, token, device authorization, introspection and end session endpoints. |

## Not in place yet

Three protections are not live. A relying party or an operator should not
count on them until their issues close:

- revoking a user's tokens when a rotated refresh token is replayed (T4,
  #4786);
- `prompt=login` and `max_age` (T14, #4785);
- request rate limits on the authorization, token and device endpoints of
  the hosted service (T12). They are written and wait to be rolled out,
  on the development environment first.

## Device authorization

The library also implements the device authorization grant (RFC 8628). It
is off unless the host supplies a `DeviceAuthorizationStore`. The service
supplies one, and the CLI signs in with it. The table above has no row for
this grant. The shared rows still apply to it: client checks (T9, T17),
expiry (T12), error codes (T13) and response caching (T16).
