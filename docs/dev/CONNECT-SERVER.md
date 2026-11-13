# Connect server infrastructure

This document records the decisions (D1 to D9, and D6b) behind the shared
serving stack that every Connect surface mounts on. The `connect`, `http`,
`auth`, `connect_testing` and crate-root modules of `codewire-server-core`,
the probe proto and the edge routing files cite them by number. Each
section states the rule as it stands, then the reason.

## D1: Same binaries, same ports, same middleware

Connect services mount into the existing axum binaries. A binary passes each
`connectrpc::Router` to one of the `AppBuilder::with_connect_routes*`
methods, which delegate to the mount helpers in the `connect` module. The
standard `AppBuilder` stack then applies to RPCs as it does to plain HTTP
routes: request id, trace span, optional CORS, panic recovery and the
`x-codewire-service` response header. The helper registers one route per
service (`/{package}.{Service}/{*method}`), never a catch-all. Health and
metrics routes stay plain HTTP.

Exception: a small closed set of cluster-local services listens on separate
ports that no public edge routes to. They use the same `AppBuilder` and
Connect stack.

| Listener | Port | Served by | Services |
|---|---|---|---|
| `internal-connect` (TLS only) | 8088 | orchestration | `MeshAuthorizationService`, `EnvironmentMeshService` |
| `workspace-binding` | 8087 | orchestration | `WorkspaceBindingService` |
| `derp-admission` | 8097 | coordinator, mesh | `DerpAdmissionService` |

All four are in the `codewire.internal.v1` package. The public listeners
carry none of them.

Reason: with one stack an RPC cannot miss request ids, tracing or panic
recovery, and every binary wires Connect the same way. A closed listener
keeps an internal service off the public port, so it does not depend on
edge configuration to stay private.

## D2: Listeners accept HTTP/1.1 and cleartext HTTP/2

`codewire_server_core::serve` and `serve_with_listener` accept HTTP/1.1 and
prior-knowledge cleartext HTTP/2 (h2c) on the same port. `axum::serve` with
axum's `http2` feature detects the HTTP/2 preface. `serve_with_h2_keepalive`
is an opt-in sibling that adds HTTP/2 keepalive pings for long-lived
bidirectional services. The coordinator is its only caller.

Reason: Connect unary and server-streaming calls work over HTTP/1.1, but
gRPC and full-duplex bidirectional streams need HTTP/2 end to end. Solving
this at the listener leaves only the edge leg to configure per service.

## D3: Authentication is a layer in front of the dispatcher

`ConnectAuthLayer` wraps the shared credential resolver in the `auth`
module. It resolves the same three user credentials as the plain HTTP
surface ([AUTH-POLICY.md](AUTH-POLICY.md)): session cookie,
organization-scoped `cw_` API key, and opaque OAuth bearer. On success it
inserts `AuthUser` and the credential context into request extensions.
Handlers read them with `connect::auth_user` and `connect::auth_context`.

| Mount | Constructor or helper | Behaviour |
|---|---|---|
| authenticated | `ConnectAuthLayer::authenticated` | Rejects with `unauthenticated` unless a product credential validates. |
| admin | `ConnectAuthLayer::admin` | Also rejects non-admin users with `permission_denied`, for every method of the mount. |
| OAuth bearer only | `ConnectAuthLayer::oauth_bearer_only` | Admits only an opaque OAuth bearer with the product scope. Ignores cookies and rejects API keys before any lookup. |
| credential mutation | `ConnectAuthLayer::credential_mutation` | Admits an OAuth bearer, or a browser session from the exact configured origin. Rejects API keys before any lookup. |
| self-authenticating | `connect_router` (no user-auth layer) | The handler validates its own machine credential before any domain lookup. |
| private service hop | `MeshAuthorizationLayer`, `InternalServiceLayer` | Validates a scoped HMAC service credential on a cluster-local listener and removes raw credentials before dispatch. |

Three per-method sets refine a mount. Each defaults to empty and is
reviewed like a route registration:

- `allow_public`: full `/{package}.{Service}/{Method}` paths that bypass
  authentication. Handlers see no `AuthUser`.
- `allow_anonymous`: paths that need no credential but validate one when it
  is presented. An invalid credential is refused, never treated as
  anonymous.
- `admin_only`: paths raised to the admin check inside an authenticated
  mount. Only the probe service (D8) uses it.

Further rules:

- Admin gating is per service. `codewire.admin.v1` services mount with the
  admin layer.
- Organization membership is checked in handlers, not in the layer.
- The layer runs before method dispatch. A request without a credential to
  an unknown method of a mounted service gets `unauthenticated`, never
  `unimplemented`, so method names cannot be enumerated without a
  credential. An authenticated request to an unknown method gets the
  dispatcher's `unimplemented`.
- Credential resolution is bounded by `CONNECT_AUTH_RESOLUTION_TIMEOUT`
  (10 seconds), or the caller's `connect-timeout-ms` when shorter. On
  expiry the layer answers `deadline_exceeded`.

Reason: one layer reuses the credential logic with no duplication, and no
service can forget to authenticate. Per-service interceptors would repeat
that logic in every service.

## D4: Infrastructure errors are Connect-shaped

Rejections from the auth layers render through the Connect renderer of the
[error model](CONNECT-ERROR-MODEL.md), D2 and D4: a canonical code plus an
`ErrorInfo` detail with the reason, hint and request id. They never use the
plain HTTP JSON envelope. An infrastructure fault during credential
validation renders through the same mapping as `internal`.

Two responses are not Connect-shaped: the content-type gate (D6b) answers
a bare `415`, and `CatchPanicLayer` answers a bare `500`.

Reason: the layer sits in front of the dispatcher, so no handler exists to
shape its errors. Connect clients map a non-Connect response to a code from
the HTTP status, which is enough for a panic or a malformed request.

## D5: Edge routing is per service, with a drift check

Public Connect paths are `/{package}.{Service}/{Method}`. Edge matchers
do not depend on the HTTP method, because reads marked `NO_SIDE_EFFECTS`
may use GET. Six files hold the routing rules: `Caddyfile`,
`Caddyfile.docker`, `deployments/k8s/base/ingress.yaml`, the `ingress.yaml`
of the `local-kind` and `local-kind-static` overlays, and
`tests/e2e/kind/ingress.yaml`.

- Services owned by a binary other than orchestration have explicit
  per-service rules. A `/codewire.` prefix fallback sends every other
  Connect path to orchestration, so an unmatched RPC path gets a Connect
  answer from a service and never dashboard HTML.
- `scripts/checks/repo_checks.py connect-edge-routing` reads the services
  under `proto/codewire/` and requires each one to appear in exactly one
  class of `scripts/checks/contracts/connect-edge-ownership.json`:
  `owners`, `pending` or `unrouted`. An owned service has rules in all six
  files. `pending` is for a proto whose serving is not wired yet.
  `unrouted` is the closed map of the cluster-local listeners in D1. It
  records the binary, listener and port, and the check rejects any public
  matcher for those services.
- Streaming responses must cross the edge unbuffered. The mount sets
  `X-Accel-Buffering: no` on streaming responses, and the Connect Ingress
  turns proxy buffering off and uses long read and send timeouts.
- An overlay that changes the public host must patch the host and TLS
  identity of every public Connect Ingress it inherits, including the
  fallback. The fallback is a Connect backend. It does not take the
  gRPC-only backend annotations of the bidirectional services.

Reason: a package can span binaries. For example, `codewire.admin.v1`
holds both an orchestration-owned and a billing-owned service, so routing
by package prefix alone is wrong. The check keeps the six files in step.

## D6: CORS is off unless an origin is named

Browsers reach every service through the dashboard's own origin, so by
default no service answers CORS. A deployment with a browser front end on
another origin lists it in `CODEWIRE_CORS_ALLOWED_ORIGINS`: comma-separated
exact `http` or `https` origins, with no wildcard and no path. An invalid
value stops the service at startup. For a listed origin the layer allows
`GET` and `POST` and the headers `content-type`, `authorization`,
`connect-protocol-version` and `connect-timeout-ms`. It never allows
credentials.

Reason: same-origin is the supported browser posture. A wildcard policy
adds nothing for a same-origin client and widens what other origins may
read.

## D6b: CSRF and caching for cookie-authenticated Connect

The CSRF defence is structural. No CSRF token exists for Connect calls.

- The session cookie is `HttpOnly; SameSite=Lax`.
- CORS never allows credentials (D6).
- A POST to a Connect route must carry `application/json`,
  `application/proto`, `application/connect+json` or
  `application/connect+proto`. Any other content type gets
  `415 Unsupported Media Type` with an `Accept-Post` header that names the
  allowed types, before any credential is examined and before any
  dispatcher or handler code runs. The default mount also refuses
  `application/grpc*` (D9).
- `Connect-Protocol-Version` is validated when present and never required.
  The dispatcher rejects any value other than `1` with `invalid_argument`.
- A credentialed Connect GET response gets `Cache-Control: private` unless
  the handler set its own directive. A handler that needs a stricter one,
  such as `no-store` for a payload that holds a credential, sets it.
- `NO_SIDE_EFFECTS` is trusted, not verified. A mutating method labelled as
  a read would be reachable by a cross-site GET that carries the Lax
  cookie. The annotation is reviewed like a route registration
  ([PROTO-STYLE.md](PROTO-STYLE.md)).

Reason: every allowed Connect POST content type forces a browser preflight,
and the preflight fails cross-origin. Requiring the version header as well
adds no protection and would stop a plain `curl` call from working.

## D7: Request ids and one log event per RPC

Because Connect mounts inside the `AppBuilder` stack (D1), `x-request-id`
is minted and propagated, and trace spans exist, with no extra work. The
request id also reaches clients inside error payloads
([error model](CONNECT-ERROR-MODEL.md), D4). Connect handlers do not invent
their own correlation headers. Anything beyond `x-request-id` is outside
the contract.

The mount emits one `tracing` event at INFO per request to a mounted
Connect path, with target `connect_rpc` and message `connect rpc`.

| Field | Value |
|---|---|
| `service` | Fully qualified service name, for example `codewire.v1.ApiKeyService`. |
| `method` | Method name from the path. |
| `protocol` | `connect` or `grpc` once the content-type gate admits the request; `unknown` for a request rejected before that. |
| `code` | Connect code. HTTP 200 is `ok`. A unary error reads the `code` field of the error document. A gRPC response reads `grpc-status` from the response headers. Otherwise the Connect HTTP-to-code table applies. |
| `http_status` | HTTP status as a number. |
| `duration_ms` | Duration in milliseconds. |
| `credential` | `session`, `api_key`, `oidc`, or `none`. |
| `principal_fingerprint` | Truncated domain-separated SHA-256 of the user id, or `unknown`. |
| `synthetic` | `true` when the user id is in the mount's configured synthetic set. Request headers are never consulted. |
| `user_agent` | Request `User-Agent`, or `unknown` when missing or not UTF-8. |

Content-type rejections and unknown-method responses on mounted services
are logged. Panics are not, because `CatchPanicLayer` sits outside the
mount. A streaming error that exists only in body trailers is not visible
at this layer and logs `ok`.

Reason: one structured event per RPC shows which clients, credentials and
protocols use each method, without per-handler logging.

## D8: A probe service tests the infrastructure

`proto/codewire/testing/v1/ping.proto` defines `PingService`:

- `PublicPing`: on the public allowlist (D3).
- `Ping`: authenticated. It rejects an empty `message` with
  `invalid_argument` and a `google.rpc.BadRequest` detail, which exercises
  the error model end to end.
- `AdminPing`: raised to the admin check.
- `StreamPing`: an allowlisted server-streaming method that sends a fixed,
  server-paced sequence, so edge tests can prove that streamed responses
  are not buffered.

`AppBuilder::with_connect_testing_surface` mounts it in orchestration and
billing only when `CONNECT_TESTING_SURFACE` is exactly `1`. Local
development and test manifests set the flag. Base deployment manifests
never do. With the flag unset the router is identical to one without the
probe. The service has no stability guarantee, is not part of any SDK's
public surface, and has edge rules only in the local and test files.

Reason: the probe proves mount, authentication, error wire shape and edge
routing without depending on any product service.

## D9: Connect by default, native gRPC by explicit opt-in

Every mount defaults to `ProtocolPolicy::ConnectOnly`. The `connectrpc`
library serves Connect, gRPC and gRPC-Web from one registration and has no
switch for each protocol, so the content-type gate (D6b) enforces the
policy: a default mount answers `application/grpc*` with `415`.

A mount may opt into `ProtocolPolicy::ConnectAndGrpc`, which also admits
`application/grpc` and `application/grpc+proto`. These first-party
bidirectional services do so: `CoordinatorService`,
`MeshCoordinatorService`, `EnvironmentSessionService`, `HostAgentService`
and `CredentialDelegationService`. Their clients use native gRPC across the
public edge and Connect over direct h2c. The opt-in changes protocol
admission only. The same auth layer, error mapping, handler and state serve
both protocols.

No mount admits gRPC-Web. Connect GET is enabled for `NO_SIDE_EFFECTS`
methods. The daemon's own gRPC service (`codewire-daemon-proto`) is
separate and unaffected.

Reason: Connect needs no HTTP/2 at the edge for unary calls and works with
plain HTTP tooling. Native gRPC adds an end-to-end HTTP/2 requirement and a
wider protocol commitment, so it is admitted only where a first-party
bidirectional stream must cross a public edge that does not carry Connect
bidirectional streams reliably. gRPC-Web has no consumer.
