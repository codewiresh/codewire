# Proto Style Guide

Canonical authoring rules for every proto under `proto/`. Promoted from
`docs/plans/connect-rpc/02-proto-authoring-guide.md` (WI-3); amendments
land here, not in the plan doc. Program context:
`docs/plans/connect-rpc/00-MASTER.md` and the ADR
(`docs/plans/2026-07-10-connect-rpc-api-contract-design.md`).

## Layout

```
proto/
  codewire/v1/            # public-intended (strictest stability)
    organization.proto    # one file per resource aggregate
    environment.proto
    exec.proto
    file.proto
    api_key.proto
    secret.proto
    preset.proto
    port.proto
    common.proto          # canonical ProjectSpec plus RepositorySpec,
                          # ApplicationPort, agents, skills, resources,
                          # secrets, and access bindings shared by public APIs
  codewire/console/v1/    # first-party UX surface
  codewire/admin/v1/
  codewire/internal/v1/
  codewire/testing/v1/    # never-routed probe fixture (03 D8) — see below
  google/rpc/             # vendored error-detail types (01 WI-1)
```

(`daemon.v1` is the Rust-consumed private gateway-to-daemon protocol under
`libs/gateway-proto/proto/`; see `proto/README.md`.)

`codewire.testing.v1` (an 03-D8 amendment to this layout) is the
Connect serving infrastructure's conformance fixture (`PingService`):
mounted only when `CONNECT_TESTING_SURFACE=1` (dev-stack, the
selected service-integration family, kind/local-kind manifests — never base or
production deploys), absent from the production edge rules, no
stability posture, and not part of any SDK's public surface. Its
generated code is checked in like every other package so the codegen
drift gates stay uniform, but nothing may publish or wrap it.

One file per resource aggregate; the service and its request/response
messages live together in that file.

## Naming and shape rules

- Services: `<Resource>Service` (buf STANDARD already enforces the
  suffix). One service per resource aggregate; lifecycle verbs stay on
  the resource's service (`EnvironmentService.StopEnvironment`), no
  grab-bag `MiscService`.
- Methods: `Get/List/Create/Update/Delete<Resource>` for CRUD; domain
  verbs otherwise (`StopEnvironment`, `AcceptInvitation`,
  `RedeemMeshNodeEnrollment`). Server-streaming reads are `Stream*`
  (`StreamLogs`, `StreamExec`); state-change feeds are `Watch*`
  (`WatchEnvironmentCreate`).
- Every method has exactly one `<Method>Request` / `<Method>Response`
  message, even when empty today — wire evolution insurance.
- Fields snake_case; ids are `string` (`environment_id`, `org_id` —
  match the REST path-param names so the migration diff is legible);
  timestamps `google.protobuf.Timestamp`; durations
  `google.protobuf.Duration`; money/quantities as integer minor units
  with a `_cents`/`_bytes` suffix, never floats.
- Enums: zero value `<ENUM>_UNSPECIFIED`; wire values mirror the
  existing REST string enums 1:1 (environment statuses in the docs
  Reference are already a public vocabulary — do not rename).

### Pagination

Every `List*` on `codewire.v1` takes `page_size` + `page_token` and
returns `next_page_token` — even where today's REST returns
unpaginated arrays (servers may return everything in one page; the
*shape* must not need a breaking change later). Until a list is really
paginated, the server returns everything in one page with
`next_page_token = ""` and rejects any non-empty `page_token` with
`invalid_argument` — never silently re-serve page 1 to a client that
thinks it is paginating. Contract suites assert both behaviors (06/07
contract WIs).

### `NO_SIDE_EFFECTS` is a security review gate

Reads carry `option idempotency_level = NO_SIDE_EFFECTS;` (the
protobuf `MethodOptions` enum literal — no `IDEMPOTENCY_LEVEL_`
prefix) — this is what lets Connect serve them as cacheable HTTP GETs.
This annotation is a security review gate, not a hint: a method with
any side effect labeled `NO_SIDE_EFFECTS` becomes reachable by
cookie-bearing GET and therefore a CSRF vector (03 D6b). Proto review
must verify the handler is genuinely read-only before the label lands,
and credential-minting reads never carry it (09's `GetBinding`
precedent).

## JSON compatibility

Proto JSON names are lowerCamelCase of the field names. This is the
curl-facing surface of `codewire.v1` — treat JSON names as public API
from the first release. Never use the `json_name` option to paper over
a bad field name; rename before first release instead.

## Stability postures per package

| Package | `buf breaking` | Process |
|---|---|---|
| `codewire.v1` | FILE (config) + never break post-publish (process) | Additive evolution only; removals require a deprecation cycle |
| `codewire.console.v1` | FILE | Breaking allowed with same-PR client flips |
| `codewire.admin.v1` | FILE | Internal discipline, coordinate in-repo |
| `codewire.internal.v1` | FILE | Coordinate atomic in-repo changes |

During the prelaunch clean cutover, an intentional break must list the exact
pre-change SHA-256 digest and path in
`scripts/checks/contracts/proto-breaking-preimages.sha256`. The same change
must update every generated and handwritten consumer. The ledger is
append-only: only entries added relative to the checked base authorize that
exact change, historical replacements return to strict Buf checking, and a
deleted contract cannot be recreated. This mechanism keeps no compatibility
shim.

## Authentication

`docs/dev/AUTH-POLICY.md` is the canonical credential policy. Proto services do
not define new credential flavors: user-facing product RPCs use the shared
Connect authentication layer for the browser session cookie,
organization-scoped `cw_` API key, or opaque OAuth user bearer; internal
services use only their declared HMAC sidecar boundary.

Missing or invalid credentials map to `unauthenticated`. A valid credential
without the required scope, role, organization binding, or method authority
maps to `permission_denied`. Never encode credentials, scopes, or authorization
booleans into request or response messages merely to bypass the shared
authentication layer.

When an internal service must ask the canonical identity boundary to authorize
an already-authenticated caller, the caller credential stays outside protobuf.
WS18's Mesh authorization hop is the binding pattern: ordinary
`Authorization` authenticates the scoped HMAC service hop; exactly one
reserved sensitive binary metadata entry carries the existing session,
OAuth/API-key, or environment credential; outer middleware removes it before
Connect dispatch and inserts only a typed principal/organization/role/
credential-kind context into request extensions. The raw value is redacting in
memory and may not enter logs, traces, metrics, errors, retries, persistence,
or response metadata. A typed authorization RPC returns the authorized
principal context or a canonical error, never a boolean decision or a new
credential.

## Error model

The full contract (design decisions D1–D6) is
`docs/plans/connect-rpc/01-error-model.md`; this section is the
authoring/consuming summary.

### Server side

Handlers keep returning the one shared error type
(`codewire_server_core::AppError`). Its two renderers — the HTTP
envelope (`error.rs`) and the Connect renderer
(`connect_error.rs::ConnectError`) — derive from the same accessors, so
REST and Connect answers cannot disagree while an area dual-serves.
Never hand-construct Connect codes or details in a handler; raise the
right `AppError` and let the renderer map it.
Authentication failures follow `docs/dev/AUTH-POLICY.md`; they use this same
renderer and detail discipline.

The canonical status→code mapping (D2), total by fallback:

| HTTP today | Connect code |
|---|---|
| 400 malformed request / 422 validation | `invalid_argument` (422 adds `BadRequest.field_violations`) |
| 400 valid request missing required configuration or a lifecycle prerequisite | `failed_precondition` (REST may retain its legacy 400 while the area dual-serves) |
| 401 | `unauthenticated` |
| 403 | `permission_denied` |
| 404 | `not_found` |
| 409 create-collision | `already_exists` |
| 409 lifecycle-state conflict | `failed_precondition` |
| 429 | `resource_exhausted` |
| 502 / 503 | `unavailable` |
| 504 server-enforced deadline | `deadline_exceeded` |
| everything else | `internal` |

Bounded Connect credential resolution is the first
`deadline_exceeded` producer; `aborted` remains reserved for its first
real producer. Detail types are the vendored `google.rpc` messages only
(`proto/google/rpc/`): `BadRequest` for validation (dotted field paths
per D3 — `spec.name`, `ports[0].target`, body root = empty field),
`ErrorInfo` (`domain = "codewire.sh"`, `reason` = the envelope's
machine code in SCREAMING_SNAKE, `metadata` carries `hint` and
`request_id`), `RetryInfo` where a retry delay is actually known —
never fabricated. A Codewire-owned detail type requires its own ADR
note; do not extend the vendored files.

### Client ergonomics (SDK ergonomic layers)

Today's layers surface one typed error per language carrying
`{status, detail, request_id}` (Go `codewire.Error`, TS/Python
`CodewireError`); none parse the 422 envelope's `errors[]` array, and
only the CLI additionally reads `code`/`hint`. The Connect flip is
where field-level violations first become part of each SDK's public
error surface. When a client WI flips an area (05 onward):

- **One typed error per language, evolved not replaced.** The existing
  error type gains the canonical Connect `code` (string form:
  `invalid_argument`, …) alongside `message` and `request_id` — no
  parallel error hierarchy.
- **`BadRequest` violations become a typed slice.** sdk-go returns
  `ValidationError{Field, Message}` entries (a `Violations` accessor on
  the typed error); sdk-ts and sdk-python expose the equivalent
  array/list on theirs. `Field` is the D3 dotted path; empty means the
  body root.
- **Branch on code + field path, never message text** — the same rule
  the HTTP envelope docs give for status + JSON-pointer today.
- **`ErrorInfo` carries the corrective layer.** `reason` is the
  SCREAMING_SNAKE form of today's `code` (CLI branching migrates from
  envelope `code` to `reason`); `metadata["hint"]` is display-only
  corrective text; `metadata["request_id"]` mirrors the
  `x-request-id` header for support tooling.
- **Honor `RetryInfo.retry_delay` when present**; otherwise keep each
  SDK's existing backoff. Absence of `RetryInfo` is not a "do not
  retry" signal — the code (`unavailable`, `resource_exhausted`)
  governs retryability.

## Codegen pipeline

- **Rust (server + client):** pinned contract generation writes two checked-in
  descriptor sets: customer/control-plane contracts in
  `crates/codewire-proto/codewire_descriptor.bin`, and global-administrator
  contracts in `crates/codewire-admin-proto/codewire_admin_descriptor.bin`.
  Each crate feeds only its descriptor to `connectrpc-build`, so ordinary Rust
  and image builds do not invoke ambient `protoc`; a customer binary cannot
  pull billing-admin contracts through `codewire-proto`. Server traits and
  client stubs remain in their audience-specific crate, with client stubs
  behind the default-on `client` feature. New proto files must be added to the
  appropriate crate's `build.rs` list, and `make proto-generate` refreshes
  both descriptor sets.
- **Go:** `protoc-gen-go` + `protoc-gen-connect-go` via
  `proto/buf.gen.codewire.yaml` into the one
  standalone `libs/gen-go/` module. buf managed mode supplies `go_package`
  for the client-facing `codewire.*` packages — those contract files carry no
  language-specific file options (adding one later is itself a breaking FILE
  change).
- **TypeScript:** `protoc-gen-es` v2 writes client-facing `codewire/**` schemas
  and the vendored `google.rpc` error-detail schemas into
  `packages/codewire-proto-ts/src/gen/`; the latter uses the separate local
  `proto/buf.gen.google-rpc-ts.yaml` template so Go/Python output remains
  excluded. connect-es v2 consumes these schemas directly (no separate connect
  plugin exists for v2).
- **Python:** protoc built-in `python`/`pyi` generators (via the
  *pinned* protoc in `.proto-tools/` — their output is
  protoc-version-dependent and checked in) plus
  `protoc-gen-connectrpc` with Google protobuf compatibility (pinned into
  the repo-root `.venv-proto` venv) write `codewire/**` to
  `libs/gen-python/`. The separate local
  `proto/buf.gen.google-rpc-python.yaml` template writes the vendored
  `google.rpc` error-detail messages beside them, so the Python SDK can decode
  standard Connect details without a second schema source or runtime package.
- All plugins pinned + local (`make proto-tools` for Go/Python; the TS
  generator `@bufbuild/protoc-gen-es` is a root `package.json`
  devDependency installed by `bun install`) — no remote buf plugins
  (restricted-network CI).
  Generated code and the Rust descriptor set are checked in; CI regenerates and diffs
  (`make proto-drift-check` locally).
- `buf lint` and `buf breaking --against main` gate every proto change.

## Workflow

```sh
make proto-tools        # install pinned generators (Go plugins, protoc, Python venv)
make proto-lint         # buf lint
make proto-generate     # regenerate all checked-in codegen templates
make proto-drift-check  # CI gate: fails if generated code is stale
```
