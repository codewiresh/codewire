# Contract testing

Contract tests talk to running Codewire services over real network listeners
and assert only externally observable behavior: status codes, Connect codes and
details, protocol handshakes, response shapes, and stream framing. Product
correctness is owned by the current product implementation, which is Rust.

## Why

Black-box tests keep the wire boundary honest without coupling assertions to
handler internals. Their language is not what creates independence: a real
listener and externally observable assertions do. Language-specific suites are
reserved for behavior that actually promises interoperability to that language.

## Policy

The Rust-owned black-box suite is the authority for Rust service behavior.
Adding or changing behavior means changing proto first where applicable and
adding current-owner wire coverage in the same WI. While an area dual-serves
REST and Connect, the same Rust suite must prove both transports answer from the
same service semantics. After REST deletion, its parity assertions are deleted
with that route rather than preserved as historical behavior.

Go has two explicit, narrower roles:

- generated Connect client and ergonomic SDK interoperability, selected for
  proto/generated-Go/Go-SDK or release changes; and
- Tailscale Go-client transport interoperability plus the bounded Go Tailnet
  differential diagnostic, selected only for the relevant transport surface or
  dispatched manually.

Neither is a complete Rust-server acceptance suite. The deleted Go product
implementation is not an oracle or specification.

## Rules for suites

- Keep one Rust-owned black-box area per service or audience package.
- Do not import a service's private implementation modules. Shared generated
  proto messages and generated clients are contract artifacts, not service
  internals.
- Selected CI must reject skips and zero executed tests. Developer convenience
  may permit an unset base URL only outside a selected gate.
- Assert only what every implementation must guarantee. Log formats, header
  ordering, and timing are not contract.
- Keep reusable authentication, Connect framing, canonical error-detail, and
  process/listener support in one Rust harness.
- Keep browser-only semantics in connect-es/Playwright, not a synthetic Go
  browser driver.
- Never depend on `apps/api`, a retired implementation package, or fixtures
  whose authority is defined as matching the former implementation.

## Current inventory

| Existing suite | Service | Disposition |
|---|---|---|
| `crates/codewire-server-core/tests/connect_{mount,auth,stream}.rs` | shared Connect serving infrastructure | Rust-owned serving, auth, error, and stream matrix |
| `crates/codewire-orchestration/tests/wire_contract.rs` | codewire-orchestration | Rust-owned real-listener contract |
| `crates/codewire-billing/tests/wire_contract.rs` | codewire-billing | Rust-owned real-listener Connect contract; both codecs, auth, retained reads, catalog authorization, and retired REST absence |
| `crates/codewire-coordinator/tests/wire_contract.rs` | codewire-coordinator | Rust-owned real-listener HTTP, WebSocket, Connect, auth, and peer-exchange contract |
| `crates/codewire-orchestration/src/bin/file-service-smoke.rs` | FileService | Rust-owned generated-client streaming, backend-selection, and framing Kind contract |
| `tests/contract/derp` | codewire-derp | Keep the real Tailscale Go-client cases as transport interoperability |
| `crates/codewire-orchestration/src/bin/deploy-shape-smoke.rs` | Connect create and Temporal/Port-DNS dispatch | Rust-owned all-up deploy-shaped proof; historical Go workflow-failure expectations are not product behavior |
| `libs/gen-go/interop` through `crates/codewire-server-core/tests/go_consumer_interop.rs` | generated Go client against the Rust Connect probe | Retain as the selected unary/error/stream Go-consumer proof, not service completeness |

The WI-C11A assertion map for the removed Go `connectcore` suite is:

| Removed Go assertion | Current Rust authority |
|---|---|
| public unary JSON and response request id | `connect_mount::unary_json_roundtrip_with_standard_middleware` and `public_ping_and_admin_ping_are_mounted` |
| generated-client binary Connect unary | `connect_mount::coordinator_policy_accepts_connect_and_native_grpc_but_never_grpc_web` and `h2c_prior_knowledge_request_served` |
| session cookie and `cw_` API-key auth | `connect_auth::connect_auth_matrix` |
| explicit `NO_SIDE_EFFECTS` Connect GET and private cache posture | `connect_mount::connect_get_served_for_no_side_effects_read` and `connect_auth::connect_auth_matrix` |
| canonical unauthenticated and permission-denied errors with `ErrorInfo` and request id | `connect_auth::connect_auth_matrix` and `admin_mount_gates_whole_service` |
| admin success | `connect_auth::connect_auth_matrix` |
| invalid argument with `BadRequest` field violation | `connect_auth::connect_auth_matrix` |
| incremental server streaming | `connect_stream::stream_ping_arrives_incrementally` |

The Rust authority additionally covers OIDC scope/expiry, raw-session-bearer
transition behavior, whole-service admin mounts, auth-before-dispatch ordering,
bounded stalled lookups, protocol/content-type policy, h2c, deadlines, panic
containment, request telemetry, and streaming anti-buffering. WI-C11A therefore
removes duplication without dropping a current contract assertion.

## Connect-RPC suites

The Rust tests `connect_mount`, `connect_auth`, and `connect_stream` are the
wire contract for the shared Connect serving stack
(`docs/plans/connect-rpc/03`): unary over both Connect codecs, Connect GET for
`NO_SIDE_EFFECTS` reads, the auth mount modes, and the 01 error model on the wire
(`unauthenticated` / `permission_denied` / `invalid_argument` with
`google.rpc.ErrorInfo` / `google.rpc.BadRequest` details, request id
mirrored into `ErrorInfo.metadata`). They drive the same D8 probe service
(`codewire.testing.v1.PingService`) mounted by real services with
`CONNECT_TESTING_SURFACE=1`. Selected service integration runs the PostgreSQL-
backed Rust matrix and directly probes each enabled service binary; it fails on
a skip or an empty test count.

While an area dual-serves REST and Connect, both answer from the same service
layer and the area's Rust-owned suites must be green on both before clients flip
(`docs/plans/connect-rpc/00-MASTER.md`, gate G4/G5). Per-service Connect
suites (api-keys first, `docs/plans/connect-rpc/05`) build on
the Rust shared harness rather than re-proving the serving stack.
