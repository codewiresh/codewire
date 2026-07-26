# Tailnet Go/Rust Parity Harness

Status: active fixture layer. The peer-relay fixture rollout shipped through
Gitea #327 and #257; Go-peer checksum and MTU parity follow-up is tracked by
Gitea #375.

## Purpose

The Go tailnet remains the compatibility oracle until the Rust tailnet proves
and keeps parity. This is not only a one-time porting aid: `libs/tailnet` and
the Tailscale module it wraps can keep changing, and those changes must either
be accepted into Rust intentionally or rejected with an explicit compatibility
decision.

The harness should catch drift in four places:

- protocol fixtures: disco, DERP framing, UDP peer-relay descriptors, path
  classification
- coordinator lifecycle: repeated peer updates, peer removal, DERP-map changes,
  node republish after local endpoint changes
- tunnel behavior: TCP bytes over WireGuard through DERP, direct UDP, and peer
  relay
- product smoke: `cw doctor`, `cw shell`, `cw run`, websocket fallback, and
  Docker/Postgres inside a commodity guest

## Oracle Sources

Use these remaining Go and Rust sources as the parity target:

- `libs/tailnet/conn_test.go`
- `libs/tailnet/path_test.go`
- `crates/codewire-cli/src/tailnet_ssh.rs`
- `crates/codewire-cli/src/lib.rs` (`cw doctor tailnet`)

Do not copy every Go implementation detail. Copy the behavioral contract:
which packets are accepted, which paths are reported, how repeated updates are
handled, and which fallback must still work.

## Layers

### 1. Fast Fixtures

Fast fixtures run on normal PRs touching `libs/tailnet`,
`crates/codewire-tailnet`, `crates/codewire-gateway`, gateway orchestration, or
CLI tailnet code.

Current checked-in shape:

- Go oracle: `libs/tailnet/parity_fixture_test.go`
- Fixture: `tests/fixtures/tailnet/go_tailnet_parity.json`
- Rust consumer: `crates/codewire-tailnet/src/conn/tests.rs`
  `go_tailnet_parity_fixture_matches_rust_contracts`

The fixture also records oracle metadata: the pinned `tailscale.com` module
version and SHA-256 fingerprints of the core Go tailnet source files
(`conn.go`, `coordinator.go`, `derp.go`, `node.go`, and `path.go`). This is
intentional. A future Go tailnet or Tailscale update must create an explicit
fixture diff so the Rust port review can decide whether the behavior is still
compatible, even if the first fixture cases happen to serialize the same
outputs.

The first behavior fixture covers path transport labels, Go path precedence,
ULA prefix derivation, and `Node` JSON encoding. It is intentionally small; it
establishes the regeneration and review workflow before we add the higher-risk
disco and peer-relay lifecycle fixtures.

Run the current fixture gate:

```sh
scripts/ci/verify/tailnet-parity.sh
```

Regenerate the Go fixture after an intentional Go/Tailscale behavior change:

```sh
cd libs/tailnet
UPDATE_TAILNET_PARITY_FIXTURES=1 GOWORK=off go test ./... -run TestTailnetParityFixture -count=1
```

Then update the Rust consumer in the same PR if the contract changed. If only
the oracle metadata changed, keep the fixture diff and explain why the existing
Rust contract remains compatible.

Target shape:

- Go fixture generator test emits checked-in JSON fixtures under
  `tests/fixtures/tailnet/`.
- Rust tests consume the same fixtures.
- Fixture updates are explicit and reviewed in the same PR as the behavior
  change.

Initial fixture groups:

- path classification: `direct_udp`, `udp_relay`, `derp`, `unknown`; legacy
  fixture aliases `peer_relay` and `derp_relay` remain accepted only where the
  Go oracle still emits them
- safe tailcfg node display/capability metadata
- disco sealed round trips and wrong-recipient rejection
- UDP peer-relay descriptors, bind lifetimes, VNI, and address lists
- coordinator peer update accumulation and peer removal
- coordinator websocket heartbeat while idle

### 2. Hermetic Interop

Hermetic interop runs locally and in targeted CI without a Kubernetes cluster.

Expected shape:

- Rust DERP client against the `codewire-derp` server binary.
- Rust `Conn` to Rust `Conn` tunnel over the same transport ladder.
- Rust STUN-derived direct UDP tunnel with no static advertised endpoints:
  `cargo test -p codewire-tailnet conn_tunnel_uses_stun_discovered_direct_udp_path_without_static_endpoints`.
- Go fixture/client to Rust gateway/tailnet where practical.
- Repeated coordinator `peer_update` messages must not churn an active
  peer-relay allocation or invalidate the selected VNI mid-stream.

These tests must prove bytes move, not just that the reported path shape looks
right.

### 3. Dev Smoke

Dev smoke is the live product proof. It should stay out of the generic KIND
gate unless the change directly needs KIND.

Required dev evidence for #257:

- no per-sandbox direct-UDP NodePort Services
- `cw doctor tailnet --expect udp_relay`
- normal `cw shell`
- `cw run <environment> -- <command>`
- forced DERP path reports `derp` and is ready
- websocket fallback
- Docker, compose/network, and Postgres inside the commodity guest

### 4. Drift Audit

When `libs/tailnet`, Rust `cw`, or the pinned Tailscale module changes:

1. Run the Go tailnet tests.
2. Regenerate tailnet fixtures if the Go behavior intentionally changed.
3. Run Rust fixture consumers and hermetic interop.
4. If Rust cannot match the behavior yet, keep the fixture update and Rust
   implementation in the same tracked issue/PR or mark the change as an
   intentional incompatibility in #327.

## Current Fixed Regression Gates

The 2026-07-02 peer-relay live proof fixed one concrete parity gap: repeated
coordinator peer updates must be idempotent while a relay allocation is pending
or fresh. The Rust gateway now has
`peer_relay_allocation_tracker_rate_limits_repeated_peer_updates`, and the
dev/node1 smoke proved normal `peer_relay`, forced `derp_relay`, websocket,
environment command execution, and Docker/Postgres after coordinator updates
during real SSH.

The 2026-07-03 dev smoke for PR #374 fixed two stacked Rust/Go interop gaps:

- the Rust tunnel emitted TCP packets without transmit checksums, which
  Rust-to-Rust smoltcp tests accepted but the Go/Tailscale peer dropped before
  gVisor saw the stream
- the tunnel MTU allowed relay datagrams that exceeded the cross-node pod
  network budget after WireGuard and relay overhead; same-node Kubernetes
  routing could mask the failure

Those regressions define the next parity gates, tracked by Gitea #375:

- Rust-emitted tunnel packets need a Go-peer-style checksum verifier in the
  fast harness
- TCP stream tests need to cover maximum segment behavior over DERP and peer
  relay with the production tunnel MTU
- live smoke evidence for transport changes must include a cross-node relay
  topology, normal tailnet, forced DERP, websocket fallback, and Docker/Postgres
  only after the SSH stream gates pass

The checked-in CI gate is `scripts/ci/verify/tailnet-parity.sh`. It runs the Go
fixture oracle and the full `codewire-tailnet` Rust test suite, including:

- `loopback_packets_carry_go_verifiable_checksums`
- `production_tunnel_mtu_fits_cross_node_peer_relay_budget`
- `channel_shim_max_segment_stream_stays_under_peer_relay_budget`
- `conn_tunnel_uses_verified_peer_relay_path`

Keep expanding the harness with Go-client-to-Rust-gateway interop tests where
practical. Live smoke remains the product gate for full `cw shell` behavior
until that hermetic interop layer exists.
