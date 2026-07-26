# `crates/`

Rust crates for Codewire. The root `Cargo.toml` is the server/runtime/shared
workspace and intentionally lists members explicitly. Desktop app crates live
under `crates/` too, but are excluded from the root workspace so GPUI/font-kit
are only resolved when building the desktop app explicitly.

## Layout

A `(bin)` marker means the crate produces a service/app binary.

### Backend services & chassis

| Crate                   | Role                                                                              | License  |
| ----------------------- | -------------------------------------------------------------------------------- | -------- |
| `codewire-server-core`  | Shared backend chassis: HTTP scaffold, auth, error envelope, tracing, DB/NATS helpers. | AGPL-3.0-only |
| `codewire-idp`          | OIDC provider service (bin) — wires `codewire-oidc` to Postgres and the session/org model. | AGPL-3.0-only |
| `codewire-orchestration`| Environment lifecycle: reconciliation, sandbox client, Temporal worker (bin).    | AGPL-3.0-only |
| `codewire-billing`      | Billing service (bin): catalog, plans, Stripe webhooks.                          | AGPL-3.0-only |
| `codewire-coordinator`  | Coordinate service (bin): peer/session fan-out over WebSocket + Connect.          | AGPL-3.0-only |
| `codewire-mesh`         | Hosted Codewire Mesh node/network control plane (bin).                            | AGPL-3.0-only |

### Networking & tunnel

| Crate                  | Role                                                                               | License      |
| ---------------------- | ---------------------------------------------------------------------------------- | ------------ |
| `codewire-gateway`     | Sandbox gateway (bin): SSH/tailnet adapter, Connect-RPC to the daemon.             | AGPL-3.0-only |
| `codewire-daemon`      | Workspace daemon (bin): exec, PTY, and file RPCs inside the sandbox.               | AGPL-3.0-only |
| `codewire-derp`        | DERP relay core (bin).                                                             | BSD-3-Clause  |
| `codewire-udp-relay`   | UDP peer-relay allocation and forwarding (bin).                                    | AGPL-3.0-only |
| `codewire-tailnet`     | Tailscale-style tailnet client: WireGuard (boringtun) + DERP + coordinator client. | BSD-3-Clause |
| `codewire-network-auth`| Mesh runtime credential and delegation tokens.                                    | AGPL-3.0-only |

### Contract & shared types

| Crate                   | Role                                                            | License  |
| ----------------------- | -------------------------------------------------------------- | -------- |
| `codewire-types`        | Pure shared types and functions (no tokio, WASM-safe).         | MIT             |
| `codewire-api-types`    | Generated Rust models for the OpenAPI surface.                 | MIT             |
| `codewire-api-contract` | Rust-owned OpenAPI contract assembly helpers.                  | AGPL-3.0-only   |
| `codewire-client`       | Shared ergonomic Rust client over generated Connect-RPC stubs. | AGPL-3.0-only   |
| `codewire-proto`        | Generated Connect-RPC contract types for the control-plane API. | AGPL-3.0-only   |
| `codewire-gateway-proto`| Generated protobuf types for the gateway/daemon boundary.      | AGPL-3.0-only   |

### Auth library

| Crate           | Role                                                                                       | License            |
| --------------- | ------------------------------------------------------------------------------------------ | ------------------ |
| `codewire-oidc` | Standalone OIDC/OAuth2 provider library — storage-trait based, transport-agnostic, optional axum. | MIT OR Apache-2.0 |

### CLI

| Crate              | Role                          | License |
| ------------------ | ----------------------------- | ------- |
| `codewire-cli`     | `cw` CLI implementation.       | AGPL-3.0-only |
| `codewire-cli-bin` | `cw` CLI binary wrapper (bin). | AGPL-3.0-only |

### Desktop app (excluded from the root workspace)

| Crate                      | Role                                                       | License |
| -------------------------- | ---------------------------------------------------------- | ------- |
| `codewire-core`            | Platform-agnostic app business logic.                      | MIT     |
| `codewire-ui`              | Reusable GPUI components.                                  | MIT     |
| `codewire-platform-native` | Native platform impls (reqwest, russh, keyring).          | MIT     |
| `codewire-desktop`         | GPUI desktop app entrypoint (bin).                        | MIT     |

The root workspace default is **AGPL-3.0-only**. `codewire-cli`,
`codewire-cli-bin`, and `codewire-network-auth` intentionally inherit that
default. Every permissive crate declares an explicit override, and every crate
directory carries the applicable license text.

`codewire-tailnet` and `codewire-derp` remain BSD-3-Clause as standalone
crates. Their current dependency graph includes the AGPL-3.0-only
`codewire-proto`; a combined distribution must therefore satisfy the
AGPL-3.0-only obligations for the combined work. A package's permissive
metadata does not relicense its dependencies.

## Adding a server crate

```sh
cargo new --lib crates/codewire-billing
```

Then in `crates/codewire-billing/Cargo.toml`:

```toml
[package]
name = "codewire-billing"
version.workspace = true
edition.workspace = true
authors.workspace = true
license = "AGPL-3.0-only"
description = "Billing service: Stripe webhooks, plans, usage."

[dependencies]
codewire-server-core = { workspace = true }
axum = { workspace = true }
sqlx = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
anyhow = { workspace = true }
```

A minimal `main.rs`:

```rust
use codewire_server_core::{AppBuilder, ServiceConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ServiceConfig::from_env("billing")?;
    codewire_server_core::obs::init(&cfg)?;
    let pool = codewire_server_core::db::connect(&cfg.database_url).await?;

    let app = AppBuilder::new("codewire-billing")
        .with_health_and_db(pool)
        // .with_routes(my_routes(...))
        .into_router();

    codewire_server_core::serve(app, cfg.bind_addr).await
}
```

That's the whole boilerplate — HTTP server, request IDs, CORS, tracing, panic
recovery, `/healthz` + `/readyz` (with DB ping), and the typed error envelope
are all wired up by `codewire-server-core`.

## Working in the workspace

```sh
# Server/runtime/shared crates.
cargo build --workspace

# A single crate, fast.
cargo build -p codewire-server-core

# Desktop app, explicit because it pulls GPUI/native desktop deps.
cargo build --manifest-path crates/codewire-desktop/Cargo.toml
```

## Tests

`codewire-server-core` carries unit tests for each module plus an integration
test that spins up the full `AppBuilder` router on a random port and asserts
the error-envelope wire shape matches what the SDKs read. Per-service crates
should follow the same pattern: unit tests close to the code, an integration
test that hits the public HTTP surface end-to-end.
