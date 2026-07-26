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
| `codewire-server-core`  | Shared backend chassis: HTTP scaffold, auth, error envelope, tracing, DB/NATS helpers. | AGPL-3.0 |
| `codewire-idp`          | OIDC provider service (bin) — wires `codewire-oidc` to Postgres and the session/org model. | AGPL-3.0 |
| `codewire-orchestration`| Environment lifecycle: reconciliation, sandbox client, Temporal worker (bin).    | AGPL-3.0 |
| `codewire-billing`      | Billing service (bin): catalog, plans, Stripe webhooks.                          | AGPL-3.0 |
| `codewire-coordinator`  | Coordinate service (bin): peer/session fan-out over WebSocket + Connect.          | AGPL-3.0 |
| `codewire-mesh`         | Hosted Codewire Mesh node/network control plane (bin).                            | AGPL-3.0 |

### Networking & tunnel

| Crate                  | Role                                                                               | License      |
| ---------------------- | ---------------------------------------------------------------------------------- | ------------ |
| `codewire-gateway`     | Sandbox gateway (bin): SSH/tailnet adapter, Connect-RPC to the daemon.             | AGPL-3.0     |
| `codewire-daemon`      | Workspace daemon (bin): exec, PTY, and file RPCs inside the sandbox.               | AGPL-3.0     |
| `codewire-derp`        | DERP relay core (bin).                                                             | MIT¹         |
| `codewire-udp-relay`   | UDP peer-relay allocation and forwarding (bin).                                    | AGPL-3.0     |
| `codewire-tailnet`     | Tailscale-style tailnet client: WireGuard (boringtun) + DERP + coordinator client. | BSD-3-Clause |
| `codewire-network-auth`| Mesh runtime credential and delegation tokens.                                    | MIT¹         |

### Contract & shared types

| Crate                   | Role                                                            | License  |
| ----------------------- | -------------------------------------------------------------- | -------- |
| `codewire-types`        | Pure shared types and functions (no tokio, WASM-safe).         | MIT¹     |
| `codewire-api-types`    | Generated Rust models for the OpenAPI surface.                 | MIT¹     |
| `codewire-api-contract` | Rust-owned OpenAPI contract assembly helpers.                  | AGPL-3.0 |
| `codewire-proto`        | Generated Connect-RPC contract types for the control-plane API. | AGPL-3.0 |
| `codewire-gateway-proto`| Generated protobuf types for the gateway/daemon boundary.      | AGPL-3.0 |

### Auth library

| Crate           | Role                                                                                       | License            |
| --------------- | ------------------------------------------------------------------------------------------ | ------------------ |
| `codewire-oidc` | Standalone OIDC/OAuth2 provider library — storage-trait based, transport-agnostic, optional axum. | MIT OR Apache-2.0 |

### CLI

| Crate              | Role                          | License |
| ------------------ | ----------------------------- | ------- |
| `codewire-cli`     | `cw` CLI implementation.       | MIT¹    |
| `codewire-cli-bin` | `cw` CLI binary wrapper (bin). | MIT¹    |

### Desktop app (excluded from the root workspace)

| Crate                      | Role                                                       | License |
| -------------------------- | ---------------------------------------------------------- | ------- |
| `codewire-core`            | Platform-agnostic app business logic.                      | MIT¹    |
| `codewire-ui`              | Reusable GPUI components.                                  | MIT     |
| `codewire-platform-native` | Native platform impls (reqwest, russh, keyring).          | MIT     |
| `codewire-desktop`         | GPUI desktop app entrypoint (bin).                        | MIT     |

Licenses are set per crate. The workspace default is **MIT** (`[workspace.package]
license` in the root `Cargo.toml`); backend service crates set **AGPL-3.0** explicitly.
Crates marked **¹** omit an explicit license and inherit the MIT default via
`license.workspace = true` — including `codewire-derp`, a server-side relay, which is
worth reconciling with its AGPL-3.0 siblings.

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
license = "AGPL-3.0"
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
