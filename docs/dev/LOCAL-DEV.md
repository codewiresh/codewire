# Local Development

This guide covers the non-kind local development loop. Use the local Kind
cluster (see [Local Kind](#local-kind)) when you need the real Kubernetes
sandbox lifecycle, ingress routing, the workspace daemon, tailnet, or local
release proof.

## Current Local Shape

The web interface and control-plane services are Rust-owned. Local development
has two useful modes:

- **Non-kind presentation work:** Postgres from Docker Compose plus the Rust
  dashboard process. Point its typed upstream origins at the focused Rust
  services or a running Kind edge.
- **Rust service work:** run focused Rust binaries (`codewire-idp`,
  `codewire-billing`, `codewire-orchestration`, `codewire-coordinator`) against
  a seeded Postgres and the required supporting services for that slice.

NATS is not part of the default non-kind app loop. The local Rust integration
stack starts private NATS only for realtime fanout smoke coverage, currently
coordinator cross-replica tests. Mesh may also use NATS when it needs
multi-replica realtime node/network fanout. The Rust orchestration lifecycle
path is Temporal-primary, not NATS-consumer-primary.

Caddy is optional local HTTPS edge tooling. It is not used by the default
Docker Compose app loop and it is not part of local kind.

## Prerequisites

- Rust toolchain (`rustup`)
- `protoc`, the Protocol Buffers compiler, which the Rust build runs; set
  `PROTOC` to its path when it is not on `PATH` (CI pins 35.1, see `Makefile`):
  `sudo apt-get install protobuf-compiler` (Debian/Ubuntu),
  `sudo pacman -S protobuf` (Arch), `brew install protobuf` (macOS), or a
  release archive from <https://github.com/protocolbuffers/protobuf/releases>
- Go toolchain
- Bun
- Docker and Docker Compose
- `psql`
- `wasm-pack` when changing the dashboard WASM package
- `kind` and `kubectl` for the cluster path in [Local Kind](#local-kind)
- Temporal CLI when running the local Rust integration stack

## Workspace Layout

Most development can run from this repo alone. Local kind and CI use the
agent-sandbox API/controller pinned by this repo, not an arbitrary sibling
checkout. If `../agent-sandbox` exists, local image builds may reuse it as a Git
object source, but they check out the pinned commit into a temporary worktree.

```text
/src/codewire/
  agent-sandbox/   # optional
  codewire/
```

Update the agent-sandbox pin in lockstep across `.gitea/workflows/ci.yaml` and
the vendored controller/CRD/RBAC manifests under
`deployments/k8s/agent-sandbox/`. Do not rely on `go.work` or a floating sibling
checkout to select the API version; run Go checks with `GOWORK=off` unless a
task explicitly creates a pinned temporary workspace.

The Rust CLI and tailnet modules are inside this repo (`crates/codewire-cli`
and `libs/tailnet`); they are not separate sibling checkouts. `apps/cli` now
holds release/install packaging and the Mesh chart, not a second CLI runtime.

## Non-Kind App Loop

Start Postgres:

```bash
make dev
```

Apply the pending SQLx migrations:

```bash
make db-init
```

Run the Rust dashboard:

```bash
make web
```

For frontend work, use the incremental watcher. It restarts only the local
dashboard when Rust source, Askama templates, or shared design-system
HTML/CSS/JavaScript changes:

```bash
make dashboard-watch
```

Set a different browser port without editing configuration:

```bash
make dashboard-watch DASHBOARD_PORT=5180
```

When the existing `codewire` Kind cluster owns the database and backend
services, use:

```bash
make dashboard-watch-kind
```

That target starts the repository-managed Postgres forward and serves the
incrementally rebuilt UI without rebuilding images or recreating Kind. Stop it
with Ctrl+C before Kind verification. Its exit handler also stops the managed
Postgres forward, releasing the host port used by the disposable Kind topology.

The dashboard listens on port `5173`. By default its orchestration, identity,
and browser API origins are `http://127.0.0.1:8080`, while billing is
`http://127.0.0.1:8081`. Override `CODEWIRE_API_ORIGIN`,
`CODEWIRE_IDENTITY_ORIGIN`, `CODEWIRE_BILLING_ORIGIN`, and
`CODEWIRE_BROWSER_API_ORIGIN` when running a different focused topology. The
public origin must remain the exact browser origin. Access the app at:

```text
http://127.0.0.1:5173
```

Stop the Compose services:

```bash
make dev-down
```

## Focused Rust Service Loop

For Rust service slices, run the specific binary you are working on instead of
the old monolithic-server command. Common ports are:

| Service | Command | Port env |
|---|---|---|
| IdP/auth | `cargo run -p codewire-idp` | `IDP_PORT` |
| Billing | `cargo run -p codewire-billing` | `BILLING_PORT` |
| Orchestration | `cargo run -p codewire-orchestration` | `ORCHESTRATION_PORT` |
| Coordinator | `cargo run -p codewire-coordinator` | `COORDINATOR_PORT` |

All Rust backend services need:

```bash
export DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable"
export SESSION_SECRET="dev-secret-must-change-in-production"
```

Additional slice-specific requirements:

- `codewire-orchestration` requires `TEMPORAL_HOST_PORT`.
- `codewire-billing` enables Stripe paths only when `STRIPE_SECRET_KEY` is set.
- `codewire-coordinator` uses NATS only when `NATS_URL` is set.
- IdP and billing email flows select SES only when the workload-specific
  `CODEWIRE_SES_ENABLED=true` marker, `CODEWIRE_SES_FROM`, and
  `CODEWIRE_SES_REGION` are set. The activated workload also needs its own
  `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` projection; it does not use
  an AWS profile, metadata service, or configured endpoint override. An unset
  or `false` marker selects the legacy Resend rollback sender when
  `RESEND_API_KEY` is present; it sends from `CODEWIRE_RESEND_FROM`, which has
  no default and whose domain the Resend account must have verified
  ([configuration reference](../CONFIGURATION.md)). Leave both delivery credentials unset for local development.
- SES and the Resend rollback sender each make one bounded
  eight-second HTTP attempt. `SendEmail` has no idempotency token, so a timeout
  can still leave delivery uncertain; verification, access, and receipt email
  flows are at-least-once from the recipient's perspective when a caller
  retries.
- Public access requests require both Turnstile values. The dashboard receives
  only the public `TURNSTILE_SITE_KEY` from the dedicated
  `codewire-dashboard-public-config`; the IdP receives `TURNSTILE_SECRET_KEY`
  through its secret projection. Leave both unset for local development. Never
  put the server secret in a ConfigMap.

For an interactive Rust service launcher, use:

```bash
scripts/dev/dev-stack.sh
scripts/dev/dev-stack.sh down
```

That script builds the Rust orchestration and billing services, starts or
reuses private NATS and Temporal as needed, checks both service health probes,
and leaves the processes running. For authoritative selected service proof,
run `scripts/ci/verify/run-integration-verification.sh services`; for the
explicit all-up diagnostic, run
`scripts/ci/verify/rust-stack-rehearsal.sh`.

## Local Kind

Use local kind for the sandbox lifecycle, the workspace daemon, tailnet,
ingress, billing-through-nginx and release proof. Create one retained cluster
and keep iterating on it:

```bash
make kind-up                         # create and deploy the retained cluster
make kind-status
make kind-deploy SERVICE=orchestration   # rebuild one service from source
make kind-watch                      # serve the dashboard from source
make kind-test                       # the Kind suites the changed paths select
make kind-down
```

Never recreate the cluster to test a change; `make kind-deploy` replaces only
the services whose source differs from what the cluster runs. The ingress
listens on `http://127.0.0.1:8080`; run `make seed-e2e-users` once for the
documented manual-login identities.

After changing dashboard behavior, run the Playwright suite through that
cluster:

```bash
make test-ui-kind
```

This is the local browser development loop. It proves real Rust dashboard
sign-in/session handling and the organization/environment lifecycle against
the same Kind services and database; it does not replace those services with
browser mocks. See [../TESTING.md](../TESTING.md) for the suite.

`make e2e-kind` runs the full product gate in its own throwaway cluster. It
is not an iteration step; run it only when a change needs the whole gate.

## Optional Caddy Edge

If you need HTTPS with `.localhost` domains:

```bash
caddy run --config Caddyfile
```

Or run the same edge config in Docker:

```bash
docker run --rm --network host \
  -v "$PWD/Caddyfile.docker:/etc/caddy/Caddyfile:ro" \
  -v codewire_caddy_data:/data \
  -v codewire_caddy_config:/config \
  caddy:2-alpine
```

This is optional local edge tooling only.

## Database

The local development database URL used by `make dev` is:

```bash
export DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable"
```

Reset a local database by recreating the Compose volume, then reapply the
SQLx history:

```bash
docker compose down -v
make dev
make db-init
```

## Troubleshooting

Check Compose service status:

```bash
docker compose ps
```

If the dashboard cannot reach a service, confirm the configured
`CODEWIRE_API_ORIGIN`, `CODEWIRE_IDENTITY_ORIGIN`, and
`CODEWIRE_BILLING_ORIGIN` are listening. Use the coherent Kind path for login
or cross-service behavior instead of combining the dashboard with absent
default upstreams.

If Rust services fail on startup, check the required environment variables
first: `DATABASE_URL`, `SESSION_SECRET`, and any slice-specific dependency such
as `TEMPORAL_HOST_PORT`.
