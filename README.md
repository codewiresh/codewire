# Codewire

Agent-ready sandbox environments. Open source under AGPL-3.0-only.

## What it is

Codewire orchestrates sandbox environments on Kubernetes via the `agent-sandbox` CRD operator. Each environment is a long-lived development environment that users or AI agents can SSH into, exec inside, transfer files into, and tunnel ports through.

This repository contains the control plane, dashboard, CLI, SDKs, and generated API types for that stack.

## Repo layout

```
apps/
  api/         Go support module: database schema, e2e tests, and temporary parity oracle
  dashboard/   Vite/React web UI
  docs/        Starlight documentation site
  desktop/, ios/, mobile/  client apps

libs/
  daemon/             shared gateway↔daemon protocol types
  gatewayauth/        JWT helpers shared between API and gateway
  gateway-proto/      Connect proto + generated Go (gateway.v1, daemon.v1)
  sdk-go/, sdk-ts/, sdk-python/  language SDKs (consume the OpenAPI surface)
  sdk-examples/       end-to-end SDK parity smoke (run-claude)
  tailnet/            Tailscale userspace helpers

crates/        Rust workspace for services, CLI, desktop, and shared clients
deployments/   k8s manifests + kustomize overlays
docs/          stable docs + planning notes
```

## Quick start

### Local kind control plane

```bash
# Interactive development cluster
make up

# Separate isolated Rust-owned product gate
make e2e-kind
```

The interactive local kind ingress listens on `http://127.0.0.1:8080`; the e2e
gate creates and deletes its own cluster. Use `docs/dev/KIND-E2E.md` for the
full local cluster workflow.

### Local sandbox environment (CLI)

```bash
# Build the CLI
cargo build -p codewire-cli-bin --bin cw

# Create a named local environment from the workspace image.
./target/debug/cw env --local create \
  --backend lima \
  --name codewire-dev \
  --image workspace \
  --path .

# Run a durable session in that environment.
./target/debug/cw run codewire-dev -- bash

# Inspect and manage the same environment through the unified lifecycle.
./target/debug/cw env --local info codewire-dev

# Resize a Lima environment. A terminal shows the current-to-desired plan,
# active-session warning, and a default-no confirmation before the restart.
./target/debug/cw env --local resize codewire-dev --cpu 6 --memory 12Gi --disk 120Gi

# Automation must provide explicit resources and --yes.
./target/debug/cw env --local resize codewire-dev --cpu 6 --yes --output json
```

`cw env resize ENV` resolves the placement when it is unambiguous. Local resize
currently supports Lima only; it stops and restarts a running VM without
recreating it, and disk growth cannot be reversed. Platform resize is tracked
separately in #860.

### Local database and dashboard loop

```bash
make dev           # Start local Postgres
make db-init       # Apply the baseline schema
make web           # Run the dashboard dev server
```

### SDK tests

```bash
make test-sdk      # Typecheck + unit tests across Go, Python, TypeScript SDKs
```

## Architecture (one-paragraph)

The **control plane** (`codewire`) accepts API requests, manages environment lifecycle, integrates with Kubernetes via the `agent-sandbox` CRD, handles billing, and exposes OIDC. Each running environment is a pod containing a workspace container + a **gateway** sidecar; the gateway routes SSH/SCP/SFTP from outside the cluster to a **daemon** running alongside user code. Gateway↔daemon talks over Connect-RPC. The web dashboard and the `cw` CLI are first-class clients of the control plane.

## Status

Codewire is pre-1.0. The OSS surface is stable enough to run and contribute against but breaking changes can land between releases. Architectural direction and current work tracked in [docs/plans/](docs/plans/) and on the issue tracker.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — stable architecture summary
- [docs/GLOSSARY.md](docs/GLOSSARY.md) — canonical terms
- [docs/dev/CODEWIRE-APP-GUIDE.md](docs/dev/CODEWIRE-APP-GUIDE.md) — internal engineering guide
- [docs/plans/](docs/plans/) — design proposals + in-flight architecture work

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

Codewire is licensed under AGPL-3.0-only. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
