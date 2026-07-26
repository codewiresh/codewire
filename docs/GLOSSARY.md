# Codewire Glossary

Status: current, canonical terminology

Use these terms consistently in repo docs.

## Organization

The main account boundary for billing, membership, secrets, and environment ownership.

## Environment

The canonical product object. An environment is an isolated development machine for agents and developers.

Environments have a lifecycle: pending, creating, starting, running, stopping, stopped, deleting, deleted, failed, suspended, and related operational states.

## Session

A running process inside an environment, often an AI agent or shell command.

## Preset

Defaults for creating environments, including runtime image, CPU, memory, disk, commands, and ports.

## API Key

A `cw_` prefixed key for programmatic access. SHA-256 hashed, prefix-based lookup. Used by SDKs and CLI.

## Sandbox

The native runtime backing Codewire environments. Sandboxes are backed by
Agent Sandbox CRDs, a Codewire runtime profile, and Guard controls.

## Codewire Guard

The in-repo defense-in-depth layer around sandbox runtime profiles. Runtime
profiles are `runc`, `commodity`, and `confidential`; `runc` is diagnostic
or bootstrap only for managed sandboxes.

## Codewire Mesh

The hosted or self-hosted node network control plane used by the CLI and
environment runtime for remote access, node discovery, membership, access
grants, and task/reporting coordination.

Rust CLI config and environment inputs are Mesh-only: use
`CODEWIRE_MESH_URL`, `CODEWIRE_MESH_AUTH_TOKEN`, `CODEWIRE_MESH_NETWORK`,
`CODEWIRE_MESH_INVITE_TOKEN`, `mesh_url`, `mesh_auth_token`, and
`mesh_selected_network`.

## Network

A membership scope inside Codewire Mesh. Networks group users and nodes that
may discover and reach each other.

Do not use `network` as a synonym for the whole hosted service.

## Relay

A transport role that forwards traffic when direct peer connectivity is not
available. DERP relay and UDP peer relay are data-plane relay terms.

Do not use bare `relay` as the user-facing name for the hosted control service.

## isol8

A separate Xen runtime project. It is useful for cloud-VM experiments and
historical reference, but it is not an approved managed Codewire runtime
profile.

## Tenant

Legacy or internal implementation term.

Use `tenant` only when referring to:

- existing database/table names
- current provisioning internals
- older implementation details that still use that name in code

Do not use `tenant` as the preferred product term in new top-level docs.

## SDK

Official client libraries for the Codewire API. Shipped in a separate repo: [`codewiresh/sdk`](https://github.com/codewiresh/sdk).

- TypeScript: `@codewire/sdk`
- Go: `codewire.sh/sdk-go`
- Python: `codewire`
