# Codewire Glossary

Status: current, canonical terminology

Use these terms consistently in repo docs.

## Organization

The main account boundary for billing, membership, secrets, and environment ownership.

## Environment

The canonical product object. An environment is an isolated development machine for agents and developers.

Environments have a lifecycle: pending, creating, starting, running, stopping, stopped, deleting, deleted, failed, suspended, and related operational states.

## Stored material

A protected value at rest. Storing material does not expose it to an
environment and does not select how it will be used.

## Secret-blind execution

The target default for new secret delivery. A process receives only the
non-secret configuration needed to exercise explicitly bound capabilities. AV
adds protected material at the allowed operation boundary; the process cannot
read or export it. A placement must not claim this property until its runtime
boundary enforces it.

## Environment projection

The child-visible values assembled for one process launch after an explicit raw
binding. A projection is ephemeral, is not a workload-readable shared file,
and cannot restore a workspace or VM. It reuses the owning runtime operation's
identity; there is no separate secret-generation history. This capability is
not implemented yet.

## Credential integration

A typed AV adapter that uses protected material without giving that material to
the workload. Examples include an HTTP credential proxy, request signer, or
repository executor. The credential provider is the service being accessed,
such as OpenAI or GitHub; the protected store is its material source, not its
provider.

## AV proxy helper

Reusable edge code, not a secrets database or a separately named control
plane. It gives a child a credential-free local endpoint and manages bounded
relay/session lifecycle. The trusted broker outside the sandbox remains the
only process that may resolve material, inject authorization, own a private CA
key, or open the credential-bearing provider connection. Extraction of this
library is planned; the existing local Codex bridge is its first Codewire
building block.

## Workspace storage

The live, mutable files owned by an environment. It survives an ordinary stop
or restart, but it is not an immutable point-in-time copy and is not a
snapshot.

## Snapshot

Saved state that Codewire can reuse or restore. Always qualify what was saved:
a skill snapshot, workspace snapshot, or environment snapshot. Only skill
snapshots are implemented today.

## VM checkpoint

Saved running-VM execution state, including memory and device state. A
checkpoint is backend-specific and is not an environment projection. Codewire
does not implement VM checkpoints yet.

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
`CODEWIRE_MESH_INVITE_CODE`, `mesh_url`, `mesh_auth_token`, and
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
