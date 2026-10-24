# Codewire Glossary

Status: current, canonical terminology

Use these terms consistently in repo docs.

## Organization

The main account boundary for billing, membership, secrets, and environment ownership.

## Environment

The canonical product object. An environment is an isolated development machine for agents and developers.

Environment states are `pending`, `pending_build`, `building`,
`build_failed`, `pulling_snapshot`, `creating`, `starting`, `running`,
`stopping`, `stopped`, `archiving`, `archived`, `restoring`, `resizing`,
`destroying`, `destroyed`, `error` and `unknown`. See
[ARCHITECTURE.md](ARCHITECTURE.md).

## Placement

Where an environment runs: a hosted sandbox on the platform, a local VM on
the user's machine, or a trusted host session as the user's own account.

## Application secret

A named application value, such as `DATABASE_URL`, stored in a user,
organization or project secret source. Selecting a source for an environment
injects its values into managed processes under their original names; those
processes and the environment's root can read them.

## Provider credential

A named identity for an external provider (Codex/OpenAI, Anthropic, GitHub,
an SSH key). Its private material stays outside the sandbox behind a typed
proxy, signer or repository executor, except for the listed direct delivery
exceptions in `dev/SECRETS-AND-CREDENTIALS.md`.

## Credential profile

A named selection of provider identities. A profile contains no
application-secret mappings or exposure rules. Storing a credential does not
attach it to an environment; selecting a profile does.

## Stored material

A protected value at rest. Storing material does not expose it to an
environment and does not select how it will be used.

## Environment projection

The child-visible values assembled for one process launch from the selected
application-secret sources. A projection is ephemeral, is not a
workload-readable shared file, and cannot restore a workspace or VM. It reuses
the owning runtime operation's identity; there is no separate
secret-generation history.

## Credential integration

A typed adapter that uses protected material without giving that material to
the workload. Examples include an HTTP credential proxy, request signer, or
repository executor. The credential provider is the service being accessed,
such as OpenAI or GitHub; the protected store is its material source, not its
provider.

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
Sessions are durable: they outlive the client that launched them.

## Preset

Defaults for creating environments, including runtime image, CPU, memory, disk, commands, and ports.

## API Key

A `cw_` prefixed key for programmatic access. SHA-256 hashed, prefix-based lookup. Used by SDKs and CLI.

## Sandbox

The native runtime backing hosted Codewire environments. Sandboxes are backed
by Agent Sandbox CRDs, a Codewire runtime profile, and Guard controls.

## Daemon

The in-environment control plane, `cw __hosted-daemon` in a hosted sandbox
and the guest daemon in a local VM. It serves sessions, files, SSH and the
environment's tailnet peer. See `dev/SANDBOX-DAEMON.md`.

## Codewire Guard

The in-repo defense-in-depth layer around sandbox runtime profiles. Runtime
profiles are `runc`, `commodity`, and `confidential`; `runc` is diagnostic
or bootstrap only for managed sandboxes.

## Codewire Mesh

The hosted or self-hosted node network control plane used by the CLI and
environment runtime for remote access, node discovery, membership, access
grants, and task/reporting coordination.

Mesh does not use the credential proxy. Hosted Mesh sends the one Codewire
user credential already presented to it over a private, method-scoped Connect
RPC and receives only typed identity, organization, role, and credential-kind
metadata. It does not store that credential. For a native VM, a confined
one-shot enrollment issuer on the host uses the selected owner login to mint
one narrow node enrollment and transfers it directly to the Mesh transport.
Neither the owner login nor a workload-provider secret enters the VM. A hosted
environment's daemon gets a one-use enrollment code for its own node from
orchestration, which Mesh redeems through orchestration and rechecks at least
every 60 seconds; no user credential enters the Sandbox.

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

## Tenant

Legacy or internal implementation term that survives in some database and
table names. Do not use `tenant` as the product term in new docs.

## SDK

Official client libraries for the Codewire API, in this repository under
`libs/`:

- TypeScript: `@codewire/sdk` (`libs/sdk-ts`)
- Go: `codewire.sh/sdk-go` (`libs/sdk-go`)
- Python: `codewire` (`libs/sdk-python`)
