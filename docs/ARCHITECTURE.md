# Hosted platform architecture

Status: current. This page describes how the hosted platform is put together
on Kubernetes. [SPEC.md](../SPEC.md) is the specification of the whole
product: its model, every placement, the contracts, access paths and security
model. For component detail use the linked docs; for proposals use the
maintainers' private design repository.

## 1. Scope

A Codewire environment runs in one of three placements, all driven by the
same `cw` CLI and the same in-environment daemon: a hosted sandbox on the
platform, a local VM on the user's machine, or a trusted host session
([SPEC.md, Product model](../SPEC.md#2-product-model)). Each environment runs
in its own hardware-virtualized VM with its own kernel, because agents run
untrusted code and a shared kernel would make one exploit reach every
environment on the node. The cost is more work in networking, storage and
orchestration, which this document describes for the hosted platform.

## 2. Platform overview

```text
  cw CLI / dashboard / SDKs
            |
   Rust services (one chassis: codewire-server-core)
   idp | orchestration | billing | credential-service | coordinator | mesh
            |                          |
       PostgreSQL                  Temporal (lifecycle workflows)
            |
   sandbox client (kube-rs) -> SandboxTemplate / SandboxClaim / Sandbox
            |
   agent-sandbox controller (kubernetes-sigs) -> Pod
            |
   RuntimeClass from the runtime profile
     commodity: Kata + Cloud Hypervisor     confidential: Kata + QEMU-SNP
            |
   Pod: workspace container (cw __hosted-daemon) + dind container
```

Services, all in `crates/` (see `crates/README.md` for the full map):

- `codewire-server-core`: HTTP scaffold, auth, request identity, error
  envelope, tracing, database and NATS helpers, the application migrations.
- `codewire-idp` (+ `codewire-oidc`): accounts, sessions, two-factor, API
  keys, OIDC provider.
- `codewire-orchestration`: environment API, Temporal worker and reconciler,
  Kubernetes sandbox client, workspace binding, credential relay, terminal and
  SSH proxy, previews, admin.
- `codewire-billing`: catalog, plans, Stripe, usage metering.
- `codewire-credential-service` (+ `codewire-credential-broker`): the
  isolated broker that holds provider material and answers typed requests.
- `codewire-coordinator`, `codewire-derp`, `codewire-udp-relay`: tailnet
  coordination and relays.
- `codewire-mesh`: Codewire Mesh, the hosted or self-hosted network control
  plane for nodes and clients.
- `codewire-dashboard-web`: the server-rendered dashboard (HTMX), which also
  serves the documentation site.

Data stores: PostgreSQL for product state; Temporal for durable lifecycle
workflows (create, start, stop, destroy are signalled intents handled by the
orchestration worker); NATS only for service-internal realtime fan-out where a
service needs it (the coordinator across replicas).

Canonical concepts: organization (billing, members, secrets), environment
(the product object), preset (creation defaults), session (a process or agent
inside an environment), API key (`cw_` prefix, hashed at rest). See
[GLOSSARY.md](GLOSSARY.md).

## 3. Hosted environments on Kubernetes

### agent-sandbox CRDs

Codewire uses the kubernetes-sigs `agent-sandbox` controller:

| CRD | Purpose |
| --- | --- |
| `SandboxTemplate` | private, environment-scoped Pod template |
| `SandboxClaim` | the platform's request for one sandbox from a template |
| `Sandbox` | the stateful singleton Pod with stable identity and storage |
| `SandboxWarmPool` | prestarted members of one workspace shape |

The sandbox client (`crates/codewire-orchestration/src/sandbox/`) renders a
private `SandboxTemplate` and a zero-replica shadow `SandboxWarmPool` per
environment (the claim API requires a pool reference), then creates a claim
named `sandbox-<environment id>`. Creation is idempotent.

### Warm pools

Optionally, orchestration also keeps identity-free warm pools: one shared
template and pool per exact workspace shape (CPU, memory, disk), configured by
`SANDBOX_WARM_POOL_SHAPES`. A claim of exactly that shape adopts a prestarted
member; the member gains its environment identity only when bound, and no
environment secret reaches the pool template. Unset means no pools and every
start is cold. Confidential environments are never pooled.

### Runtime profiles

A product-level runtime profile selects the RuntimeClass and capability
defaults (`SANDBOX_RUNTIME_PROFILE`):

- `commodity`: Kata Containers with Cloud Hypervisor (`kata-clh`); the normal
  profile.
- `confidential`: Kata with QEMU-SNP on SNP-capable nodes; attestation and
  secret release are separate gates.
- `runc` / `none`: diagnostics only; managed creation refuses them unless
  `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true`.

See [dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md](dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md).

### The workspace Pod

The Pod holds two containers. `workspace` runs the user's image with
`/home/codewire` and `/workspace` on the environment's persistent volume and
starts `cw __hosted-daemon`, which comes read-only from the pinned support
image. `dind` runs a guest-local Docker daemon inside the same VM; the
workspace sees `DOCKER_HOST=unix:///var/run/docker/docker.sock`. The node's
container runtime socket is never mounted or proxied into a sandbox; any path
that forwards to host Docker is a node-escape regression.

### The daemon

The daemon is the in-environment control plane
([dev/SANDBOX-DAEMON.md](dev/SANDBOX-DAEMON.md)):

- gRPC service for exec, PTY, durable sessions and files, used by
  orchestration, the dashboard terminal and `cw`;
- an SSH server with SFTP and SCP on port 2222, with a per-binding Ed25519
  host key whose public line orchestration records;
- the environment's tailnet peer (WireGuard), started from the access grant
  orchestration issues at binding;
- the credential bridge: a loopback relay that orchestration pulls and
  forwards to the broker.

Startup: the Pod starts, the daemon calls `BindWorkspace` on orchestration's
internal listener (8087) with its workspace token, receives its binding and
access grant, then serves SSH and joins the tailnet. Orchestration waits for
the claim to be Ready, records the Pod in `sandbox_environment_backend`, and
marks the environment running. There is no per-environment gateway or sidecar
workload.

### Environment lifecycle

Environment states: `pending`, `pending_build`, `building`, `build_failed`,
`pulling_snapshot`, `creating`, `starting`, `running`, `stopping`, `stopped`,
`archiving`, `archived`, `restoring`, `resizing`, `destroying`, `destroyed`,
`error`, `unknown`. Desired states (`started`, `stopped`, `destroyed`,
`archived`, `resized`) drive the reconciler in
`crates/codewire-orchestration/src/worker/lifecycle.rs`. The create flow
(`worker/create.rs`, `CreateAction`) advances one action per pass:
`EnsureNamespace`, `CreateClaim`, `WaitForReady`, `ResumeWorkspace`,
`StoreBackend`, `MarkRunning`, `PublishSetup`, `Done`.

```mermaid
sequenceDiagram
    participant Client as cw / dashboard / SDK
    participant API as orchestration API
    participant Worker as orchestration worker
    participant K8s as Kubernetes
    participant Ctrl as agent-sandbox controller
    participant Daemon as cw __hosted-daemon

    Client->>API: create environment
    API->>Worker: Temporal lifecycle intent
    Worker->>K8s: namespace, SandboxTemplate, shadow pool, SandboxClaim, daemon Service, NetworkPolicy
    K8s->>Ctrl: reconcile claim
    Ctrl->>K8s: Sandbox, Pod (RuntimeClass from profile)
    Daemon->>Worker: BindWorkspace (8087)
    Worker-->>Daemon: binding + access grant
    Daemon->>Daemon: serve SSH :2222, join tailnet
    Worker->>API: state running
```

## 4. Reaching an environment

```text
cw / VS Code / OpenSSH
  -> WireGuard to the daemon's SSH server
       direct UDP  ->  UDP relay  ->  DERP (TCP fallback)
  -> WebSocket SSH proxy through orchestration (final fallback)
dashboard terminal -> orchestration -> daemon gRPC
```

The CLI builds a WireGuard tunnel to the environment's daemon and tries
direct UDP, then the shared UDP relay, then DERP; the WebSocket proxy through
orchestration is the last resort and the browser path. `cw setup ssh` writes
an OpenSSH block whose `KnownHostsCommand` asks the platform for the recorded
host key, so there is no trust-on-first-use. Previews are HTTPS URLs that
orchestration forwards to an application port inside the sandbox. See
[dev/DERP-STUN.md](dev/DERP-STUN.md) and
[dev/SANDBOX-PREVIEWS.md](dev/SANDBOX-PREVIEWS.md).

## 5. Secrets and credentials in a hosted sandbox

Application secrets and provider credentials are separate concepts; the
product model, the direct delivery exceptions and the authority reuse limits
are in [SPEC.md](../SPEC.md#8-security-model), the contract in
[dev/SECRETS-AND-CREDENTIALS.md](dev/SECRETS-AND-CREDENTIALS.md). In a hosted
sandbox the path is:

```text
child -> daemon loopback ingress -> daemon bridge -> orchestration relay -> credential service -> provider
```

The relay legs hold no provider material: the credential relay in
orchestration dials the daemon over the daemon Service and relays the bridge
to the broker in the credential service, which injects the credential and
redacts it from responses.

## 6. Other placements and contracts

Local VMs, trusted hosts and the client contracts are specified in
[SPEC.md](../SPEC.md) (sections 5 and 6), with the detail in
[dev/LINUX-LOCAL-VMS.md](dev/LINUX-LOCAL-VMS.md),
[dev/MACOS-CLI.md](dev/MACOS-CLI.md) and
[dev/PROTO-STYLE.md](dev/PROTO-STYLE.md).
