# Codewire Architecture

Status: current, stable overview

This document is the canonical architecture reference for the Codewire platform, covering
the full stack from control plane through Kubernetes abstraction to hypervisor runtime.

For implementation details, use the dev docs in `docs/dev/`. For future roadmap work, use
the design plans in `docs/plans/`.

If a plan doc and this document disagree, treat the plan as **proposed work** and this file
as the **current stable summary**.

---

## 0. Implementation language for new services

The control-plane product runtime is Rust-owned. The completed Go-to-Rust
cutover untangled the monolith into focused services behind stable contracts
and established the `codewire-server-core` shared crate. Remaining Go is
accepted SDK, generated-client, contract-harness, or explicit compatibility
oracle code; it is not a product server.

**Policy from Phase 1 onward:**

- A **new service** — a new binary owning a new bounded context — is written in
  Rust on top of `codewire-server-core` (see `crates/README.md`).
- New product/runtime work belongs in Rust services and the Rust `cw` CLI. The
  old Go `cmd/codewire` monolith source has been deleted; remaining Go code is
  non-product test/support or explicitly tracked cleanup.
- Runtime behavior is verified against the wire contract with
  `tests/contract/` and the affected `Database`, `Service integration`, or
  `Rust transport` product family. The all-up
  `scripts/ci/verify/rust-stack-rehearsal.sh` remains available for explicit
  diagnosis, not as an automatic gate for every change.

The desktop app (`crates/codewire-desktop`) is Rust. The web dashboard is a
Rust server-rendered application with HTMX progressive enhancement and embeds
the Zola documentation site; the retained mobile client is native Swift/iOS.

---

## 1. Problem Statement

Cloud development environments give developers and AI agents full Linux machines in the
cloud. The agent gets a shell, installs packages, runs code, clones repos. It operates the
same way a developer would on their laptop, except the machine lives on someone else's
infrastructure.

The key constraint is that agents run **untrusted code**. An AI coding agent executes
whatever it generates. If it hallucinates `rm -rf /`, if it pulls a malicious dependency,
or if it tries to escape its sandbox, the isolation layer is the only thing standing between
that code and the rest of the system.

Most platforms solve this with containers. Containers are fast, cheap, and well understood.
But containers share the host kernel. Every container on a node makes syscalls into the same
kernel, and the kernel is the isolation boundary. When that boundary fails, the consequences
are total:

- **CVE-2024-21626** -- file descriptor leak in runc allowed container escape
- **CVE-2022-0185** -- heap overflow in the kernel filesystem layer broke out of a user
  namespace

In both cases, a process inside a container gained root on the host, with access to every
other container on that node. For a platform running thousands of untrusted agent workloads,
one kernel exploit compromises every environment on the node.

### Why hypervisor isolation

Codewire runs each development environment in its own hardware-virtualized VM with its
own kernel. A vulnerability inside the guest kernel has nowhere to go -- there is no
shared kernel. The hypervisor sits between guests, and the hypervisor boundary is the
security boundary. The default `commodity` runtime uses Kata Containers with Cloud
Hypervisor (see §4); the external isol8 backend (§5) provides the same guarantee with Xen
paravirtualized domains.

This is the same isolation model used by:

- **AWS Firecracker** (powers Lambda and Fargate) -- microVM-per-function
- **Kata Containers** -- VM-per-pod in Kubernetes
- **Google gVisor** -- user-space kernel (different approach, same goal)

The trade-off: real isolation at the cost of higher complexity in networking, storage, and
orchestration. The rest of this document explains how the three system layers compose to
manage that complexity.

---

## 2. System Overview

```text
                          Codewire Platform
                    (control plane, API, auth, billing)
                                 |
                    API Keys / Sessions / SDKs
                                 |
              +------------------+------------------+
              |                                     |
       PostgreSQL                              Temporal
    (product data,                         (durable workflows,
     auth, billing)                         lifecycle retries)
              |
              v
       NATS JetStream
    (optional realtime
     fanout/presence)
              |                                     |
              +------------------+------------------+
                                 |
                          Sandbox Client
                     (k8s dynamic client)
                                 |
     +-----------+---------------+-----------------+
     |           |               |                 |
  Sandbox    Sandbox         Sandbox           Sandbox
  Claim      Template        WarmPool          (core)
     |           |               |                 |
     +-----------+---------------+-----------------+
                                 |
                    Agent Sandbox Controller
              (kubernetes-sigs CRD reconciliation)
                                 |
                           Pod + Service
                                 |
                    RuntimeProfile: "commodity" | "confidential"
                                  |
                    RuntimeClass from profile
                                 |
     +-----------+---------------+-----------------+
     |           |               |
  runc        Kata + CH       CoCo/TEE
  diag only   commodity       confidential
              backend         path
     |           |               |
     +-----------+-------+-------+
                         |
                  Isolated workload
          (container or VM depending on profile)
                         |
              +----------+----------+
              |                     |
          guest-init           guest-zone
          (PID 1)              (IDM server)
                                    |
                            styrolite containers
                          (namespace-isolated workloads)
```

**Layer 1 -- Codewire Platform:** Control plane handling auth, billing,
environment lifecycle, realtime node/network control, and SDK access. Rust
services are backed by PostgreSQL for durable product state and Temporal for
durable workflows. NATS is an implementation option for realtime fanout,
presence, and cross-replica state in services such as Mesh and coordinator.

**Layer 2 -- Agent Sandbox:** Kubernetes CRDs (kubernetes-sigs/agent-sandbox) providing
declarative management of isolated, stateful, singleton workloads. The controller
reconciles SandboxClaims into Sandboxes into Pods.

**Layer 3 -- Runtime Profile + Guard Controls:** Codewire selects a
product-level runtime profile and renders the matching Kubernetes RuntimeClass
plus capability defaults. Guard controls are the defense-in-depth checks around
that selection. Managed sandboxes use `commodity` as the normal Kata + Cloud
Hypervisor profile. `runc` and `none` are diagnostic/bootstrap paths only and
are refused by managed creation unless an explicit diagnostic override is set.
The `confidential` profile keeps the same product contract but schedules only
onto infra-proven SNP nodes. The first dev proof uses Kata + QEMU-SNP; Trustee
attestation and secret release remain separate proof gates.

---

## 3. Codewire Platform

### What it is

Codewire is a control plane for agent-oriented cloud development environments. It manages
the full lifecycle from user signup through environment provisioning, execution, and
teardown.

### Canonical concepts

| Concept | Description |
|---------|-------------|
| **Organization** | Billing, member, and secret boundary |
| **Environment** | The canonical product object: an isolated sandbox for agents and developers |
| **Environment Template** | Type-specific template for creating environments |
| **API Key** | `cw_` prefixed key for programmatic SDK/CLI access (SHA-256 hashed, prefix-indexed) |
| **Session** | A process or agent running inside an environment |

### Server architecture

```text
Web / Native / SDK / cw Clients
         |
         v
  +------+--------------------------+
  | Rust services                   |
  | idp / orchestration / billing   |
  | coordinator / mesh / derp       |
  +------+--------------------------+
         |
    +----+----+----+----+----+----+
    |    |    |    |    |    |    |
  auth  API  OIDC billing temporal sandbox
         |              |    |    client
         v              v    v       |
    HTTP routes    plans workflows    v
    environment    usage  jobs    k8s CRDs
    CRUD           checkout
         |              |
         v              v
    +----+----+    +----+----+
    |PostgreSQL|    |Temporal |
    |          |    |         |
    +----------+    +---------+
```

**Key areas** — the live control plane and its correctness fixtures are
Rust-owned. The former Go application and its general service drivers have
been deleted; retained Go is consumer or Tailscale interoperability only:

- `codewire-server-core` -- shared HTTP scaffold, auth, request identity, error envelope, tracing, DB/NATS helpers
- `codewire-idp` + `codewire-oidc` -- OIDC provider and federated auth flows
- `codewire-billing` -- plans, checkout, usage, billing operations
- `codewire-orchestration` -- async lifecycle, reconciliation, and the Kubernetes sandbox client/informers
- `codewire-server-core/migrations/` -- the sole application SQLx history, embedded and applied by `codewire-server-core`

### Data stores

**PostgreSQL** -- auth, product data, organizations, billing state, environment lifecycle,
usage accounting.

**Temporal** -- durable environment lifecycle workflows. Environment
create/stop/start/destroy operations are SignalWithStart intents handled by
the Rust orchestration worker.

**NATS JetStream** -- optional realtime bus for high-churn service-internal
fanout, presence, and cross-replica state. It is not the durable lifecycle
owner after the Temporal cutover. Mesh and coordinator may use NATS behind
their service boundaries when process-local state or database polling would be
the wrong fit.

### Protected values and saved state

Storage is not delivery. Selecting a protected value only makes it eligible
for a later binding:

```text
stored value
  +-- brokered binding --> allowed operation; child never receives the value
  `-- exposed binding  --> value enters one explicitly admitted child
```

The brokered path is the target default. It is a typed proxy, signer, or
executor, not a generic secret-read API. New credential bindings are
broker-only and never silently become exposed values.

The secret-bearing broker stays outside the sandbox:

```text
local:    child -> local relay -> guest edge -> host broker -> provider
platform: child -> local relay -> gateway Pod -> internal broker -> provider
```

The relay and edge hold no provider credential. The platform workspace daemon
cannot be that edge because it shares the workload's container and process
boundary. `av-credential-proxy` and `av-proxy-helper` are reusable libraries
inside the placement-owned processes, not new control planes. Proxying is only
cooperative credential non-disclosure while direct provider egress remains
open; enforced mediation also requires denying bypass.

The target command surface is:

```text
cw secrets run -- COMMAND           # brokered
cw secrets run --expose -- COMMAND  # brokered plus permitted raw values
```

An **environment projection** is the child-visible value set built for one
explicit launch. It is never a shared file or a second version history. A
stored value without a matching binding is unavailable. An environment policy
may apply the same launch choice automatically, so a configured plain `codex`
can work without another login or wrapper.

This command must not ship until both paths are real. The brokered form needs
the reusable AV edge; the exposed form needs a trusted executor that launches
the exact child. Both must reject stale runtime operations.

Current status is narrower: local Codex brokerage and protected-value
storage/metadata exist. General `cw secrets run`, raw per-child projection, and
the platform broker boundary do not yet ship. The platform's old raw secret and
credential bootstrap paths are removed; brokered or exposed bindings fail
closed until their current runtime path exists.

Saved-state names describe what can actually be restored:

- A **skill snapshot** is immutable, reusable skill content and is implemented.
- **Workspace storage** is the live mutable filesystem. Persistence across a
  stop is not a snapshot.
- A **workspace snapshot** will be restorable workspace filesystem state.
- An **environment snapshot** will combine a workspace snapshot with the
  Codewire settings needed to create an independent environment.
- A **VM checkpoint** will contain backend-specific running-VM memory and device
  state for a future hot environment snapshot.

Workspace snapshots, environment snapshots, and VM checkpoints are reserved
capability names; they are not implemented today. In short: projections launch
processes, snapshots restore saved state, and checkpoints resume execution.

> **Rust port status:** lifecycle execution, environment reconciliation,
> sandbox liveness, warm-pool reconciliation, and sandbox billing-session
> loops are Rust-owned by default in `crates/codewire-orchestration`. Billing
> metering, overage, and trial-expiry crons are Rust-owned by default in
> `crates/codewire-billing`. The rendered local-kind, dev, and prod runtime no
> longer includes the Go fallback server, and the old Go monolith source has
> been deleted.

### Environment lifecycle

The environment state machine has 18 states:

```text
                                     +---> building ---> build_failed
                                     |
  pending ---> pending_build --------+
     |
     +-------> pulling_snapshot
     |              |
     +-------> creating -----> starting -----> running
                                                  |
                                          +-------+-------+
                                          |       |       |
                                       stopping resizing archiving
                                          |       |       |
                                       stopped  running archived
                                          |               |
                                       starting       restoring
                                          |               |
                                       running         running

  (any state) ---> destroying ---> destroyed

  (any state) ---> error ---> (retry to pending/starting)

  unknown (fallback)
```

**Desired states** drive transitions: `started`, `stopped`, `destroyed`, `archived`,
`resized`. The reconciler in `crates/codewire-orchestration/src/worker/lifecycle.rs`
(porting the Go `worker/handler_environment.go` oracle) detects mismatches between
current state and desired state, then enqueues the appropriate transition.

**Create-flow state machine** (`crates/codewire-orchestration/src/worker/create.rs`, the
`CreateAction` enum):

1. `EnsureNamespace` -- create the k8s namespace (and the SandboxTemplate scaffolding)
2. `CreateClaim` -- create the SandboxClaim
3. `WaitForReady` -- watch the claim until its Ready condition is True
4. `StoreBackend` -- store pod IP/name in `sandbox_environment_backend`
5. `MarkRunning` -- transition the environment to `running`
6. `PublishSetup` -- publish the setup job

The reconciler advances one action per pass via `next_create_action`, reaching `Done` once
setup completes.

### Auth model

- **Session tokens** work as Bearer tokens (raw token, not OIDC encrypted). Sliding expiry
  via `UPDATE...WHERE expires_at > NOW()`.
- **API keys** use `cw_<64 hex>` format, SHA-256 hashed in DB, prefix-indexed for lookup.
- **OIDC** provider for federated auth flows.
- **2FA** available for user accounts.

---

## 4. Agent Sandbox (Kubernetes Abstraction)

### What it is

[agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) is a kubernetes-sigs
project providing CRDs for managing isolated, stateful, singleton workloads. It follows the
standard Kubernetes controller pattern: users create custom resources, the controller
reconciles underlying runtime resources.

### CRDs

| CRD | Group | Purpose |
|-----|-------|---------|
| `Sandbox` | `agents.x-k8s.io/v1alpha1` | Core: single stateful pod with stable identity and persistent storage |
| `SandboxTemplate` | `extensions.agents.x-k8s.io/v1alpha1` | Platform-defined reusable template for creating sandboxes |
| `SandboxClaim` | `extensions.agents.x-k8s.io/v1alpha1` | User/platform request to create a sandbox from a template |
| `SandboxWarmPool` | `extensions.agents.x-k8s.io/v1alpha1` | Pre-warmed pod pool configuration for fast allocation |

### Controller reconciliation flow

```mermaid
flowchart TD
    Platform["Codewire Platform"]
    Claim["SandboxClaim"]
    Template["SandboxTemplate"]
    Sandbox["Sandbox"]
    ClaimCtrl["Claim Controller"]
    SandboxCtrl["Sandbox Controller"]
    Pod["Pod (RuntimeClass from profile)"]
    WarmPool["SandboxWarmPool"]

    Platform -->|"creates"| Claim
    Claim -->|"references"| Template
    Claim -->|"reconciled by"| ClaimCtrl
    ClaimCtrl -->|"creates"| Sandbox
    ClaimCtrl -->|"adopts pod from"| WarmPool
    Sandbox -->|"reconciled by"| SandboxCtrl
    SandboxCtrl -->|"creates"| Pod
    WarmPool -->|"pre-warmed pods"| Pod
```

### Codewire integration

The sandbox client (`crates/codewire-orchestration/src/sandbox/`) bridges the
Codewire platform to the agent-sandbox CRDs using `kube-rs`.

**DB tables:**

| Table | Purpose |
|-------|---------|
| `sandbox_template_config` | Links `environment_templates` to k8s SandboxTemplate names, image refs, warm pool size |
| `sandbox_environment_backend` | Per-environment: namespace, claim name, pod name, pod IP, agent port, setup state |

**Claim creation:** The sandbox client generates a claim named `sandbox-{envID}`, labels it
with environment and org IDs, and references the SandboxTemplate. Handles idempotency --
reuses existing claims rather than failing.

**Readiness watching:** `WaitForReady` watches the SandboxClaim until the `Ready` condition
becomes `True` (5 min timeout). A concurrent pod health checker detects terminal failures
(ImagePullBackOff, CrashLoopBackOff) for fast failure.

**Informer:** A continuous informer watches Sandbox and Pod resources, syncing pod IP/name
to the DB and detecting unexpected pod failures or sandbox expiry.

**Runtime profile scheduling:**

- `SANDBOX_RUNTIME_PROFILE=commodity` renders `RuntimeClass: commodity`.
- `SANDBOX_RUNTIME_PROFILE=confidential` renders `RuntimeClass: confidential`
  for the future hardware TEE-backed runtime lane.
- `SANDBOX_RUNTIME_PROFILE=runc`, `none`, or an empty profile is diagnostic
  only for managed creation and requires
  `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true`.
- `commodity` relies on the RuntimeClass scheduling stanza to select Kata
  runtime candidate nodes.
- The Rust orchestration warm-pool reconciler is the default owner for
  `SandboxTemplate` and `SandboxWarmPool` reconciliation. Go fallback worker
  loops are no longer rendered in local-kind, dev, or prod runtime paths.

---

## 5. External isol8 Xen backend

### What it is

isol8 is a separate OCI runtime project that replaces runc with Xen PV domains.
It remains useful as an optional external backend, but it is not the default
Codewire path and is not an approved managed runtime profile. Current
commodity runtime work uses Kata + Cloud Hypervisor through the `commodity`
profile.

### Control plane

```text
kube-apiserver
  -> MutatingAdmissionWebhook (isol8-webhook)
       converts cpu/memory -> domain-vcpus/domain-memory-mb extended resources

kubelet
  -> containerd
    -> io.containerd.runc.v2 shim
      -> /usr/local/bin/isol8-runtime
           -> DomainService  (/run/isol8/domd.sock)
           -> NetworkService (/run/isol8/netd.sock)

systemd
  -> isol8-domd.service   (socket-activated)
  -> isol8-netd.service   (socket-activated)
  -> isol8-orchd.service
       -> advertises domain-vcpus + domain-memory-mb on node status
```

### System layout

```text
Host node
+-- Xen hypervisor
    +-- dom0
        |-- kubelet
        |-- containerd
        |   +-- RuntimeClass "isol8"
        |       -> BinaryName=/usr/local/bin/isol8-runtime
        |
        |-- isol8-runtime
        |   |-- parses OCI bundles
        |   |-- stores task state in /run/isol8/runtime/
        |   |-- forks per-task monitors
        |   |-- calls isol8-domd over UDS
        |   +-- calls isol8-netd over UDS
        |
        |-- isol8-domd
        |   |-- Xen PV domain lifecycle
        |   |-- Xen console / IDM transport
        |   |-- guest container RPCs
        |   |-- exec / stream forwarding
        |   |-- 9PFS backend for kubelet volumes
        |   +-- Docker proxy + policy (workspace domains)
        |
        |-- isol8-netd
        |   |-- host-side VIF setup
        |   |-- routed /32 datapath
        |   |-- proxy_arp + rp_filter tuning
        |   +-- nftables anti-spoofing per VIF
        |
        |-- isol8-orchd
        |   |-- daemon health checks
        |   |-- orphan reconciliation
        |   |-- warm-pool maintenance
        |   +-- Prometheus metrics / cordon state
        |
        +-- Xen guest domains (one per pod)
            |-- guest-init (/init, PID 1)
            +-- guest-zone (/bin/zone)
                |-- styrolite containers
                +-- Docker stream tunnel (workspace only)
```

### Four components

| Component | Type | Runs as | Role |
|-----------|------|---------|------|
| `isol8-runtime` | OCI binary | root via containerd | OCI lifecycle: `create`, `start`, `exec`, `delete`, `kill`, `state` |
| `isol8-domd` | systemd service + UDS | root | Xen domain lifecycle, IDM bridge, 9PFS, Docker proxy |
| `isol8-netd` | systemd service + UDS | root (`CAP_NET_ADMIN`) | Host-side guest networking |
| `isol8-orchd` | systemd service | root | Health supervisor, warm pool, orphan cleanup, metrics |

### OCI runtime flow

**1. `isol8-runtime create`**

- Parses the OCI bundle
- Determines whether the task is a sandbox or workload container
- Records the sandbox network namespace path for sandboxes
- Forks a monitor process (containerd expects a process to wait on)
- Writes task state to `/run/isol8/runtime/<id>/state.json`

**2. `isol8-runtime start` (sandbox)**

Creates the Xen PV domain:

1. Parse resource limits from OCI spec (memory, vCPUs)
2. Verify base guest rootfs squashfs exists
3. Resolve guest network config from sandbox netns and CRI annotations
4. Call `CreateDomain` on isol8-domd with base guest rootfs
5. Call `AllocateNetwork` / `AttachVif` on isol8-netd
6. Persist `domid`, `vif_name`, `network_ip` to sandbox state

**3. `isol8-runtime start` (workload container)**

Creates a container inside the already-running guest:

1. Verify sandbox domain exists
2. Build squashfs image for the container rootfs
3. Call `CreateContainer` in the guest through isol8-domd

### Sandbox vs workload rootfs

**Sandbox rootfs** (`CreateDomainRequest.rootfs_path`): Host-side base guest image
(Alpine + guest-init + guest-zone), shared across all pods on the node. Located at
`/var/lib/isol8/images/ami-combined/rootfs.squashfs`. This boots the Xen PV domain.

**Workload rootfs** (`CreateContainerRequest.rootfs`): Per-container OCI image
(e.g., nginx, postgres), delivered into the guest via 9PFS and used as the overlay
lowerdir by guest-zone. Located at `/containerd/<container-id>/rootfs` inside the guest.

```text
/tmp/overlay-<ctr>-merged   (merged view -- container sees this as /)
  |-- upperdir: /tmp/overlay-<ctr>/upper   (writable tmpfs)
  +-- lowerdir: /containerd/<ctr-id>/rootfs   (workload image via 9PFS, read-only)
```

---

## 6. Guest Execution Model

### Boot sequence

Each pod gets one Xen PV guest domain. At boot:

1. `guest-init` (PID 1) performs early mount and initramfs setup
2. Waits for `eth0` if guest networking is enabled
3. Configures guest networking from kernel cmdline (`isolate.ip`, `isolate.gw`, `isolate.dns`)
4. Prepares `/etc/resolv.conf`
5. Launches `guest-zone`

### guest-zone

`guest-zone` is the long-running agent inside the VM:

- Serves the guest side of the IDM protocol over `/dev/hvc0`
- Creates and manages workload containers with `styrolite`
- Handles exec, signals, TTY resize, and stdio streaming
- Creates containers with 7 namespaces (Mount, PID, IPC, User, UTS, Cgroup, Time)
- NET is **not** unshared -- all containers share the guest init network namespace
- Exposes the Docker stream tunnel (workspace domains only)

### IDM protocol

Protobuf over the Xen console (`/dev/hvc0`), bidirectional request/response.

**Dom0 -> Guest (`IdmRequest`):**

| Message | Purpose |
|---------|---------|
| `ExecRequest` | Execute command in domain |
| `ContainerCreateRequest` | Create container (styrolite `CreateRequest::wrap`) |
| `ContainerExecRequest` | Exec into existing container (styrolite `AttachRequest::wrap`) |
| `ContainerStopRequest` | Stop container (SIGTERM -> SIGKILL) |
| `SignalRequest` | Send signal to process |
| `ResizePtyRequest` | Resize exec PTY |
| `ShutdownRequest` | Graceful guest shutdown |
| `PortForwardRequest` | Establish port-forward tunnel |
| `DockerStreamData` | Docker proxy data |
| `VolumePrepareRequest` | Stage volume data via IDM |

**Guest -> Dom0 (`IdmResponse`):**

| Message | Purpose |
|---------|---------|
| `ReadyResponse` | Guest booted, zone ready (includes version and workspace flag) |
| `ExecStarted` | Exec process started (returns PID) |
| `ExecOutput` | stdout/stderr data |
| `ExecDone` | Exec process exited (returns exit code) |
| `ContainerCreatedResponse` | Container created (returns supervisor PID) |
| `ContainerStoppedResponse` | Container stopped (returns exit code) |
| `ErrorResponse` | Error message |

**Handshake:** Guest boots -> zone sends `ReadyResponse` -> domd marks domain `RUNNING`.

---

## 7. Isolation Model (Defense in Depth)

```text
+---------------------------------------------------------------+
| Layer 1: Xen Hypervisor                                       |
|   - Separate kernel per pod                                   |
|   - Separate memory address space                             |
|   - Separate network stack (xen-netfront virtual interface)   |
|   - No shared kernel attack surface                           |
+---------------------------------------------------------------+
                           |
+---------------------------------------------------------------+
| Layer 2: Linux Namespaces + pivot_root (styrolite)            |
|   - 7 namespaces: Mount, PID, IPC, User, UTS, Cgroup, Time   |
|   - NET is VM-level (hypervisor provides isolation)           |
|   - Mount: pivot_root into OCI rootfs, /dev/hvc0 not visible |
|   - PID: workload cannot see zone or init processes           |
|   - User: full 65536-UID mapping (0 0 65536)                 |
+---------------------------------------------------------------+
                           |
+---------------------------------------------------------------+
| Layer 3: Hardening                                            |
|   - Capabilities: drop ALL + 12 safe K8s defaults             |
|   - Seccomp-bpf: ~275 syscall allowlist, W^X enforcement      |
|   - Cgroup v2: per-container memory/pids/cpu limits           |
|   - Per-process rlimits: NPROC=256, NOFILE=1024, AS=4G       |
|   - All fds > 2 closed before exec (IDM transport protection) |
|   - 14 masked /proc paths + /proc/sys readonly                |
|   - Yama LSM: ptrace restricted to parent-child               |
+---------------------------------------------------------------+
```

Layer 1 (the hypervisor) provides the **primary security boundary**. Layers 2 and 3 add
defense-in-depth and ensure security auditing tools see the expected isolation properties.

### Capabilities

Drop ALL (41 capabilities), then add 12 safe Kubernetes defaults:

```text
CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, SETGID, SETUID,
SETFCAP, SETPCAP, NET_BIND_SERVICE, SYS_CHROOT, KILL
```

Excluded: `NET_RAW`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `NET_ADMIN`, `SYS_RAWIO`.

### Seccomp-BPF

Default-deny allowlist model. ~275 explicitly permitted syscalls matching Docker defaults.

- `socket()` -- only AF_UNIX, AF_INET, AF_INET6 allowed
- `mmap`/`mprotect` -- W^X enforcement (PROT_WRITE + PROT_EXEC blocked)
- Blocked: `mount`, `unshare`, `setns`, `ptrace`, `bpf`, `io_uring_*`, `clone3`

### Why NET namespace is not unshared

In a VM-based isolator, the guest kernel runs a completely independent network stack. The
guest's `eth0` is a Xen virtual network interface connected to dom0 -- it is not the host's
physical network. Calling `unshare(CLONE_NEWNET)` inside the VM would create an empty
namespace with only a disabled loopback, breaking all connectivity.

This matches Kata Containers, Firecracker, and every other VM-based runtime: PID, IPC,
USER, Mount, and UTS namespaces are unshared for defense-in-depth, but NET isolation comes
from the hypervisor boundary.

---

## 8. Networking

### Routed /32 VIF datapath

isol8 uses a routed /32 model, not a bridge. Each guest gets a Xen VIF with a /32 host
route and nftables anti-spoofing.

### Packet path

```mermaid
flowchart LR
    Guest["Guest eth0<br/>(xen-netfront)"]
    VIF["Host VIF<br/>(vif{domid}.1)"]
    Route["/32 route<br/>+ proxy_arp"]
    NFT["nftables<br/>anti-spoof"]
    Forward["ip_forward"]
    NAT["SNAT masquerade<br/>(guest subnet)"]
    Ext["External<br/>network"]

    Guest --> VIF --> Route --> NFT --> Forward --> NAT --> Ext
```

### Network setup flow

1. Runtime resolves pod IP from sandbox netns and CRI annotations
2. `isol8-domd` receives IP via `CreateDomain` and passes it on the kernel cmdline
3. `isol8-netd` receives IP via `AllocateNetwork` and programs host-side routes
4. `guest-init` configures guest networking from kernel cmdline parameters

### isol8-netd responsibilities

Per VIF:
- Install nftables anti-spoof rules (source IP must match allocated IP)
- Enable `proxy_arp` on the VIF
- Disable `rp_filter` on the VIF
- Bring VIF up
- Install `/32` route to guest IP through VIF

Boot-time (`isol8-setup.sh`):
- Enable IPv4 forwarding
- Set up base `isol8` nftables forward chain
- Add no-inter-guest rule for `vif* -> vif*`
- Install NAT masquerade for guest subnet

### Known gap: Cilium NetworkPolicy

Guest traffic does **not** traverse the Cilium endpoint path. The Xen VIF datapath gives
host-managed networking, but Cilium `NetworkPolicy` enforcement does not apply to isol8
guests in the current design. Connectivity works, but network policies are not enforced.

---

## 9. Warm Pools

### Purpose

Reduce pod creation latency by pre-booting Xen domains with kernel + IDM ready but no
container image loaded.

### How it works

**Host-level (isol8-orchd):**

- Manages warm domain pool via domd `CreateWarmDomain` / `WarmPoolStatus` RPCs
- Pre-boots bare Xen domains (Alpine kernel + guest-init + guest-zone, IDM handshake
  complete)
- On pod creation: runtime requests a warm domain instead of cold-booting
- `DrainWarmPool` for graceful shutdown of all warm domains

**Kubernetes-level (agent-sandbox SandboxWarmPool CRD):**

- `SandboxWarmPool` CRD configures target pool size per template
- Claim controller adopts pre-warmed pods from the pool on claim creation
- `sandbox_template_config.warm_pool_size` column stores target in Codewire DB

---

## 10. Docker in Workspaces

### Profile-dependent architecture

Docker support is a runtime-profile capability, not a RuntimeClass by itself.
Users should get dev-machine Docker semantics inside the sandbox, but the
Kubernetes node's Docker/containerd socket must never be mounted or proxied into
Codewire sandboxes.

```text
workspace process
  -> DOCKER_HOST=unix:///var/run/docker/docker.sock
  -> guest-local dockerd inside the sandbox VM/runtime boundary
```

For `commodity`, dockerd must run inside the Kata VM. Privileged nested
Docker containers are scoped to that VM, not to the Kubernetes node. The
rendered workspace pod includes a `dind` container with a pod-local socket
volume. The workspace receives
`DOCKER_HOST=unix:///var/run/docker/docker.sock`, which points at the guest-local
dind socket, not a Kubernetes node socket.

The guest Docker data root must be backed by a real Linux filesystem. The
commodity renderer currently uses an ext4 image in the workspace volume,
mounted at `/var/lib/docker`, and starts dockerd with `vfs`. This is the
near-term Kata equivalent of the isol8 lesson that Docker layer unpack and
nested container workloads need ext4/xattr semantics. The durable target is a
separate raw block PVC presented to the Kata guest, formatted and mounted at
`/var/lib/docker`; see
`docs/plans/2026-07-03-guest-docker-block-backed-data-root-plan.md`.
The bootstrap verifies the target is mounted as ext4 specifically, because
`docker:dind` can make `/var/lib/docker` an existing virtiofs mount under Kata.

For local kind, tests may use `SANDBOX_DOCKER_MODE=local-dind-direct`, which
injects the existing `docker:dind` sidecar.

The separate isol8 Xen project owns its own backend-specific Docker behavior.
Codewire emits neutral `codewire.sh/*` annotations for active profiles.

The sandbox gateway is a separate per-environment workload. It reaches the
workspace daemon through the environment-local daemon Service and does not
currently mount Docker sockets in the split commodity path.

See `docs/dev/SANDBOX-GATEWAY-DAEMON.md` for the gateway, daemon, Docker
hardening, and validation contract.

### Security boundary

Future Docker proxy/filtering work is a defense-in-depth integration point and
a place to add telemetry. It is not the primary security boundary. The
VM/runtime boundary is the security boundary. If any path ever forwards to host
Docker, that is a node-escape regression.

---

## 11. Data Flow Examples

### Environment creation

```mermaid
sequenceDiagram
    participant Client as SDK / Web
    participant API as Rust Orchestration API
    participant DB as PostgreSQL
    participant Temporal as Temporal
    participant Worker as Rust Orchestration Worker
    participant SC as Sandbox Client
    participant K8s as Kubernetes API
    participant Ctrl as Agent Sandbox Controller
    participant Node as Runtime Node

    Client->>API: POST /environments
    API->>DB: INSERT environment (state=pending)
    API->>Temporal: SignalWithStart lifecycle workflow
    Temporal->>Worker: dispatch workflow activity
    Worker->>DB: state -> creating
    Worker->>SC: EnsureNamespace
    SC->>K8s: create Namespace
    Worker->>SC: EnsureTemplate
    SC->>K8s: create/update SandboxTemplate
    Worker->>SC: CreateSandboxClaim
    SC->>K8s: create SandboxClaim
    K8s->>Ctrl: reconcile claim
    Ctrl->>K8s: create Sandbox
    Ctrl->>K8s: create Pod (RuntimeClass from profile)
    K8s->>Node: schedule pod
    Node->>Node: runtime creates sandbox boundary
    Node->>Node: workspace + gateway start
    Worker->>SC: WaitForReady (watch claim)
    Ctrl-->>K8s: Ready=True
    SC-->>Worker: ready (pod IP, pod name)
    Worker->>DB: store backend, state -> running
```

### Terminal access

```mermaid
sequenceDiagram
    participant Client as CLI / Web
    participant API as Rust Orchestration API
    participant Sidecar as Pod Sidecar
    participant Zone as guest-zone
    participant Ctr as Container

    Client->>API: POST /environments/{id}/terminal (get ticket)
    API-->>Client: WebSocket ticket
    Client->>Sidecar: WebSocket connect (ticket auth)
    Sidecar->>Zone: kubectl exec -> AttachRequest
    Zone->>Ctr: setns() into container namespaces
    Zone->>Ctr: execvpe(shell)
    Ctr-->>Zone: stdout/stderr
    Zone-->>Sidecar: IDM ExecOutput
    Sidecar-->>Client: WebSocket frames
```

---

## 12. Privilege Separation

| Component | Runs as | Owns | Communicates via |
|-----------|---------|------|------------------|
| `isol8-runtime` | root (containerd child) | OCI lifecycle, state files | UDS to domd + netd |
| `isol8-domd` | root | Xen domains, IDM channels, 9PFS exports | UDS server, Xen console |
| `isol8-netd` | root (`CAP_NET_ADMIN`) | VIF routes, nft rules, proxy_arp | UDS server |
| `isol8-orchd` | root | Cross-daemon health, warm pool | UDS client to domd + netd |
| `guest-init` | PID 1 in guest | Guest mounts, network config | Launches guest-zone |
| `guest-zone` | Inside guest | Containers, exec, Docker tunnel | IDM over `/dev/hvc0` |
| `styrolite` | Inside guest (via zone) | Namespace creation, seccomp | fork/unshare/execvpe |

### Reconciliation ownership

Each daemon owns reconciliation for its own artifact class. No daemon cleans another
daemon's artifacts.

| Daemon | Owns | Reconciles on | Artifacts |
|--------|------|---------------|-----------|
| netd | Network artifacts | Startup | VIF /32 routes, nft rules, proxy_arp sysctl |
| domd | Xen domains | On-demand (CleanupOrphans RPC) | Xen PV domains, IDM channels, 9PFS exports |
| orchd | Cross-daemon health | Periodic timer | Triggers domd.CleanupOrphans, cleans loop devices |
| runtime | State files | Per-operation | `/run/isol8/runtime/*/state.json`, domain locks |

### Invariants

1. netd NEVER destroys Xen domains or modifies state.json
2. domd NEVER modifies network state (routes, nft rules)
3. orchd NEVER directly modifies artifacts -- it triggers owner daemons
4. runtime is the single writer for state.json (via OCI command lifecycle)
5. Reconciliation prefers leak over incorrect cleanup (conservative)
