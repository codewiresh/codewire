# Sandbox Daemon

This document describes the in-sandbox control plane of Codewire workspaces:
the environment daemon, which also serves the workspace's SSH, tailnet and
credential bridge. There is no per-environment gateway workload.

Source files:

- `crates/codewire-daemon/` — the daemon
- `crates/codewire-workspace-access/` — the SSH, SFTP, SCP and tailnet server
  the daemon runs
- `crates/codewire-cli/src/hosted_access.rs`, `hosted_binding.rs` — binding
  and access startup in `cw __hosted-daemon`
- `crates/codewire-daemon-proto/` — shared constants and the daemon,
  bridge and broker protos
- `libs/daemon-proto/proto/daemon/v1/daemon.proto`
- `proto/codewire/internal/v1/workspace_binding.proto`

## Components

### Orchestration's internal listeners

Orchestration serves two cluster-internal TLS listeners, both with the
cert-manager leaf of its internal authority:

- **8087, workspace binding**, for
  `codewire-orchestration-workspace-binding.<namespace>.svc.cluster.local`.
  It serves only `WorkspaceBindingService` (BindWorkspace, RefreshAccess,
  RecordHostKey, AllocatePeerRelay, IssueMeshEnrollment,
  ReportMeshAttachment) to workspace Pods in the sandbox namespace, under its
  own connection, request and database limits.
- **8088, internal Connect**, for
  `codewire-orchestration.<namespace>.svc.cluster.local`. It serves only
  `MeshAuthorizationService` and `EnvironmentMeshService`, to Mesh. The
  second accepts only a service credential signed with its own derived key,
  never a forwarded user credential.

There is no plaintext listener.

- Inside a cluster, orchestration refuses to start without that leaf, and
  refuses to serve unless `codewire-orchestration-internal-roots` in the
  sandbox namespace verifies it for both names. Its only sandbox-namespace
  read is that ConfigMap (Role `codewire-orchestration-internal-roots`).
- Outside a cluster (`scripts/dev/dev-stack.sh`, integration verification) it
  serves no internal API.
- Workspace daemons mount those roots and verify 8087 with them; Mesh
  verifies 8088 with `meshAuthorization.tlsRootsConfigMap`.

Each cluster's site issues the authority and publishes the public roots
before it deploys a release that requires them.

### Environment daemon

The self-contained `cw` binary provides the environment daemon through the
private `cw __hosted-daemon` entrypoint. The support image contains that
binary at `/usr/local/bin/cw`, and the workspace container runs it as
`/codewire/bin/cw`. Commodity workspaces mount the support image's
`usr/local/bin` there as a read-only OCI image volume, so they start without a
daemon init container; with guest DinD, their only init container prepares
Docker's data image (see Runtime Profiles and Docker). Confidential, `runc` and
Kind workspaces keep a
`codewire-daemon-init` init container that copies only `cw` into a
`/codewire/bin` emptyDir: confidential guests pull images inside the guest,
where image volumes do not apply. There is no standalone daemon binary,
executable-name alias, or public daemon command.

Every Start or resume re-pins an existing Sandbox's daemon to orchestration's
current support image, in the same Sandbox patch that sets it running, so a
stopped Sandbox restarts on the current daemon. The re-pin rewrites only the
`codewire-bin` image volume's reference, or the `codewire-daemon-init` image of
a Sandbox that copies its daemon, and only from an image in the configured
support image's repository (`SANDBOX_DAEMON_IMAGE`,
[configuration reference](../CONFIGURATION.md)) to that digest-pinned image. A running Pod keeps its image until it is next started or replaced:
`cw daemon repair`, a restart-mode resize and the replacement of a
terminal Pod re-pin the running Sandbox the same way before they delete its
Pod, and an unbound Pod that fails its binding check is deleted after a
best-effort re-pin. Confidential Sandboxes are never re-pinned in place:
each start publishes the whole measured Pod template it authorizes in
Trustee instead (see "Confidential workspaces" below).

The daemon performs operations that must use the workspace container's process
namespace, filesystem view, UID/GID, and environment:

- run non-interactive commands and interactive PTY sessions
- forward stdin, stdout, stderr, resize, exit, and error messages
- provide file operations: list, stat, read, write, mkdir, remove, rename,
  setstat, and readlink
- own durable session lifecycle, attach/detach, output cursors, health, and
  capability/version diagnostics
- build process environment from session input plus
  `/home/codewire/.codewire/environment.json`, which it writes from the saved
  project on every bind; it is not a file to edit by hand, and an edit lasts
  only until the next bind
- default workspace paths to `/workspace` and `/home/codewire`

The daemon RPC listener is `0.0.0.0:7777` inside the workspace Pod. Kubernetes
exposes it only through the environment-local `cw-daemon-<env>` ClusterIP
Service, and NetworkPolicy admits only the Codewire orchestration workload in
the server namespace to it. Every daemon RPC requires the bound Pod's daemon
credential in the `x-codewire-daemon-token` metadata header.

The daemon does not own user identity, organization membership or environment
authorization; those belong to the Codewire API.

### Workspace access

Once bound, the daemon also serves the workspace's access paths from the
same process:

- **SSH** on TCP 2222 in the Pod, with SFTP and SCP served internally over
  the daemon's file RPCs. Only orchestration reaches it: its SSH proxy for
  `cw ssh` and the setup health check. Its Ed25519 host key is generated per
  binding generation, never leaves the VM, and only its public line is
  recorded with orchestration, write-once, through `RecordHostKey`. Clients
  pin that recorded key.
- **Tailnet** on UDP 31000: the daemon joins the coordinator as the
  environment's node with the coordinate capability from its binding, and
  serves the same SSH server over tailnet. The world reaches 31000 through
  the environment's direct-UDP LoadBalancer `cw-tailnet-udp-<env>`, and
  clients fall back to the shared UDP relay (allocated through
  `AllocatePeerRelay`) and then DERP.
- **Credential bridge**: the credential relay in orchestration dials the
  daemon over the daemon Service and relays the bridge to the broker.

`/codewire/run/daemon/access-ready` appears once the daemon is bound, SSH
listens and the host key is recorded. `RefreshAccess` renews the access
material before it expires. Nothing listens on 2222, 7777 or 31000 before
binding.

### Mesh network membership

An environment created with a network (`CreateEnvironmentRequest.network`)
joins that hosted Codewire Mesh network as one node, named after the
environment. This membership is separate from the environment's own access
tailnet above: another node, keys and coordinator.

- The creating user is recorded as the one who attached it. Mesh admits the
  node only while that user is enabled, still in the organization and a
  member of the network.
- The access grant names the network (`WorkspaceAccess.mesh`: Mesh origin,
  organization, network, node name) and no credential for it.
- For each Mesh peer stream the daemon calls `IssueMeshEnrollment`. It gets
  one enrollment code (`cw_eenr_…`): used once, refused after 60 seconds,
  and bound to its Pod and the environment's operation generation.
  Orchestration stores only the code's SHA-256, and holds at most eight
  unused codes per environment.
- Mesh redeems the code with orchestration's `EnvironmentMeshService`, which
  consumes it only while its Pod is still the environment's live binding at
  that generation. Mesh rechecks every member it holds at least every 60
  seconds: a stopped or replaced Pod's stream closes, and a destroyed or
  detached environment's node is removed.
- A refused peer stream says why, by its Connect code:
  - `not_found`: no such network in the organization;
  - `unauthenticated`: the code was refused, so ask for another;
  - `permission_denied`: the attaching user is not a network member;
  - `failed_precondition`: a network owner revoked the node;
  - `already_exists`: another node has the environment's name;
  - `unavailable`: Mesh could not reach orchestration.

  A stream that a recheck, a revocation or a newer stream of the same node
  ends just closes, and the next enrollment gives the reason.
- Network deletion removes the nodes of destroyed environments first, so they
  never keep a network alive. A network owner's `cw network revoke` of an
  environment's node is permanent for that network.
- The daemon runs the node next to the access tailnet:
  - it has its own WireGuard and disco keys, made fresh for each stream;
  - it has its own ephemeral UDP socket, with STUN and then Mesh's DERP;
  - it looks up names as absolute DNS names (#2701);
  - it serves the environment's application ports, the same set as on the
    tailnet, on its Mesh address.

  When a stream ends, the daemon rejoins with a new code. It retries a fault
  after 1 to 30 s and a refusal after 60 to 300 s, and reports each change
  once.
- Members reach each other. A member's peer stream may subscribe to up to
  64 other members of its own network: Mesh derives the target from the
  subscriber's own network, so another network's node is never addressed.
  The daemon serves `cw network connect NODE PORT` on its owner-only socket
  `/codewire/run/daemon/mesh.sock`: one request line, then a TCP stream to
  that member's port. A member serves only its application ports there.
- The daemon reports what it observed with `ReportMeshAttachment`. The
  environment shows the report only for its current Pod, so a new Pod reads
  as pending until its daemon reports.

The workload shares the daemon's UID, so it can read a code during its 60
seconds, like the access peer token, and it can make the daemon's reports:
the attachment state an environment shows is what its runtime reported. A
code admits only its own environment's node, and only while its Pod is live.
No user, platform or long-lived Mesh credential enters the Sandbox.

The node acts for the user who attached the environment. Anyone who can run
commands in the environment (its creator, an organization owner or admin, or
a user granted operator access) can use the node's membership.

The hop from Mesh is signed with a key derived for it alone. This separates
it from every other credential made from the same internal secret. It does
not isolate orchestration from a Mesh that holds that secret.

## Startup Sequence

1. Kubernetes starts the workspace Pod from the `SandboxClaim` (or adopts a
   warm-pool member).
2. On commodity, the kubelet mounts `/codewire/bin` read-only from the
   support image and no daemon init container runs. Elsewhere, the
   `codewire-daemon-init` init container copies `/usr/local/bin/cw` from the
   support image to `/codewire/bin/cw` and prepares `/codewire/run/processes`.
   A hosted daemon with launch projection creates its owner-private (0700)
   `/codewire/run/processes` itself when it is missing. The daemon also
   prepares Codex's home, `~/.codex` on the persistent home volume, before it
   listens, and once listening keeps Codex's own ChatGPT login there while
   the broker delivers one (see
   [Secrets and credentials](SECRETS-AND-CREDENTIALS.md#codex-home-in-hosted-sandboxes)).
3. A managed image runs `cw __hosted-daemon` as its primary supervised process.
   A custom image runs the same private entrypoint as a supervised side process
   beside the image command and restarts it while that workload remains alive.
4. The daemon writes `/codewire/run/daemon/ready` and long-polls
   `BindWorkspace` on 8087. Orchestration creates the environment's access
   objects (the daemon Service, the direct-UDP LoadBalancer and the workspace
   NetworkPolicy) and records the binding as soon as the chain is bind-ready.
5. Bound, the daemon listens on 7777, starts SSH on 2222, records its host
   key, writes `access-ready`, and joins the tailnet.
6. Create and start wait for the Claim to be Ready and for access: setup's
   health check completes a pinned SSH handshake with the recorded host key.

What bounds a daemon that never comes up is the tier's workspace ready
timeout: 10 minutes for commodity and 30 minutes for confidential, whose guest
initializes encrypted storage before the daemon listens. The workspace's
daemon-ready startup probe uses the same budget.

Docker is not on this path (Program #2238; owner, 2026-10-27: "Gate on the
daemon/SSH ... Docker comes up shortly after; a docker command run before then
waits for it"). See "Docker readiness" below.

## Daemon API Surface

The support image ships the self-contained Rust `cw` binary. Its private
hosted-daemon mode serves only the typed gRPC daemon service on 7777; it has
no HTTP router, unauthenticated health route, or shell-based diagnostic
endpoint.

| Surface | Source | Purpose | Status |
|---|---|---|---|
| typed daemon service | `libs/daemon-proto/proto/daemon/v1/daemon.proto` | typed daemon RPC contract | the only path |

The typed service exposes:

- `GetCapabilities` and `GetHealth` for version negotiation, readiness, and
  actionable `unsupported`, `starting`, `unhealthy`, and `upgrade_required`
  states
- durable session launch/list/get/stop/restart, attach/detach, input, resize,
  events, and lossless output reads by byte offset
- a launch setting, `end_after_detached_seconds` (capability
  `session_end_after_detached.v1`, at most 7 days): the session ends, as an
  explicit stop does (a PTY is hung up), once no client has been attached for
  that long, counted from launch or restart until the first attachment and
  from each last detach. Every attach stream counts, whichever path it came
  by. The record keeps the setting and says `ended: no client for N minutes`.
  Zero, the default, never ends a session this way
- `ExecSession`: bidirectional stream for non-PTY commands
- `PtySession`: bidirectional stream for interactive shells
- `List`, `Stat`, `OpenFile`, `Read`, `Write`, `Mkdir`, `Remove`, `Rename`,
  `SetStat`, and `Readlink`

Orchestration (its exec, file and health paths and the credential relay) and
the daemon's own access server use `daemon.proto` through authenticated
tonic/gRPC: orchestration over the workspace daemon Service with the bound
Pod's daemon credential, the access server over the daemon's in-process
transport. Treat `daemon.proto` as the compatibility contract.

The legacy WebSocket session path (`/session`) and legacy HTTP file API
(`/files/*`) are retired. The old Go daemon command, Go daemon package, and Go
helper module have been deleted. Do not reintroduce the legacy frame protocol;
new work must target the typed daemon service.
## Command Semantics

For both exec and PTY sessions:

- empty command defaults to the workspace shell
- empty working directory defaults to the workspace user home
- command process env starts from the workspace container env
- persisted env from `/home/codewire/.codewire/environment.json` is merged in
- session-provided env wins over persisted env
- PTY sessions set `TERM` from the request
- `HOME`, `USER`, and `SHELL` are filled with sane defaults when missing
- stdout/stderr are drained before `Wait` to avoid losing buffered output
## File Semantics

Daemon file operations are intentionally workspace-scoped. Paths are cleaned and
resolved against:

- `/workspace`
- `/home/codewire`

Relative paths resolve under `/workspace`. Attempts to operate outside those
roots fail before the filesystem operation. The typed gRPC service applies
this rule to every file operation. This path
boundary is defense in depth for the workspace control channel. It is not a
substitute for the runtime boundary: a user command still runs as the workspace
user inside the sandbox and can do whatever that user can do in the workspace
container.
## Runtime Profiles and Docker

Docker support is a runtime-profile capability, not a Kubernetes RuntimeClass
by itself.

| Profile | Default Docker mode | Shape |
|---|---|---|
| `runc` | `none` | no Docker socket |
| local kind override | `local-dind-direct` | workspace talks directly to a pod-local `docker:dind` socket |
| `commodity` | `guest-dind` | workspace talks to guest-local `docker:dind` inside the Kata/Cloud Hypervisor boundary |
| `confidential` | `guest-dind` | same pod shape as commodity, with future TEE gates |

For commodity and future confidential profiles, the intended Docker path is:

```text
docker CLI in workspace
  -> DOCKER_HOST=unix:///var/run/docker/docker.sock
  -> docker:dind running inside the same Kata/CoCo pod
```

The workspace container must not mount `/var/run/docker.sock`,
`/run/docker.sock`, or the Kubernetes node's containerd socket. The
`/var/run/docker/docker.sock` path is the pod-local dind socket inside the
runtime boundary, not the Kubernetes node's socket.

The `dind` data root must stay inside the runtime boundary and must not use the
Kubernetes node's Docker/containerd sockets. Commodity keeps an ext4 image at
`/workspace/.codewire/docker-data.ext4`, mounts it at `/var/lib/docker`, and
uses dockerd `vfs`, because the current Kata guest rejects `overlay2` for this
path. The commodity smoke checks for the ext4 over-mount specifically, not
just any mountpoint.

The DinD image ships no filesystem tools since Docker 29.9.2 (#3208), so the
`codewire-docker-data-init` init container prepares the image from the support
image's e2fsprogs before DinD starts, and DinD only mounts it and starts
dockerd with busybox. The init container runs as root with only the workspace
volume, and reads the same `CODEWIRE_DOCKER_DATA_IMAGE`, `_SIZE` and
`_MOUNT_MODE` as DinD, and follows `codewire-daemon-init`. On commodity the
workspace is a Block volume, and `mount-workspace` prepares the image with the
same script and variables right after it mounts the workspace, so no separate
data init renders there (#3718).

The image is created on the Pod's first start as a sparse file of
`CODEWIRE_DOCKER_DATA_SIZE`, and formatted with `-E
lazy_itable_init=1,lazy_journal_init=1`. A freshly truncated file reads as
zeros, so skipping the inode-table and journal zeroing is safe, and the
format writes a few MiB at any size instead of the journal (512 MiB at
78 GiB, 1 GiB at 198 GiB). Where the storage cannot discard, the kernel
zeroes the inode tables in the background after the mount. A grown workspace
disk renders a larger size: the next start extends the image to it, never
shrinking it, then checks (`e2fsck -f`) and grows (`resize2fs`) its
filesystem offline, which also finishes an interrupted grow. A failed format
or grow never fails the init container: Docker then reports the missing image,
or starts at its previous size. A Start or Pod replacement re-renders a
Sandbox whose DinD still formats or grows the image itself, adding the init
container in the same patch.

Confidential QEMU-SNP is different: the confidential guest has ext4 support
but no loop devices, so `mount -o loop` fails even when the target directory exists. For
confidential, the renderer starts dockerd with `--data-root
/workspace/.codewire/docker-root`, `--storage-driver vfs`, and
`CODEWIRE_DOCKER_MOUNT_MODE=none`.

Commodity bootstrap candidates use the source-bound storage fixture in the
[agent development workflow](AGENT-WORKFLOW.md#local-verification). Render
without Kubernetes credentials on native Linux, transfer `fixture.json`, and
apply the reviewed bundle through the trusted host's Dev access wrapper. The
fixture owns its Pod, Block workspace and exact product network policy.

### Docker readiness

Docker never decides whether a workspace is Ready. The workspace container's
probes are the same with or without DinD: an identity-free workspace's
startup and readiness probes test only the daemon's marker, and an
environment-token workspace has none. The `dind` container has no probe, so a
running `dind` counts as ready while its bootstrap mounts the ext4 data image
and dockerd starts; a bootstrap that exits still leaves the
Pod unready until the kubelet restarts it, and a dockerd that exits is
restarted the same way. So the Claim turns Ready, and MarkRunning, setup and
SSH proceed, without waiting for dockerd; nothing that waits for the Claim
changed.

A Docker client that runs before dockerd listens waits for its socket:

- setup's install command and startup script run after a wait of up to 60
  seconds for `/var/run/docker/docker.sock` whenever `DOCKER_HOST` names it,
  in any image. The wait never fails the command; it then runs as before and
  any Docker error is Docker's own;
- the managed workspace image's `docker` waits the same way, then runs the
  real CLI (`/usr/local/libexec/codewire/docker`) unchanged. A custom image's
  own `docker`, and clients that open the socket directly, do not wait
  outside setup.

The wait ends once the socket exists. A socket left by a `dind` container
that is restarting exists but refuses connections, so a client then fails at
once, as before this change.

## Security Invariants

- External clients never connect to the daemon directly. The daemon Service
  is ClusterIP-only and NetworkPolicy admits only orchestration to 7777 and
  2222; only the world reaches UDP 31000, through the LoadBalancer.
- App-preview traffic is separate from daemon traffic: public preview requests
  terminate at ingress/orchestration, then the orchestration preview proxy
  connects to the workspace Pod on the registered TCP app port. Preview ports
  may be any port except 2222.
- Typed daemon RPCs require the bound Pod's daemon credential via
  `x-codewire-daemon-token`.
- The API owns user authentication, organization membership, and environment
  authorization; orchestration's SSH proxy and the coordinator admit access.
- The workspace container must not receive Kubernetes node credentials, host
  Docker sockets, host containerd sockets, or privileged host mounts.
- In CoCo profiles, privileged Docker-in-Docker is acceptable only when the pod
  is actually using the Kata/CoCo runtime class and the Docker daemon is inside
  the guest VM boundary.

The daemon's SSH server uses no SSH client auth: admission happens before
traffic reaches it, in orchestration's SSH proxy or the tailnet coordinator.
Never expose 2222 outside that path.

The SSH server offers russh's default key exchanges, `mlkem768x25519-sha256`
first, so OpenSSH negotiates a post-quantum exchange. Its larger key-exchange
packets need a path that carries full-size tunnel packets.

Tailnet interop has two packet-level invariants: packets must carry checksums
a Go/Tailscale peer accepts, and the tunnel MTU must leave room for WireGuard,
relay, UDP, IP and pod network overhead across nodes.

## Claim-time workspace binding

Every hosted workspace binds at claim time, confidential ones included
(Program #2238 B2 and B2c):

- **Identity-free Pod.** The workspace container carries no daemon token,
  environment ID, operation generation, projection digest, managed-client
  selection or derived client variables, and the template no environment
  label or Codex ConfigMap. It carries a
  Pod-bound projected token (`codewire.internal.workspace-binding.v1`, 600 s,
  `/var/run/secrets/codewire/workspace-binding`; the volume asks for 0440, and
  because the Pod sets `fsGroup` kubelet writes it 0640 with group 1000),
  `CODEWIRE_WORKSPACE_BINDING_URL` and its own UID (`CODEWIRE_POD_UID`, from
  the downward API). A golden fixture and the `identity-free-workspace`
  policy guard enforce this.
- **Bind, then listen.** The daemon writes `/codewire/run/daemon/ready`,
  which the readiness probe tests (never Docker, in any mode), and
  long-polls `WorkspaceBindingService.BindWorkspace` on orchestration's
  dedicated listener (TCP 8087). After a valid response for its own Pod UID
  it writes its credential to `/codewire/run/daemon/credential` (0400),
  which the fixed-purpose hosted exec reads, prepares Codex's `~/.codex` for
  the bound clients, and only then listens on 7777, serves SSH on 2222 and
  joins the tailnet (see "Workspace access" above).
- **Record before release.** As soon as the chain is bind-ready, while
  create and start still wait for Claim Ready, orchestration
  verifies the Claim → Sandbox → Pod UID chain, images and the workspace PVC
  UID and records Pod UID → environment. Bind-ready means:
  - identity labels converged;
  - the Sandbox status reporting its current generation;
  - the Pod `Running` with every container started from a resolved image.

  Claim Ready still gates MarkRunning and setup; Docker in DinD may still be
  starting after both. Create, start, a Pod replaced while running, resize,
  daemon repair and setup recovery all bind this way. Stop and destroy release the binding
  only after the Pod is gone. The `workspace_bind` stage measures it.
- **Rotating the session secret** changes every daemon credential. Bound
  daemons never re-bind, so it requires restarting the workspace Pods.
- **No environment-token mode.** The daemon serves SSH and the tailnet only
  once bound, so nothing renders an environment token. A Sandbox rendered
  before binding is upgraded to the identity-free rendering on its next start,
  and a running one is never treated as current, so recovery restarts it onto
  the binding rendering.

Exposure statement:

> A workspace Pod receives a Pod-bound projected token with the audience
> `codewire.internal.workspace-binding.v1`, in the `workspace` container
> only. The daemon uses it to fetch its binding, then keeps the daemon
> credential in memory and in an owner-only file under `/codewire/run`.
>
> The workload runs as the daemon's uid and can reach VM root through
> privileged DinD, so it can read both the binding token and the daemon
> credential, just as it can read today's environment-variable token. Both
> are scoped to this environment and this Pod. They grant the Pod's own
> binding response and the private daemon RPC boundary of the same Pod. They
> grant no provider credential, no other Pod's binding and no Kubernetes API
> access: the API server rejects the custom audience, and
> `automountServiceAccountToken` is false. The bind response also carries the
> Pod's coordinate capability, which admits only this environment's tailnet
> node.

Warm-pool members are identity-free and bind at adoption the same way. The
zero-replica `SandboxWarmPool` referenced by a cold claim remains only because
the Agent Sandbox CRD requires that indirection for cold creation.

### Confidential workspaces (B2c)

A confidential workspace binds exactly like a standard one, on the SEV-SNP
runtime, with its trust anchors in its measured Kata init-data:

- **Measured anchors.** Its workspace container carries
  `CODEWIRE_WORKSPACE_BINDING_URL`, `CODEWIRE_MEASURED_BINDING_ROOTS` (the PEM
  of orchestration's own issuing CA, beside its internal leaf, never the
  sandbox-namespace ConfigMap) and `CODEWIRE_MEASURED_ENVIRONMENT_ID` (the
  UUID the init-data already measures as the storage key ID). The measured
  policy admits the workspace container only with each exactly once and with
  its rendered value, so the init-data Trustee authorizes before it releases
  the workspace key commits to them.
- **Measured mode in the daemon.** With those entries the daemon trusts only
  the measured roots for 8087, held in memory, binds only as the measured
  environment, and trusts the coordinator through WebPKI alone, never a
  mounted bundle.
- **No ConfigMap, state in guest memory.** The Pod mounts no ConfigMap: under
  `shared_fs=none` the host supplies every mounted file. `codewire-run`,
  which holds the credential and the SSH host key, is a memory emptyDir.
- **What boots is what Trustee authorizes.** Start and terminal Pod
  replacement publish the whole measured Pod template they authorize, and
  replacement waits until the stale Pod shows the new init-data before
  deleting it. Repair and resize reuse the Sandbox's current, authorized
  template. A changed binding root, policy text, workspace or DinD image
  changes the measurement, so the next start republishes it.
- **Confidential stays cold.** It is never pooled.
- **Not a hostile-host boundary yet.** A host that uses the Kata agent API
  (exec), forges the Pod at 8087, reads plaintext 7777 or connects to 2222 can
  still reach a running workspace. The design note lists the follow-up that
  closes these paths.

## Troubleshooting

If shell, exec, or file operations fail:

1. Run `cw daemon status ENV`; it reports daemon state, protocol version,
   capabilities, pod identity, and diagnostics without exposing the daemon
   credential.
2. Check the workspace Pod exists with `workspace` (and `dind`) containers
   and that `/codewire/run/daemon/access-ready` exists in it.
3. Run `cw daemon logs ENV`; a bound daemon logs its binding, its SSH
   listener and its tailnet join. An unbound one logs its binding attempts.
4. If the daemon is unhealthy or unavailable, run `cw daemon repair ENV`.
   Repair replaces only the workspace Pod, binds the replacement, and
   preserves the environment, Sandbox, claim, PVCs, and identity.
5. For OpenSSH hangs over tailnet, compare `CW_SSH_TRANSPORT=websocket` and
   `CW_SSH_TRANSPORT=tailnet` and inspect `CW_DEBUG_TAILNET=1` path-probe
   output; then check packet checksums, tunnel MTU/MSS, forced-DERP behavior,
   and whether the relay path was tested cross-node.

If Docker fails in a Kata-backed sandbox:

1. Confirm the pod has `runtimeClassName: commodity` or `confidential`.
2. Confirm the workspace pod has `workspace` and `dind` containers.
3. Confirm the workspace has `DOCKER_HOST=unix:///var/run/docker/docker.sock`.
4. Confirm no host Docker/containerd socket is mounted into the workspace.

## Validation Checklist

For a `confidential` sandbox, run
`scripts/runtime/confidential/prove-dev-confidential-binding.sh` on Dev.

For a `commodity` sandbox, expected evidence is:

- workspace pod `runtimeClassName` is `commodity`
- workspace pod containers are `workspace` and `dind`
- the workspace has no environment token: it binds through 8087
- workspace env has `DOCKER_HOST=unix:///var/run/docker/docker.sock`
- workspace does not have `/var/run/docker.sock` or `/run/docker.sock`
- workspace daemon Service is ClusterIP-only on TCP `7777`
- `cw ssh`, `scp`, `sftp` and tailnet SSH reach the workspace with the
  recorded host key
- `docker version` works from the workspace
- `docker compose` can run a simple service

Do not flip `commodity` to a default runtime from pod readiness alone.
Docker/compose and no-host-socket evidence are part of the gate.
