# Codewire runtime profiles and Guard controls

Status: active contract for Codewire sandbox runtime selection.

Codewire runtime profiles sit above Kubernetes `RuntimeClass`. A product
profile chooses the runtime class and sandbox capability defaults. Codewire
Guard is the set of defense-in-depth controls around those profiles; it is not
itself a runtime or a CRI handler.

## Profiles

| Profile | RuntimeClass | Backend | Status | Security claim |
|---|---|---|---|---|
| `none` | none | Kubernetes default runtime | local diagnostics only | whatever isolation the disposable test cluster provides |
| `runc` | `runc` | containerd runc | diagnostic/bootstrap only | baseline Kubernetes container isolation only |
| `commodity` | `commodity` | Kata + Cloud Hypervisor through `kata-clh` | normal commodity runtime | VM boundary and defense in depth; no CoCo/SNP/TDX host-root secrecy |
| `confidential` | `confidential` | Kata + QEMU-SNP through `kata-qemu-snp` for the first dev proof | host/SNP proof in progress | hardware TEE boundary; attestation and Trustee secret-release gates are later proof work |

There are no accepted alias profile names. Backend choices such as Cloud
Hypervisor, SNP, TDX, CoCo guest-components, Trustee, and KBS are
implementation details under `commodity` or `confidential`, not
`SANDBOX_RUNTIME_PROFILE` values.

## Configuration

Use `SANDBOX_RUNTIME_PROFILE` for new configuration:

```text
SANDBOX_RUNTIME_PROFILE=commodity
SANDBOX_DOCKER_MODE=profile-default
```

Managed environment creation accepts `commodity` or `confidential`. It accepts
`none` or `runc` only with `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true`. Empty and
unknown profiles are always rejected. The diagnostic override flag is for
local-kind and explicit diagnostics only; it must not be enabled in the normal
managed sandbox path.

`SANDBOX_RUNTIME_PROFILE` is the sole runtime selector. The renderer derives
the Kubernetes RuntimeClass from it; there is no separate runtime-class input
or fallback. The shared base and managed overlays select `commodity`. Checked-in
local verification may select `runc` or `none` only together with the explicit
diagnostic gate.

The hosted Dev and Production overlays, including Dev's active runtime profile
and its confidential SNP template, live in codewire/deploy `hosted/`.
Activating the confidential profile is a two-repository change: the deploy
README owns the procedure, the confidential-smoke Kustomization template stays
in `deployments/k8s/runtime-profiles/confidential-smoke`, and
`repo_checks.py hosted-overlay-contract` pins the source resources the hosted
overlays patch.

`RuntimeClass/confidential` is present only when the site's matching host
handler and SNP scheduling label are present. It selects
`node.codewire.sh/confidential-snp=true`; do not special-case the node name in
Codewire manifests or renderers.

## Docker Capability

Docker is a profile capability, not a runtime profile.

`SANDBOX_DOCKER_MODE=profile-default` resolves as:

| Profile | Docker mode | Meaning |
|---|---|---|
| `runc` | `none` | no Docker socket unless local DinD is explicitly enabled |
| `commodity` | `guest-dind` | workspace talks directly to guest-local `docker:dind` inside the Kata VM |
| `confidential` | `guest-dind` | same shape as commodity, inside the SNP-backed Kata VM |

Local kind may use `SANDBOX_DOCKER_MODE=local-dind-direct`, which preserves the
existing privileged `docker:dind` sidecar for local tests. Local-kind overlays
must pair that with `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true` because they use
`SANDBOX_RUNTIME_PROFILE=none`.

For commodity and confidential profiles, the security boundary is the
guest VM. The workspace may run Docker commands with dev-machine semantics
inside that VM, including privileged nested containers, but the sandbox must
never mount or proxy the Kubernetes node's Docker/containerd socket. The
renderer runs `docker:dind` in the same pod and exposes it through
the pod-local socket volume; the workspace uses
`DOCKER_HOST=unix:///var/run/docker/docker.sock`. That path is inside the Kata
guest, not the Kubernetes node's Docker socket.

The `dind` data root must avoid host Docker/containerd sockets and must remain
inside the runtime boundary. On commodity `mount-workspace` creates
`/workspace/.codewire/docker-data.ext4` from the support image's e2fsprogs
once the workspace is mounted, and DinD mounts it inside the guest at
`/var/lib/docker`
and starts dockerd with `vfs`. Confidential QEMU-SNP guests
currently have ext4 support but no loop devices (`/dev/loop-control` and
`/dev/loop*` are absent), so confidential uses a plain workspace-local
`vfs` data root at `/workspace/.codewire/docker-root` instead of `mount -o
loop`. This is intentionally tactical; a block-backed data root is planned
with the workspace storage work.

See `docs/dev/SANDBOX-DAEMON.md` for the daemon, Docker boundary, and
validation details.

## Kata Agent Policy Init Data

`commodity` and `confidential` can render Codewire-owned Kata init-data on the
SandboxTemplate pod template:

```text
io.katacontainers.config.hypervisor.cc_init_data=<gzip+base64 init-data TOML>
```

For `commodity`, enable the annotation with
`SANDBOX_KATA_AGENT_POLICY_ENABLED=true`. This carries only `policy.rego`.
The base policy keeps the Codewire lifecycle, logs, exec, guest Docker, and
tailnet paths working while denying host-driven policy replacement,
diagnostic-data collection, and tracing requests:

- `default SetPolicyRequest := false`
- `default GetDiagnosticDataRequest := false`
- `default StartTracingRequest := false`
- `default StopTracingRequest := false`

For `confidential`, `SANDBOX_KATA_AGENT_POLICY_ENABLED=true` can carry the same
policy. `SANDBOX_KATA_COCO_INIT_DATA_ENABLED=true` is the confidential/CoCo
compatibility switch for the same annotation plus optional Trustee/KBS data.
When `SANDBOX_KATA_COCO_KBS_URL` is set, the payload also carries CoCo
guest-components config:

- `aa.toml` with `[token_configs.kbs].url`
- `cdh.toml` with `[kbc].name = "cc_kbc"`, the same KBS URL, and
  `protected_resource_uri_prefixes = ["kbs:///default/codewire-workspace-luks/"]`

Codewire does not prefetch test resources with a `[[credentials]]` block in the
default smoke path. CDH credential prefetch runs during guest component startup,
before pod networking is reliably available on the kata-qemu-snp path. The
confidential profile does not start `api-server-rest`: workload containers share
the guest network namespace, so loopback is not an isolation boundary. Internal
Agent image pulls and volume activation use CDH over its private Unix socket;
the runtime smoke proves the workload cannot reach port 8006.

Private registry pulls from inside a confidential guest need a second
annotation from the CoCo authenticated-registry path:

```text
io.katacontainers.config.hypervisor.kernel_params=
  agent.image_registry_auth=kbs:///default/containers/auth
  agent.image_resource_timeout_secs=300
  agent.guest_components_procs=confidential-data-hub
  agent.aa_kbc_params=cc_kbc::<KBS URL>
```

Codewire renders the 300-second image-resource deadline,
`agent.guest_components_procs=confidential-data-hub`, and `agent.aa_kbc_params` whenever
`SANDBOX_KATA_COCO_KBS_URL` is set on the `confidential` profile. The inner
deadline includes fresh attestation and remains below the outer image-pull and
kubelet deadlines. Codewire adds `agent.image_registry_auth` only when
`SANDBOX_KATA_COCO_IMAGE_REGISTRY_AUTH_URI` is set. For Codewire-owned support
images, prefer public immutable digests and later signing/encryption; use the
KBS auth URI for private user images or a constrained dev proof.

`SANDBOX_KATA_AGENT_POLICY_ENABLED` defaults to `false` in the base config and
is enabled in the hosted Dev profile once the active Kata/Cloud Hypervisor node
accepts the annotation. `SANDBOX_KATA_COCO_INIT_DATA_ENABLED` remains `false` for
commodity dev because commodity is not claiming CoCo, SNP, TDX, Trustee, or
cryptographic host-root protection.

For `commodity`, Agent Policy is defense in depth only: a malicious node root
can still modify the policy, guest image, or agent. `confidential` is the tier
where the same mechanism becomes part of a cryptographically verified
secret-release path.

The guest-components plus Trustee/KBS test resource must be
public/non-sensitive until SNP/TDX attestation is part of the release path;
it proves wiring, not secrecy. Confidential proof runs use Agent-only CDH/KBS
operations plus a negative workload port-8006 check through reviewed probe
Jobs; no local script patches the active runtime ConfigMap.

## Resource Accounting

Kata profiles use explicit Docker support container resources until real guest
overhead is measured.

Before closing the `commodity` P1 resource-accounting gate, collect resource
measurements for:

- idle workspace
- `docker version`
- image pull
- `docker compose up`
- build and unpack peak

Use `scripts/runtime/dev/measure-dev-commodity-overhead.sh` against a kept
real-node commodity environment. The script captures Kubernetes
requests/limits, live `kubectl top` observations when metrics are available,
guest Docker/dind idle details, and an optional Docker/Postgres load phase.
Record the generated `summary.md` evidence before changing runtime defaults.

## Workspace Storage

Workspace PVC storage is separate from the runtime profile.
`SANDBOX_WORKSPACE_STORAGE_CLASS` has no default: orchestration refuses to
start while it is empty, unless the runtime profile is `confidential`.
Confidential workspaces claim a raw `volumeMode: Block`, `ReadWriteOncePod`
volume from `SANDBOX_CONFIDENTIAL_WORKSPACE_STORAGE_CLASS`, which also has no
default: a confidential environment is refused while it is empty. Its class
must expose an all-zero, exactly sized raw device with no host encryption
layer, because the guest formats it as LUKS2 with dm-integrity using a key
Trustee releases after attestation; on Dev that is LINSTOR
`linstor-confidential` (codewire#2321). Confidential volumes never grow (#860).

A site sets `SANDBOX_WORKSPACE_STORAGE_CLASS` to its own StorageClass for
`commodity` workspaces; the Kind overlays use Kind's built-in `standard`. A disk resize expands the workspace PVC only when that
StorageClass advertises volume expansion.

A `commodity` workspace claims a `volumeMode: Block`, `ReadWriteOnce` volume
that the guest formats and mounts itself, so its writes reach the disk with no
host page cache (#3718; `kata-clh` opens Block disks with direct I/O). Its
class must serve Block volumes; on Dev that is `linstor-local`. A runc or Kind
workspace keeps a Filesystem claim.

- **Mount.** The one-shot init container `mount-workspace` is the only
  container that ever holds the device, at `/dev/cwws`. It is privileged
  inside the guest only, and runs from the support image. A Kata container
  with a `volumeDevice` cannot restart, so it fails closed and is never
  retried in place; recovery is a new Pod. It mounts the filesystem into a
  guest-memory emptyDir (`wsmnt`, `Bidirectional`), which the workspace and
  DinD containers mount at `/workspace` and `/home/codewire`
  (`HostToContainer`). The guest keeps the kernel's writeback defaults.
  Beside a guest DinD
  it then prepares the Docker data image, as the data init does elsewhere; a
  failure there never stops the workspace. A Block Pod so has one init
  container that must exit, as a Filesystem Pod does: each one delays the
  next container by about a second.
- **Flush.** The `workspace-flush` sidecar (an init container with
  `restartPolicy: Always`) waits for SIGTERM, then runs `syncfs` on the
  workspace with a 35 s bound, inside the Pod's 60 s grace period. The guest
  keeps the kernel's writeback defaults, so the most it can have to write is
  its dirty limit: 6.22 GiB in a 32 GiB guest, about 20 s at the measured
  327 MB/s. The kubelet stops it after the workspace and
  DinD have exited, and the VM is destroyed only after it returns, so every
  planned stop, suspension, resize, replacement, rotation and drain keeps
  every completed write. It is unprivileged and sees only the mounted
  workspace. A VM killed outright (OOM, a crashed VMM, node loss) loses what
  the guest had not yet written back, as any disk does (owner, 2026-11-02, on
  #3718: "If the sandbox crashes, the sandbox crashes").
- **Format.** Only a volume the create operation provisioned, rendered as
  `new`, is formatted, and only if `blkid -p` does not find ext4 on it. A
  linstor-local volume is LUKS-encrypted, so a new one reads as random bytes
  that may match a short foreign magic by chance: any other signature is
  wiped first. Whether a volume is new comes from the create operation, never
  from its contents. Every other volume is `existing` and must be ext4: a
  fork's from the start, and every other one from the first stop, suspension
  or Pod replacement after a Pod's `mount-workspace` exited 0. A first Pod
  that failed before its format leaves `new`, so its replacement can still
  format. An `existing` volume with no filesystem or another one, a device
  that does not read, a failed or ambiguous probe and an `e2fsck -f -p` above
  1 are refused with one `codewire mount-workspace:` line. The last line of a
  mount gives `e2fsck_ms` and `total_ms`.
- **Policy.** The warm-pool template policy admits `mount-workspace` only
  with its exact rendered script and a `new` or `existing` argument, from the
  image the workspace daemon's `codewire-bin` volume comes from, and admits a
  `volumeDevice` on no other container. Kyverno admits it as a privileged
  container only by its script's sha256, and the renderer's test prints that
  hash.
- **Temporary files (R1).** `.codewire/tmp` on the workspace disk is emptied
  at every boot and mounted at `/tmp` and `/var/tmp`, which takes the heaviest
  temporary writers off the host-backed root filesystem.
- **Growth.** A disk resize grows the device under a running guest; the
  filesystem grows online in the next Pod's `mount-workspace`, so a running
  environment's resize replaces its Pod.
- **Before the Block workspace.** A commodity environment whose workspace is
  still a Filesystem volume cannot start; existing ones are deleted at cutover.

## Managed Runtime Gates

The normal managed sandbox path is allowed to create `commodity` or
`confidential` profiles. Any `runc` or `none` profile request must be an
explicit diagnostic path; empty and unknown profiles are rejected. Keep these
gates green while retaining the checked-in local diagnostic paths:

- Codewire environment creation through `commodity`
- logs and exec through the apiserver path
- tailnet-first SSH and WebSocket fallback through the workspace daemon
- full Docker/compose inside the Kata VM
- two environments do not share Docker images, containers, volumes, or networks
- no host Docker/containerd socket or Kubernetes node credentials are reachable
- CoCo guest-components plus Trustee test-resource proof remains distinct from
  raw Kata pod success

Keep any remaining runc use in explicitly labeled diagnostic or local-kind
paths, not in the normal environment creation path.
