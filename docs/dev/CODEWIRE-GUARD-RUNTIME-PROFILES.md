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

Target, not shipped (#5602): a third managed profile, `standard`, with RuntimeClass
`standard` on the node's ordinary handler. Its backend is Codewire's own VM
runtime, Cloud Hypervisor started inside the Pod by a non-root container. Its
security claim is a VM boundary whose VM process is itself confined to a
container with no capabilities; like `commodity`, it claims no secrecy from
the host's root. ["The `standard` profile"](#the-standard-profile) below has
its rules.

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

Managed environment creation accepts `commodity`, `confidential` or `standard`.
It accepts `none` or `runc` only with `SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME=true`.
`standard` (#5602, not yet observed working) also needs
`SANDBOX_STANDARD_RUNTIME_IMAGE`, `SANDBOX_STANDARD_IMAGE_DISK` and hosted
egress on; without them orchestration stops at startup
([docs/CONFIGURATION.md](../CONFIGURATION.md)). On `standard`, an environment
whose image does not have the digest of the workspace image the disk was
built from (a user's own image, or a workspace image whose disk has not been
published) is created on `commodity`, and no warm pool is rendered yet. Empty and
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
| `standard` | `none` | Docker runs inside the VM; the Pod has no Docker container, and any other mode is refused |

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

## Hosted Egress Setup

A broker-mode Sandbox (hosted egress, #4000) renders only on a VM runtime
profile, `commodity` or `confidential`. Its egress path is set up inside the
guest before the workload starts, by one init container, `hosted-egress-tun`.

- **What it runs:** exactly the support image's own
  `/usr/local/bin/cw __hosted-egress-tun --owner-uid <workspace uid>`, with no
  other arguments, environment or inputs. It never runs the daemon volume's
  `cw`, which the workspace can write.
- **What it holds, and when:** it is privileged inside the guest, and only for
  the setup. It is an init container, so it exits before the workload starts.
  The workspace container is not privileged. It runs as the workspace uid and
  keeps the runtime's default capability set, so `sudo` in a hosted workspace
  yields root with those capabilities and no others. The VM is what contains
  it. Admission pins this container by name, image, command and mount in
  every layer: the warm-pool template policy, the pool member's first-bind
  isolation, and the cluster's policy.
- **The TUN device:** a Kata container has no `/dev/net/tun`, though the
  guest kernel has TUN built in. So the Pod carries one more volume, `egress-devnet`:
  - an `emptyDir` with `medium: Memory` and `sizeLimit: 1Mi`, a tmpfs inside
    the guest. It is never disk-backed: that would be the node's filesystem
    shared into the VM, and a device node must never be written there;
  - mounted at exactly `/dev/net`, with no subPath or propagation, by
    `hosted-egress-tun` and the workspace container only.
- **The node:** the init trusts nothing at the path, because the workspace can
  write the volume.
  - It opens `/dev/net` itself as a directory, without following a link, and
    checks it is a tmpfs. On anything else it removes and creates nothing,
    and fails the Pod. Every later step is relative to that open directory.
  - It removes whatever is at `/dev/net/tun`. Removing a symbolic link removes
    the link, never its target.
  - It creates the node afresh as character device 10:200.
  - It opens the node without following a link, and checks on the open
    descriptor that it is character device 10:200 before any ioctl. Anything
    else fails the Pod.
  - It gives the node mode 0600, owned by the workspace uid, through that
    descriptor.
  - Only then does it create the persistent TUN `cwegress0` for the workspace
    uid, and make the routing.
- **What the workload gains:** nothing it couldn't already have. Root in a
  hosted workspace can make device nodes, and the guest lets an unprivileged
  process open this one. Opening it attaches only the interface made for the
  daemon's uid. What a Sandbox can reach is still decided outside the guest,
  by `cw-egress` and the cluster's fence.

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

The workspace's network policy admits the key broker on the URL's port. By
default the peer is the namespace in the URL's Service name.
`SANDBOX_KATA_COCO_KBS_PEER=NAMESPACE:key=value,...` names the key broker's Pods
instead, matched by namespace and labels together. A URL whose host is an
address names no namespace, and a policy rule on a Service address never
matches after the address is translated, so such a URL requires the peer, and
orchestration refuses to start without it.

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
  guest-memory emptyDir (`mnthome`, `Bidirectional`), which the workspace and
  DinD containers mount at `/home/codewire` (`HostToContainer`). It also
  creates the filesystem's `workspace/` folder and binds it into a second
  emptyDir (`mntws`), which is what the workspace and DinD mount at
  `/workspace`, so `/workspace` starts empty and the home stays the
  filesystem's root (#4026); DinD sees that root at `/mnt/home` for its data
  image. The
  guest keeps the kernel's writeback defaults.
  Beside a guest DinD
  it then prepares the Docker data image, as the data init does elsewhere; a
  failure there never stops the workspace. A Block Pod so has one init
  container that must exit, as a Filesystem Pod does: each one delays the
  next container by about a second.
- **Flush.** The `workspace-flush` sidecar (an init container with
  `restartPolicy: Always`) waits for SIGTERM, then runs `syncfs` on the
  workspace with a 35 s bound, inside the Pod's 60 s grace period. The bound
  is a watchdog on the sidecar's own shell: a `syncfs` stuck in
  uninterruptible sleep holds even SIGKILL, so the sidecar never waits on it
  past 35 s. It reports the flush failed and exits, and nothing waits for
  the stuck `syncfs` again: it holds the disk until its writes complete or
  the Pod's VM goes (#5089). A `syncfs` that returns before the bound is
  reported by its own status. The guest
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

## The `standard` profile

Target, not shipped (#5602). `SPEC.md` section 4 states what the Pod and the
VM hold. This section states what Guard requires around them.

**Admission.** Under Kata a VM wraps the whole Pod, which is why a privileged
Docker container is admitted there. Nothing wraps a `standard` Pod, so its
rule is stricter and applies to every Pod of the class, not only to pool
templates:

- exactly one container, at an allowed digest of Codewire's runtime image;
- it runs the image's own entrypoint: a Pod that sets a command or
  arguments is refused, because the rule pins the image and not what is run
  from it;
- it does not run as root, is not privileged, cannot escalate privilege,
  drops every capability and keeps the runtime's default seccomp profile;
- it changes none of the container runtime's default confinement: no
  SELinux options, no `procMount`, no sysctls, and no AppArmor or seccomp
  profile other than the runtime's default. An SELinux type or an
  unconfined profile would remove the second layer the claim below rests
  on;
- no host namespace, host path or host port;
- no init container and no ephemeral container;
- one device, `/dev/kvm`, and no supplemental group to reach it;
- only these volumes: the workspace claim, the projected tokens, the roots
  ConfigMap and the workspace image's disk;
- the workspace image's disk is an image at an allowed digest, mounted
  read-only. Otherwise a Pod of the class could make the node pull an image
  of its choosing.

The `/dev/kvm` device resource is refused on a Pod of any other class.

Orchestration's own template policy holds a `standard` template to its broker
arm like any other, but without the TUN init and the TUN device: the VM's
network is its own netstack, so a `standard` template has neither, and the
TUN rule still refuses a TUN init under `standard`. A pool template may run
under `standard` only in exactly the standard shape (#5602): one container,
the workspace, and no init container; the workspace disk its one image
volume, pinned by digest and mounted read-only at `/image`; the one
`codewire.sh/kvm` device; its VM state `new`, its egress mode
`guest-carried` and its first process a literal `systemd` or `image`; and its
VM settings as literals. Those settings are allowed on no other pool
template. These rules must be live before a deployment sets a `standard`
pool shape.

The workspace container's `CODEWIRE_VM_EGRESS_MODE` says how the guest's
workload reaches the network: `guest-carried`, its own network session with
only the platform peers, or `broker`, hosted broker mode inside the VM.
Orchestration renders `broker` on an environment's own template and
`guest-carried` on a pool's. In `broker` mode cw-egress's 8089 stream is one
of the Pod's literal platform peers, as on every broker-mode Pod; the Pod's
settings name it on the host, and no guest message adds or changes it. The
guest holds the Pod-bound cw-egress token, so cw-egress's admission is the
check: the token opens only this Pod's stream, on this node, matched to the
token's Pod UID, the Pod's label and the stream's source address as cw-egress
sees them. A claimed pool member stays `guest-carried` until pools render
broker mode.
The template policy and the class's Pod rule admit it only on a `standard`
workspace, once, as one of those two literal values. The runtime refuses any
other value. The binding listener waives the guest's own egress self-check
only for `broker`, whose stream cw-egress's lockdown check covers as on Kata,
and reads the value from the Pod spec the API server returns, never from the
guest. The broker label alone never waives it: every `standard` Pod carries
that label while hosted egress is on.

**The claim.** Outside the VM are the supervisor and the VM process, with
the Pod's address and the Sandbox's projected tokens. The boundary a
workload has to cross is KVM, Cloud Hypervisor and the supervisor's own
interface to the guest. A break-out reaches a container that is not root and
has no capabilities, on the node's shared kernel, with that Sandbox's own
tokens and the fenced Pod network. The node is a second, kernel-level
escape away. The container is a second layer, not a second VM.

**The device.** A device plugin on the node hands `/dev/kvm` to the Pod. The
container opens it as its own user. On a node where the device is not open to
every user, that needs the container runtime to give a device the
container's own owner (containerd's `device_ownership_from_security_context`).

The plugin is `cw-kvm-device-plugin`, a DaemonSet from the services image on
the sandbox runtime nodes (`deployments/k8s/kvm-device-plugin`). It registers
the extended resource `codewire.sh/kvm` with the kubelet, 110 per node, the
kubelet's default Pod limit, so the count never binds before the node's own
limits. For each container given one, the kubelet adds the node's `/dev/kvm`
at `/dev/kvm` with read and write access, and nothing else: no mount, no
variable, no other device. A Pod on a node with none free stays Pending with
"Insufficient codewire.sh/kvm". When the device is missing the plugin reports
every one unhealthy, and the scheduler stops placing Pods there.

The plugin runs as root and privileged, the one privileged container this
profile adds. Root, to make its socket in the kubelet's root-owned device
plugin directory and reach the kubelet's socket there, its only host path.
Privileged, because an enforcing SELinux policy on our nodes lets the kubelet
connect only to a privileged container's socket. It reads no Kubernetes
object and holds no credential.

The `standard` RuntimeClass runs on the node's ordinary handler, `runc`. It
carries the runtime nodes' toleration and no node selector: the resource
already keeps the Pod on a node whose plugin advertises it. Its `podFixed`
overhead (1 GiB and one CPU) is an estimate, to be measured on Dev.

**Resources.** The container's requests are the size the user chose, as on
the other profiles, because billing reads them. The VM process's own memory
and CPU are added to the limit and to the RuntimeClass overhead, never to
the request.

**Storage.** The VM's disks are files on the Sandbox's filesystem volume,
opened with direct I/O so that the guest's writes are not also held in a
page cache charged to the Pod.

**What changes for an operator.** `kubectl exec` into `workspace` lands in
the runtime's container, outside the VM. The container's log carries the
daemon's log.

### Moving an organization

A deployment can make `standard` available without making it every
organization's default (#5602, `private-docs: designs/standard-per-organization.md`).
`standard` is available when `SANDBOX_STANDARD_RUNTIME_IMAGE` and
`SANDBOX_STANDARD_IMAGE_DISK` are set and hosted egress is on; orchestration
reads and validates the two settings whenever they are set, on any profile.
`SANDBOX_RUNTIME_PROFILE` stays the default for every organization that is not
moved, and `SANDBOX_RUNTIME_PROFILE=standard` still means every organization.

- **Moving one.** A global administrator sets
  `organizations.standard_runtime_enabled` with the AdminService call
  `SetOrganizationStandardRuntime`, or the "Standard runtime" checkbox on the
  admin organization page. The change and its audit entry
  (`admin.organization.standard_runtime`: the actor, the organization, the
  previous and new values) commit together. A move onto `standard` is refused
  while the deployment doesn't make it available; a move back is always
  allowed. `ListStandardRuntimeOrganizations` lists the moved ones.
- **What a create records.** Each create records its profile once
  (`environments.runtime_profile`): `confidential` on the confidential tier;
  `standard` when the organization is moved and `standard` is available;
  otherwise the deployment's default; and `commodity` whenever a `standard` VM
  would not boot the image. A fork decides afresh under its own
  organization's move.
- **Every later render reads the record**, never the organization's flag,
  the deployment's default or its current disk. So a move, or a republished
  disk, changes only new creates: an existing environment starts on the
  profile it was created on. One created on `standard` whose deployment no
  longer has it is refused at start, never rendered onto another profile.
  Before this record, a plain environment's profile was derived again on
  every start, so a republished disk could move it.
- **Warm pools** serve only the deployment default's profile. A moved
  organization's creates start cold until pools are kept per profile.
- **A `standard` default** is refused at startup while any plain environment
  recorded `commodity` runs on another runtime class in its live Sandbox, and
  when the Sandboxes can't be read.

### Building the workspace disk in CI

A `standard` workspace boots its image from a disk built from that image
(`SANDBOX_STANDARD_IMAGE_DISK`). Dev accepts only a disk CI built and signed,
or until then a digest the deploy repository's hosted policy waives by name.
So CI builds, pushes and signs one disk for each workspace image it pins.

- **Where and when.** The disk jobs are in `deploy-dev.yaml`, beside the
  pod-runtime image: Deploy Dev's publisher identity is the one that holds
  the runtime signing key, so no other identity gains it. They run only on
  main's own events, never a pull request's or another branch's. Like
  pod-runtime, the disk is keyed by a planner fingerprint, of the pinned
  workspace images (`crates/codewire-workspace-image/src/pin.rs`) and the
  disk's build inputs. The jobs are skipped when a signed disk already
  carries that fingerprint's `fp-` tag.
- **Inputs, prepared on the trusted light runner.** A job there compiles
  `codewire-local-vmm-smoke` and takes the runtime from the signed pod-runtime
  image that the source pins (`deployments/k8s/orchestration/pod-runtime-image.digest`),
  checking main CI's signature first. It packs both in one tar, which keeps
  the runtime's modes (directories 0700, executables 0500, other files 0400),
  because a workflow artifact keeps no file mode. Its sha256 is a job output.
- **The build, on the KVM runner.** `workspace-disk.sh build` runs on
  `ci-trusted-medium-kvm` (infra `docs/ci/runners.md` section 2.6b), the one
  CI runner with `/dev/kvm`, whose jobs run on the host kernel. The job holds
  no credential. It refuses the tar unless its sha256 is the job output,
  unpacks it with its modes and checks them against the runtime's lock.
  It pulls the workspace image anonymously from its public GHCR mirror, and
  refuses one whose digest is not the pinned digest. The `workspace-disk.sh
  line` value names the platform registry's reference at that digest
  (`codewire/workspace` or `codewire/workspace-systemd`), as the hosted
  policy requires; `line` checks only the digest. Its scratch is a
  dedicated volume on the node, because the build peaks at about 13 GB plus
  the pulled image, and the scratch parent's path is at most 28 bytes. The
  job needs `e2fsck`, `resize2fs`, `dumpe2fs`, `setpriv` and `python3` on the
  runner. Until the volume exists, the job does not run.
- **Publishing, back on the trusted light runner.** Signing the disk with
  the runtime key makes that key vouch for bytes computed on a host-kernel
  runner that boots a VM of the image; a sha256 over the hand-back proves
  only their transport. The owner accepted that on 2026-11-24 (recorded on
  #5602): Deploy Dev's publisher signs the disk the KVM runner builds, with
  the codewire-runtime key, as family `workspace-disk`. Every credential
  stays off the KVM runner. The job hands the disk directory back as an
  artifact with its sha256 as a job output, and removes its own copy and
  scratch at its end, failure included. Deploy Dev's publish job checks the
  sha256, then pushes `codewire/workspace-disk` with the `fp-` tag and signs
  it. The pin of `SANDBOX_STANDARD_IMAGE_DISK` to the `line` value comes
  after that. The hosted policy's check of the disk's signature replaces the
  waivers in the same change.

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
