# A workspace that boots systemd

Target, not yet observed working (#5638). This page was written before the
code, as the contract the code must make true. The image and its
publication, the organization opt-in, and orchestration's rendering and
checks are on `main`; none of it has run on Dev yet. The acceptance journey
is
[../journeys/systemd-workspace.md](../journeys/systemd-workspace.md).

A default workspace has no init system: its first process is a small
supervisor that runs the environment daemon
([SANDBOX-DAEMON.md](SANDBOX-DAEMON.md), "Startup Sequence"). Software that
expects a normal Linux boot finds nothing: `systemctl --user` has no manager
to talk to, a package's unit never starts, and `rex server install` says the
system has no systemd. A systemd workspace is a cloud sandbox in which every
session sees systemd as PID 1, with the environment daemon as one of its
units. The workspace container's first process is a small fixed command that
starts systemd and outlives it ("The first process", below).

On `commodity` it is an opt-in image, on a deployment that turns it on, for
an organization that a global admin has opted in. On `standard` it is the
default ("On the `standard` profile", below). It is offered on Dev and
nowhere else ("Stop", below). The default `commodity` workspace does not
change.

## The image

`images/workspace-systemd` builds on the published workspace image and adds:

- `systemd`, `systemd-sysv`, `dbus`, `dbus-user-session` and
  `libpam-systemd` from the same dated archive snapshot as the workspace.
- `codewire-daemon.service`, enabled, which runs `cw __hosted-daemon` as the
  workspace user with the container's own environment. It sets
  `KillMode=process`, because the daemon ends its sessions' processes itself;
  `Delegate=yes`; and `TasksMax=infinity`. Units get no resource controllers
  in this container (below), so no task limit is enforced today; the setting
  keeps systemd's default, 15% of the container's, from ever capping every
  session together if that changes.
- Lingering for the workspace user, so its user manager runs from boot.
  Nothing in a sandbox logs in through PAM, and without it no
  `systemctl --user` would ever have a manager.
- `STOPSIGNAL SIGRTMIN+3`, the signal that makes systemd shut down, and
  `DefaultTimeoutStopSec=10s`, which bounds each unit that sets no stop
  timeout of its own, so that an ordinary shutdown fits inside the Pod's
  grace period. That clean stop is best effort. The guarantee is the kill at
  the grace period ("Stop").
- Masks for the units a container has no use for: consoles, package timers
  and network management.

Every session gets `XDG_RUNTIME_DIR=/run/user/1000`, the user manager's
directory, so `systemctl --user` and `loginctl` work in `cw shell`, `cw exec`
and over SSH.

Main's support-images run publishes it to Harbor and mirrors the same digest
to `ghcr.io/codewiresh/workspace-systemd`, as it does the workspace, because
the `standard` disk builder pulls its image anonymously (#5602).

## How orchestration renders it

`CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY` names one image repository,
with no tag or digest. It is unset by default, and then nothing here applies.

### The organization opt-in

Each organization is opted in by a global admin, as for confidential
environments:

- An organization has a `systemd_environments_enabled` flag, off by default,
  for every existing and new organization.
- `SetOrganizationSystemdEnvironments` sets it for one organization. It is
  global-admin only. The change and its audit entry commit together; the
  entry, `admin.organization.systemd_environments`, names the admin, the
  organization and the new value.
- `ListSystemdOrganizations` lists the organizations opted in. It is
  global-admin only, since it answers across organizations.
- The admin dashboard's toggle comes after the calls, in its own change.

### When an environment is a systemd workspace

It is decided once, at create, and recorded on the environment
(`environments.systemd_workspace`), with the runtime profile its Pod renders
on (`environments.runtime_profile`, which every environment records; for a
systemd workspace `commodity` or `standard`). An
environment is a systemd workspace
when its create named an image from the configured repository, pinned by
digest, and passed every check below. Every later Pod is rendered from that
record, not from the image and the setting. So setting the repository later
never turns an existing custom-image environment into a systemd workspace,
and unsetting it never renders a systemd workspace as an ordinary custom
image: that start is refused instead.

The record is written once, by the create's insert, and nothing changes it
afterwards: the database refuses an update to either column. A systemd
workspace created before the profile was recorded was given `commodity` by
migration 0056. A fork from a snapshot takes its source environment's record
instead of deciding from the image it names: a fork never turns a plain
workspace into a systemd one, and a systemd fork passes every check below
afresh, for the caller and organization that fork it.

### Where it is checked

No operation brings up a Pod with the added capability unless all of these
hold at that moment:

- the deployment sets the repository;
- the profile its Pod renders on is `commodity` or `standard`. At create
  that is `standard` only for the image the deployment's disk was built
  from, and `commodity` for any other image on a `standard` deployment. An
  existing environment renders on its recorded profile on a `standard`
  deployment ("On the `standard` profile"), and on the deployment's own
  profile on any other;
- on `commodity` only, the environment's organization is opted in;
- the image names the repository with a well-formed digest;
- the environment is not confidential.

These checks are product policy. The privilege boundary is the cluster's
admission rule for the systemd Pod shape ("What is loosened"), which refuses
that shape on its own, whatever orchestration renders.

The operations that bring up a Pod, and so check them first, are create, a
fork from a snapshot, start, resize, a setup retry, `cw daemon repair`, and
orchestration's restart of a failed Pod. A refused create or fork leaves no
environment. A refused start, resize, retry or repair fails with the reason,
and the environment stays as it was. A refused restart leaves the
environment stopped, with `systemd_refused` as its stop reason:
orchestration does not render the Pod, and its reconciler stops a systemd
workspace whose bring-up the checks refuse.

A replacement Pod that orchestration did not ask for, such as one the
cluster brings up after a node is lost, cannot be checked before it starts:
it comes from the template orchestration wrote when it last brought the
environment up under these checks. Orchestration checks it when it first
sees it: its liveness check marks the environment as starting again, and if a
check fails then, the reconciler stops it, with the same stop reason.

Stop, delete and reconciliation's removal never consult these checks, so
turning the opt-in off never strands an environment: it can always be
stopped and removed. A systemd workspace that is running when its
organization's flag goes off keeps running and stays reachable until it
stops. Its next bring-up (a start, a resize, a repair, or a restart or
replacement of its Pod) is refused, and it stays stopped until the
organization is opted in again.

The refusal that names the opt-in goes only to a caller already allowed to
create or start in that organization, after the ordinary checks. Anyone else
gets the ordinary refusal for that organization, so nobody learns another
organization's flag. Confidential does the same.

### Only inside a VM

The rendering exists for the `commodity` runtime profile, whose runtime
classes run each sandbox in a VM of its own, and for `standard` ("On the
`standard` profile"), whose Pod boots its own VM. On `runc`, on any
diagnostic runtime and on a deployment with no runtime profile, this
container could reach the node, so there is no such rendering there, on a
local Kind cluster either.

### How its container differs

A systemd workspace's container differs from the default one in four ways:

1. **It runs as root**, as systemd must. The daemon's unit drops to the
   workspace user, so sessions are that user's as before, and the Pod's other
   settings (its groups, its service account, its network policy) are the
   default ones.
2. **It adds one capability, `CAP_SYS_ADMIN`, and holds it for the
   container's life.** The first process needs it to make the container's
   cgroup tree writable and to start systemd in namespaces of its own (next
   section). On systemd's side the capability is removed from the bounding
   set before `/sbin/init` executes, so systemd, the daemon and every session
   start with the default workspace's capability set, and `sudo mount` fails
   as it does there. That drop is parity, not a boundary. `/proc` is not at
   parity ("What is loosened"). A Kubernetes exec into the container still
   receives the capability, and what an exec runs is a file in the container
   (`cw __hosted-exec`, a probe's command), which root in the container can
   replace. So treat the container as holding `CAP_SYS_ADMIN` throughout.
   What contains it is the VM.
3. **`/run` and `/run/lock` are memory volumes.** systemd would otherwise
   mount its own over `/run` and hide the binding token below it, and after
   the drop it cannot mount `/run/lock` itself.
4. **It is never a warm-pool member.** A `commodity` pool holds default
   workspaces only, and the pool member's isolation check refuses a root
   workspace container.

Everything else is the default sandbox's. With hosted egress on, a systemd
workspace is a broker-mode Sandbox like any other: the same label, TUN init
container, egress token and admission policy, and the same refusals from
inside it.

### The first process

The container's first process is a fixed command that orchestration renders
as the Pod's command. It is not taken from the image. It runs the image's
`/bin/bash`, and through it the image's `unshare`, `setpriv` and
`/sbin/init`, all before any workload exists. In order, it:

1. remounts the container's cgroup tree read-write and creates the child
   cgroup `workspace`;
2. starts `unshare --pid --fork --mount --propagation private`. Its child
   moves itself into `workspace`, mounts its own `/proc`, removes
   `CAP_SYS_ADMIN` from its bounding set and executes `/sbin/init`, which is
   PID 1 of the new PID namespace;
3. then only waits. On `SIGTERM` or `SIGRTMIN+3` it sends `SIGRTMIN+3` to
   systemd. When systemd exits it exits too. While it waits it uses shell
   builtins only and runs no program from the container's filesystem, since
   root in the container can replace those files.

Its exit status tells orchestration whether the end was asked for:

- After a stop signal, it exits with systemd's exit status, or 128 plus the
  signal that ended systemd. The Pod is being deleted, and nothing reads it.
- When systemd ends without a stop signal (a `systemctl poweroff` or
  `reboot` in a session, or systemd failing), it exits with status 1, so the
  Pod is `Failed` (`restartPolicy: Never`). Orchestration restarts a failed
  workspace Pod, subject to "Where it is checked". A clean poweroff in a
  session is therefore a restart, never a Pod that ended without error,
  which orchestration would mark as an error.

The kill at the grace period ("Stop") does not depend on the forward having
worked.

### Why the child cgroup

A VM runtime's guest agent adds every process of a Kubernetes exec to the
container's own cgroup. Once systemd manages that cgroup and turns on
controllers for its children, the kernel refuses new processes there, and
every exec fails. The readiness probe and orchestration's own commands are
execs. With systemd in a child cgroup, nothing turns controllers on in the
container's cgroup, and exec keeps working. The child must not be named
`system`: systemd treats that name as part of its own layout.

### Why the first process stays

The first process stays the container's first process and never moves.
systemd runs below it, in `workspace`, as PID 1 of a PID namespace of its
own. So when the runtime ends the first process, the kernel ends every
process in its PID namespace, systemd's nested namespace included.

What crosses between the two sides: execs run in the container's namespaces,
not systemd's. They reach the daemon over loopback, and the files they test
(the daemon's credential and ready markers) are on volumes both sides see.
`systemctl` from a raw exec does not reach systemd. Sessions, which the
daemon starts inside systemd's namespaces, do. systemd's mount namespace is
private: a mount made in the container after systemd starts does not appear
on systemd's side, and Kubernetes makes none.

The cost: with a process in the container's cgroup, the kernel refuses to
delegate controllers below it, so units get no resource controllers.
`MemoryMax=` and its like are accepted and do nothing. The sandbox's own
memory and CPU limits still hold ("What is loosened").

## On the `standard` profile

Implemented on `main` (#5638, #5602), not yet observed live on Dev: both
orchestration's rendering/checks and the `standard` runtime's host/guest
handoff (`CODEWIRE_WORKSPACE_INIT=image|systemd`) are wired.

On `commodity`, Kubernetes and Kata build the workspace container, so the
Pod has to ask for systemd's shape itself: root, `CAP_SYS_ADMIN` and the
bootstrap above. On `standard`, the Pod runs `cw __pod-runtime`, which boots
a VM whose PID 1 is Codewire's guest init, and guest init builds the
workspace container itself. So none of the above is rendered there:

- **The Pod is the default `standard` Pod.** Its container carries
  `CODEWIRE_WORKSPACE_INIT`, which the runtime carries into the guest. Every
  `standard` Pod has it, exactly once: `systemd` for systemd as the workspace
  container's first process, `image` for the image's own entrypoint. The
  runtime refuses a missing or empty value and any other value, compared
  exactly (`Systemd` is refused). No capability, no root, no bootstrap, and
  no change to the cluster's admission for that shape. A `standard` Sandbox
  rendered before the setting existed lacks it, so its next Pod is refused;
  such a Sandbox is recreated.
- **The disk decides it.** A `standard` deployment boots one published disk
  (`SANDBOX_STANDARD_IMAGE_DISK`), and a disk is the kind of the image it was
  built from, by the same rule as a `commodity` create: `systemd` when that
  image is a digest-pinned image of
  `CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY`, `image` otherwise,
  including when the repository is unset. orchestration reads it once at
  startup and renders it on every `standard` Pod.
- **systemd is the default on `standard`.** A `standard` deployment's
  default disk is built from the workspace-systemd image, so every `standard`
  workspace boots systemd. There is no organization opt-in on `standard`: the
  opt-in exists because the `commodity` shape loosens the Pod, and the
  `standard` Pod is not loosened. A deployment switches only once its runtime
  boots systemd; until then its disk is built from the workspace image and
  renders `image`.
- **The record and the checks are the same as on `commodity`.** A create of
  the disk's image records the environment as a systemd workspace
  ("When an environment is a systemd workspace"), and every bring-up checks
  it on the profile its Pod renders on ("Where it is checked"), without the
  opt-in. A warm-pool member renders the same Pod, so a `standard` pool
  holds systemd members when its disk does.
- **A republished disk moves nothing.** An existing `standard` Sandbox keeps
  its own disk, by digest, and is never re-rendered on start. A systemd
  workspace's checks read its recorded profile, never the current disk, so
  after a republish one created on `standard` still starts without the
  opt-in. If one is ever rendered afresh after a republish, it is rendered
  as a `standard` Pod on the current disk, which the runtime refuses because
  the image differs: it fails closed, and never becomes a `commodity` Pod
  without the opt-in. One created on `commodity` always renders there and
  always needs the opt-in.
- **Open.** Restore and fork on `standard` are not built (#5602). They need
  their own disk rule, either keeping the source's disk digest or moving
  deliberately. Keeping it needs the registry to retain every workspace disk
  digest an environment still boots (#5602).
- **In the guest,** guest init stays the VM's PID 1 and keeps what only it
  holds: the vsock control channel, the hosted ingress, the daemon's listener
  on 127.0.0.1:17777 and the per-boot bind check. systemd becomes PID 1 of
  the workspace container, in its own pid, mount and cgroup namespaces with a
  delegated cgroup v2 subtree and separate `/run` and `/run/lock` tmpfs mounts.
  The daemon is still the one guest init executes in the container, as the
  workspace user (`codewire`, with `XDG_RUNTIME_DIR=/run/user/1000` and inside
  `init.scope`), with the held listener; the image's `codewire-daemon.service`
  (in `/etc/systemd/system`), `docker.service` and
  `systemd-machine-id-commit.service` (in `/run/systemd/system`) are masked.

**The boundary.** The whole guest, guest init included, belongs to the
Sandbox's user: a systemd workspace is a full operating system whose user can
become root, and root in a container that shares the guest's kernel should be
assumed able to reach guest init. The boundary is the VM: the host kernel,
cloud-hypervisor and the Pod runtime. So everything the host side receives
from the guest is that one Sandbox's claim, and is never trusted beyond that
Sandbox. The runtime's per-interface audit, which cw-security accepted on
2026-11-22, is on #5602; each line below is one of its rows:

- **Hosted control (vsock 7780).** The host dials. The guest's answer is a
  challenge and a MACed reply, keyed from this Pod's own boot token; a bad
  one ends the Pod. It can only lie to its own Pod or end it. It never
  chooses the binding, the environment, the Pod's identity, the egress
  policy or another Sandbox's state; those come from the Pod spec and
  orchestration.
- **Ingress (7781, 7782).** The host dials in and copies raw bytes without
  parsing them. The guest sees orchestration's connections, so the daemon
  credential orchestration presents is scoped to this environment and Pod and
  useless against any other. SSH trusts the host key this same guest
  recorded, which proves only "this Sandbox".
- **The bind, `RecordHostKey` and the self-check record.** The guest's own
  claims. Identity comes from the attested Pod: a TokenReview of the Pod's
  token, the live Pod's name, UID and namespace, and its IP, mapped through
  its Sandbox and claim to the stored binding on every call; never from the
  request. The self-check is the Dev floor; Production's gate is
  orchestration's own lockdown check.
- **Egress.** Its mode is named on the runtime container,
  `CODEWIRE_VM_EGRESS_MODE=guest-carried|broker`, and the runtime refuses a
  missing or unknown value. With `guest-carried` the workload has no egress.
  With `broker` (#5602 comment 130891) the daemon runs broker mode inside the
  VM and `cw-egress` polices the workload, and #5800's host-side check is the
  orchestration-side lockdown check that Production needs for those Pods. In
  both, the host end's own network worker policy is `locked` plus
  `CODEWIRE_POD_PLATFORM_PEERS`, compiled at boot from the Pod's environment;
  a policy change (`ReplacePolicy`) is applied only from the worker's
  inherited control socket, and the Pod runtime builds no runner call that
  reaches it, so no guest message widens the policy, adds a peer or changes
  its target.
- **Platform peers.** They are enforced per Pod, not per process, so each
  authenticates its caller with a credential scoped to this Pod: the binding
  listener (the binding token), `cw-egress` on 8089 (the egress token, broker
  mode only), and the gateway and DERP (the peer token).
- **The credential service.** The guest holds a credential token bound to its
  Pod (audience `CREDENTIAL_WORKSPACE`, 600 s). The credential service maps it
  to the Pod's binding by the reviewed Pod UID, and also requires
  orchestration's relay token. It is not a platform peer, and it serves only
  this environment's placeholders (#4002).
- **The coordinator and Mesh.** The peer token names this environment at its
  generation, and Mesh enrollment is tied to the binding's environment, Pod
  and generation, so a guest can misreport only its own attachment.

This holds for a default `standard` workspace as well, whose user can `sudo`.
A host-side path that took a guest answer as more than that Sandbox's claim
would be a gap to fix before either reaches Production.

**The container is defense in depth.** It keeps casual tampering and
accidents away from guest init's own pieces, on these conditions:

1. **Guest init out of reach.** The container's root cannot see guest init's
   `/proc` (separate pid, mount and cgroup namespaces). Its bounding set has
   no `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` or `CAP_SYS_BOOT`, and no
   `CAP_SYS_ADMIN` outside the delegated subtree. It has no device beyond the
   workspace's own.
2. **No vsock from the container.** Its seccomp filter refuses `AF_VSOCK`
   sockets (`socket` and `socketpair`, plus 32-bit `socketcall` on `x86_64`),
   so root in it cannot speak to the host's control port or the ingress ports
   as guest init would; sleep control (`7784`) goes through guest init's
   fixed-request Unix-socket relay (`/run/codewire-hosted/sleep/control.sock`).
   The same filter refuses `io_uring_setup`, `io_uring_enter` and
   `io_uring_register`, since io_uring can make a socket without the socket
   call. The default `standard` container gets the same filter.
3. **What the held listener protects.** The listener and the daemon's
   non-dumpable state protect it from unprivileged processes only, not from
   root in the container. The listener still means no other process binds
   17777 before the daemon.
4. **The masked unit stays masked.** A unit that starts another daemon on
   17777 fails to bind; a test proves it.

None of these is what keeps another Sandbox or the platform safe; the
boundary above is.

**Stop.** The Pod runtime stops the VM within its stop timeout. Guest init
sends `SIGRTMIN+3` to the container's systemd, waits a bounded time well
inside that timeout, kills the container and powers off. As on `commodity`,
the clean stop is best effort and the bound is the runtime's.

**Docker.** A `standard` workspace's Docker is the guest's own `dockerd`,
which runs outside the container on a Docker disk the runtime sizes from
`CODEWIRE_VM_DOCKER_DISK_MIB`. orchestration sets it on every
`standard` Pod, splitting the volume evenly with the state disk. A systemd
workspace reaches that `dockerd` through the same socket a default workspace
uses, and the image's `docker.service` is masked.

## What is loosened, and why it adds nothing

- The workspace container runs as root. The workspace user already has
  passwordless `sudo`.
- The container holds `CAP_SYS_ADMIN` for its life (above). In a VM runtime
  the guest also runs Docker's privileged container, which the workspace user
  controls through the `docker` group, so root with every capability in the
  guest is already the user's. The VM is the boundary, and nothing here
  changes it.
- **`/proc` on systemd's side has neither the runtime's masked paths nor its
  read-only ones.** So root in any session, by plain `sudo` and with no
  capability beyond the default set, can write `/proc/sys` and
  `/proc/sysrq-trigger` and read the files the runtime hides. That is the
  guest kernel of this Sandbox's own VM, which the user already reaches
  through Docker's privileged container; nothing outside the VM is behind
  it. The masks are not re-applied.
- The container's cgroup subtree is writable to its root. Root there can
  raise or remove the limits of its own cgroups, and can break exec for its
  own sandbox by turning controllers on at the top. What holds the sandbox's
  memory and CPU limits is the VM's size and the VM's own cgroup on the node,
  neither of which the guest can touch.

Unchanged: no-new-privileges (off, as `sudo` needs), the absence of a seccomp
filter, the network policy, and the tokens the workload can already read.

A cluster that polices sandbox Pods must admit the capability for this
image's workspace container, on its VM runtime classes only, before the
setting is turned on. Without that, creates are refused by the cluster, not
by Codewire.

## Stop

A stop deletes the Pod. The kubelet sends the image's stop signal to the
first process, which forwards it to systemd as `SIGRTMIN+3`. systemd stops
its units (the daemon ends its sessions as on any stop) and exits, the first
process exits after it, and the Pod ends. This clean stop is best effort: a
unit with a stop timeout of its own, or none, can outlast the grace period.

**The guarantee.** At the end of the Pod's grace period, which is 60 s on a
commodity Block workspace (`BLOCK_WORKSPACE_GRACE_SECONDS`) and Kubernetes'
30 s otherwise, the runtime kills the first process. The kernel then ends
systemd's namespace, and the Pod is gone within the grace period plus 15 s,
the bound #5645's standing check uses.

**What it covers.** A unit whose stop hangs, a systemd that hangs, and a
systemd that root in the container broke. **What it does not cover:** a
workload that uses root in the container to avoid the stop. That is tracked
in #5645.

**Where it is offered.** Dev, and nowhere else. Before any other deployment
sets the repository, three things must be true:

- that deployment has decided to offer it;
- its cluster has its own reviewed admission change for the image;
- #5645 is fixed on its VM runtime.

Production is not offered.

## What a systemd workspace does not do

- **Local VMs.** A local VM's workspace starts from Codewire's own guest
  init, with the daemon outside the workspace container. Nothing here
  applies to it.
- **Confidential environments and custom images.** A systemd workspace is
  always a create from the one configured repository. On `commodity` it is
  always a cold create; on `standard` it may be a warm-pool member.
- **`cw daemon logs`.** The daemon's log is in the journal
  (`journalctl -u codewire-daemon`), not in the container's output, so
  `cw daemon logs` shows nothing until it reads the journal.
- **Unit sandboxing that needs to mount.** `PrivateTmp=`, `ProtectSystem=`
  and their like are skipped by systemd, which logs that; `DynamicUser=` and
  `BindPaths=` fail the unit.

## Observed before this page

All of this ran by hand on 2026-11-20, not through this rendering:

- On a local Kind cluster (`runc`), a systemd workspace passed the same
  walk as the default image: exec, named and terminal sessions, session
  stop and restart, ports, `cw cp`, stop and start, `sudo`, Docker and the
  desktop launcher. systemd took 0.25 to 0.33 s to start.
- On Dev's VM runtime, in a scratch Pod outside the product: systemd started
  in 0.16 to 0.22 s with no failed unit; exec failed with systemd at the
  container cgroup's root and worked with it in the `workspace` child.
- On Dev's VM runtime, in a scratch Pod outside the product, with a 30 s
  grace period: with the bootstrap on this page and a system unit whose stop
  never ends, systemd was `running` in `/workspace/init.scope` and exec
  worked. A delete ended the Pod in 31.7 s. The stop signal was not
  forwarded in that run, so what was seen is the kill at the grace period
  alone.
- On Dev's VM runtime, the same bootstrap on the published workspace image,
  with systemd added at boot (#5638):
  - systemd started in 176 ms with no failed unit, and the workspace user's
    manager was running from boot.
  - Over OpenSSH inside the Pod, `rex server install` wrote `rex.service`
    and `rex.socket` as user units, and `rex server status` answered through
    ssh.
- Under Docker, the forward worked, and systemd stopped cleanly in 2.3 s.
  Neither the forward nor the clean stop has been seen on the VM runtime.
