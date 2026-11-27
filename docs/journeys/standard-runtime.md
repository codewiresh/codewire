# A cloud sandbox on the `standard` runtime profile

A cloud sandbox whose VM is started by Codewire's own runtime inside the Pod
behaves as one on `commodity` does (#5602). The contract is the `standard`
paragraph of `SPEC.md` "4. Hosted sandboxes" and "The `standard` profile" in
[`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`](../dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md).
This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-26. `standard-admission` is observed on Dev, and
`standard-create`, `standard-exec`, `standard-application-secrets`,
`standard-docker`, `standard-network`, `standard-stop-start` and
`standard-beside-commodity` are partly observed on Dev (`#5602`), except the
parts the table names; the rest are not yet observed.

| ID | Kind | Dev | Production |
| --- | --- | --- | --- |
| `standard-create` | not yet observed | observed 2026-11-26 through `cw` (paused and unpaused warm-pool creates, cold create, and side-by-side `commodity` baseline, `#5602`); dashboard, SDK, uncached image disk and no-KVM pending not yet | not yet observed |
| `standard-exec` | not yet observed | observed 2026-11-26 for `cw exec`, `cw run`, `cw shell --durable` persistence, `cw setup ssh` + OpenSSH login and `codewire.yaml` setup (`#5602`); dashboard terminal not yet | not yet observed |
| `standard-application-secrets` | not yet observed | observed 2026-11-26 for setup and `cw exec` (`#5602`); unset check on a no-secrets sandbox not yet | not yet observed |
| `standard-docker` | not yet observed | steps 1 to 3 observed 2026-11-26 (`#5602`); Docker-published preview port not yet | not yet observed |
| `standard-network` | not yet observed | observed 2026-11-26 for allowed HTTPS, RFC1918 refusal, live `locked`/`open` policy switch, applied NetworkPolicy read, pre-bind self-check, credential interception and 11 min silent TCP hold (`#5602`, `#6399`); `cw --cloud policy log` no command yet (`#4000`) | not yet observed |
| `standard-closed-egress` | not yet observed | not yet observed | not yet observed |
| `standard-stop-start` | not yet observed | steps 1 to 3 observed 2026-11-24 and 2026-11-26 (`#5602`); step 4 not yet | not yet observed |
| `standard-admission` | not yet observed | observed 2026-11-26 (all 12 refusal cases vs passing baseline via live `--dry-run=server`, `#5602`) | not yet observed |
| `standard-beside-commodity` | not yet observed | step 2 observed 2026-11-26 (custom `--image` fallback to `commodity`, `#5602`); step 1 not yet | not yet observed |
| `standard-organization-move` | not yet observed | not yet observed | not yet observed |
| `standard-suspend` | not yet observed | not yet observed | not yet observed |
| `standard-systemd` | not yet observed | not yet observed | not yet observed |
| `standard-hibernate` | not yet observed | not yet observed | not yet observed |
| `standard-hibernate-fallback` | not yet observed | not yet observed | not yet observed |

## Before the walk

- The walking organization is on `standard`. No command sets an
  organization's profile yet (#5602); until one exists the walk runs on a
  surface whose configured profile is `standard`, and the record says so.
- Hosted egress is on for the surface. Without it a `standard` sandbox has no
  network at all and `standard-network` fails for the wrong reason.
- On Dev, walk as the Dev smoke identity
  (`scripts/runtime/dev/with-dev-smoke-auth.sh`); on Production as the smoke
  identity (`scripts/runtime/prod/with-prod-smoke-auth.sh`).
- The steps that read a Pod need read-only cluster access to the sandbox
  namespace. They are for the operator's half of the proof, not the user's.
- Record `cw version`, the source the surface was running and the runtime
  image's digest with every observation.
- Remove each sandbox at the end with `cw rm --yes NAME`.
- This walk covers what differs on `standard`. Every step of
  [cloud-sandbox.md](cloud-sandbox.md) is also walked on it before an
  organization is moved (#5602).

## `standard-create`: a create gives a VM that Codewire's runtime started

- **Entry points:** `cw --cloud create`, the dashboard's create page, the SDK
  create call.
- **States to exercise:** a cold create; a create from the warm pool; a
  create whose workspace image disk is not on the node yet; a create on a
  node with no free `/dev/kvm` device, which stays pending and says why.
- **Driving it:**
  1. `cw --cloud create --name std-a`, then `cw info std-a` reads `running`.
  2. `cw exec --in std-a -- uname -r` prints the runtime's guest kernel, which is
     not the node's kernel.
  3. The operator reads the Pod: one container named `workspace`, the
     RuntimeClass `standard`, a non-root user, no added capability, and no
     container named `dind`.
- **Proof:** the guest kernel version in step 2 beside the node's, and the
  Pod's container list and security context in step 3.
- **Gotchas:** `kubectl exec` into `workspace` lands in the runtime's
  container, outside the VM, and proves nothing about the sandbox.
- **Observed:** on Dev, 2026-11-26 (`cw v0.4.26`, source `f07496877d` with
  runtime digest
  `sha256:34d0586252dae97b2a87f9a4a6ee5f3ddf624aa450fbed3ca2d3f24ff09d5550`,
  and source `e06341033f` with runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`): warm-pool creates reached `bound` in `488–493 ms`, `access_ready`
  in `797–896 ms` and `setup_complete` in `967 ms` (`cw` printed
  `SSH access ready` in `0.5–0.6 s`; two concurrent warm-pool creates both
  adopted in `0.6–0.7 s`), and paused warm-pool creates (`#6632`) reached
  `bound` in `454–469 ms`, `access_ready` in `927 ms` (`0.6–0.7 s` CLI;
  `3,174 ms` after >3 min pause including automatic `cw-egress` reconnect)
  while idling at `22.2–25.6 mCPU` pod-level total (`0.3%` of 8 vCPUs on the
  8 vCPU pool member; `0` billing warnings). A non-pooled cold create
  (`1 vCPU / 4 GiB / 90 GiB`) reached `bound` in `13.1 s`, `access_ready` in
  `15.2 s` and `setup_complete` in `15.6 s`, with `128 MiB` `fdatasync`
  throughput of `263–284 MB/s` (side-by-side `commodity` cold create of the
  same shape on `e06341033f`: `bound` `7.49 s`, `access_ready` `9.90 s`,
  `setup_complete` `10.30 s`, `128 MiB` `fdatasync` `204 MB/s`). `uname -r`
  inside the guest printed `6.18.48-codewire3`; the Pod ran one `workspace`
  container on RuntimeClass `standard` with no `dind` container. Dashboard
  and SDK entry points, an uncached image disk and a node with no free
  `/dev/kvm` device are not yet observed.

## `standard-exec`: commands, shells and setup run inside the VM

- **Entry points:** `cw exec`, `cw shell`, `cw run`, the dashboard terminal,
  `cw setup ssh` and an SSH client.
- **States to exercise:** a command's exit code and output; a shell that
  outlives the client; a `codewire.yaml` whose setup step writes a file; SSH
  over the tailnet's relays.
- **Driving it:**
  1. `cw exec --in std-a -- sh -c 'echo ok; exit 7'` prints `ok` and exits 7.
  2. A `codewire.yaml` with a setup step that writes a nonce to a file:
     after `cw --cloud create --name std-b`, `cw exec --in std-b -- cat` of that
     file prints the nonce.
  3. `cw shell std-a`, start `sleep 600`, close the terminal, open
     `cw shell std-a` again: the `sleep` is still listed.
  4. `cw setup ssh`, then `ssh` to the sandbox's host name and run `id`.
- **Proof:** the exit code and nonce, the surviving process's PID, and the
  user `id` prints over SSH.
- **Observed:** on Dev, 2026-11-26 (`cw v0.4.26`, source `78401cfc72` with
  runtime digest `sha256:a6d8ab5fa9d8d05263fceebc6dcb5256019cde5fc11972e4f0436cd4f4fe7d30`,
  source `f07496877d` with runtime digest
  `sha256:34d0586252dae97b2a87f9a4a6ee5f3ddf624aa450fbed3ca2d3f24ff09d5550`,
  and source `e06341033f` with runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`): `cw exec` ran commands and returned output (including 10 parallel
  `cw exec` calls across two running sandboxes in `3.745 s`), `cw run`
  streamed output and reported `Session exited with code 7`,
  `cw shell --durable` kept `sleep 600` (PID `62`) running across `Ctrl-B d`
  disconnect with the session still `Running` in `cw ls`, `cw setup ssh`
  wrote the managed SSH config (`StrictHostKeyChecking yes` +
  `KnownHostsCommand cw --cloud ssh known-hosts %H`) and `ssh` logged in
  cleanly (`uid=1000(codewire) gid=1000(codewire) groups=1000(codewire),1001(docker)`,
  kernel `6.18.48-codewire3`), `codewire.yaml` `install_command` and
  `startup_script` wrote files read back via `cw exec`, and
  `cw ports --publish 8080 --access public` served a preview from the
  sandbox. On Dev, neither `standard` nor `commodity` published a direct UDP
  endpoint (`stun_server_count=0`; `commodity` connected via relay and
  `standard` via DERP). The dashboard terminal is not yet observed.

## `standard-application-secrets`: a sandbox's application secrets reach its commands and setup

- **Entry points:** `cw --cloud create` with a project that selects
  application secrets, then `cw exec` and the create's setup steps.
- **States to exercise:** a setup step that reads a secret; a command after
  the create; a sandbox with no secrets selected.
- **Driving it:**
  1. A project with one application secret whose value's sha256 is known,
     and a `codewire.yaml` install step that checks the variable is set and
     its sha256 matches: `cw --cloud create --name std-k` reaches running.
  2. `cw exec --in std-k -- sh -c 'printf %s "$NAME" | sha256sum'` prints the
     known hash.
  3. In `std-a`, which selects none, the variable is unset.
- **Proof:** the create's setup log with one install run and exit 0, and
  the hash from step 2.
- **Gotchas:** the daemon adds the values at launch through
  `/codewire/bin/cw __environment-launch`; without that file every command
  in the sandbox is refused, and setup reports "the daemon reported a
  failure", not an exit code.
- **Observed:** on Dev, 2026-11-26 (`cw v0.4.26`, source `78401cfc72`, runtime
  digest `sha256:a6d8ab5fa9d8d05263fceebc6dcb5256019cde5fc11972e4f0436cd4f4fe7d30`,
  `#5602`): a sandbox created with `--user-secrets platform` ran its
  `codewire.yaml` `install_command` and `startup_script` with the attached
  secret present (`INSTALL=install-ok`, `SECRET_CHECK=secret-present`,
  `STARTUP=startup-ok`), and `cw exec` read the same secret (`ENV_SECRET_LEN=25`).
  Step 3 (confirming the variable is unset in a sandbox selecting no secrets)
  is not yet observed.

## `standard-docker`: Docker runs in the VM and is not shared

- **Entry points:** `docker` in a shell or a command.
- **States to exercise:** a container run; a published port reached through
  a preview; two sandboxes side by side.
- **Driving it:**
  1. `cw exec --in std-a -- docker run --rm busybox echo hello` prints `hello`.
  2. `cw exec --in std-a -- docker images -q` lists the image; the same command
     in `std-b` lists nothing.
  3. `cw exec --in std-a -- docker run --rm busybox df -h /` shows Docker's own
     disk, about half the room the VM's disks have on the sandbox's volume.
     Docker's data root is `/var/lib/docker` in the guest, outside the
     workspace container, so the workspace itself has no such directory.
- **Proof:** the image ID present in one sandbox and absent in the other, and
  Docker's data on its own disk.
- **Observed:** steps 1 to 3 on Dev, 2026-11-26 (`cw v0.4.26`, source
  `f07496877d` with runtime digest
  `sha256:34d0586252dae97b2a87f9a4a6ee5f3ddf624aa450fbed3ca2d3f24ff09d5550`,
  and source `e06341033f` with runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`): two `standard` sandboxes ran `docker run --rm busybox` and
  `docker run --rm alpine` concurrently; sandbox A listed one image while
  sandbox B listed zero images before its own pull, showing isolated per-VM
  Docker daemons. In an 80 GiB sandbox, `lsblk` showed separate `35.1G`
  `vda` (`/workspace` + `/home/codewire`) and `35.1G` `vdb` disks,
  `docker info` reported `DockerRootDir=/var/lib/docker`, and
  `docker run --rm busybox df -h /` showed a `34.2G` overlay (~half the
  sandbox volume). Reaching a Docker-published port through a preview is not
  yet observed.

## `standard-closed-egress`: the first version refuses every workload connection

- **Entry points:** any program in the sandbox; the daemon's start.
- **States to exercise:** a TCP connection to a public address; a DNS
  lookup of a public name; a connection to a private address that is none of
  the Pod's platform peers. Each is made by the workload, in the sandbox.
- **Driving it:** `cw exec NAME -- curl -sS --max-time 5 https://example.com`,
  `cw exec NAME -- getent hosts example.com` and a dial to the cluster's
  DNS Service address.
- **Proof:** each command fails without an answer; the create reached
  `access_ready`, which a guest-carried daemon cannot reach before its
  self-check passes, and the daemon's log line names each probe, its target
  and `refused`; the
  orchestration log has no `egress lockdown is not applied` for the Pod, so
  the lockdown check passed it against its own template policy.
- **Observed:** not yet observed. Until the supervisor's join to cw-egress
  lands this step stands in for `standard-network`.

## `standard-network`: every connection goes through the node's egress service

- **Entry points:** any program in the sandbox; `cw --cloud policy` for the
  policy and `cw --cloud policy log` for the refusal log.
- **States to exercise:** an allowed destination; a destination the policy
  refuses; a private address, which is always refused.
- **Driving it:** the hosted steps of
  [network-and-egress.md](network-and-egress.md), on a `standard` sandbox.
- **Proof:** the refusal log's entry for the refused destination, and no
  route out of the Pod other than to the egress service (the operator reads
  the Pod's NetworkPolicy). The daemon's log has "guest-carried egress
  self-check passed" with its three probes, before the create's
  `access_ready`. A daemon whose check did not pass never records its host
  key, and the create fails rather than finishing.
- **Observed:** on Dev, 2026-11-26 (`cw v0.4.26`, source `f07496877d` with
  runtime digest
  `sha256:34d0586252dae97b2a87f9a4a6ee5f3ddf624aa450fbed3ca2d3f24ff09d5550`,
  and source `e06341033f` with runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`, `#6399`): allowed HTTPS egress returned HTTP 200 (10/10 parallel
  requests across two sandboxes), RFC1918 egress to `10.96.0.1:443` was
  refused, live switching with `cw --cloud update --policy locked` enforced
  `locked` (refusing `https://example.com/`) and switching back to `open`
  restored HTTP 200, warm members logged `egress stream authenticated
  (ca=true)` and `egress self-check passed; the daemon serves` before claim,
  Dev's exact-source credential interception smoke passed on `standard`, and
  two silent guest TCP connections through `cw-egress` (`SO_KEEPALIVE=0` on
  guest sockets) survived `660 s` and `670 s` idle and carried data cleanly
  afterwards with zero redials (`#6399`). Operator inspection of the Pod's
  NetworkPolicies (`cw-daemon-net-<env>`, `<template>-network-policy`, and
  ingress-only `cw-daemon-warm-<env>`) confirmed egress is restricted solely
  to platform peers (`egress:8089`, `orchestration:8087`, `derp:8443`,
  `envoy-gateway:10443`, `udp-relay:41641`). `cw --cloud policy log` has no
  hosted command yet (`#4000`, `network-and-egress.md`).

## `standard-stop-start`: the home, the workspace and the root persist until the image changes

- **Entry points:** `cw stop`, `cw start`, the dashboard's stop and start.
- **States to exercise:** a stop while a process writes; a start on the same
  volume; a file written outside the home and the workspace; a used volume
  whose disk has gone.
- **Driving it:**
  1. `cw exec --in std-a -- sh -c 'echo NONCE > ~/keep; echo NONCE > /workspace/keep; sudo sh -c "echo NONCE > /opt/gone"'`.
  2. `cw stop std-a`, then `cw start std-a`.
  3. `cw exec --in std-a -- cat ~/keep /workspace/keep /opt/gone` prints the
     nonce three times. The root disk is named by the image build, and setup's
     install state and output live on it, so setup does not run again on a
     start. A create on a new image build starts a fresh root, and `/opt/gone`
     is gone there.
  4. The Sandbox's `workspace` container has `CODEWIRE_VM_STATE=existing`.
     On a scratch sandbox only: stop it, remove its state disk from the
     volume, start it. Its Pod fails, and no empty workspace binds.
- **Proof:** the nonce read back from the three paths, the Sandbox's
  `existing`, and the failed Pod with nothing bound.
- **Gotchas:** a stop that takes the whole grace period means the guest did
  not power off when asked; record the stop's duration.
- **Observed:** steps 1 to 3 on Dev, 2026-11-24 (#5602): stop took 5 s,
  start 12 s, and all three nonces were kept. Re-observed on Dev, 2026-11-26
  (`cw v0.4.26`, source `78401cfc72` with runtime digest
  `sha256:a6d8ab5fa9d8d05263fceebc6dcb5256019cde5fc11972e4f0436cd4f4fe7d30`,
  and source `f07496877d` with runtime digest
  `sha256:34d0586252dae97b2a87f9a4a6ee5f3ddf624aa450fbed3ca2d3f24ff09d5550`,
  `#5602`): `CODEWIRE_VM_STATE=existing` was set on restart, all three paths
  persisted, and three consecutive `cw stop` (`5.55–5.71 s`) and `cw start`
  (`9.33–9.40 s`) cycles preserved appended workspace state (`LINES=1`, `2`,
  `3`); snapshot clearing (`--standard-vm`, `475–534 ms`) and snapshot fork
  (`13.22 s`, `CODEWIRE_VM_STATE=existing`, `~/keep` and `/workspace/keep`
  intact, `/tmp/gone` absent) also passed on Dev. Step 4 not yet observed.

## `standard-admission`: a Pod of the class that breaks the rule is refused

- **Entry points:** the cluster's admission policy; no user reaches this.
- **States to exercise:** a Pod of the class with a second container; one
  that asks to be privileged; one with a host path; one at another image
  digest; one that sets a command, and one that sets arguments; one with an
  SELinux type, and one with an unconfined seccomp or AppArmor profile; one
  whose image disk is another image, and one that mounts it writable; a Pod
  of another class that asks for the `/dev/kvm` device.
- **Driving it:** no command yet (#5602). The policy and the manifests that
  try each case are added with the profile.
- **Proof:** each refusal's message names the rule it broke, and nothing is
  created.
- **Observed:** on Dev, 2026-11-26 (source `e06341033f`, runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`): against Dev's enforced `codewire-shared-sandbox-runtime-security`
  and `codewire-standard-runtime-no-ephemeral-containers` Kyverno policies,
  an unmutated live `standard` Pod spec passed `kubectl create
  --dry-run=server`, while every single-field mutation was refused by
  `validate.kyverno.svc-fail` naming the broken rule (creating nothing):
  second container (`standard-runtime-pod-shape`), `privileged: true`
  (`deny-privileged`, `standard-runtime-pod-shape`), `hostPath` volume
  (`deny-host-path`, `standard-runtime-pod-shape`), another runtime image
  digest (`standard-runtime-image`), explicit `command` or `args`
  (`standard-runtime-pod-shape`), `seLinuxOptions.type`
  (`standard-runtime-pod-shape`), unconfined `seccompProfile` or
  `appArmorProfile` (`standard-runtime-pod-shape`), another image-disk
  reference (`standard-runtime-pod-shape`), writable image-disk mount
  (`standard-runtime-pod-shape: a standard Pod mounts its image disk
  read-only`), and a `commodity` Pod requesting `codewire.sh/kvm: 1`
  (`kvm-device-only-on-standard`).

## `standard-beside-commodity`: the other profiles do not change

- **Entry points:** `cw --cloud create` from an organization on `commodity`,
  and from one on `standard` with a user's own image.
- **States to exercise:** a sandbox created before its organization moved to
  `standard`; a create that names an image other than the workspace image.
- **Driving it:**
  1. A sandbox created on `commodity` is stopped and started after its
     organization moves to `standard`; the operator reads its Pod's
     RuntimeClass, which is still `commodity`.
  2. On `standard`, `cw --cloud create --name std-c --image IMAGE` with a
     user's own image; the operator reads its Pod's RuntimeClass, which is
     `commodity`.
- **Proof:** the two RuntimeClass names, and that the user sees no
  difference in either case: the create and the start print no warning,
  and `cw exec --in NAME -- true` exits 0.
- **Observed:** step 2 on Dev, 2026-11-26 (`cw v0.4.26`, source
  `e06341033f`, runtime digest
  `sha256:e4f91de6b6d50c720fe8da5fd1a914d3f6c0da2a03361fee0d83f3d8982e2995`,
  `#5602`): creating a sandbox with `--image ubuntu:24.04` in a
  `standard`-enabled organization printed no warning, ran on RuntimeClass
  `commodity` (guest kernel `7.2.15`, `codewire.sh/egress: broker`), and
  `cw exec -- true` exited 0. Step 1 (a pre-move `commodity` sandbox
  stopping and starting after its organization moves to `standard`) is not
  yet observed.

## `standard-organization-move`: one organization moves, the others don't

Built, not yet observed (#5602): the per-organization selector.

- **Entry points:** a global admin's `SetOrganizationStandardRuntime` and
  `ListStandardRuntimeOrganizations`, or the "Standard runtime" checkbox on the
  admin organization page; `cw --cloud create` in a moved and in an unmoved
  organization.
- **States to exercise:**
  - the flag turned on while the deployment offers `standard`, and again while
    it doesn't, which is refused;
  - a create in each organization;
  - a sandbox created before the move, stopped and started after it;
  - the flag turned off again;
  - an organization admin or an API key trying to set the flag, which is refused.
- **Driving it:** as the global admin, set the flag for the walking
  organization and list the moved organizations. Then:
  1. `cw --cloud create --name std-m` in it, and `--name std-u` in an unmoved
     organization; the operator reads each Pod's RuntimeClass.
  2. Stop and start a sandbox that existed before the move; the operator reads
     its RuntimeClass.
  3. Turn the flag off and start `std-m` again.
  4. On a surface whose deployment has no `standard` settings (Kind with
     both `SANDBOX_STANDARD_*` unset), the global admin's set of the flag is
     refused, and the organization's flag reads unchanged.
- **Proof:**
  - `std-m` is `standard` and `std-u` is the default;
  - the older sandbox keeps its profile across the move;
  - `std-m` still starts on `standard` after the flag is turned off;
  - on the surface without `standard`, the set is refused and the flag is
    unchanged;
  - each flag change has its audit entry, naming the admin, the organization
    and the new value;
  - the refused attempts change nothing and leave no change-audit entry,
    but each emits the auth layer's denial log line, naming the caller, the
    method and the reason.
- **Observed:** not yet observed.

## `standard-suspend`: an idle sandbox's VM pauses in its Pod and any use resumes it

Target, not shipped (#5529). The contract is
[`docs/dev/IDLE-STOP.md`](../dev/IDLE-STOP.md), "Suspend".

- **Entry points:** `idle_suspend` in `codewire.yaml`, `cw create --idle-suspend`,
  `cw update NAME --idle-suspend`, `cw suspend NAME`, `cw resume NAME`; waking by
  `cw resume`, `cw exec`, `cw shell`, `ssh`, a preview visit, an agent request or
  the dashboard's terminal.
- **States to exercise:**
  - `cw suspend NAME` on a running `standard` sandbox (even with `idle_suspend` off): pauses immediately and `cw ls` reads `suspended`; a repeat `cw suspend NAME` prints already suspended and exits 0 without waking it;
  - `cw resume NAME` on a suspended `standard` sandbox: wakes immediately, keeps running processes, and `cw ls` reads `running`; a repeat `cw resume NAME` prints already running and exits 0;
  - `cw suspend NAME` on a stopped or `commodity` sandbox, and `cw resume NAME` on a stopped sandbox: each refused with its reason;
  - `idle_suspend` off (the default): an idle sandbox never suspends;
  - on: it suspends after its timeout, and `cw ls` reads `suspended`;
  - set on a `commodity` sandbox: refused by name;
  - each wake path;
  - a long-lived connection through a pause of 10+ minutes;
  - the guest clock after a 30-minute pause;
  - idle stop reached while suspended: the sandbox resumes, then stops cleanly;
  - a pause asked by a guest process, not the daemon: the sandbox stays `running`, and the next activity check resumes it;
  - a freeze that fails after `ok`: the sandbox is back to `running` within 30 seconds, and the time is billed as running;
  - a sandbox on a runtime image from before suspend: never asked, and `cw info` says it can't suspend;
  - a gap in a boot's pause records: up to 60 seconds billed as suspended; longer, billed as running past the last state record and flagged for review;
  - a stop of a suspended sandbox: it is woken, its last lines are read, then it stops, and nothing is flagged;
  - a Pod deleted while its VM is paused, not by orchestration's stop: suspended time ends at the Pod's end, and the end is settled as a gap;
  - from #6367:
    - after resume, the front door re-admits the Sandbox, its leaves are re-signed, and the first request waits rather than drops (#6267);
    - the first proxied request after resume refreshes a real token that expired while it slept;
    - a credential revoked while suspended is refused on the first request after resume;
    - the no-token-at-rest scan of the suspended image finds placeholders only (for hibernate, when hibernate lands: the memory image).
- **Driving it:**
  1. `cw --cloud create --name std-s --idle-suspend 5m`, start a `sleep 3600` in a shell, and leave it idle for 5 minutes. `cw ls` reads `suspended`, and the operator reads the Pod still Ready and its CPU near zero.
  2. `cw exec --in std-s -- date` answers. The time from the command to the answer is recorded, `date` matches the client's clock, the `sleep` is still listed, and `cw ls` reads `running`.
  3. Repeat with `ssh`, a preview visit and the dashboard's terminal, each from `suspended`.
  4. Hold an `ssh` session open across a 10-minute suspend: it survives. A TCP stream through `cw-egress` either survives or resets once, as the contract says.
  5. `cw update std-s --idle-suspend off`: it no longer suspends. On a `commodity` sandbox, `--idle-suspend 5m` is refused.
  6. Inside `std-s`, a process other than the daemon sends `suspend` on vsock port 7784. The operator reads a `paused` record in the Pod log, `cw ls` still reads `running`, and the next activity check (at most 30 seconds later) resumes it, leaving a `resumed` record.
  7. The operator compares the billing session's suspended seconds with the Pod log's `paused` and `resumed` records for the walk: they match to the second, and no gap is flagged.
  8. With `idle_suspend` off, run `cw suspend std-s`, verify `cw ls` reads `suspended` and a second `cw suspend std-s` exits 0 ("already suspended") without waking the VM; run `cw resume std-s`, verify `cw ls` reads `running`, the `sleep` PID is unchanged, and a second `cw resume std-s` exits 0 ("already running"). Verify `cw suspend` on a `commodity` or stopped sandbox and `cw resume` on a stopped sandbox are each refused with a clear next step.
- **Proof:** the state transitions in `cw ls` and the API, the wake times, the `sleep`'s PID unchanged across the pause, the clock difference, the operator's Pod reads (Ready, the same Pod UID, no restart), the billing record's suspended seconds taken from the supervisor's pause record, and #6367's four checks.

## `standard-systemd`: a `standard` sandbox on a `workspace-systemd` disk boots systemd as container PID 1

Contract: [`docs/dev/SYSTEMD-WORKSPACE.md`](../dev/SYSTEMD-WORKSPACE.md), "On the `standard` profile" (#5638, #5602).

- **Entry points:** `cw --cloud create` on a `standard` deployment whose `SANDBOX_STANDARD_IMAGE_DISK` is built from `workspace-systemd`, with `CODEWIRE_WORKSPACE_INIT=systemd`.
- **States to exercise:** boot with no failed units; `systemctl --user` user manager and persistent user unit across stop/start; guest Docker with `docker.service` masked; `codewire-daemon.service` masked and `127.0.0.1:17777` unbindable; `CAP_SYS_ADMIN` dropped and `AF_VSOCK` refused by seccomp (for both user and `sudo`); clean stop via `SIGRTMIN+3`.
- **Driving it:**
  1. `cw --cloud create --name std-sd`, then `cw exec --in std-sd -- sh -c 'cat /proc/1/comm; systemctl is-system-running; systemctl --failed --no-legend | wc -l; stat -fc %T /sys/fs/cgroup'`.
  2. `cw exec --in std-sd -- sh -c 'systemctl is-enabled codewire-daemon.service || true; systemctl is-enabled docker.service || true; systemctl --user is-system-running; echo $XDG_RUNTIME_DIR'`.
  3. Enable and start a user unit (`~/.config/systemd/user/keep.service`), run `cw stop std-sd && cw start std-sd`, and confirm `systemctl --user is-active keep.service` prints `active`.
  4. `cw exec --in std-sd -- docker run --rm busybox echo ok`, verify `sudo -n mount -t tmpfs none /mnt` fails, and verify `socket(AF_VSOCK, SOCK_STREAM)` fails with `EAFNOSUPPORT` both as `codewire` and under `sudo -n`.
- **Proof:** step 1 prints `systemd`, `running`, `0`, `cgroup2fs`; step 2 shows `masked` / `masked-runtime`, `running`, and `/run/user/1000`; step 3 prints `active` across restart; step 4 runs Docker while refusing both `mount` and `AF_VSOCK`, and `cw stop` completes cleanly well inside the Pod grace period.
- **Observed:** not yet observed on Dev (local `/dev/kvm` A/B verification passed on 2026-11-27; Dev walk follows merge and Dev promotion).

## `standard-hibernate`: a `standard` sandbox hibernates to its volume and restores with processes intact

Target, not shipped (`#6647`). The contract is
[`docs/dev/SANDBOX-SLEEP.md`](../dev/SANDBOX-SLEEP.md) and
[`docs/dev/SANDBOX-DAEMON.md`](../dev/SANDBOX-DAEMON.md) ("Claim-time
workspace binding").

- **Entry points:** `idle_hibernate` in `codewire.yaml`,
  `cw create --idle-hibernate`, `cw update NAME --idle-hibernate`,
  `cw hibernate NAME`, `cw start NAME`, start-on-access (`cw exec`,
  `cw shell`, `ssh`, preview visit), `cw ls`, `cw info`, and the dashboard
  state pill.
- **States to exercise:**
  - `idle_hibernate` off (the default): an idle sandbox never hibernates;
  - `idle_hibernate` on (`5m` in the walk) and manual `cw hibernate NAME`
    from both `running` and `suspended`: `cw ls` reads `hibernated`, the Pod
    is gone, and the PVC stays;
  - `cw hibernate NAME` and `--idle-hibernate` on a `commodity` or
    `confidential` sandbox: refused, naming the runtime profile;
  - `--idle-suspend 10m --idle-hibernate 5m`: refused, naming both settings;
  - restore by `cw start NAME` and by start-on-access: the running process
    keeps its PID and keeps writing, files and durable sessions stay, the
    guest clock matches the host, and the name, preview URL and tailnet
    name/address stay;
  - `cw-security` re-bind and memory-file boundaries (`#5484`, `#6647`):
    - new Pod tokens replace checkpointed copies before the workload thaws
      and before re-bind;
    - a request to the new Pod's port `7777` between restore and re-bind is
      refused;
    - after re-bind, the old Pod's daemon credential and an old credential
      bridge epoch handle are refused;
    - the re-bind makes a fresh tailnet node key and the coordinator drops
      the old node key in the same bind;
    - the memory file sits outside guest reach, is restored at most once,
      and is deleted from the volume after re-bind succeeds;
  - product disk snapshot and fork of a hibernated sandbox: the memory file
    is excluded;
  - billing: the running/paused session closes at the host-observed
    `hibernated` record and a `hibernated` session draws only allocated
    `disk_gib` (excluding memory-file headroom) at the admin pricing table's
    storage rate (`0` until set, `#5782`);
  - `#6367`: no-token-at-rest scan of the hibernate memory image finds
    placeholders only, and proxied credentials still work / honor revocation
    after restore.
- **Driving it:**
  1. `cw --cloud create --name std-h --idle-hibernate 5m` (no command yet,
     `#6647`), start a background loop writing its PID and counter to
     `/tmp/beat` and a file in `/workspace/keep`, and publish a preview port.
  2. `cw hibernate std-h` (and separately let a fresh sandbox cross its
     `idle_hibernate` timeout): `cw ls` reads `hibernated`, `cw info std-h`
     names when and why it hibernated, and the operator confirms the Pod is
     gone while the PVC remains.
  3. On a `commodity` sandbox, run `cw hibernate` and
     `cw update --idle-hibernate 5m`: both refuse and name `commodity`.
  4. `cw start std-h` (and separately wake a hibernated sandbox via
     start-on-access): `cw exec --in std-h -- cat /tmp/beat` read twice shows
     the same PID still ticking, `/workspace/keep` is intact, `date` matches
     the host clock, and the preview URL serves under the same hostname.
  5. Operator's half (and automated boundary tests): verify port `7777` is
     refused between restore and re-bind; verify the old daemon credential
     and an old credential bridge epoch handle are refused after re-bind;
     verify the coordinator no longer holds the old tailnet node key; verify
     the memory file is absent from the volume after re-bind; verify a
     snapshot/fork excludes the memory file; verify billing recorded the
     hibernated stretch from host-observed records at the admin storage rate.
- **Proof:** unchanged process PID and advancing `/tmp/beat` across Pod
  deletion and recreation (new Pod UID), the `commodity` refusal naming the
  runtime, each `cw-security` refusal (7777 pre-bind, old daemon credential,
  old epoch handle, dropped old tailnet node key), absence of the memory file
  post-bind and in snapshots, and billing's host-observed `hibernated`
  session matching the Pod log record.
- **Gotchas:** record the hibernate write duration, restore duration, and
  re-bind duration; clean up all scratch sandboxes by exact name with
  `cw rm --yes NAME`.
- **Observed:** not yet observed.

## `standard-hibernate-fallback`: an unrestorable hibernate boots cleanly from the disks

Target, not shipped (`#6647`). The contract is
[`docs/dev/SANDBOX-SLEEP.md`](../dev/SANDBOX-SLEEP.md), "When a restore
cannot happen (fallback)".

- **Entry points:** `cw start NAME`, `cw info NAME`, and the dashboard
  Sandbox page.
- **States to exercise:**
  - memory file missing, incomplete, or damaged on the volume;
  - workspace image disk rebuilt (`image_disk_id` or `build_id` mismatch);
  - VMM `sha256` or runtime image digest mismatch, or runtime image past its
    30-day admission allow window;
  - restore generation already consumed (restore-once guard).
- **Driving it:**
  1. Hibernate a scratch `standard` sandbox that has a file written in
     `/workspace/keep` and `~/keep` plus a background process.
  2. Induce each unrestorable condition in turn (corrupt/truncate the memory
     file on the scratch volume, mismatch the image disk build or VMM/runtime
     digest, or expire the hibernate record past the 30-day allow window).
  3. Run `cw start NAME`, then `cw info NAME` and
     `cw exec --in NAME -- cat /workspace/keep ~/keep`.
- **Proof:** the start succeeds via cold boot from the disks without hanging
  or failing, `/workspace/keep` and `~/keep` are intact, the background
  process from before hibernate is gone, the broken memory file is deleted
  from the volume, and `cw start` and `cw info` clearly state that processes
  were lost and files were kept, naming why restore could not happen.
- **Gotchas:** never mutate a non-scratch sandbox volume; remove scratch
  sandboxes by exact name at the end.
- **Observed:** not yet observed.
