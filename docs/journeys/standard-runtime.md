# A cloud sandbox on the `standard` runtime profile

A cloud sandbox whose VM is started by Codewire's own runtime inside the Pod
behaves as one on `commodity` does (#5602). The contract is the `standard`
paragraph of `SPEC.md` "4. Hosted sandboxes" and "The `standard` profile" in
[`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`](../dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md).
This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-25. Written first. `standard-stop-start` is observed on Dev;
the other steps are not yet.

| ID | Kind | Dev | Production |
| --- | --- | --- | --- |
| `standard-create` | not yet observed | not yet observed | not yet observed |
| `standard-exec` | not yet observed | not yet observed | not yet observed |
| `standard-application-secrets` | not yet observed | not yet observed | not yet observed |
| `standard-docker` | not yet observed | not yet observed | not yet observed |
| `standard-network` | not yet observed | not yet observed | not yet observed |
| `standard-closed-egress` | not yet observed | not yet observed | not yet observed |
| `standard-stop-start` | not yet observed | steps 1 to 3, 2026-11-24 | not yet observed |
| `standard-admission` | not yet observed | not yet observed | not yet observed |
| `standard-beside-commodity` | not yet observed | not yet observed | not yet observed |
| `standard-organization-move` | not yet observed | not yet observed | not yet observed |
| `standard-suspend` | not yet observed | not yet observed | not yet observed |

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
- **Observed:** not yet observed.

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
- **Observed:** not yet observed.

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
- **Observed:** not yet observed.

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
- **Observed:** not yet observed.

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
- **Observed:** not yet observed.

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
  start 12 s, and all three nonces were kept. Step 4 not yet observed.

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
- **Observed:** not yet observed.

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
- **Observed:** not yet observed.

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
  `cw update NAME --idle-suspend`; waking by `cw exec`, `cw shell`, `ssh`, a preview
  visit, an agent request or the dashboard's terminal.
- **States to exercise:**
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
- **Proof:** the state transitions in `cw ls` and the API, the wake times, the `sleep`'s PID unchanged across the pause, the clock difference, the operator's Pod reads (Ready, the same Pod UID, no restart), the billing record's suspended seconds taken from the supervisor's pause record, and #6367's four checks.
