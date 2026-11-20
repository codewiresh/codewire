# A cloud sandbox on the `standard` runtime profile

A cloud sandbox whose VM is started by Codewire's own runtime inside the Pod
behaves as one on `commodity` does (#5602). The contract is the `standard`
paragraph of `SPEC.md` "4. Hosted sandboxes" and "The `standard` profile" in
[`docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md`](../dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md).
This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-20. Written first; every step is not yet observed.

| ID | Kind | Dev | Production |
| --- | --- | --- | --- |
| `standard-create` | not yet observed | not yet observed | not yet observed |
| `standard-exec` | not yet observed | not yet observed | not yet observed |
| `standard-docker` | not yet observed | not yet observed | not yet observed |
| `standard-network` | not yet observed | not yet observed | not yet observed |
| `standard-stop-start` | not yet observed | not yet observed | not yet observed |
| `standard-admission` | not yet observed | not yet observed | not yet observed |
| `standard-beside-commodity` | not yet observed | not yet observed | not yet observed |

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

## `standard-docker`: Docker runs in the VM and is not shared

- **Entry points:** `docker` in a shell or a command.
- **States to exercise:** a container run; a published port reached through
  a preview; two sandboxes side by side.
- **Driving it:**
  1. `cw exec --in std-a -- docker run --rm busybox echo hello` prints `hello`.
  2. `cw exec --in std-a -- docker images -q` lists the image; the same command
     in `std-b` lists nothing.
- **Proof:** the image ID present in one sandbox and absent in the other.
- **Observed:** not yet observed.

## `standard-network`: every connection goes through the node's egress service

- **Entry points:** any program in the sandbox; `cw --cloud policy` for the
  policy and `cw --cloud policy log` for the refusal log.
- **States to exercise:** an allowed destination; a destination the policy
  refuses; a private address, which is always refused.
- **Driving it:** the hosted steps of
  [network-and-egress.md](network-and-egress.md), on a `standard` sandbox.
- **Proof:** the refusal log's entry for the refused destination, and no
  route out of the Pod other than to the egress service (the operator reads
  the Pod's NetworkPolicy).
- **Observed:** not yet observed.

## `standard-stop-start`: the home and the workspace persist, the root does not

- **Entry points:** `cw stop`, `cw start`, the dashboard's stop and start.
- **States to exercise:** a stop while a process writes; a start on the same
  volume; a file written outside the home and the workspace.
- **Driving it:**
  1. `cw exec --in std-a -- sh -c 'echo NONCE > ~/keep; echo NONCE > /workspace/keep; sudo sh -c "echo NONCE > /opt/gone"'`.
  2. `cw stop std-a`, then `cw start std-a`.
  3. `cw exec --in std-a -- cat ~/keep /workspace/keep` prints the nonce twice;
     `cw exec --in std-a -- cat /opt/gone` fails with "No such file".
- **Proof:** the nonce read back from the two kept paths, and the missing
  third file.
- **Gotchas:** a stop that takes the whole grace period means the guest did
  not power off when asked; record the stop's duration.
- **Observed:** not yet observed.

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
