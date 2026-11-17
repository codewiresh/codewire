# Local VMs on a Mac

A local VM on an Apple silicon Mac ([SPEC.md section 5](../../SPEC.md#5-local-vms-and-trusted-hosts)):
`cw` installs, creates a VM through Virtualization.framework, opens a shell in
it, runs a command, and stops and starts it. Launch step 11 (#4370) needs this
walk observed on macOS 27 and on macOS 26. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-17.

| ID | macOS 27 | macOS 26 |
| --- | --- | --- |
| `mac-vm-lifecycle` | observed on a development build of the v0.4.22 candidate (df5ceafd0); failure observed on v0.4.16 | observed on a development build of the #4478 fix |
| `mac-vm-refused-start` | refused create observed on a development build | not yet observed |
| `mac-vm-cached-image` | observed on a development build of #5036 (e42e2f457) | not yet observed |
| `mac-vm-mesh-ingress` | not yet observed | not yet observed |

## Before the walk

- Use an Apple silicon Mac and record `sw_vers -productVersion` and
  `cw --version` with every observation.
- For a walk that leaves the Mac's own `cw` state alone, give it a throwaway
  `HOME` and keychain (`CODEWIRE_LOCAL_CREDENTIAL_KEYCHAIN`), as
  `scripts/dev/test-cli-local-vm-macos.py` does, and remove both afterwards.
  `cw`'s sockets go to a directory keyed by the state root, so two `HOME`s
  never share a supervisor.
- An application firewall must allow the installed `cw` to reach
  `releases.codewire.sh`, `ghcr.io` and `pkg-containers.githubusercontent.com`.
  The guest's own DNS and connections leave the Mac through `cw` too. Each `cw`
  version runs from its own path under
  `~/.local/share/codewire/cli/versions/`, so a firewall that decides per
  executable asks again after every upgrade. Until it was allowed, guest egress
  failed with `bad address` (DNS), then with `Connection refused` (TCP).

## 1. `mac-vm-lifecycle`: install, create, shell, run, stop, start

Issues: #4478 (VMs did not start on macOS 27), #4370 (launch step 11).

- **Entry points:** `cw` in a terminal on the Mac. Local VMs have no
  dashboard entry point.
- **States to exercise:**
  - a fresh install, and `cw upgrade` from the previous release;
  - a first create, which pulls the image, and a create from cached layers;
  - a stopped VM started again, and a command run after the restart;
  - a VM with a credential profile whose egress broker was lost
    (`egress_broker_exit`): `cw --local start` alone, and `cw --local stop`
    then `start`, each finish in their usual time and egress works again
    (#4953);
  - a start macOS refuses (`mac-vm-refused-start`).
- **Driving it:**
  1. Install: `curl -fsSL https://codewire.sh/install.sh | sh`, or
     `cw upgrade`. Then `cw --version`.
  2. `cw setup --local` prints `Local VM runtime installed (ID).`
  3. `cw create --local --name mac-walk --path-mode empty --yes` ends with
     `✓ Environment mac-walk created · local VM`.
  4. `cw --local shell mac-walk` opens a login shell in `/workspace`. Type
     `uname -m` (it prints `aarch64`), then `exit`.
  5. `cw run --in mac-walk --no-tty -- sh -c 'echo before-restart'`.
  6. `cw --local stop mac-walk`, then `cw --local ls` shows `stopped`.
  7. `cw --local start mac-walk` ends with `✓ Environment mac-walk started`.
     `cw run --in mac-walk --no-tty -- sh -c 'echo after-restart; uptime'`.
  8. `cw --local rm mac-walk`.

  `scripts/dev/test-cli-local-vm-macos.py --cw CW --runtime DIR` walks steps
  2, 3 and 5 to 8 with a small image, without the interactive shell. It adds
  guest egress, a lost network worker or egress broker failing closed, a
  stalled VM resuming, and the VZ helper's sandbox posture. The release dry
  run's Mac job runs it with each run's own `cw` and runtime
  (`scripts/ci/verify/macos-local-vm-journey.sh`); it is advisory until #4506.
- **Proof:** the shell prints `aarch64`; `cw --local ls` reads `stopped` after
  step 6 and `running` after step 7; the command after the restart prints
  `after-restart` and an uptime under a minute. After a lost egress broker,
  `cw --local info` reads `Error: egress_broker_exit` with the broker's exit
  status and its name, such as `exited 72: egress_broker_protocol` (#4953).
- **Gotchas:**
  - A first create with the default workspace image pulls about a minute of
    layers; a slow pull is not a failure.
  - A `cw` built from source has no provenance. `cw setup --local --from DIR`
    installs a runtime directory from `make macos-local-runtime` and warns
    that it cannot check the runtime's source.
  - macOS 26 has no test Mac since the CI Mac moved to macOS 27 (owner,
    2026-11-13; no new hardware). It stays supported, and its last observation
    stands until the helper's Seatbelt profile or its use of
    Virtualization.framework changes, or a regression shows only on macOS 26;
    then this walk needs a macOS 26 Mac again.
- **Observed:**
  - macOS 27.2.1, release v0.4.16, 2026-11-13: failure observed. Every create
    failed at "Starting the VM" with `create_failed` (#4478).
  - macOS 27.2.1, a development build of main 3abfebe8b with the #4478 fix
    and v0.4.16's kernel, guest root and cw runtime, 2026-11-13: steps 3 to 7
    observed, after `cw setup --local --from DIR` in place of steps 1 and 2.
    The create took 126 s, 71 s of it the image pull; the stop took
    2 s and the start 3 s. With the helper from 3abfebe8b instead, and the same
    `cw`, the create failed at "Starting the VM" (#4478).
  - macOS 27.2.1, the same `cw` and runtime directory, 2026-11-13, once the
    Mac's firewall allowed that `cw`: `test-cli-local-vm-macos.py` passed
    every check in 108 s, including egress, both fail-closed losses, the stall
    and the helper's posture (#4478).
  - macOS 26.6.2, the same `cw` and runtime directory, 2026-11-13: steps 3 to
    8 observed, after `cw setup --local --from DIR`. The create took 195 s,
    about 2 minutes of it the image pull; the stop took 1 s and the start 4 s.
  - macOS 27.2.1, a development build of the v0.4.22 candidate df5ceafd0,
    2026-11-17, by cw-mac, in a scratch `HOME`: steps 3 to 8 observed after
    `cw setup --local --from DIR`. The runtime was packed on the Mac from
    df5ceafd0's guest root and sealed `cw`, built with the release's own
    scripts, and v0.4.21's released arm64 kernel, byte-identical to the one
    df5ceafd0's recipe builds (its only changed input is #5098's timeout
    hook); the VZ helper was built from df5ceafd0 and signed ad hoc. The
    create took 117 s. The shell opened in `/workspace` and printed
    `aarch64`; the stop took 1.7 s and `ls` read `stopped`; the start took
    6.3 s, `ls` read `running`, and the command after it printed
    `after-restart` with an uptime of 0 minutes. The same walk moved two
    v0.4.18 VMs onto this runtime and forked a disk snapshot
    ([local-vm-upgrade.md](local-vm-upgrade.md),
    [snapshots-and-forks.md](snapshots-and-forks.md)).

## 2. `mac-vm-refused-start`: a VM macOS refuses to start says so

Issues: #4478.

- **Entry points:** `cw create --local` and `cw --local start`.
- **States to exercise:** a refused create, and a refused start of a VM that
  ran before.
- **Driving it:** no command makes macOS refuse a start on purpose. A
  helper built without its macOS 27 cache-directory rule is refused on macOS
  27, which is how this state was produced for #4478.
- **Proof:** the create fails with `create_vm_start_refused`, or the start
  with `start_vm_start_refused`, and the message says macOS refused to start
  the VM, never `create_failed`.
- **Gotchas:** a helper from before #4478 exits 1 when it is refused, so it
  reports `create_failed`, and that `cw` cannot do better.
- **Observed:**
  - macOS 27.2.1, the development build above with its helper's `/var` rule
    removed, 2026-11-13: a refused create observed. It failed at "Starting
    the VM" with `create_vm_start_refused` and the hint "macOS's
    Virtualization framework refused to start the VM", and the supervisor
    logged `runner_error=vm_start_refused` (#4478).
  - A refused start of an existing VM: not yet observed.

## 3. `mac-vm-cached-image`: a cached image needs no registry

Issues: #4968, #4917.

- **Entry points:** `cw create --local` with the default workspace image,
  which is pinned by digest, or `--image` with a `REPOSITORY@sha256:…`
  reference, and `--image` with a tag.
- **States to exercise:** a create whose image is all in the content store
  while the registry can't be reached; the same with a tag.
- **Driving it:** create and remove a VM with the default image, so the
  repository's retained image keeps its content. With the registry out of
  reach (the Mac offline, or a firewall holding the connection), create
  another VM with the same image, then one with a tag of that repository.
- **Proof:** the digest create succeeds with no registry connection, and its
  image step reads "Using the cached image". The tag
  create fails at "Preparing the image" and says it asked the registry for
  the tag.
- **Gotchas:** a cached image is one the content store still keeps: an
  environment's, a pending create's, or the repository's retained image.
  After `cw prune --local`, the next create downloads it again. Linux local
  VMs behave the same way.
- **Observed:** macOS 27.2.1, a development build of #5036 at e42e2f457,
  2026-11-16, at a new path that the Mac's application firewall held at
  ghcr.io (#4917), in a HOME that had pulled the default image earlier that
  day:
  - The default-image create succeeded. Its image step read "Using the
    cached image" (0.9 s), and the supervisor logged
    `workspace_image_cached`. The firewall logged no connection from the
    supervisor during it.
  - The create with `ghcr.io/codewiresh/workspace:latest` failed after 11 s at
    "Preparing the image" with `create_registry_transport`. The hint said the
    registry could not be reached and that a tag is always checked with its
    registry. The firewall logged that supervisor's DNS lookup of ghcr.io and
    its connection to ghcr.io:443.

## 4. `mac-vm-mesh-ingress`: a Mesh connection reaches the VM whole, under load

Issue: #5084.

- **Entry points:** `cw create --local --network NAME`, with the ports the
  project declares; then a connection from another member of that Mesh
  network to one of those ports on the VM's node.
- **States to exercise:** the Mac idle; the Mac under load, with other
  processes passing and closing sockets (the churn of
  `in_flight_sockets_keeping_their_bytes` in `codewire-egress-policy`); a
  client that writes as soon as it connects; many connections one after
  another; a network worker that does not acknowledge a connection.
- **Driving it:** create a VM on a Mesh network with a server on a declared
  port that echoes what it reads. From another node of the network, open 200
  connections in turn, each writing a few bytes at once and reading them
  back, first with the Mac idle and then under the churn. No command wraps
  this yet.
- **Proof:** every connection gets its bytes back, idle and under load: none
  ends at once, and none loses what its client wrote first. The runner's
  copy of each accepted connection is released when the network worker
  acknowledges it, and the Mesh transport's when the runner does, so a
  connection the VM's server closes still ends at once for its client. A
  connection not acknowledged within two seconds is closed by whichever of
  the two was holding it: its client sees it end, never hang, and
  `mesh_ingress_unacknowledged` is recorded. After three in a row the
  environment turns `error`, as when the forwarder or the transport is lost
  for any other reason.
- **Gotchas:** Mesh attachment on a Mac local VM is implemented but not yet
  observed with a real Mesh sign-in (`docs/dev/MACOS-CLI.md`), so this step
  waits on that walk too. Linux local VMs keep a socket in flight and do
  not show the loss; the rule is the same on both.
- **Observed:** not yet observed. The loss itself is measured outside the
  product (`docs/dev/MACOS-CLI.md`); the fix is not built.
