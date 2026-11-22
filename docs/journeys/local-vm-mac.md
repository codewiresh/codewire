# Local VMs on a Mac

A local VM on an Apple silicon Mac ([SPEC.md section 5](../../SPEC.md#5-local-vms-and-trusted-hosts)):
`cw` installs, creates a VM through Virtualization.framework, opens a shell in
it, runs a command, and stops and starts it. Launch step 11 (#4370) needs this
walk observed on macOS 27 and on macOS 26. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-22.

| ID | macOS 27 | macOS 26 |
| --- | --- | --- |
| `mac-vm-lifecycle` | observed on v0.4.22; failure observed on v0.4.16 | observed on a development build of the #4478 fix |
| `mac-vm-refused-start` | refused create observed on a development build | not yet observed |
| `mac-vm-cached-image` | observed on a development build of #5036 (e42e2f457) | not yet observed |
| `mac-vm-mesh-ingress` | not yet observed | not yet observed |
| `mac-vm-intercept` | boots observed on #4916 on #5124 (268f2709e), 5 of 5; serving partly observed on a scratch merge with the placeholder seed (245992e87) | not yet observed |
| `mac-vm-refresh` | not yet observed (#5539) | not yet observed (#5539) |
| `local-vm-git-mounted` | not yet observed ([local-vm-git.md](local-vm-git.md), #5478) | not yet observed |
| `mac-vm-indexed-root` | not yet observed (#5831) | not yet observed (#5831) |
| `mac-vm-backup-excluded` | not yet observed (#5900) | not yet observed (#5900) |

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
  A dry run that embeds no runtime walks nothing, so that job reads skipped,
  never green, and the release tag receipt counts only a walk that printed
  `local-vm: all checks PASS` (#5253). A dispatched candidate dry run builds
  a missing arm64 kernel so that its walk can run.
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
  - macOS 27.2.1, released v0.4.22, 2026-11-17, by cw-mac, in a scratch
    `HOME`: the installer put v0.4.21 there and `cw upgrade --cli --version
    v0.4.22` replaced it, so `cw setup --local` and the upgrade installed the
    released runtimes. v0.4.22's VZ helper carries the release's Developer
    ID signature (team PXQZM3GLP5, secure timestamp 2026-11-17) and passes
    `codesign --verify --strict` against Apple's anchor. Steps 3 to 8
    observed: the create took 55 s with the image cached; the shell opened
    in `/workspace` and printed `aarch64`; the stop took 1.7 s and `ls` read
    `stopped`; the start took 4.0 s and the command after it printed
    `after-restart` with an uptime of 0 minutes; `rm` worked. A v0.4.21
    create pulled the image in 221-277 s. Commands and outputs:
    #4370, comment 112323.

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
  the two was holding it: its client sees it end, never hang, and when it
  was the runner, its log has `mesh_ingress_unacknowledged`. After three in
  a row the environment turns `error`, as when the forwarder or the
  transport is lost for any other reason.
- **Gotchas:** Mesh attachment on a Mac local VM is implemented but not yet
  observed with a real Mesh sign-in (`docs/dev/MACOS-CLI.md`), so this step
  waits on that walk too. Linux local VMs keep a socket in flight and do
  not show the loss; the rule is the same on both.
- **Observed:** not yet observed. The loss itself is measured outside the
  product (`docs/dev/MACOS-CLI.md`). The hold is built and unit-tested on
  Linux (#5084); its walk on a Mac is not done.

## 5. `mac-vm-intercept`: a VM boots with agent interception switched on

Issues: #3999, #4916.

- **Entry points:** the file `egress-intercept` in the local VM state root
  (`~/.codewire/native-v1` by default) with the content `on`, then
  `cw create --local --profile local:P` or `cw --local start` of a VM bound
  to a local profile.
- **States to exercise:** a boot with the switch on, and the same VM stopped
  and started after the file is removed.
- **Driving it:** write `on` to the file, create a VM bound to a local
  profile, find its front-door process (`cw __native-front-door`), and in the
  VM read the CA that `NODE_EXTRA_CA_CERTS` names. A VM with no profile has no
  local credential broker, so it boots without interception, and the
  supervisor's log records `egress_intercept switch=on
  skipped=no_credential_broker`. Any credential works for the walk. A
  generated SSH key (`cw credentials --local generate ssh`) needs no sign-in.
- **Proof:** the boot succeeds. The front-door process runs under a Seatbelt
  profile: `sandbox_check(pid, NULL, 0)` is 1, as the `native_front_door`
  test checks. The guest trusts the boot's CA, and an intercepted HTTPS
  request reaches the credential broker with its bound host.
- **Gotchas:**
  - The CA is made inside the confined process for each boot, so a stop and
    start brings a new CA.
  - A runtime packed from released parts around a newer guest `cw` is
    refused at "Checking the VM runtime" (`SupervisorError::Artifact`), with
    interception on or off. Use a runtime built from the same tree.
- **Observed:**
  - Partly observed: the front door serving a request, on macOS 27.2.1,
    2026-11-16. The tree was a scratch merge, 245992e87: #4916 at 1eeee1872
    with the head that carries the placeholder seed and login (5820971c7),
    which #4916 does not yet have under it. The `cw` was built with
    `local-broker-synthetic-smoke`, whose credential broker answers the
    provider itself, and the profile held a made-up Anthropic API key:
    - The guest's `ANTHROPIC_AUTH_TOKEN` was a `cwp1_` placeholder, and
      `ANTHROPIC_BASE_URL` was unset.
    - A request to `api.anthropic.com/v1/messages/count_tokens` carrying the
      placeholder was served with the stored key (200,
      `{"input_tokens":42}`). The two headers that echo the key arrived
      redacted, and the key never reached the guest. The placeholder beside
      another credential was refused (400, `credential_conflict`).
    - After the first credential broker renewal, about 10 minutes in, the
      successor logged `front_door_pairing outcome=paired pairing=2`, and the
      request was served again.
    - With the front door killed, the request ended in 7 ms
      (`ECONNREFUSED`), and the VM kept running. After a stop and start the
      placeholder was the same, and the request was served.
  - Five VM boots on macOS 27.2.1, with a development build of #4916 rebased
    onto #5124 and #4914 (268f2709e), 2026-11-16. The runner holds the ends
    it sends until the front door answers. Each VM was bound to a profile
    holding a generated SSH key and created from the cached image:
    - All five came up. In each, the credential broker had
      `--boot-secrets-fd 4`, and the runner logged
      `front_door_pairing outcome=paired`.
    - In each, `curl --cacert` to `https://api.anthropic.com/v1/models` was
      answered by "Codewire environment egress CA" with status 403, three
      times.
    - Right after each `cw --local stop`, no front-door process ran.
    - On the first boot, the guest's first lookup of `api.anthropic.com` got
      no answer in 11 s, and every later lookup answered at once. A lookup
      goes through the egress broker, not the front door; the cause is not
      known.
    - `native_front_door`, confined, passed 5 of 5 runs of its whole suite.
      Before #4914 the same runs failed 3 of 3.
  - Five VM boots on macOS 27.2.1 at d246247f6 (#4916 with the boot secret
    at FD 4, on #4884's 07a35b9fc, plus #5036), 2026-11-16: three came up
    and were intercepted as above. Two failed at the front door's pairing:
    the runner logged `outcome=paired`, then `front_door_gone` in the same
    millisecond, then `guest_start_failed detail=guest_shutdown` at about
    50 s. That runner dropped the ends it sent as soon as it had sent them,
    and macOS can discard a socket in flight once its sender has closed it
    (the sender audit on #4916). #4914 is the fix.
  - The VM boot, on macOS 27.2.1 with a development build of #4916 at
    e75051ae5, 2026-11-16, with a VM bound to a profile holding a generated SSH
    key:
    - The supervisor logged `egress_intercept switch=on`. The front-door
      process ran under Seatbelt (`sandbox_check` = 1).
    - The guest's `NODE_EXTRA_CA_CERTS` named the boot's CA. Requests to
      `https://api.anthropic.com/v1/models` with that CA, from `curl --cacert`
      and from Node, were answered by "Codewire environment egress CA" with
      status 403. The profile held no Anthropic credential.
    - With the file removed, after a stop and start the log read
      `switch=off`, no front door ran, and the guest had no
      `NODE_EXTRA_CA_CERTS`.
    - The same build with no profile logged `skipped=no_credential_broker`
      and reached the provider directly.
  - The confined process alone, on macOS 27.2.1 with a development build of
    #4916, 2026-11-15: `native_front_door` passed. The real process ran
    under Seatbelt (`sandbox_check` = 1), reported its CA, and terminated
    TLS for a handed-over stream.

## 6. `mac-vm-refresh`: a sign-in due for refresh refreshes

Issues: #5537, #5539. The rule is in
[SECRETS-AND-CREDENTIALS.md](../dev/SECRETS-AND-CREDENTIALS.md), "Children".

- **Entry points:** a Claude, Codex or GitHub sign-in in a VM's credential
  profile; the guest's next request, or a host checkout's `git`, once the
  sign-in's access token is due for refresh.
- **States to exercise:** a due Claude or Codex sign-in, and a due GitHub
  login on a host checkout.
- **Driving it:** the broker's Seatbelt profile only reads the keychain, so
  the broker sends the refreshed bundle in Commit and the authority writes it
  to the keychain. A synthetic Claude sign-in from
  the featured smoke build (#5374) is due on its first use. Walk it with a
  throwaway `HOME` and keychain, as in [Before the walk](#before-the-walk).
- **Proof:**
  - The due Claude or Codex sign-in's request succeeds with the refreshed
    login, and a due GitHub login renews before `git` runs.
  - `brokers.log` shows no broker ending, and the credential is at material
    generation 2 with no refresh row left in the journal.
- **Gotchas:** before #5539 the broker's own keychain write failed inside its
  Seatbelt profile (`Operation not permitted`, #5537), so a Mac VM's sign-in
  worked only until its access token was due, about 8 hours for a Claude
  sign-in. Assert on the refresh's result, not the Sandbox log: that refusal
  logged no file-write denial.
- **Observed:** not yet observed.

## 7. `mac-vm-indexed-root`: a state root Spotlight may index is warned about

Issues: #5831, #5830.

- **Entry points:** `cw setup --local`, `cw create --local` and
  `cw --local start`.
- **States to exercise:** the default state root under `~/.codewire`; a
  visible one set with `CODEWIRE_NATIVE_STATE_ROOT`, such as
  `~/cw-visible/native-v1`; and one under a `.noindex` folder, such as
  `~/vms.noindex/native-v1`.
- **Driving it:** set the override in the walk's throwaway `HOME`, then run
  each entry point once with it and once without.
- **Proof:** with the visible root, each command prints one warning on
  stderr naming the root: Spotlight may index that folder, and its image
  importer reads the VM's disks there, so keep the state root in a folder
  whose name ends in `.noindex`, or in a dot folder such as the default
  `~/.codewire`. The command still completes, and with `-o json` its stdout
  is still only the JSON. With the default root and the `.noindex` root, no
  warning is printed. A dot folder or a `.noindex` folder anywhere in the
  path counts.
- **Gotchas:** the warning goes by the path alone; it does not ask
  Spotlight. `~/Library` is not a folder Spotlight skips. The rule was
  measured with `mdfind` on macOS 27.2.1
  ([SECRETS-AND-CREDENTIALS.md](../dev/SECRETS-AND-CREDENTIALS.md)); external
  volumes were not. It goes away once #5830 gives the disks an
  extension no importer claims.
- **Observed:** not yet observed.

## 8. `mac-vm-backup-excluded`: a local VM's disks stay out of Time Machine

Issues: #5900.

- **Entry points:** `cw create --local`, and `cw --local start` on a state
  root made before #5900.
- **States to exercise:** a new state root, and an existing one whose `vms/`
  carries no exclusion.
- **Driving it:** in the walk's throwaway `HOME`, create a VM; for the
  existing root, clear the exclusion with `tmutil removeexclusion` on `vms/`,
  then start a VM.
- **Proof:** `tmutil isexcluded` reports `[Excluded]` for the state root's
  `vms/` and for the VM's directory under it, after the create and after the
  start. Folders shared from the host into the VM are not excluded.
- **Gotchas:** the exclusion is the attribute `tmutil addexclusion` writes, so
  it moves with the folder and needs no Time Machine settings change.
- **Observed:** not yet observed.
