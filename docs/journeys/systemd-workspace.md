# A workspace that boots systemd

A cloud sandbox in which every session sees systemd as PID 1, with the
environment daemon as a unit ([SYSTEMD-WORKSPACE.md](../dev/SYSTEMD-WORKSPACE.md), #5638). The
journey proves that it boots, that it behaves as a default sandbox does, and
that software which needs systemd then works, with a Rex server as the
example. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-21. Written first; nothing here is built yet.

| ID | Dev | Production |
| --- | --- | --- |
| `systemd-workspace-boot` | not yet observed; the setting-off create on a local Kind cluster, not yet observed | not offered |
| `systemd-workspace-refusals` | not yet observed; the runtime refusal on a local Kind cluster, not yet observed | not offered |
| `systemd-workspace-sessions` | not yet observed | not offered |
| `systemd-workspace-egress` | not yet observed | not offered |
| `systemd-workspace-user-units` | not yet observed | not offered |
| `systemd-workspace-stop` | not yet observed | not offered |
| `systemd-workspace-rex` | not yet observed | not offered |

A systemd workspace exists only on a VM runtime, so a local Kind cluster,
which runs sandboxes on `runc`, can prove two things: that it refuses, and
that without the setting the image is an ordinary custom image.

Outside the product, scratch Pods on Dev's VM runtime have shown the
bootstrap booting, taking exec and being killed after a stop. With OpenSSH in
the Pod, they also showed `rex server install` and `rex server status`
working (#5638). None of that counts as an observation below, which
needs the product's own create.

## Before the walk

- The deployment sets `CODEWIRE_SYSTEMD_WORKSPACE_IMAGE_REPOSITORY`, and its
  cluster admits the workspace container's one added capability for that
  image. Without either, the first step is a refusal; record its text.
- A global admin has opted the walking identity's organization in with
  `SetOrganizationSystemdEnvironments`, and `ListSystemdOrganizations` lists
  it. A second organization, not opted in, is needed for
  `systemd-workspace-refusals`.
- `IMAGE` below is that repository with the digest of the published
  workspace-systemd image, as `REPOSITORY@sha256:…`.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- Run the computer's side in a disposable home, as
  [rex-server.md](rex-server.md) says: `cw setup ssh` and
  `rex server install` change the SSH config and Rex hosts of whoever runs
  them.
- The examples call the sandbox `sd`.

## `systemd-workspace-boot`: systemd is PID 1 for every session

- **Entry points:** `cw create --cloud --image IMAGE`.
- **States to exercise:** a create with the setting on; a create with the
  setting off, where the image is an ordinary custom image and systemd does
  not start.
- **Driving it:**
  1. `cw create --cloud --name sd --image IMAGE --no-profile --yes`.
  2. `cw exec --in sd -- sh -c 'cat /proc/1/comm; systemctl
     is-system-running; systemctl --failed --no-legend | wc -l;
     systemd-analyze | head -1'`.
  3. `cw exec --in sd -- sh -c 'systemctl show codewire-daemon.service -p
     ActiveState,TasksMax,KillMode; cat /proc/self/cgroup; id -un'`.
  4. `cw exec --in sd -- sh -c 'grep CapBnd /proc/1/status; sudo -n mount -t
     tmpfs none /mnt'`.
  5. `cw exec --in sd -- sh -c 'cat /proc/1/cgroup; grep -c "^0$"
     /sys/fs/cgroup/cgroup.procs'`.
  6. On a local Kind cluster whose orchestration does not set the
     repository, with the walking organization opted in there, `cw create
     --cloud --name sd-off --image IMAGE --no-profile --yes`, then read the workspace container of its Pod with `kubectl get
     pod -o json`, then `cw rm --yes sd-off`.
- **Proof:**
  - step 2 prints `systemd`, `running`, `0`, and a startup time;
  - step 3 prints `ActiveState=active`, `TasksMax=infinity`,
    `KillMode=process`, a cgroup path that ends in
    `/workspace/system.slice/codewire-daemon.service`, and `codewire`;
  - step 4 prints the same `CapBnd` value as a default sandbox does, and the
    mount fails, as it does there: systemd started without the bootstrap's
    capability;
  - step 5 prints `0::/workspace/init.scope` and a count of at least `1`.
    The container's own cgroup holds processes outside systemd's PID
    namespace, which a session sees as `0`, and the first process is one of
    them. The stop's guarantee rests on this arrangement;
  - in step 6 the workspace container is a custom image's: its command is
    the custom-image supervisor running the image's own command (`/sbin/init`)
    beside the daemon, it adds no capability, and it does not run as root. So
    systemd does not start as PID 1. No refusal names systemd workspaces.
- **Gotchas:** `systemctl is-system-running` says `starting` for the first
  moments; the create returns when the daemon is ready, which is before the
  last unit. Compare `CapBnd` with a default sandbox created on the same
  cluster, not with a number from this file. In step 6 the image's
  `/sbin/init` is not expected to get far as an ordinary workload without
  root, so the create may end as it does for any custom image whose command
  fails; record what it reports, but the proof is the Pod's spec.
- **Observed:** not yet observed.

## `systemd-workspace-refusals`: where it must not exist

- **Entry points:** `cw create --cloud --image …`.
- **States to exercise:** an organization that is not opted in; the
  repository by tag; a confidential environment; a deployment whose runtime
  is not a VM runtime; the opt-in turned off again, with a systemd workspace
  stopped before and started after; the list call from a caller who is not a
  global admin.
- **Driving it:**
  1. As the organization that is not opted in, `cw create --cloud --name
     sd-org --image IMAGE --no-profile --yes`.
  2. `cw create --cloud --name sd-tag --image REPOSITORY:latest --no-profile
     --yes`.
  3. `cw create --cloud --name sd-conf --image IMAGE --isolation
     confidential --no-profile --yes`.
  4. On a local Kind cluster whose orchestration has the setting, with the
     walking organization opted in there too, `cw create --cloud --name
     sd-runc --image IMAGE --no-profile --yes`.
  5. With the flag on, `cw create --cloud --name sd-keep --image IMAGE
     --no-profile --yes`, then `cw stop sd-keep`. With `sd` from
     `systemd-workspace-boot` running, `cw stop sd`. A global admin then
     turns the walking organization's flag off, and the walk runs
     `cw exec --in sd -- true` (refused: it is stopped), `cw start sd`, step
     1 again as that organization, and `cw rm --yes sd-keep`. Then the flag
     goes back on and `cw start sd` again.
  6. `ListSystemdOrganizations` called by a caller who is not a global admin.
- **Proof:**
  - Steps 1 to 4 are refused before any Pod exists. Step 1 says the
    organization is not opted in to systemd environments, step 2 that the
    image must be pinned by digest, step 3 that a systemd workspace cannot be
    a confidential environment, and step 4 that a systemd workspace needs a
    VM runtime. `cw ls` shows none of them.
  - In step 5, with the flag off, `cw start sd` and the create are refused
    as not opted in, and no Pod appears. `cw rm` of `sd-keep` succeeds. With
    the flag back on, `cw start sd` succeeds and `sd` is a systemd workspace
    again.
  - Step 6 is refused as not permitted.
  - The admin audit log has an `admin.organization.systemd_environments`
    entry for each change of the flag, naming the admin, the organization and
    the new value.
- **Gotchas:** step 4 is the only step a Kind cluster can run. A refusal by
  the cluster's admission, not by Codewire, is a different result: record
  which one answered.
- **Observed:** not yet observed.

## `systemd-workspace-sessions`: it behaves as a default sandbox

- **Entry points:** `cw exec`, `cw run`, `cw shell`, `cw stop --session`,
  `cw ports`, `cw cp`, `ssh cw-cloud-sd`.
- **States to exercise:** a detached named session with background children;
  stopping it; a terminal session; a fork burst; Docker.
- **Driving it:**
  1. `cw run --in sd --name web --detach -- bash -c 'python3 -m http.server
     8080 >/dev/null 2>&1 & sleep 100000'`, then `cw ls sd`.
  2. `cw exec --in sd -- curl -s -o /dev/null -w '%{http_code}\n'
     http://127.0.0.1:8080/`, then `cw ports sd --publish 8080`.
  3. `cw stop sd --session web --all`, then `cw exec --in sd -- pgrep -c
     'sleep|python3'`.
  4. `cw exec --in sd -- sh -c 'for i in $(seq 1 4000); do sleep 300 & done;
     sleep 2; pgrep -c sleep; pkill sleep'`.
  5. `cw exec --in sd -- sh -c 'sudo -n id -u; docker run --rm busybox:1.37
     echo from-docker'`.
  6. `cw setup ssh`, then `ssh cw-cloud-sd 'echo $XDG_RUNTIME_DIR; systemctl
     --user is-system-running'`.
- **Proof:** step 1 lists `web` as `Running`; step 2 prints `200` and a
  preview URL; step 3 ends the session `Stopped` and counts `0`; step 4
  prints `4000`, with no "Resource temporarily unavailable"; step 5 prints
  `0` and `from-docker`; step 6 prints `/run/user/1000` and `running`.
- **Gotchas:** in step 4 units get no controllers here, so no task limit
  applies today; the step guards against one ever capping sessions at
  systemd's default, near 15% of the sandbox's limit. Each step is compared
  with a default sandbox on the same cluster.
- **Observed:** not yet observed.

## `systemd-workspace-egress`: a broker-mode Sandbox like any other

- **Entry points:** `cw create --cloud --image IMAGE` on a deployment with
  hosted egress on.
- **States to exercise:** the create passing the cluster's broker-mode
  admission; an allowed destination; the refusals of
  [network-and-egress.md](network-and-egress.md), `hosted-enforcement`, from
  inside the systemd workspace, as the workspace user and as root.
- **Driving it:** create `sd` as in `systemd-workspace-boot`, then run
  `hosted-enforcement`'s commands with `sd` as the Sandbox, each once through
  `cw exec --in sd --` and once through `cw exec --in sd -- sudo -n`.
- **Proof:** the create succeeds and the Sandbox's traffic leaves through
  the node's egress service; every destination `hosted-enforcement` says is
  refused is refused, with the same answer as from a default Sandbox, for
  the user and for root.
- **Gotchas:** `hosted-enforcement` has no command yet (#4000); until it
  does, this step has none either. Do not stand in a hand-picked address for
  it.
- **Observed:** not yet observed.

## `systemd-workspace-user-units`: a user's own service

- **Entry points:** `systemctl --user` in any session.
- **States to exercise:** a unit started now; a unit enabled and found
  running after the sandbox is stopped and started, with nobody logged in.
- **Driving it:**
  1. `cw exec --in sd -- sh -c 'mkdir -p ~/.config/systemd/user && printf
     "[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=default.target\n"
     > ~/.config/systemd/user/keep.service && systemctl --user daemon-reload
     && systemctl --user enable --now keep.service'`.
  2. `cw exec --in sd -- systemctl --user is-active keep.service`.
  3. `cw stop sd`, `cw start sd`, then step 2 again.
- **Proof:** step 2 prints `active` both times. The second is the proof of
  lingering: the user manager started at boot with no session.
- **Gotchas:** the unit file is in the home, which is the persistent
  workspace; a unit under `/etc` is in the image and does not survive.
- **Observed:** not yet observed.

## `systemd-workspace-stop`: a stop ends it cleanly

- **Entry points:** `cw stop`, `cw rm`.
- **States to exercise:** a stop with a running named session and a user
  unit; a removal while a unit's stop never ends.
- **Driving it:**
  1. With `web` and `keep.service` running, time `cw stop sd`, then
     `cw start sd` and `cw ls sd`.
  2. In a second sandbox `sd-hang`, a system unit installed with `sudo` and
     started: `ExecStart=/bin/true`, `RemainAfterExit=yes`,
     `ExecStop=/bin/sleep 600` and `TimeoutStopSec=infinity`. Read the Pod's
     grace period from the Pod, then time `cw rm --yes sd-hang` and watch the
     Pod.
- **Proof:**
  - In step 1 the stop returns within the bound a default sandbox's stop
    has, well inside the grace period. The sandbox reads `stopped`, and after
    the start the session `web` reads `Stopped`, not `Interrupted`.
  - In step 2 the Pod is gone after the grace period and within the grace
    period plus 15 s, with no node-side help. The unit's infinite stop
    timeout overrides systemd's default, so systemd cannot finish its
    shutdown: a Pod that ends then ends by the kill. A Pod gone well before
    the grace period means the hang did not hold, and the step is redone.
- **Gotchas:** step 2 uses a system unit, as the Dev run did, so the user
  manager's own stop timeout plays no part. A Pod that stays
  `Terminating` is a failure of this journey. Record it here and on #5645, with the Pod's name, and tell
  whoever runs the Dev nodes.
- **Observed:** not yet observed.

## `systemd-workspace-rex`: `rex server install` as on any Linux machine

- **Entry points:** `rex server install ssh://cw-cloud-sd`.
- **States to exercise:** the install; the server after a stop and start;
  the connection from the computer's Rex.
- **Driving it:**
  1. `rex server install ssh://cw-cloud-sd --label sd --yes`.
  2. `cw exec --in sd -- sh -c 'systemctl --user is-enabled rex.socket;
     systemctl --user is-active rex.socket'`.
  3. `cw stop sd`, `cw start sd`, then step 2 again, then `cw exec --in sd
     -- rex server status`.
  4. `rex -S sd server status`.
- **Proof:** step 1 prints `rex.socket is listening` and `Lingering is on
  for your account`, with no warning that the host has no systemd; step 2
  prints `enabled` and `active`, before and after the restart; step 3's
  status names the socket under `/run/user/1000`; step 4 answers from the
  sandbox's server.
- **Gotchas:** step 4 needs the environment's SSH server to forward Unix
  sockets (#5608, landed in #5621). On a deployment still running a release
  without it, step 4 fails with `open failed: administratively prohibited`,
  in a default sandbox too; then record steps 1 to 3 and the release, and
  say that step 4 waits.
- **Observed:** not yet observed.
