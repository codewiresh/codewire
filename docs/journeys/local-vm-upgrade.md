# Local VMs across an upgrade

A user's local VMs keep working when `cw` is upgraded to a release whose
runtime changes the guest runtime ABI: the seed format, or the network session
protocol, in the guest init's ABI marker
([SPEC.md section 5](../../SPEC.md#5-local-vms-and-trusted-hosts);
`docs/dev/CLI-ORCHESTRATION.md`, the paragraph on retained boot assets). The
format is in [README.md](README.md). Issue: #4980.

## Where it stands

Updated 2026-11-17.

| ID | Linux | macOS |
| --- | --- | --- |
| `local-vm-runtime-upgrade` | observed working from v0.4.21 to v0.4.22: the moved start with its line, `cw upgrade --vms`, the guest cw, the checkpoint listing, restore and fork refusals, the disk-snapshot fork and removal; a restore before the move is served by v0.4.21 (#5243) | observed working from v0.4.21 to v0.4.22: the moved start with its line, `cw upgrade --vms`, the moved restart, the guest cw, the disk-snapshot fork and removal; with #5088, a failed move retried |
| `local-vm-upgrade-credentials` | not yet observed (#5238): failure observed from v0.4.15 to v0.4.21, 2026-11-17 | not yet observed |

## 1. `local-vm-runtime-upgrade`: an upgrade across a guest ABI change

Issue: #4980. The decision: a start moves a stopped environment onto the
installed runtime (orchestrator, 2026-11-15, recorded on #4980).

- **Entry points:** `cw upgrade`, or the installer for a named release. Then
  `cw --local start`, `cw --local ls`, `cw --local checkpoint ls`,
  `cw --local checkpoint restore`, `cw --local checkpoint rm` and
  `cw --local rm`. Local VMs have no dashboard entry point.
- **States to exercise:**
  - an environment stopped before the upgrade, then started;
  - an environment left in `error` by a start an earlier `cw` refused, then
    started;
  - an environment running at the upgrade, then stopped and started;
  - a restart of an environment running at the upgrade, and one whose move
    can't be staged (the installed runtime's image can't be fetched), which
    is refused with the VM still running;
  - a VM checkpoint taken before the upgrade: listed, restored, forked
    (`cw create --local --checkpoint`), removed;
  - a restore of that checkpoint while another environment still runs on
    the earlier `cw`: refused as a start is, naming the environment to
    stop, with the checkpoint's own environment left as it was (#5243);
  - a disk snapshot taken before the upgrade, then forked;
  - the earlier `cw` installed again, restoring that checkpoint;
  - an environment and its checkpoints removed after the upgrade without a
    start;
  - an upgrade that changes no guest ABI, which moves nothing.
- **Driving it:**
  1. With the earlier release:
     `curl -fsSL https://get.codewire.sh | sh -s -- --version vEARLIER`, then
     `cw setup --local`,
     `cw create --local --name up-walk --path-mode empty --yes` and
     `cw run --in up-walk --no-tty -- sh -c 'echo kept > /workspace/marker'`.
  2. `cw --local checkpoint create up-walk --name before`, then
     `cw --local stop up-walk`.
  3. Upgrade: `cw upgrade` to the release with the guest ABI change. Don't
     stop or kill anything by hand.
  4. `cw --local checkpoint ls` lists `before` as unrestorable, with the
     reason.
  5. `cw --local start up-walk` moves the environment and starts it. It says,
     on one line, which runtime it moved from and to, and that one VM
     checkpoint is left unrestorable. Then
     `cw run --in up-walk --no-tty -- sh -c 'cat /workspace/marker'` reads a
     file written in step 1.
  6. `cw --local checkpoint restore before --yes` is refused, saying why and
     naming `cw --local checkpoint rm before`.
  7. `cw --local checkpoint rm before` succeeds, then
     `cw --local rm up-walk --yes` succeeds.
- **Proof:**
  - the start's line names both runtimes and the count of checkpoints left
    unrestorable, and the environment is `running` afterwards with its disk's
    contents;
  - no command after the upgrade fails without saying what to do next;
  - removal works on an environment and on a checkpoint the installed runtime
    cannot run;
  - a fork of the earlier VM checkpoint is refused as its restore is, and a
    fork of the earlier disk snapshot starts on the installed runtime;
  - with the earlier `cw` installed again, before step 7, the checkpoint
    restores. Its boot assets are kept for that; the restore itself is to be
    observed;
  - a restart whose move can't be staged leaves the VM `running`;
  - while an environment still runs on the earlier `cw`, `cw --local
    checkpoint restore` is refused with the line a start gets, and nothing
    is stopped or booted (#5243);
  - in the moved VM, `cw` is the installed runtime's (`cw run --in up-walk
    --no-tty -- cw --version`): its runtime cache was rebuilt from the
    installed bootstrap. Not yet observed;
  - a moved start whose boot fails leaves the environment in `error` with the
    move still staged, and `cw --local start` boots it again, and
    `cw --local rm` removes it. Not yet observed.
- **Gotchas:**
  - A `cw` built from source has no provenance, and a newer `cw` won't drive
    a supervisor started by a source build. Walk with released builds on the
    earlier side; the later side can be a release candidate.
  - After an upgrade, the earlier supervisor keeps serving until it exits,
    so the change only shows after a reboot or the supervisor's stop. Walk
    both: straight after the upgrade, and after the earlier supervisor's
    SIGTERM.
  - A walk from a scratch `HOME` needs its `cw`'s network allowed by the host
    firewall. The installed paths are allowed; scratch copies are not.
  - A start that fails says why, with the next step, and never "lost
    contact" when the operation has a terminal result. If the supervisor
    stops after journaling the failure, `cw` asks the next one for the
    operation once and reports its failed step and reason (#5144). Only an
    operation that is still running reads "lost contact … it may still
    finish". `supervisor.log` keeps the failed supervisor's lines across
    restarts, and a supervisor that stops itself logs `supervisor_halted`
    with its reason.
- **Observed:**
  - Linux, development builds, 2026-11-15: failure observed. An environment
    and a VM checkpoint were made with #4809's `cw` and runtime (seed 10),
    then #4915's (seed 9, `net=2`) was installed with `cw setup --local
    --replace`. The restore failed with "native local supervisor operation
    failed", the start with `start_artifact`, and the removal with
    `delete_failed` (`cause=process_recovery`). The earlier side's
    supervisor had been stopped with `kill`, so the removal failure is not
    yet separated from that (#4980).
  - Linux, released v0.4.21 to a development build of #4809 (seed 10),
    2026-11-15. The earlier side made an environment and a VM checkpoint, and
    `cw setup --local --replace` installed the later runtime:
    - With nothing stopped, everything still worked, because the later `cw`
      kept talking to v0.4.21's supervisor. The supervisor protocol hadn't
      changed, and a supervisor that holds environments never exits by itself.
    - After a simulated reboot (SIGTERM to that supervisor), the later `cw`
      started its own. The restore and the start were refused as
      `start_artifact` with no next step, and `checkpoint ls` still listed
      the checkpoint as `ready`. `checkpoint rm` and `rm` both worked.
      Failure observed for the start, the restore and the listing; removal
      observed working (#4980).
  - Linux, released v0.4.21 to #5088 at e4c1a2c4d with its runtime from
    955494e45, 2026-11-16. `checkpoint ls` listed the earlier checkpoint as
    `unrestorable` with the reason. Its restore and its fork were refused,
    naming `cw --local checkpoint rm before`, and the fork of the earlier disk
    snapshot booted on the installed runtime and read the file written under
    v0.4.21. The moved start and the moved restart failed: the guest powered
    off with "native runtime bootstrap identity changed" with the installed
    catalog, and "trusted runtime launcher changed" with the earlier one. The
    guest's runtime cache on the state disk is bound to the earlier bootstrap
    and init; the move's seed field in `docs/dev/CLI-ORCHESTRATION.md`
    answers it. A failed move used
    to leave staging no operation owned, which stopped the supervisor at the
    next drain of that environment; a failed move now stays staged. Failure
    observed for the moved start and restart; listing, restore and fork
    refusals and the disk-snapshot fork observed working (#4980).
  - macOS, released v0.4.18 to #5088 at e4c1a2c4d, 2026-11-16, by cw-mac: the
    same network-step failure for a start from stopped and from `error` and
    for a restart. A `cw setup --local --replace` while v0.4.18's supervisor
    still ran a VM was refused with the next step (#2826's hand-off), as
    designed (#4980).
  - Linux, released v0.4.21 to #5088 at 292323d03 with its runtime,
    2026-11-16. After the earlier supervisor's SIGTERM, `cw --local start
    up-walk` moved the environment and booted it on the installed runtime in
    1m 25s; it read the file written under v0.4.21, and `cw --version` in the
    VM printed the installed runtime's `cw`. supervisor.log recorded
    `cw_runtime_move` with both catalogs, and the environment's binding read
    the installed catalog active and the earlier one as its rollback. The
    restart of up-run, still running on v0.4.21's runner, moved it the same
    way. `checkpoint ls` listed the earlier checkpoint as `unrestorable`; its
    restore and its fork were refused naming `cw --local checkpoint rm
    before`; the disk-snapshot fork booted on the installed runtime with the
    file; `checkpoint rm`, `snapshot rm` and `rm` of all three worked. The
    start printed no move line, though its result recorded the move: the CLI
    read it from progress updates, which never carry the finished operation.
    Observed working except the move line (#4980).
  - macOS, released v0.4.18 to #5088 at 292323d03, 2026-11-16, by cw-mac:
    with v0.4.18's supervisor still running VMs, `setup --replace` and a
    restart were refused with the next step; after stopping them through
    it, `setup --replace` was accepted. Starts of a stopped environment, one
    in `error` and one stopped from running each moved and booted (52-60 s),
    with the marker, the installed guest `cw` and the bindings as on Linux. A
    move boot failed on purpose kept the move staged, and the next start
    moved it and booted. A restart of a moved VM moved nothing. `rm` worked
    on all three. No move line, for the same reason (#4980).
  - Linux, released v0.4.21 to #5088 at be6a7e93c, 2026-11-16: one
    environment with a VM checkpoint, moved by its start after the earlier
    supervisor's SIGTERM. The start printed "! Moved up-walk to this cw's VM
    runtime (guest seed 9 to 10, net none to 2); its 1 VM checkpoint from
    before can't be restored (`cw --local checkpoint ls` lists it)", and the
    file written under v0.4.21 read back. Observed working (#4980).
  - macOS, released v0.4.18 to #5088 at be6a7e93c, 2026-11-16, by cw-mac:
    under `TERM=dumb` the start printed "+ Moved up-line to this cw's VM
    runtime (guest seed 9 to 10, net none to 2)", the form without
    checkpoints, and the marker read back. Observed working (#4980).
  - macOS 27.2.1, released v0.4.18 (guest ABI `seed=9;cw_catalog=1`, as
    v0.4.21's) to a development build of the v0.4.22 candidate df5ceafd0
    (`seed=11;cw_catalog=1;net=2`), 2026-11-17, by cw-mac. Under v0.4.18,
    up-stop was stopped with a marker and up-run left running. While v0.4.18's
    supervisor ran up-run, `setup --replace` was refused naming `cw upgrade
    --vms`; after `cw --local stop up-run` it installed the runtime.
    `cw --local start up-stop` printed "+ Moved up-stop to this cw's VM
    runtime (guest seed 9 to 11, net none to 2)" and booted in 58 s; the
    marker read back and the VM's `cw --version` was the installed build's.
    up-run moved the same way in 57 s, and its restart then moved nothing
    (7 s). supervisor.log recorded `cw_runtime_move` for both, and both
    bindings read the installed catalog active and v0.4.18's as rollback.
    The disk snapshot of the moved, stopped up-stop and its fork are in
    [snapshots-and-forks.md](snapshots-and-forks.md); `rm` of all worked.
    Observed working (#4980).
  - Linux, released v0.4.21 to released v0.4.22 with `cw upgrade --cli
    --version v0.4.22`, 2026-11-17, by cw-mac, each in a scratch `HOME` the
    installer filled. With no VM running at the upgrade: `checkpoint ls`
    listed `before` as `unrestorable`; `cw --local start up-walk` printed "!
    Moved up-walk to this cw's VM runtime (guest seed 9 to 11, net none to
    2); its 1 VM checkpoint from before can't be restored (`cw --local
    checkpoint ls` lists it)" and booted in 114 s with the marker and the
    VM's `cw v0.4.22`; restore and fork of `before` were refused naming the
    earlier guest ABI and `cw --local checkpoint rm before`; the disk
    snapshot taken under v0.4.21 forked onto v0.4.22 with the marker;
    `checkpoint rm`, `snapshot rm` and `rm` worked. With a VM still running
    at the upgrade, `upgrade` said so and named `cw upgrade --vms`; start,
    the checkpoint fork and the snapshot fork were refused naming the
    running VM, and `cw upgrade --vms` then moved both VMs
    (`cw_runtime_move` twice) in 438 s, under a host load average of 45-60.
    `cw --local checkpoint restore before` in that state was accepted and
    served by v0.4.21's supervisor on its own runtime (#5243). Observed
    working; commands and outputs on #4980, comment 112320.
  - macOS 27.2.1, released v0.4.21 to released v0.4.22 the same way,
    2026-11-17, by cw-mac. `cw --local start up-stop` printed "+ Moved
    up-stop to this cw's VM runtime (guest seed 9 to 11, net none to 2)" and
    booted in 63 s with the marker and the VM's `cw v0.4.22`. A VM running at
    the upgrade was moved by `cw upgrade --vms` in 63 s with its marker, and
    its restart then moved nothing. v0.4.21 refused a disk snapshot ("Local
    disk snapshots need a Linux host for now"); v0.4.22's of a moved VM
    worked ([snapshots-and-forks.md](snapshots-and-forks.md)). Observed
    working; commands and outputs on #4370, comment 112323.
  - Linux, released v0.4.21 to a build of `main` at 7fd4e58ee (#5258),
    2026-11-17, in a scratch `HOME`, with no credentials. Under v0.4.21,
    up-walk was given a VM checkpoint `before` and stopped, and up-run was
    left running. With the build of `main`: `cw checkpoint ls` listed
    `before`; `cw --local start up-walk` and `cw checkpoint restore before
    --yes` were both refused with "Your local VMs up-run still run on the cw
    you updated from; this cw starts and changes local VMs once they stop
    (`cw --local stop NAME`)", the restore with exit status 1; up-walk was
    still `stopped` at generation 1 and up-run `running`. Observed working
    for the restore's refusal (#5243).

## 2. `local-vm-upgrade-credentials`: credentials across an upgrade

Issue: #5238. The spec is "Credentials after an upgrade" in
`docs/dev/LINUX-LOCAL-VMS.md`.

- **Entry points:** `cw upgrade`, or the installer for a named release. Then
  `cw update --local ENV --profile`, `cw --local start`, `cw create --local
  --profile` and `cw --local stop`.
- **States to exercise:**
  - a credential service left running by the earlier release, with no VM
    running, then a start that needs a credential profile;
  - the same service still serving while a VM runs under this `cw`: the
    state of a `HOME` that passed through v0.4.21, which never replaced it.
    A create with a profile, and an update of the running VM to a profile;
  - a VM with no credential profile started while the earlier service still
    serves;
  - an upgrade between two releases with the same runner protocol, which
    replaces nothing and refuses nothing;
  - a credential service with no earlier release behind it (a fresh `HOME`).
- **Driving it:**
  - **No VM running**, the earlier release then the release under test, in a
    scratch `HOME`:
    1. With the earlier release: `cw credentials --local list`, which leaves
       its credential service running.
    2. With the release under test: `cw setup --local`, then
       `cw create --local --name up-plain --no-file --no-profile --yes`. No
       VM ran, so this replaces the service.
    3. `cw credentials --local generate ssh --name up-key`,
       `cw credentials --local --profile up set ssh up-key`, then
       `cw update --local up-plain --profile local:up --yes`: it succeeds,
       and `cw --local info up-plain` reads `running` with the profile.
  - **A VM still running**, in a second scratch `HOME`, through v0.4.21:
    4. With the earlier release (v0.4.15): `cw credentials --local list`.
       With v0.4.21: `cw setup --local` and
       `cw create --local --name up-keep --no-file --no-profile --yes`.
       v0.4.21 leaves v0.4.15's service serving.
    5. With the release under test, the key and profile of step 3, then
       `cw update --local up-keep --profile local:up --yes`: refused, naming
       up-keep to stop, and `cw --local info up-keep` still reads `running`
       at the generation it had.
    6. `cw --local stop up-keep`, then `cw --local start up-keep` and the
       update again: it succeeds.
  - **The only VM, restarted**, in a third scratch `HOME` prepared as in
    step 4:
    7. With the release under test: `cw --local restart up-keep`. It is not
       refused: the VM stops, the service is replaced, and the VM starts.
  - **A broker that cannot start**, to read the logs. In a `HOME` of the
    release under test, with a VM that has a credential profile: stop the
    VM, replace the credential service's `cw` by one whose broker ends at
    its first step (the local VM credentials smoke's way of doing it, when
    that case is written; #5220), and start the VM.
    8. `cw --local start NAME` fails. Read `logs/runner-ID.log` and the
       credential service's `logs/brokers.log`.
    9. `cw create --local --name up-fail --profile local:up --no-file --yes`
       in the same state fails; read `logs/runner-failed-create-up-fail.log`.
    10. The negative: with the credential service working again, start a VM
        that has a credential profile and end its VMM while it boots (the
        runner's own tests' way of doing it). Read `logs/runner-ID.log`.
  - Afterwards, in each `HOME`: `cw credentials --local delete up-key`, which
    also removes the key from the operating system's keyring, and
    `cw --local rm` of its VM.
- **Proof:**
  - after step 2 the credential service is the installed release's (its
    process runs the installed `cw`), and after step 3 the credential
    service's broker log has `broker_ready` for the VM's new generation;
  - step 5 changes nothing: the VM keeps running, and the message names the
    VM to stop. Where the release under test also has a newer supervisor
    protocol than v0.4.21's, the supervisor's own refusal ("still run on the
    cw you updated from") comes first and names the same stop; the proof of
    the credential check's own words is then the test
    `a_boot_another_cws_credential_service_cannot_serve_names_the_vms_to_stop`
    in `crates/codewire-cli/src/commands/credential_authority.rs`;
  - no start fails in the guest start for want of a credential broker. Where
    one does fail for another reason, the runner's log line carries the exit
    status of the helper that ended;
  - step 7 leaves the VM running on the release under test's service, with
    no refusal;
  - step 8: `cw` fails with `start_credential_broker_unavailable`, says the
    VM's credentials could not be served and names the broker log; the
    supervisor's `operation_failed` line carries `observed=` naming what
    the runner saw; the runner's `vm_start_failed` line reads
    `error_code=credential_broker_unavailable` and `broker=never`, and
    `helper_exit=` names the exit of any helper that ended; the broker
    log's `broker_not_ready` line carries the broker's
    exit status and its `stage` and `kind`, never `status=running …
    error=-`. For a broker of another runner protocol the kind is
    `runner.protocol_mismatch` with both numbers;
  - step 9: the VM is gone and `logs/runner-failed-create-up-fail.log` holds
    the failed start's lines;
  - step 10: the start fails as `vmm_exited`, with `helper_exit=` naming the
    VMM's exit, and nothing sends the user to the broker log, although the
    VM has a credential profile and no broker had connected.
- **Gotchas:**
  - The earlier side must be a released build: a `cw` built from source has
    no provenance.
  - A scratch `HOME` does not isolate the operating system's keyring
    (#5255): walk with credentials only in a private D-Bus session and
    keyring of the walk's own, as the local VM credentials smoke does
    (#5220), never against your own.
  - A first VM start from a scratch `HOME` can spend minutes in its network
    step where the host firewall has no rule for that `cw`.
- **Observed:**
  - Linux, released v0.4.15 to released v0.4.21, 2026-11-17: failure
    observed, the symptom #5238 fixes. v0.4.15's credential service was left
    running; under v0.4.21 a VM created with no profile ran. `cw update
    --local NAME --profile local:NAME --yes` failed with
    `environment_sources_guest_start_failed` and left the VM stopped; `cw
    start --local NAME` failed with `start_guest_start_failed`. The runner's
    log read `detail=guest_workspace_failed` for the first and
    `detail=egress_broker_exited guest_stage=runc_running daemon_ready=1`
    for the second. The credential service's broker log read
    `broker_not_ready … reason=lease_closed_before_ready … error=stage_runner.connect_kind_other`
    four times. v0.4.21 did not replace the service with every VM stopped.
    The same commands with v0.4.21 alone, in a fresh `HOME`, succeeded, with
    `broker_ready` after 0.2 s.
  - Linux, the same `HOME` continued with released v0.4.22, 2026-11-17:
    `cw start --local NAME` was refused with "Your local VMs NAME still run
    on the cw you updated from; this cw starts and changes local VMs once
    they stop". After `cw --local stop NAME`, `cw --local start NAME`
    replaced the credential service with v0.4.22's and the VM ran with its
    profile. Observed working for that pair of releases; the steps as
    written, and the logs' lines, are not yet observed (#5238).
  - Step 8's lines, by another road, Linux, 2026-11-18, a `cw` built from
    the change that adds them (recorded on #5238): the credential service
    was started from one copy of `cw`, that copy was removed, and a VM with
    a profile was started with an identical copy at another path, so the
    service could start no broker. `cw start` failed after 40 s with
    `start_credential_broker_unavailable` and the words naming the broker
    log. The runner's line read `error_code=credential_broker_unavailable
    detail=network_worker_exited guest_stage=runc_running daemon_ready=1
    helper_exit=code_37_network_worker_frame_io broker=never`, the
    supervisor's `observed=network_worker_exited`, and the broker log
    `broker_spawn_failed`. With the copy put back, the next start ran.
  - Steps 7 to 10 as written, an upgrade between two releases, and their
    proofs: not yet observed (#5238 part 3).
