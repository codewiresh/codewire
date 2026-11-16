# Local VMs across an upgrade

A user's local VMs keep working when `cw` is upgraded to a release whose
runtime changes the guest runtime ABI: the seed format, or the network session
protocol, in the guest init's ABI marker
([SPEC.md section 5](../../SPEC.md#5-local-vms-and-trusted-hosts);
`docs/dev/CLI-ORCHESTRATION.md`, the paragraph on retained boot assets). The
format is in [README.md](README.md). Issue: #4980.

## Where it stands

Updated 2026-11-15.

| ID | Linux | macOS |
| --- | --- | --- |
| `local-vm-runtime-upgrade` | failure observed from v0.4.21 (start, restore, listing); removal observed working; not yet observed with the fix | not yet observed |

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
  - a restart whose move can't be staged leaves the VM `running`.
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
