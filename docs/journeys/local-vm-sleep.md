# Local VM sleep

This journey proves that local VMs on Linux support `cw suspend`, `cw resume`,
`cw hibernate`, wake-on-access, idle suspend/hibernate with active-work guards,
and clean cold-boot fallback on unrestorable memory images. The contract is
[`docs/dev/LOCAL-VM-SLEEP.md`](../dev/LOCAL-VM-SLEEP.md), and `SPEC.md` names
it under "5. Local VMs and trusted hosts" → "Sleep". Issue `#5529`. The format
is in [README.md](README.md).

Every step is written before the local implementation lands (`AGENTS.md`,
"Done means observed working") and starts as "not yet observed".

## Where it stands

Updated 2026-11-28.

| ID | Linux host | Mac |
| --- | --- | --- |
| `sleep-by-hand` | not yet observed | does not apply: Linux only (`#5529`) |
| `sleep-wake-on-access` | not yet observed | does not apply: Linux only (`#5529`) |
| `sleep-hibernate` | not yet observed | does not apply: Linux only (`#5529`) |
| `sleep-idle-policy` | not yet observed | does not apply: Linux only (`#5529`) |
| `sleep-restore-fallback` | not yet observed | does not apply: Linux only (`#5529`) |

## Before the walk

- Use a built `cw` and a local VM runtime from the same source on an x86_64
  Linux host with KVM, in an isolated `HOME` / `CODEWIRE_NATIVE_STATE_ROOT`.
- Record the host's load average alongside each suspend/resume/hibernate/restore
  timing.
- The examples call the VM `nap` (created with `--no-file --no-profile --yes`).
- Background counter session for proving process continuity:
  `cw --local run --in nap --name counter -- sh -c 'i=0; while :; do i=$((i+1)); echo $i > /tmp/count; sleep 0.1; done'`
  (detached). It writes no terminal output and uses well under 10% of one CPU.
  A sleeping VM's counter pauses; a resumed or restored VM's counter continues
  from where it stopped; a cold-booted VM has no counter running.
- Run `cw setup ssh` once if testing SSH aliases (`cw-local-nap`).

## `sleep-by-hand`: explicit `cw suspend`, `cw resume`, `cw hibernate`, and `cw start`

- **Entry points:** `cw --local suspend`, `cw --local resume`,
  `cw --local hibernate`, `cw --local start`, `cw --local stop`, `cw --local rm`,
  `cw --local ls`, `cw --local info`.
- **States to exercise:** running → suspended → idempotent second suspend →
  resumed → idempotent second resume → hibernated → idempotent second hibernate
  → started; stopping a hibernated VM; removing a hibernated VM; refusing
  suspend/resume/hibernate on a stopped VM.
- **Driving it:**
  1. Create `nap` and start the `counter` session. Note `/tmp/count` and the VM
     PID.
  2. Run `cw --local suspend nap`, then `cw --local suspend nap` again, then
     `cw --local ls` and `cw --local info nap`.
  3. Wait 5 seconds, then run `cw --local resume nap`, then
     `cw --local resume nap` again, and read `/tmp/count` twice via
     `cw --local exec --in nap -- cat /tmp/count`.
  4. Run `cw --local hibernate nap`, then `cw --local hibernate nap` again,
     check `cw --local ls`, `cw --local info nap`, and confirm the Cloud
     Hypervisor PID is gone and host free RAM increased.
  5. Run `cw --local start nap`, then check `/tmp/count` and guest clock vs
     host clock (`date +%s`).
  6. Run `cw --local suspend nap`, then `cw --local hibernate nap` directly from
     `suspended`, then `cw --local stop nap`, then `cw --local start nap` and
     check whether `counter` is running.
  7. Run `cw --local stop nap`, then try `cw --local suspend nap`,
     `cw --local resume nap`, and `cw --local hibernate nap`.
  8. Start `nap`, `cw --local hibernate nap`, then `cw --local rm nap --yes`.
- **Proof:**
  - step 2: `cw ls` shows `suspended` (JSON `"state": "suspended"`); second
    suspend exits 0 saying already suspended; `cw ls` and `cw info` do not wake
    the VM;
  - step 3: `cw resume` restores `running` in milliseconds; second resume exits
    0 saying already running; `/tmp/count` paused during suspend and resumes
    incrementing with the same VM PID;
  - step 4: `cw ls` shows `hibernated` (JSON `"state": "hibernated"`); second
    hibernate exits 0 saying already hibernated; VMM process is gone;
  - step 5: `cw start` restores `running`; `/tmp/count` continues from its
    pre-hibernate value; guest clock is within 1 second of host clock;
  - step 6: hibernating a suspended VM succeeds; `cw stop` on a hibernated VM
    discards the memory image and lands in `stopped`; subsequent `cw start`
    cold-boots with no `counter` session;
  - step 7: all three refuse cleanly on a `stopped` VM;
  - step 8: `cw rm` removes the hibernated VM and its memory file without
    waking it.
- **Gotchas:** avoid running `cw exec` while verifying `suspended`/`hibernated`,
  since `cw exec` wakes the VM.
- **Observed:** not yet observed.

## `sleep-wake-on-access`: automatic wake on `cw run`, `cw shell`, `cw exec`, `ssh`, and host ports

- **Entry points:** `cw --local run`, `cw --local shell`, `cw --local exec`,
  `ssh cw-local-nap`, and a published host port (`cw --local ports`).
- **States to exercise:** wake from `suspended` and wake from `hibernated` via
  each access path, plus concurrent connections during one restore.
- **Driving it:**
  1. Start `nap` with the `counter` session and a guest HTTP server on port
     `8000` published with `cw --local ports nap --publish 8000`.
  2. `cw --local suspend nap`, then run `cw --local exec --in nap -- cat /tmp/count`.
  3. `cw --local suspend nap`, then run `cw --local run --in nap --name ping -- echo ok`.
  4. `cw --local suspend nap`, then run `cw --local shell nap` (or `ssh cw-local-nap true`).
  5. `cw --local suspend nap`, then `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/`.
  6. Repeat wake checks from `hibernated`: `cw --local hibernate nap`, then wake
     with `cw --local exec`, `cw --local run`, `cw --local shell` / `ssh`, and
     two simultaneous requests to `http://127.0.0.1:8000/`.
- **Proof:**
  - every access path wakes `nap` back to `running` and completes without
    requiring a manual `cw resume` or `cw start`;
  - `counter` continues across every wake;
  - simultaneous requests during a single hibernate restore both return `200`
    after a single restore.
- **Gotchas:** wait for any previous session's output to quiet if testing with
  idle timers enabled.
- **Observed:** not yet observed.

## `sleep-hibernate`: memory reclamation, mounted folders, Docker, and supervisor restart

- **Entry points:** `cw --local hibernate`, `cw --local start`,
  `cw --local info`.
- **States to exercise:** default direct mount (`--path-mode mount`), isolated
  workspace (`--path-mode empty`), running Docker container across hibernate,
  hibernated VM surviving supervisor restart, and insufficient disk space.
- **Driving it:**
  1. Create `nap`, write `/workspace/keep.txt`, start `counter` and a Docker
     container (`docker run -d --name web nginx` or `busybox sleep 3600`).
  2. Record host free memory and VMM RSS, then `cw --local hibernate nap`.
  3. Confirm VMM PID is gone, free memory increased, and `cw --local info nap`
     reports the memory image size on disk.
  4. Restart the local supervisor while `nap` is `hibernated` (no running VMs),
     then `cw --local ls` and `cw --local start nap`.
  5. Verify `/workspace/keep.txt`, `/tmp/count`, guest `date +%s`, and
     `docker ps`.
  6. Repeat steps 1 to 3 and 5 with `--path-mode empty`.
- **Proof:**
  - VMM process exits and RAM is returned to the host;
  - `hibernated` state survives supervisor restart;
  - after restore, `/workspace/keep.txt`, `counter`, guest clock, and the
    Docker container are all intact.
- **Gotchas:** pull any Docker image before hibernating so image pull traffic
  does not interfere with timing.
- **Observed:** not yet observed.

## `sleep-idle-policy`: `--idle-suspend`, `--idle-hibernate`, and active-work guards

- **Entry points:** `cw create --local --idle-suspend … --idle-hibernate …`,
  `cw update NAME --idle-suspend … --idle-hibernate …`, and `codewire.yaml`
  (`idle_suspend`, `idle_hibernate`).
- **States to exercise:** idle VM auto-suspending then auto-hibernating;
  updating timeouts without waking/restarting; rejecting
  `idle_hibernate <= idle_suspend`; busy VM (CPU burn, session output, active
  agent turn, inbound port traffic) never put to sleep; outbound-only polling
  still allowed to sleep.
- **Driving it:**
  1. Try `cw create --local --name bad --idle-suspend 10m --idle-hibernate 10m --no-file --no-profile --yes`.
  2. Create `nap` with `--idle-suspend 5m --idle-hibernate 10m` (or short
     override in test harness where configured), check `cw --local info nap`,
     and leave it idle with `counter` running.
  3. Poll `cw --local ls` (without waking `nap`) past the suspend timeout and
     then past the hibernate timeout.
  4. Wake `nap`, start a CPU-busy session
     (`cw --local run --in nap --name burn -- sh -c 'while :; do :; done'`),
     and observe `cw --local ls` past the suspend timeout. Stop `burn`.
  5. Start a session that prints periodically (simulating an active turn
     heartbeat: `cw --local run --in nap --name turn -- sh -c 'while :; do echo "cw agent driver: turn running"; sleep 30; done'`),
     and observe `cw --local ls` past the suspend timeout. Stop `turn`.
  6. Update with `cw --local update nap --idle-suspend off --idle-hibernate off`
     and confirm `nap` stays `running` past the previous timeout.
- **Proof:**
  - step 1 is refused naming both `idle_suspend` and `idle_hibernate`;
  - step 3 transitions `running` → `suspended (idle)` → `hibernated (idle)`
    automatically;
  - steps 4 and 5 stay `running` the entire time (active build/turn never put
    to sleep);
  - step 6 updates `IdleSuspend: off` / `IdleHibernate: off` without restarting
    `nap`, and `nap` stays `running`.
- **Gotchas:** remember to stop each busy session before measuring the next
  idle window.
- **Observed:** not yet observed.

## `sleep-restore-fallback`: unrestorable memory image cold-boots cleanly with notice

- **Entry points:** `cw --local start`, `cw --local resume`, wake-on-access
  (`cw --local exec`), and `cw --local info`.
- **States to exercise:** truncated/corrupted hibernate memory file and
  mismatched hibernate metadata (e.g., altered `vmm_sha256` or consumed
  generation).
- **Driving it:**
  1. Create `nap`, write `hello-fallback` to `/workspace/fallback-check.txt`,
     start `counter`, and run `cw --local hibernate nap`.
  2. Corrupt/truncate the VM's hibernate `memory-ranges` file under the state
     root (`vms/<id>/checkpoints/in/memory-ranges`).
  3. Run `cw --local start nap` (or wake with `cw --local exec --in nap -- cat /workspace/fallback-check.txt`).
  4. Inspect `cw --local info nap`, `cw --local ls`,
     `/workspace/fallback-check.txt`, and whether `counter` is running.
  5. Repeat with a tampered `hibernate/record.json` (`vmm_sha256` mismatch).
- **Proof:**
  - step 3 does not strand the VM: it deletes the unusable hibernate image,
    cold-boots `nap` cleanly from its disks, and prints a clear fallback notice
    naming the reason (`damaged-memory-file` / `vmm-digest-mismatch`) and
    stating that running processes were lost while files were kept;
  - step 4: `cw ls` shows `running`; `cw info` surfaces the fallback notice;
    `/workspace/fallback-check.txt` still contains `hello-fallback`; `counter`
    is no longer running; a subsequent `cw --local stop nap && cw --local start nap`
    clears the fallback notice.
- **Gotchas:** make sure the file write in step 1 is synced before hibernating
  (the hibernate hook flushes guest disks automatically).
- **Observed:** not yet observed.
