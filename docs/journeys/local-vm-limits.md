# Limits inside a local VM

What a local VM does when its workload asks for more than the VM lets it
have ([LINUX-LOCAL-VMS.md](../dev/LINUX-LOCAL-VMS.md), "Limits inside a VM").
The first limit is on processes (#5384): a workload that forks without end
must be refused by the guest, not take the guest down. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-18.

| ID | Linux host | Mac |
| --- | --- | --- |
| `local-vm-fork-burst` | not yet observed; failure observed on v0.4.22, 2026-11-18 (#5384) | not yet observed |

## `local-vm-fork-burst`: a fork burst is refused and the VM stays up

- **Entry points:** `cw create --local`, then `cw exec` or a shell in the
  VM. A Docker container in the VM is a second way in, with its own share of
  the ceiling.
- **States to exercise:** a burst past the ceiling from the workspace; a
  command started while the workload is at the ceiling; the workload after
  the burst's children have ended; a burst from a Docker container, and
  that container stopped from the workspace while it is at Docker's
  ceiling; the guest's count of refusals; `cw --local restart` while at the
  ceiling.
- **Driving it:**
  1. `cw create --local --name burst --no-file --no-profile --yes`, with
     the default size (2 vCPU, 4 GiB).
  2. `cw exec --in burst -- python3 -c PROGRAM`, where the program forks up
     to 8,192 children that each sleep 30 seconds, stops at the first
     `OSError`, and prints how many children it made and that error's
     `errno`.
  3. While the children sleep: `cw ls --local`, and
     `cw exec --in burst -- true`.
  4. After they end: `cw exec --in burst -- echo after`.
  5. The same program in a container that outlives it:
     `cw exec --in burst -- docker run -d --name fork
     ghcr.io/codewiresh/workspace python3 -c PROGRAM`, then
     `cw exec --in burst -- docker logs fork`.
  6. While that container's children sleep:
     `cw exec --in burst -- docker kill fork`.
  7. The guest's counts: `cw exec --in burst -- docker run --rm --privileged
     --user 0 ghcr.io/codewiresh/workspace sh -c 'mount -t cgroup none /mnt
     && cat /mnt/workload/pids.max /mnt/workload/docker/pids.max && grep .
     /mnt/workload/pids.events /mnt/workload/workspace/pids.events
     /mnt/workload/docker/pids.events'`.
  8. Step 2 again, and while the children sleep, `cw --local restart
     burst`, then `cw exec --in burst -- echo restarted`.
- **Proof:**
  - step 2 prints fewer than 4,096 children and `errno` 11 (`EAGAIN`), and
    exits by itself;
  - step 3: `cw ls --local` shows `running`, and the `cw exec` fails at
    once saying that no process could be started, not with a timeout or a
    lost VM;
  - step 4 prints `after`; a file written to the workspace before step 2 is
    unchanged;
  - step 5's log shows fewer than 1,536 children and `errno` 11;
  - step 6 succeeds, and `docker ps` then lists no `fork`;
  - step 7 prints `4096` and `1536`, then each file's `max` count: the
    counts add up to more than zero after step 2, and to more again after
    step 5 (which of the three files counts a refusal depends on the guest
    kernel, so the proof is their sum);
  - step 8 prints `restarted`.
- **Gotchas:**
  - The children must outlive the burst, or the count never reaches the
    ceiling: 30 seconds of sleep is enough for 8,192 forks.
  - The ceilings count threads too, so a workspace already running a
    language server or a build starts nearer to them.
  - The first `docker run` pulls the image, which takes a few minutes;
    pull it before step 5 so the burst is not waiting on it.
  - Step 7 needs `--user 0`: the image's own user cannot mount.
- **Observed:**
  - Linux, v0.4.22, 2026-11-18 (#5384): failure observed, the symptom this
    journey exists for. The program had about 6,400 children alive when
    `cw exec` stopped answering; the VM turned `error` (`guest_shutdown`);
    `cw --local restart` recovered it in about 4 seconds and the workspace
    survived.
  - The steps as written: not yet observed (#5384).
