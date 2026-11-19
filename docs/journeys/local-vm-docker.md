# Docker in a local VM

Docker inside a local VM ([LINUX-LOCAL-VMS.md](../dev/LINUX-LOCAL-VMS.md),
"Docker in a VM"): the guest runs its own Docker daemon, and what a user does
with `docker` there behaves as it does anywhere. The first journey is
`docker exec` (#5418), which entered the guest's root instead of the
container's. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-19.

| ID | Linux host | Mac |
| --- | --- | --- |
| `local-vm-docker-exec` | observed working with #5485, 2026-11-19, steps 2–4 and 6, step 5 partly; failure observed on v0.4.22 and `main` at b5aea6404 (#5418) | partly observed with #5485, 2026-11-19: steps 2–4, step 5 partly |

## `local-vm-docker-exec`: `docker exec` runs in the container

- **Entry points:** `docker exec` from `cw exec` or a shell in a VM created
  with Docker (the default).
- **States to exercise:** a fresh container; what the exec sees of the
  guest; a write from the exec; a `--restart=always` container after the VM
  is stopped and started.
- **Driving it:**
  1. `cw create --local --name dk --no-file --no-profile --yes`, then
     `cw exec --in dk -- sh -c 'echo workspace-marker >
     /workspace/workspace/marker'`.
  2. `cw exec --in dk -- docker run -d --name beat --user 0
     ghcr.io/codewiresh/workspace sh -c 'while true; do date +%s >
     /heartbeat; sleep 1; done'`.
  3. `cw exec --in dk -- docker exec beat cat /heartbeat`, twice, two
     seconds apart.
  4. `cw exec --in dk -- docker exec beat sh -c 'echo from-exec >
     /written-by-exec'`, then `cw exec --in dk -- docker diff beat`.
  5. `cw exec --in dk -- docker exec beat sh -c 'ls -d /state /generation
     /run/codewire /dev/vsock; cat /workspace/workspace/marker; ls /proc |
     grep -c "^[0-9]"; tr "\0" " " < /proc/1/cmdline'`.
  6. `cw exec --in dk -- docker run -d --restart=always --name keep --user 0
     ghcr.io/codewiresh/workspace sh -c 'while true; do date +%s >
     /heartbeat; sleep 1; done'`, then `cw --local stop dk`,
     `cw --local start dk`, `cw exec --in dk -- docker ps`, and step 3's
     command for `keep`.
- **Proof:**
  - step 3 prints two numbers, the second larger;
  - step 4's `docker diff` lists both `A /heartbeat` and
    `A /written-by-exec`: the exec's write is in the container's own layer,
    beside what its main process wrote;
  - step 5 says each of the four paths does not exist and the marker does
    not exist, counts a handful of processes, and prints the container's
    own command as PID 1, not `/init`;
  - step 6: `docker ps` shows `keep` up with the ID it had, and the two
    numbers advance.
- **Gotchas:**
  - The first `docker run` pulls the image, which takes a few minutes.
  - `--user 0`: the workspace image's own user cannot write to `/`.
  - A container name needs at least two characters.
  - `docker run` was never wrong, so a check made with `docker run` alone
    proves nothing here.
- **Observed:**
  - Linux, a `cw` built from `main` at b5aea6404, 2026-11-19 (#5418):
    failure observed. `docker diff` listed `A /heartbeat` and
    `docker exec beat cat /heartbeat` said "No such file or directory";
    step 5 found `/state`, `/generation`, `/run/codewire`, `/dev/vsock` and
    the workspace marker, counted 96 processes and printed `/init`; and
    after a stop and start the same `cat` in a `--restart=always` container
    failed the same way. A fresh `docker run` in that VM saw none of those
    paths and four processes.
  - Linux and macOS 27.2.1 (M3), a runtime built from main with #5485
    and #5483 (scratch merge 8597d9f4ac), 2026-11-19 (#5418), observed
    working:
    - step 2 with `alpine:3.22` on Linux, and with the workspace image on
      the Mac; `docker diff` listed `A /heartbeat`;
    - step 3, once: `docker exec exec-root cat /heartbeat` printed the
      time (`1795092078` on Linux, `1795092323` on the Mac);
    - step 4: `docker diff` listed `A /written-by-exec` and
      `A /heartbeat`;
    - step 5, partly: `ls -d /state /generation /workspace /run/codewire
      /dev/vsock` said each does not exist, and on Linux the exec counted 5
      processes; the marker and PID 1's command were not checked;
    - step 6, on Linux only: after `cw --local stop` and `start`, the
      `--restart=always` container kept its ID and `docker exec` read its
      heartbeat (`1795092102`).
