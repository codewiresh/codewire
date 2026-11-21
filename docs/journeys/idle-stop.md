# Idle stop

A cloud Sandbox that nobody uses stops itself after its idle timeout, keeps
its files, and says why it stopped (#3384). The contract is
[`docs/dev/IDLE-STOP.md`](../dev/IDLE-STOP.md). This journey was written
before the code. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-21. Written first; every step is not yet observed.

| ID | Dev | Production |
| --- | --- | --- |
| `idle-stop-setting` | not yet observed | not yet observed |
| `idle-stop-stops` | not yet observed | not yet observed |
| `idle-stop-busy` | not yet observed | not yet observed |
| `idle-stop-input` | not yet observed | not yet observed |
| `idle-stop-agent` | not yet observed | not yet observed |
| `idle-stop-daemon-gone` | not yet observed | not yet observed |
| `idle-stop-off` | not yet observed | not yet observed |

## Before the walk

- Walk as the Dev smoke identity (`scripts/runtime/prod/with-prod-smoke-auth.sh`
  on Production), with `cw` from the build under test, and a balance above
  zero, so no credit stop interferes.
- Dev runs with `CODEWIRE_IDLE_STOP=on`. Check the orchestration pod's
  environment before the walk; with it off nothing stops and every step
  below fails for the wrong reason.
- Every step uses `--idle-stop 5m`, the shortest timeout, so a stop is due
  5 minutes after the last activity and happens within one more 30-second
  check.
- Remove each Sandbox at the end with `cw rm --yes NAME`.

## `idle-stop-setting`: the timeout is set, changed and carried to a fork

- **Entry points:** `idle_stop:` in `codewire.yaml`, `cw create --idle-stop`,
  `cw update NAME --idle-stop`, `cw --cloud create --snapshot`, `cw info`, the
  dashboard's Sandbox page.
- **States to exercise:** set in `codewire.yaml`; overridden by the flag;
  `on` (6 hours); `off`; refused below 5 minutes and above 7 days; none
  named (off); changed on a running Sandbox; inherited by a fork and
  overridden at the fork.
- **Driving it:**
  1. A `codewire.yaml` with `idle_stop: 45m`: `cw --cloud create --name
     idle-a`, then `cw info idle-a` prints `IdleStop: 45m`.
  2. `cw --cloud create --name idle-b` with no `idle_stop` prints
     `IdleStop: off`; `cw update idle-b --idle-stop on` prints
     `IdleStop: 6h`.
  3. `cw --cloud create --name idle-c --idle-stop 2m` and `--idle-stop 8d`
     are refused and name the range; nothing is created.
  4. `cw update idle-a --idle-stop 5m`: `cw info` prints `IdleStop: 5m`, and
     the Sandbox's start time is unchanged (no restart).
  5. `cw --cloud snapshot create idle-a --name idle-snap`, then `cw --cloud
     create --snapshot idle-snap --name idle-d`: `cw info idle-d` prints
     `IdleStop: 5m`. A second fork with `--idle-stop 1h` prints
     `IdleStop: 1h`.
- **Proof:** each `cw info` value above, the refusal's words, and the
  unchanged start time in step 4.
- **Observed:** not yet observed.

## `idle-stop-stops`: an unused Sandbox stops itself and says why

- **Entry points:** none: nobody uses it. Then `cw ls`, `cw info`, the
  dashboard, `cw shell`, `cw start`.
- **States to exercise:** a Sandbox nobody touches; a person's stop for
  comparison; a start afterwards.
- **Driving it:**
  1. `cw --cloud create --name idle-stop --idle-stop 5m`, then `cw run
     idle-stop -- sh -c 'echo kept > /workspace/marker'`. Note the time.
  2. Wait 6 minutes.
  3. `cw ls`: STATE is `stopped (idle)`. `cw info idle-stop` prints
     "Stopped itself after 5 minutes idle (CPU under 10%, no traffic or
     input). Files are kept. Start it with `cw start idle-stop`." and the
     time. The dashboard's pill reads **Stopped**, and the Sandbox's page
     says "Stopped after 5 minutes idle. Files are kept." by **Start**.
  4. `cw shell idle-stop` refuses with the same words.
  5. `cw start idle-stop`, then `cw run idle-stop -- cat /workspace/marker`.
- **Proof:** the stop lands between 5 minutes and 5 minutes 30 seconds after
  the last activity; `stop_reason` is `idle`; billing's running session for
  the Sandbox has closed; the marker reads `kept` after the start; and
  `cw ls` then shows `running` with no reason.
- **Gotchas:** creating the Sandbox and the `cw run` are activity; time the
  wait from the end of the `cw run`.
- **Observed:** not yet observed.

## `idle-stop-busy`: a busy Sandbox stays up

- **Entry points:** a detached `cw run`, a Docker container in the Sandbox.
- **States to exercise:** busy CPU for longer than the timeout; busy CPU
  inside a Docker container; the busy work ending.
- **Driving it:**
  1. `cw --cloud create --name idle-busy --idle-stop 5m`, then `cw run -d
     idle-busy -- sh -c 'end=$(($(date +%s)+480)); while [ $(date +%s) -lt
     $end ]; do :; done'`: about 8 minutes of one busy core.
  2. Check `cw ls` at 6 minutes: `running`.
  3. Repeat with the loop inside `docker run --rm alpine sh -c '…'`.
- **Proof:** the Sandbox is running at 6 minutes, and stops (`stopped
  (idle)`) between 5 and 5.5 minutes after the loop ends, in both runs.
- **Observed:** not yet observed.

## `idle-stop-input`: typing and previews count; an idle shell does not

- **Entry points:** `cw shell`, `ssh NAME`, the browser terminal, a preview.
- **States to exercise:** a shell left open with no input or output; a
  shell where someone types; a command printing output; an open preview tab
  with no requests; a preview getting requests, signed in and anonymous; a
  Sandbox polling the internet.
- **Driving it:**
  1. `cw --cloud create --name idle-shell --idle-stop 5m`, open `cw shell
     idle-shell`, and leave it at the prompt. Within 5.5 minutes the shell
     ends and `cw ls` shows `stopped (idle)`.
  2. Again, but type `date` every 2 minutes for 8 minutes: the Sandbox stays
     `running`. Repeat over `ssh` and the browser terminal.
  3. Again, with `cw shell` running `while :; do date; sleep 120; done`:
     output every 2 minutes keeps it running for 8 minutes.
  4. A Sandbox serving `python3 -m http.server 8080` with a preview: a tab
     left open stops it within 5.5 minutes; a signed-in request every 2
     minutes for 8 minutes keeps it running. Made public, an unauthenticated
     `curl` every 2 minutes also keeps it running.
  5. Over `ssh`, a connection left open with keepalives on
     (`ServerAliveInterval=30`) and no input or output stops within 5.5
     minutes.
  6. A detached `cw run -d -- sh -c 'while :; do curl -s https://example.com
     >/dev/null; sleep 60; done'`: polling out doesn't keep it up; it stops
     within 5.5 minutes.
- **Proof:** `cw ls` at each check, and the stop times.
- **Observed:** not yet observed.

## `idle-stop-agent`: an agent turn keeps its Sandbox up

- **Entry points:** a managed agent in the Sandbox.
- **States to exercise:** a turn that waits on its model for longer than the
  timeout.
- **Driving it:** start a managed agent turn that runs longer than 5 minutes
  with little CPU (a long model answer or a `sleep` tool call), in a Sandbox
  with `--idle-stop 5m`.
- **Proof:** the Sandbox is `running` for the whole turn, and stops within
  5.5 minutes after it ends.
- **Observed:** not yet observed.

## `idle-stop-daemon-gone`: a Sandbox whose daemon is gone still stops

- **Entry points:** none; the operator's view of the worker.
- **States to exercise:** a daemon that stops answering, with no agent
  request or preview request.
- **Driving it:** on Kind, with `--idle-stop 5m`, stop the Sandbox's daemon
  process (`kill` of the daemon in the Pod).
- **Proof:** the Sandbox keeps running for at least 5 minutes after the
  daemon's last answer, then stops with `stop_reason` `idle` within one more
  check.
- **Observed:** not yet observed.

## `idle-stop-off`: off means it never stops itself

- **Entry points:** `--idle-stop off`; the server switch.
- **States to exercise:** a Sandbox with idle stop off; a deployment with
  `CODEWIRE_IDLE_STOP=off`.
- **Driving it:** `cw --cloud create --name idle-off --idle-stop off`, then
  leave it untouched for 10 minutes.
- **Proof:** it is `running` after 10 minutes. On Kind with the switch off, a
  `--idle-stop 5m` Sandbox is also `running` after 10 minutes.
- **Observed:** not yet observed.
