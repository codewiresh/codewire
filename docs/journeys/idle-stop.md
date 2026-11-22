# Idle stop

A cloud Sandbox that nobody uses stops itself after its idle timeout, keeps
its files, and says why it stopped (#3384). The contract is
[`docs/dev/IDLE-STOP.md`](../dev/IDLE-STOP.md). This journey was written
before the code. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-22. Walked on Dev on 2026-11-21. Not yet observed: the
agent, a gone daemon, the dashboard, the browser terminal and a signed-in
preview request.

| ID | Dev | Production |
| --- | --- | --- |
| `idle-stop-setting` | observed 2026-11-21, but the dashboard | not yet observed |
| `idle-stop-stops` | observed 2026-11-21, but the dashboard and billing | not yet observed |
| `idle-stop-busy` | observed 2026-11-21 | not yet observed |
| `idle-stop-input` | observed 2026-11-21, but the browser terminal and a signed-in preview | not yet observed |
| `idle-stop-agent` | not yet observed | not yet observed |
| `idle-stop-daemon-gone` | not yet observed | not yet observed |
| `idle-stop-off` | observed 2026-11-21 (Kind half not yet) | not yet observed |

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
- **Observed:** 2026-11-21 on Dev, services and daemon from source 8c8c32eb2, `cw` built from 253add63c, as the Dev smoke identity. Every check matched: `idle_stop: 45m`
  in `codewire.yaml` gave `IdleStop: 45m`; no setting gave `off`, and
  `--idle-stop on` then `6h`; `2m` and `8d` were refused with "must be off,
  or from 5m to 7d" and nothing was created; `cw update idle-a --idle-stop
  5m` gave `5m` with `StartedAt` unchanged (23:02:23Z); a fork of its
  snapshot gave `5m`, and a fork with `--idle-stop 1h` gave `1h`. The
  dashboard's Sandbox page is not yet observed.

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
- **Observed:** 2026-11-21 on Dev, services and daemon from source 8c8c32eb2, `cw` built from 253add63c, as the Dev smoke identity. The marker was written at 23:04:54Z and
  `StoppedAt` was 23:09:56Z (5 min 2 s), `StopReason: idle`. `cw info` gave
  the notice word for word, `cw shell` refused with the same reason and
  `→ cw --cloud start idle-stop`, and after `cw start` the marker read
  `kept` and the Sandbox was `running` with no reason. `cw ls` was read as
  JSON (`stopped`, reason `idle`), not as its text column. Not yet observed:
  the dashboard (#5511 is merged, not yet on Dev) and the billing session's
  close.

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
  (idle)`) between 5 and 6.5 minutes after the loop ends, in both runs. CPU
  is sampled once a minute and a busy minute counts from the sample that
  ends it, so the last use can read up to a minute after the loop's last
  work, and the stop comes at the next 30-second check after the timeout.
- **Observed:** 2026-11-21 on Dev, services and daemon from source 8c8c32eb2, `cw` built from 253add63c, as the Dev smoke identity. Both busy loops kept their Sandbox
  `running` for their 8 minutes. A second run timed the stop: the plain
  loop ended at 23:32:31Z and `StoppedAt` was 23:37:56Z (5 min 25 s); the
  loop in `docker run --rm alpine` ended at 23:32:34Z and `StoppedAt` was
  23:38:26Z (5 min 52 s). Both are inside the proof. It said 5.5 minutes
  at first, and the Docker stop was past that; the cause is the
  once-a-minute sample above, not Docker (#5851).

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
- **Observed:** 2026-11-21 on Dev, services and daemon from source 8c8c32eb2, `cw` built from 253add63c, as the Dev smoke identity, steps 1 and 2 over `cw shell`. A shell
  left at its prompt (opened 23:24:32Z) stopped with `StoppedAt` 23:29:49Z
  (5 min 17 s), and the shell then ended. Typing `date` every 2 minutes
  kept the Sandbox `running` for 8 minutes; the last key was at 23:32:32Z
  and `StoppedAt` was 23:37:59Z (5 min 27 s).

  Then, the same build: over `ssh` through `cw setup ssh`'s section,
  typing `date` every 2 minutes from 23:50:18Z to 23:56:18Z kept the
  Sandbox `running`, and `StoppedAt` was 00:01:31Z (5 min 13 s after the
  last key). Step 3: output every 2 minutes, last at 23:51:24Z, kept it
  up, and it stopped at 23:58:58Z, 5 min 34 s after the shell printed its
  prompt when the loop ended (23:53:24Z). Step 4: a published preview
  nobody requested stopped at 23:49:57Z, 5 min 16 s after its create (the
  detached `cw run -d` and the publish don't count); a public one curled
  anonymously every 2 minutes (each 200) stayed up and stopped at
  23:58:27Z, 5 min 14 s after the last request. Step 5: an `ssh`
  connection with keepalives every 30 seconds and no input or output,
  connected by 23:48:38Z, stopped at 23:53:27Z, and the connection then
  closed. Step 6: polling `https://example.com` every minute from a
  detached command didn't keep it up; it stopped at 23:50:28Z, 5 min 16 s
  after its create.

  Over `ssh`, the stop ended the connection with `cw shell --stdio`'s raw
  error, "daemon session stream failed: … h2 protocol error: error reading
  a body from connection … BrokenPipe", then "Connection to
  cw-cloud-idle-keep2 closed." `cw shell` in the same case says "Stopped
  itself after 5 minutes idle (CPU under 10%, no traffic or input). Files
  are kept." and `→ cw --cloud start NAME`; the `ssh` path should say the
  same. Since then (#4717), not yet observed: `cw shell --stdio` prints
  that sentence and `→ cw --cloud start NAME` on stderr when a stop ends
  the connection, after the broken-stream line, which the environment's
  SSH server sends and `ssh` prints.

  Not yet observed: the browser terminal, and a signed-in preview
  request.

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
- **Observed:** 2026-11-21 on Dev, services and daemon from source 8c8c32eb2, `cw` built from 253add63c, as the Dev smoke identity: a Sandbox created with `--idle-stop off`
  was `running` 16 minutes later. The Kind half, with the switch off, is not
  yet observed.
