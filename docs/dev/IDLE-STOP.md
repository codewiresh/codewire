# Idle stop

A cloud Sandbox that nobody is using stops itself after its idle timeout, so
it stops drawing credit ([BILLING.md](BILLING.md) says when a Sandbox's
charge starts and ends). The stop is the ordinary stop: its disk is kept, and
`cw start` or the dashboard's **Start** brings it back. This page is the
contract. It was written before the code (#3384), and the journey is
[`docs/journeys/idle-stop.md`](../journeys/idle-stop.md). The design and the
owner's decisions are on #3384. Local VMs and hosts don't stop themselves.

## The setting

Each Sandbox has an idle timeout, a duration from 5 minutes to 7 days, or
`off`. It is off unless someone turns it on, because a stop ends whatever was
running (owner, 2026-11-19: "not on by default. stop is pretty destructive.
maybe 6 hours default?"); turned on without a duration, it is 6 hours.

- **`codewire.yaml`:** `idle_stop: 30m`. Durations are whole days, hours,
  minutes and seconds in that order (`45m`, `6h`, `1h30m`, `7d`); `on` or
  `true` is 6 hours; `off`, `false` or `0` turns it off. The key goes to its
  own request field and column and is never stored in the project spec, so a
  rollback still reads every stored spec.
- **`cw create --idle-stop 30m|on|off`** overrides `codewire.yaml`.
- **`cw update NAME --idle-stop 30m|on|off`** changes it on a Sandbox that
  exists, running or stopped, without restarting it. A running Sandbox's
  idle clock keeps its time; the new timeout applies from the next check.
- **A fork** (`cw --cloud create --snapshot`) takes the timeout its source
  had when the snapshot was captured; `--idle-stop` at the fork overrides it.
- **API:** `CreateEnvironmentRequest.idle_stop_seconds` and
  `SetEnvironmentIdleStop`, which takes the same operator access as
  `cw extend`. `0` means off. A value outside the range is refused with
  `invalid_argument`, naming the range.
- **A create that names none** is off; a fork that names none takes its
  snapshot's.
- **`cw info`** prints `IdleStop: 30m` or `IdleStop: off` for a cloud
  Sandbox, and the dashboard's Sandbox page shows the same.

## What counts as activity

The Sandbox is active in any minute in which one of these happens:

- **CPU:** the Sandbox used at least 10% of one vCPU, 6 seconds of CPU time
  in the minute. The daemon samples the CPU every minute. A cloud Sandbox
  runs under Kata (`commodity` or `confidential`), one VM to a Sandbox, so
  the daemon reads the guest kernel's `/proc/stat` (user, nice, system, irq
  and softirq time), which counts every process in the Sandbox. That
  includes its Docker containers, which run in the `dind` container, outside
  the workspace container's own cgroup. Under `runc`, used only for
  diagnostics such as Kind, the kernel is the host's, so only the workspace
  container's own cgroup counts (`cpu.stat`, `usage_usec`), without Docker.
  An idle guest uses under 2 seconds a minute (Dev, 2026-11-21).
- **Terminal input or output:** data passes, either way, through a `cw`
  session or shell, the browser terminal, or an SSH connection's channels:
  keystrokes in, or a command's output on the way out. SSH keepalives, window
  adjustments, terminal resizes and pings carry no input or output and don't
  count. The time is recorded, never the content.
- **An agent turn or `cw` runtime request in flight.** An agent waiting on
  its model uses little CPU, and it still counts.
- **Inbound traffic:** a request the preview proxy forwards into the Sandbox,
  from anyone, a login over SSH, and a new tailnet connection. A public
  preview's visitors keep its Sandbox up, scanners included, and its owner
  pays for that time (owner, 2026-11-19: "any traffic counts").

These don't count: an attached terminal or SSH connection with no input or
output, an open preview tab that makes no requests, listing sessions,
reading logs, the dashboard showing the Sandbox, orchestration's own access
check, and traffic the Sandbox sends out, so an app polling the internet
still lets it stop. An idle shell or a forgotten tab therefore doesn't keep
a Sandbox up. The access check is the login orchestration makes, as
`codewire-access-probe`, whenever it reconciles a Sandbox's runtime.

A Sandbox is idle once no minute in its timeout was active and nothing is in
flight. A Sandbox never stops within its timeout of starting.

## Where each signal is recorded

| Signal | Recorded by | Where |
| --- | --- | --- |
| CPU | the Sandbox's daemon, each minute: the guest kernel's CPU under Kata, the workspace container's cgroup under runc | its last active minute, which it reports to the worker |
| Terminal input or output: sessions, shells, the browser terminal, SSH channels | the daemon, which carries all of them | the same last active minute |
| An SSH login or a new tailnet connection | the daemon, which accepts it | the same last active minute |
| An agent turn or `cw` runtime request | orchestration, which admits and completes them | in flight: its open row in `environment_platform_agent_requests` or `environment_cw_runtime_requests`; finished: `environments.last_activity_at`, set at completion |
| A preview request, from anyone | orchestration's preview proxy | `environments.last_activity_at`, at most once a minute per Sandbox |

A start sets `environments.last_activity_at` too.

## The stop

The orchestration worker checks every 30 seconds, in the reconciler loop that
also stops Sandboxes that run out of credit.

- **Candidates:** each running Sandbox with idle stop on, desired state
  `started`, no open agent or runtime request, and `last_activity_at` older
  than its timeout. A Sandbox with a request in flight is active now, however
  long it has waited.
- **The daemon:** the worker asks each candidate's daemon for its last active
  minute, under the daemon credential, with a 5-second timeout and a bounded
  number of calls at once, apart from the credit stop. The answer is one
  timestamp; a time in the future counts as now. Only this check reads it. A
  minute within the timeout keeps the Sandbox running.
- **A daemon that doesn't answer** keeps the Sandbox running until it has
  failed to answer for a whole timeout. After that its CPU and input are
  unknown, and the Sandbox stops if nothing the server records is active. A
  Sandbox whose daemon is gone can't be used, and the stop keeps its disk, so
  it never runs and bills without end.
- **A daemon older than idle stop** answers that it doesn't support the
  call, and its Sandbox counts as active: it isn't idle-stopped until its
  daemon is updated.
- **A daemon older than the guest CPU** (#3384, 2026-11-21) counts only the
  workspace container's CPU, so work only in Docker doesn't keep its Sandbox
  up until a start updates its daemon. The worker asks for the guest's CPU
  only when the deployment's `SANDBOX_RUNTIME_PROFILE` is `commodity` or
  `confidential`.
- **One conditional update** stops it: desired state `stopped` and stop
  reason `idle`, where the desired state is still `started`, the
  `last_activity_at` is still the value it read, and no request has opened
  since. Activity that arrives during the check wins.
- The stop is the normal stop. The Sandbox's disk, its claim and its
  Sandbox object stay, and billing closes its running session within one
  60-second poll. A stopped Sandbox draws no credit.
- A start clears the stop reason. Credit and user stops record `credit` and
  `user`.

The server switch `CODEWIRE_IDLE_STOP` turns the check on (`on`) or off
(`off`, the default), so a deployment enforces nothing until it opts in.

## What a person sees

- **`cw ls`:** STATE reads `stopped (idle)`. A credit stop reads
  `stopped (credit)`, and a person's stop reads `stopped`.
- **The words**, wherever it says why it stopped (owner, 2026-11-19), with
  the Sandbox's own timeout: "Stopped itself after 6 hours idle (CPU under
  10%, no traffic or input). Files are kept. Start it with `cw start NAME`."
- **`cw info`** prints them, with the time it stopped. **Connecting** to it
  with `cw shell`, `cw attach`, `cw run` or `ssh` refuses with them. A
  person's stop keeps today's message.
- **The dashboard:** the state pill reads **Stopped (idle)**, with the same
  words by **Start**, after the owner's "land it" for the dashboard.

## After launch

- **Wake on access:** an SSH connection, attach or signed-in preview visit
  that starts an idle-stopped Sandbox and then connects, as #3384's design
  describes.
- **A second, deeper tier** for a Sandbox idle for much longer, such as a
  day.
- **An organization default** set by owners.
