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
  An idle guest uses under 2 seconds a minute (Dev, 2026-11-21). A busy
  minute counts from the sample that ends it, so when CPU was the last
  use, the recorded time can be up to a minute after the work stopped, and
  the stop comes up to a minute later than the timeout alone says (#5851).
- **Terminal input or output:** data passes, either way, through a `cw`
  session or shell, the browser terminal, or an SSH connection's channels:
  keystrokes in, or a command's output on the way out. SSH keepalives, window
  adjustments, terminal resizes and pings carry no input or output and don't
  count. The time is recorded, never the content.
- **An agent turn or `cw` runtime request in flight.** An agent waiting on
  its model or a long tool uses little CPU and writes nothing, and it still
  counts: while a managed agent's turn runs, its driver writes the fixed line
  `cw agent driver: turn running` once a minute, which is session output
  (#5897). One turn stops counting after 24 hours, so a hung agent can't
  hold its Sandbox up for ever. A message's request counts while it is
  delivered.
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

Activity only defers idle stop. The credit and spend stops, a Sandbox's
lifetime, and an administrator's or organization's suspension apply whatever
the Sandbox or its agent is doing.

## Where each signal is recorded

| Signal | Recorded by | Where |
| --- | --- | --- |
| CPU | the Sandbox's daemon, each minute: the guest kernel's CPU under Kata, the workspace container's cgroup under runc | its last active minute, which it reports to the worker |
| Terminal input or output: sessions, shells, the browser terminal, SSH channels | the daemon, which carries all of them | the same last active minute |
| An SSH login or a new tailnet connection | the daemon, which accepts it | the same last active minute |
| A managed agent's turn | the agent driver in the Sandbox, as session output the daemon carries | the same last active minute, once a minute while the turn runs, for at most 24 hours of one turn |
| A message's delivery, or a `cw` runtime request | orchestration, which admits and completes them | in flight: its open row in `environment_platform_agent_requests` or `environment_cw_runtime_requests`; finished: `environments.last_activity_at`, set at completion |
| A preview request, from anyone | orchestration's preview proxy | `environments.last_activity_at`, at most once a minute per Sandbox |

A start sets `environments.last_activity_at` too.

## The stop

The orchestration worker checks every 30 seconds, in the reconciler loop that
also stops Sandboxes that run out of credit.

- **Candidates:** each running or `suspended` Sandbox with idle stop on,
  desired state `started`, no open agent or runtime request, and
  `last_activity_at` older than its timeout. A suspended Sandbox's
  `last_activity_at` doesn't move while it sleeps, so its suspended time counts
  toward idle stop. A Sandbox with a request in flight is active now, however
  long it has waited.
- **A suspended candidate** is stopped without the daemon call below, since
  that call would wake it and nothing in the VM can have run: the stop wakes
  the VM first, so the guest shuts down cleanly, then stops it as usual.
- **The daemon:** the worker asks each running candidate's daemon for its last active
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
With it off, a server still accepts and keeps a Sandbox's timeout, and says
it doesn't enforce it: an environment's `idle_stop_enforced` is false,
`cw info` prints `IdleStop: 30m (not enforced on this server)`, and `cw
create` and `cw update` with a timeout add "This server doesn't stop idle
Sandboxes: the timeout is kept, but not enforced." A timeout is never
refused for it, since `idle_stop` in `codewire.yaml` rides on every create.

## Suspend (`standard` only; target, not shipped, #5529)

A Sandbox on the `standard` runtime profile can **suspend** before it stops:
its VM pauses inside its Pod, keeping every process, open file and
connection, and uses no CPU. Any use resumes it in milliseconds. This is not
the stop above, and not a scale-down: the Pod, its volume, its address and
its tailnet identity stay. `commodity` and `confidential` (Kata) Sandboxes
never suspend. **Hibernate** (the VM's memory written to the volume and the
Pod deleted) comes later, as `idle_hibernate`, at 6 hours.

### The setting

`idle_suspend` works as `idle_stop` does, beside it: a duration from 5
minutes to 7 days, or `off`. It is off unless someone turns it on (owner,
2026-11-24: "off by default with idle_suspend and later idle_hibernate after
6 hours, just like idle_stop"); turned on without a duration, it is 15
minutes (owner, 2026-11-21, #5484: suspend "after 15 minutes idle"), as
`idle_stop` turned on is 6 hours.
- **`codewire.yaml`:** `idle_suspend: 15m`.
- **`cw create --idle-suspend 15m|on|off`** and
  **`cw update NAME --idle-suspend 15m|on|off`**.
- **API:** `CreateEnvironmentRequest.idle_suspend_seconds` and
  `SetEnvironmentIdleSuspend`, with the same access, range and refusals as
  the idle stop's. Setting it on a Sandbox whose recorded runtime profile
  isn't `standard` is refused with `failed_precondition`, naming why.
- **`cw info`** prints `IdleSuspend: 15m` or `IdleSuspend: off`.

Idle stop keeps its own clock. A suspended Sandbox that reaches its idle
stop timeout is stopped as above, and the stop resumes the VM first so the
guest shuts down cleanly.

### The suspend

- **Candidates:** the same check as the stop's, every 30 seconds, for a
  running `standard` Sandbox with `idle_suspend` on and activity older than
  its suspend timeout.
- **The ask:** the worker asks the daemon to suspend, under the daemon
  credential the activity check uses. The daemon closes its platform
  connections whose far end sends periodic traffic (the coordinator, the DERP
  relay, the credential relay's epoch), so that traffic can't wake it,
  acknowledges, and asks the supervisor on host vsock port 7784
  (`suspend\n`, answered `ok\n` or `no\n`). The supervisor answers, then
  freezes the workload through PID 1's checkpoint hook and pauses the VM; a
  VM already paused answers `no`, and a freeze that fails leaves it running.
  The acknowledgement moves the Sandbox to `suspended`.
- **Kubernetes sees no change.** On `standard` the readiness file is the
  supervisor's, so the Pod stays Ready while the VM is paused.
- **The wake is the supervisor's, never the guest's.** Nothing the guest
  sends resumes it. It wakes on:
  - **A connection accepted on the Pod's 7777 or 2222**, which every
    orchestration path uses (previews, sessions, agents, the browser
    terminal, the SSH fallback). It is also orchestration's explicit wake: a
    connection to the Pod's 7777. The coordinator asks orchestration for one
    when it authorizes a hello naming a suspended Sandbox. The connection
    reaches the guest only once the VM runs again.
  - **A stop.** SIGTERM, including idle stop's, wakes a paused VM first, so
    the guest shuts down cleanly.
  - **Inbound bytes on a platform connection the network worker relays:**
    not yet built. It is a worker protocol change, its own change. The
    daemon closes every platform connection whose far end sends periodic
    traffic before the pause (the table below), so what's left is
    `cw-egress` return data, which the netstack's 120 s idle timeout bounds.
- **On resume,** in order:
  1. **The vCPUs resume** while the workload is still frozen.
  2. **The tokens the kubelet renewed during the pause are delivered,** as
     the first exchange after the resume: a paused guest can't receive them.
     The hosted daemon runs outside the frozen workload, so in the
     milliseconds before they land it could redial `cw-egress` with its old
     token. `cw-egress` then refuses that one Admit, and the daemon retries
     with the token file it rereads, within `cw-egress`'s start limit (10 per
     60 s per Pod IP).
  3. **The workload thaws.** A Linux guest keeps time through a pause on
     kvm-clock (observed right to the second after 150 s), so the supervisor
     doesn't step it; only a macOS guest's thaw carries the host's clock.
  4. **The waking connection goes through,** and the daemon redials its
     platform connections and reports the wake, which moves the Sandbox back
     to `running`.
- **Billing:** a suspended second costs 0 until the owner sets a suspended
  rate in the admin panel's prices (#5782). A second counts as suspended only
  between the supervisor's record of a pause and its record of the resume,
  never from the daemon's acknowledgement or anything else the guest says.
  - **The record** is the runtime's own Pod log line, one per pause or
    resume:
    `standard runtime: vm-pause-record {"event":"paused"|"resumed","generation":G,"sequence":N,"at_unix_ms":T}`.
    The generation is the boot, and the sequence counts that boot's records
    from 1, so a missing record shows. The guest can't forge one: guest
    output reaches the Pod log only escaped and prefixed `guest-daemon: `, so
    no guest byte can start a line with the record's marker.
  - **Orchestration reads it in part 3,** through the Kubernetes API, which
    needs `pods/log` read for `standard` Pods. A record lost to the kubelet's
    log rotation is billed as running.
  - Acknowledged but no pause recorded: the Sandbox shows `suspended` and is
    billed as running.
  - A wake whose resume was never reported: billing reads the supervisor's
    record when the Sandbox is next seen, and charges `running` for any time
    the record doesn't cover.

### Calls that must not wake a suspended Sandbox

One periodic call that reaches the guest keeps every Sandbox awake, so each
is listed here with how it treats a `suspended` Sandbox. A new periodic call
into a Sandbox adds its row.

| Call | Where | Reaches the guest? | While suspended |
|---|---|---|---|
| Liveness loop, every 5 s | `crates/codewire-orchestration/src/worker/loops.rs` (`SANDBOX_LIVENESS_INTERVAL`), via `RuntimeDriver::probe` → `probe_environment` | No: it reads the Pod and claim from the Kubernetes API | Treats `suspended` with a Ready Pod as healthy |
| Kubelet startup and readiness probes | `sandbox/template/workspace.rs` (`apply_daemon_ready_probes`: `test -f /codewire/run/daemon/ready`) | No: on `standard` the file is the runtime container's | Unchanged; the file stays |
| Idle activity check, every 30 s | `worker/idle_stop.rs` (`environment_daemon_activity_for_worker`) | Yes, the daemon over 7777 | Never asks a `suspended` Sandbox's daemon. While suspended, `last_activity_at` doesn't move (nothing runs), so the time counts toward idle stop: a suspended Sandbox is a stop candidate like a running one, and is stopped without the daemon call (see "The stop") |
| Credential relay epochs, reconcile every 1 s, epoch at most 600 s | `worker/credential_relay.rs` (`daemon_target`, `RECONCILE_INTERVAL`), `credential_relay/epoch.rs` (`EPOCH_MAX_LIFETIME`) | Yes, the daemon over its cluster Service | Opens no epoch for a `suspended` Sandbox; the daemon closed its own before the pause |
| Coordinator session heartbeat, every 15 s | `crates/codewire-coordinator/src/lib.rs` (`COORDINATE_HEARTBEAT_INTERVAL`), `session.rs` | Yes, over the daemon's coordinator session | The daemon closes that session before the pause; a hello naming the Sandbox wakes it through orchestration |
| DERP relay traffic to the daemon | `crates/codewire-derp` | Yes, over the daemon's relay connection | The daemon closes it before the pause and redials at the wake |
| `cw-egress` stream for broker mode | `crates/codewire-egress-node` | Yes, the admitted stream | Kept: `cw-egress` has no keepalive, idle timer or read deadline after the hello, and the stream's TCP peer is the Pod runtime's worker (it dials 8089 from the Pod's namespace), which keeps acknowledging while the VM is paused. Between that socket and the guest, though, the worker's user-space TCP stack (`codewire-netstack`) aborts a connection whose peer answers nothing for `tcp_idle_timeout` (120 s). It sends a keep-alive every 30 s (#6399), so a live but idle guest answers and keeps its connections; a paused guest can't answer, so a pause longer than about 2 minutes ends the stream, and the daemon redials at the wake; open workload connections through egress reset once. A shorter pause resumes on the old stream. The stream also ends on a `cw-egress` drain or an assignment change. The daemon handles both resuming on the old stream and redialing. Before the VM resumes, the supervisor writes the current egress token at the daemon's token path, since a pause of more than about 10 minutes outlives the copy the guest holds and a redial with it fails admission. Each redial counts against `cw-egress`'s start limit (10 per 60 s per Pod IP); a newer admitted stream replaces an older one for the same Pod |
| Kubelet token rotations | the Pod's projected tokens | No: the supervisor reads them | The supervisor holds each renewed token and delivers it at the wake |
| Billing sessions, every 60 s | `worker/billing_sessions.rs` | No: database and Kubernetes only | Counts suspended seconds from the supervisor's record |
| Setup, resize and app-port pushes | `worker/setup.rs`, `worker/resize.rs` | Yes, but only for a person's action or a create | A person's action wakes it, which is intended |

## What a person sees

- **`cw ls`:** STATE reads `stopped (idle)`. A credit stop reads
  `stopped (credit)`, and a person's stop reads `stopped`.
- **The words**, wherever it says why it stopped (owner, 2026-11-19), with
  the Sandbox's own timeout: "Stopped itself after 6 hours idle (CPU under
  10%, no traffic or input). Files are kept. Start it with `cw start NAME`."
- **`cw info`** prints them, with the time it stopped. **Connecting** to it
  with `cw shell`, `cw attach`, `cw run` or `ssh` refuses with them. A
  person's stop keeps today's message.
- **The dashboard:** the state pill reads **Stopped**, as for any stop. The
  Sandbox's page says, by **Start**: "Stopped after 6 hours idle. Files are
  kept."

## After launch

- **Wake on access:** an SSH connection, attach or signed-in preview visit
  that starts an idle-stopped Sandbox and then connects, as #3384's design
  describes.
- **A second, deeper tier** for a Sandbox idle for much longer, such as a
  day.
- **An organization default** set by owners.
