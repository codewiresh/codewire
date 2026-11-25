# Interruptions

A running cloud Sandbox can be restarted, stopped, cut off from the network,
or disconnected from its user (#6084). This file is the index of those paths
as a user sees them. For each, it names the journey that proves what the user
is told, and the issue for any gap. A path with no journey of its own gets an
ID here. The row numbers (R, S, N, D) are the survey's, recorded on #6084, so
that each path can be traced to its cause and guard. Local VMs are left to
their own journeys. The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-24. Observations stay in the journeys each row points to.
None of the IDs this file owns is observed yet.

| Path | Survey rows | What the user sees today | Journey | Gap |
| --- | --- | --- | --- | --- |
| A Pod deleted, failed or replaced from outside | R1, R2, R4, R15, R16, R17 | the unplanned-restart notice, for R1 and R2 | `sandbox-unplanned-restart` ([cloud-sandbox.md](cloud-sandbox.md)) | #5997, #6104 (R4, R15 record no cause), #6105 (the cause's wording), #5384 (R16) |
| A node lost, or rebooted without a drain | R3, R21 | an `error` with internal text | `reboot-restart-notice` ([node-reboot.md](node-reboot.md)) | #6104 (`node_lost` is never written), #6106 (the disk is lost with the node) |
| A node drained or under pressure | R18, R19 | the notice, after the fact only | `reboot-restart-notice` ([node-reboot.md](node-reboot.md)) | #6097 (no notice beforehand) |
| A release or a credential change restarts the Sandbox | R5–R9 | a notice blaming "credentials or settings" | `interrupt-release-keeps-pod`, below | #6095, #6093, #6105 |
| The daemon restarts in place | R30, D12 | sessions end `Interrupted`; no restart is recorded | `interrupt-daemon-restart`, below | #6096 |
| Idle stop | S1, D13 | `stopped (idle)`, after the fact | `idle-stop-stops` ([idle-stop.md](idle-stop.md)) | #6109 (no warning beforehand) |
| A member stops or deletes it | S2, S3 | the person who did it | `sandbox-stop-start` ([cloud-sandbox.md](cloud-sandbox.md)) | none |
| TTL deletion | S4 | the deadline; no warning reaches the user | `interrupt-ttl-delete`, below | #4366 |
| The credit stop | S5, S6 | the owner's emails beforehand; nothing at the stop | `interrupt-credit-stop`, below | #6108 |
| An account suspension | S7 | a stop that reads as a person's | `interrupt-suspended`, below | #6107 |
| An organization or account deleted | S8, S9, D7 | the deleter is warned; streams end | `org-delete-streams` ([deletion.md](deletion.md)), `access-org-deleting` ([account-access.md](account-access.md)) | #3586 |
| A systemd image where it isn't allowed | S10 | the stop reason | `systemd-workspace-refusals` ([systemd-workspace.md](systemd-workspace.md)) | none |
| Egress cut or unavailable | N1–N5, N12, N14, N20 | nothing, except `cw info`'s "blocked: the platform's egress lockdown is not in place" while a switch back on is refused (N2) | `interrupt-egress-unavailable`, below | #6111, #6110 |
| A connection refused by policy, or the lockdown | N13, N22 | the refusal and its reason | `refusal-in-environment`, `locked-refuses-managed-github` ([network-and-egress.md](network-and-egress.md)) | none |
| The credential front door during a release | N6–N9 | a failed request; never a direct path | `agent-fail-closed` ([network-and-egress.md](network-and-egress.md)) | #6099 |
| A stream held for more than an hour | N15, D14 | an abrupt close (inferred) | `interrupt-long-stream`, below | infra#2986 |
| The Mesh, coordinator or relay restarts | N17–N19, N21, D11 | nothing visible, or a Mesh refusal | `reboot-mesh`, `reboot-stun-relay` ([node-reboot.md](node-reboot.md)) | none |
| A network cut on `cw shell`, `cw attach` or `--durable` | D1, D2 | `[cw] connection lost; reconnecting…`, then the reattach | `sandbox-attach-stays` ([cloud-sandbox.md](cloud-sandbox.md)) | none |
| An SSH or editor session over a cut | D3 | the SSH client's own timeout | `editor-reconnect` ([editor.md](editor.md)) | none |
| A credential revoked or expired | D4, D5 | "Access revoked", close 1008, and the dashboard terminal's revoked line (#5660) | `access-streams`, `access-websockets`, `access-tailnet` ([account-access.md](account-access.md)) | none |
| A member removed from the organization | D6 | streams end within 30 s (#6135, not yet observed) | `access-org-removal` ([account-access.md](account-access.md)) | none |
| An orchestration rollout | D8, D9, D10 | a retryable `unavailable`; terminals close with 1012 and reconnect | `sandbox-rollout` ([cloud-sandbox.md](cloud-sandbox.md)) | #4459; #6100 (D10, the SSH proxy WebSocket's drain, closed) |
| A preview's sign-in, policy or port changes | D15 | the sign-in page or a refusal | `preview-cloud-loopback` ([previews-and-ports.md](previews-and-ports.md)) | #6102 |
| The desktop viewer ends | D16 | the close reason and Reconnect | `desktop-dashboard-ends`, `desktop-lifetime` ([desktop.md](desktop.md)) | none |
| An agent session stopped | D17 | the session's end state | `sandbox-session-stop` ([cloud-sandbox.md](cloud-sandbox.md)) | none |

A restart a member asks for (`cw env daemon repair`, a resize in restart
mode, or a source change that needs one; R10–R12) is planned, says so before
it happens, and is not indexed here. Nor is R20: the Sandbox the survey found
gone after a Dev node upgrade had been deleted by its own walk (#6394).

## `interrupt-release-keeps-pod`: a release leaves a running Sandbox alone

Issues: #6095, #6093, #6105.

- **Entry points:** `cw --cloud info`, `cw --cloud ls` and the dashboard,
  across a delivery to the surface.
- **States to exercise:**
  - a Sandbox with credentials bound, across a delivery that changes the
    orchestration image;
  - the creator's GitHub connection disconnected while the Sandbox runs
    (R9).
- **Driving it:** create a Sandbox with a credential profile, open
  `cw shell --durable NAME` running a counter, and note the time. After
  the next delivery, run `cw --cloud info NAME`. Checking that the Pod is the
  same has no command yet (#6095).
- **Proof:** `cw --cloud info` shows no unplanned restart after the noted
  time, and the counter kept counting through the delivery.
- **Gotchas:** an orchestration rollout closes terminals with 1012 and
  reattaches them (`sandbox-rollout`); that is not a restart.
- **Observed:** not yet observed.

## `interrupt-daemon-restart`: an in-place daemon restart is recorded and shown

Issue: #6096.

- **Entry points:** `cw --cloud info`, `cw --cloud ls` and the dashboard.
- **States to exercise:** a custom-image Sandbox whose daemon exits and is
  restarted by its supervisor, while a durable session is open.
- **Driving it:** no command yet (#6096).
- **Proof:** `cw --cloud info` shows a restart, when and why, as for a
  replaced Pod; the session ends `Interrupted` with "the environment daemon
  restarted".
- **Gotchas:** the Pod stays Running, so nothing that watches Pods sees it.
- **Observed:** not yet observed.

## `interrupt-ttl-delete`: the user is warned before a TTL deletes the Sandbox

Issue: #4366.

- **Entry points:** `cw --cloud create --ttl`, `cw --cloud info` and the
  dashboard.
- **States to exercise:** a running Sandbox reaching its deadline; a
  stopped one.
- **Driving it:** `cw --cloud create --name ttl-walk --no-file --ttl 10m`,
  then `cw --cloud info ttl-walk` before the deadline, and `cw --cloud ls`
  after it.
- **Proof:** the deadline shows in `cw --cloud info`; a warning reaches the
  user before it (not built: #4366); afterwards `cw --cloud ls` no longer
  lists `ttl-walk`.
- **Gotchas:** TTL deletes the disk too. It is the only automatic path that
  destroys data.
- **Observed:** not yet observed.

## `interrupt-credit-stop`: the credit stop tells the organization when it stops

Issue: #6108.

- **Entry points:** email, `cw --cloud ls` and the dashboard.
- **States to exercise:** an organization at zero credit through the 24 h
  window, with a running Sandbox.
- **Driving it:** no command yet to bring a test organization to the stop
  on Dev (#6108).
- **Proof:** at the stop, everyone in the organization is told, and the
  Sandbox shows `stopped (credit)`.
- **Gotchas:** the low-credit and "stop in 24 hours" emails go to the owner
  only today.
- **Observed:** not yet observed.

## `interrupt-suspended`: a suspension says it was a suspension

Issue: #6107.

- **Entry points:** `cw --cloud ls`, `cw --cloud info` and the dashboard,
  for a member of the suspended account.
- **States to exercise:** a running Sandbox when its account is suspended;
  a start after Unsuspend.
- **Driving it:** no command yet (#6107).
- **Proof:** the stop reason reads as a suspension, not a person's stop,
  and affected members are told.
- **Gotchas:** walk only with a test account.
- **Observed:** not yet observed.

## `interrupt-egress-unavailable`: a network cut is not silent

Issues: #6111, #6110.

- **Entry points:** `cw --cloud info` and the dashboard.
- **States to exercise:** egress unavailable while the platform's egress
  is switched or restarted; DNS unreachable.
- **Driving it:** no command yet (#6111).
- **Proof:** `cw --cloud info` and the dashboard show that egress is
  unavailable, and since when.
- **Gotchas:** a refusal by policy is a different path, with its own
  journey (`refusal-in-environment`).
- **Observed:** not yet observed.

## `interrupt-long-stream`: a stream held for more than an hour stays up

Issue: infra#2986.

- **Entry points:** `cw --cloud shell`, `cw attach` and the dashboard
  terminal.
- **States to exercise:** an idle stream, and one that prints every
  minute, each held for 65 minutes.
- **Driving it:** open `cw --cloud shell NAME`, run a loop that prints the
  time every minute, and leave it for 65 minutes.
- **Proof:** the loop's output runs past the 60-minute mark with no
  reconnect line, or the cap is found and recorded on infra#2986.
- **Gotchas:** idle stop ends a quiet Sandbox first; keep the loop
  printing, or turn idle stop off for the walk.
- **Observed:** not yet observed.
