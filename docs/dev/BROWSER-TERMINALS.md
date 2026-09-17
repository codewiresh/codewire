# Browser terminals

The dashboard is a presentation client for durable environment-daemon sessions,
not the owner of their shell processes. New terminal explicitly launches a fixed
interactive shell through EnvironmentSessionService. Reconnecting, switching
tabs, navigating away, and closing the browser transport do not launch, restart,
or stop a shell. Close terminal requires confirmation and explicitly calls Stop.
Removing an ended or unavailable tab only removes its browser presentation.

The browser keeps up to eight independent terminal presentations. Session
storage contains only immutable account, organization, environment and session
references. It never contains terminal output, input, cursors, commands or
credentials. Returning to a page authenticates afresh, reconciles the saved
references with the service inventory, and replays each surviving session's
bounded recent history into a new viewport. Reconnect on the same page retains
its viewport and resumes from the last completed render callback.

## Admission and readiness

The dashboard inventory is a closed, uncached DTO containing only account ID,
session ID and state. Mutations require current CSRF, one exact dashboard Origin,
fresh sign-in/two-factor eligibility, organization membership and the expected
immutable account ID. Browser requests cannot supply arbitrary commands or
environment variables. A lost mutation reply requires an inventory refresh;
New and Stop are not automatically retried.

A fresh authenticated readiness read, not the server-rendered Running badge,
enables terminal controls. Launch and Restart independently reject incomplete
setup or an active setup owner before dispatch. Stop remains available for an
existing shell while setup is incomplete.

The `codewire.durable-terminal.v1` WebSocket is cookie-only, exact-Origin bound,
and accepts closed `account_id`, `session_id`, `output_offset` coordinates.
Authentication must still match the inventory's expected account before daemon
attachment, even when a successor account can operate the same environment.
Durable intent cannot downgrade into the legacy new-shell transport.

## Replay and flow control

Absolute decimal cursors remain lossless unsigned 64-bit values. The daemon's
history-gap event precedes resumed bytes. The browser renders old queued bytes,
then the gap notice, then recent bytes, in that order. A persistent accessible
notice outside the terminal also reports the gap, independently of ANSI state.
Skipped bytes do not count toward output debt or forgive older outstanding ACKs.

Render callbacks, not receipt of WebSocket frames, advance the reconnect cursor
and send cumulative ACKs. Output has a 256 KiB/64-frame unacknowledged window;
gap notices count as frames but not bytes. Old disconnected-socket writes may
finish the retained presentation, but cannot ACK a replacement socket. Replay,
account change and disposal cancel old render generations. Rendering failure
requires an explicit Replay recent output action.

Final exit text waits for queued output to render. Its callback is bound to the
render generation and connection attempt so later protocol/transport errors
cannot be hidden by stale completion. Only a clean WebSocket close (1000)
finishes the clean final-state path; abnormal closure remains visible.

Browser input is bounded and batched on a fixed leading-edge interval, with a
fixed send deadline. Disconnect or uncertain delivery discards staged input;
input is never replayed on reconnect. Plain Ctrl+C remains a shell interrupt;
Copy selection and Ctrl+Shift+C copy without sending input.

Focused synthetic controller/adapter tests establish these protocol and browser
rules, not managed sandbox acceptance. The checked-in authenticated browser and
sandbox journeys separately prove the real identity, runtime and projection
boundaries, including stable shell PID, working directory and shell variables
after navigation and reconnect, and independent second-terminal state.

## Renderer-specific goldens

The existing lifecycle journey captures both terminal viewport sizes using the
desktop project. Regenerate its two Ubuntu24 goldens with
`scripts/ci/verify/update-playwright-ubuntu24-snapshots.sh --chromium-archive
<absolute-pinned-archive> --prepared-kind-terminal` after the checked-in
`codewire-e2e-ci` topology has been prepared with the intended source images.
This profile runs the real lifecycle assertions unchanged, permits only those
two snapshot updates, and does not create, deploy or forward the topology.
It requires the stock source/image/archive verification receipt and a matching
prepared-cluster workspace marker, then passes that verified image into the
test-owned preset. An older published image or caller override cannot substitute.
Renderer regeneration is not full exact-tree qualification or Dev evidence.
