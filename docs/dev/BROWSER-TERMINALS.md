# Browser terminals

The dashboard is a presentation client for durable environment-daemon sessions,
not the owner of their shell processes. New terminal explicitly launches a fixed
interactive shell through EnvironmentSessionService. Reconnecting, switching
tabs, navigating away, and closing the browser transport do not launch, restart,
or stop a shell. Close terminal requires confirmation and explicitly calls Stop.
Removing an ended or unavailable tab only removes its browser presentation.

Opening a Sandbox's page opens one terminal by itself, through the same launch
as New terminal, at most once per page load. It launches only after a fresh
ready status and a successful session list, while the page shows no terminal,
no saved reference names one, and no session is live; a live session is
re-attached instead, and a saved terminal that is gone is reported, not
replaced. A page that has shown a terminal never opens another by itself, so
closing the last one does not start a new shell. Two pages opened at the same
moment may each start one. A failed list or launch replaces the empty state's
text with the reason and a Retry button; Retry re-lists before it launches, so
a launch whose reply was lost is re-attached, not repeated.

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
fixed send deadline. A lost connection or uncertain delivery discards staged input;
input is never replayed on reconnect. Plain Ctrl+C remains a shell interrupt;
Copy selection and Ctrl+Shift+C copy without sending input.

## Automatic reconnection

A tab that is still wanted re-attaches its existing session automatically when
the WebSocket closes or errors without a final status, input delivery stalls,
or a send fails. Attempts wait 1, 2, 4 and 8 seconds, then every 15 seconds,
for as long as the page is visible. Only a replacement that stays open for five
seconds resets that backoff, so an upstream that accepts and immediately closes
cannot cause a one-second loop. Every third attempt re-reads the inventory for
that tab alone; a session that no longer exists becomes unavailable and stops
retrying, while healthy sibling tabs stay attached. Losing Sandbox readiness
pauses every transport but keeps the tabs wanted. When readiness returns, the
dashboard refreshes the inventory and re-attaches the surviving sessions.

Automatic recovery never launches, restarts or stops a shell and never resends
input. A final session status, unverifiable output, a rendering failure and a
rendering queue that does not drain stay manual until Reconnect or Replay recent
output. An attached tab offers no Disconnect; its status reads Connected, in
green. Reconnect shows only while a tab is detached and always acts immediately.
Hidden or suspended pages make no attempts; returning to the page revalidates
the account before re-attaching.

Focused synthetic controller/adapter tests establish these protocol and browser
rules, not managed sandbox acceptance. The checked-in authenticated browser and
sandbox journeys separately prove the real identity, runtime and projection
boundaries, including stable shell PID, working directory and shell variables
after navigation and reconnect, and independent second-terminal state.
