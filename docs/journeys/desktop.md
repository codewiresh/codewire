# An environment's desktop

This journey proves that a person can start, watch and control a graphical
desktop inside an environment, with `cw vnc` and in the dashboard, and that
an agent in the environment draws on it and drives it. `SPEC.md` describes
it in "7. Access paths" under "Desktop", and the contract is
`docs/dev/SANDBOX-DESKTOP.md`. Issue #3223. The format is in
[README.md](README.md).

Every step is written first, as the owner's rule of 2026-11-15 (#3013)
requires: a review refuses desktop code this file does not describe. None of
it exists yet: there is no `cw vnc` command, no desktop in the workspace
image and no Desktop panel until #3223's pull requests land. Every step reads
"not yet observed".

## Where the journey stands

Updated 2026-11-18. The CLI and the dashboard viewer are announced together,
when both have been observed.

| ID | Kind | Local VM | Dev | Production |
| --- | --- | --- | --- | --- |
| `desktop-image-inert` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-cli` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-agent` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-lifetime` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-cli-refusals` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-loopback-only` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-access` | not yet observed | does not apply: one owner | not yet observed | not yet observed |
| `desktop-dashboard` | not yet observed | does not apply: no dashboard | not yet observed | not yet observed |
| `desktop-dashboard-ends` | not yet observed | does not apply: no dashboard | not yet observed | not yet observed |

## Before the walk

- Use one running environment on the current workspace image for every step.
  The examples call it `desk-walk`. Create it with `--ttl` so an abandoned
  walk removes itself, and remove it at the end.
- Kind is the retained local cluster (`docs/dev/AGENT-WORKFLOW.md`), with a
  built `cw` and synthetic credentials. A local VM walk uses a built `cw` and
  a runtime built from the same source, on Linux and then on an
  Apple-silicon Mac.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. On Production, the smoke identity
  (`scripts/runtime/prod/with-prod-smoke-auth.sh`) uses only its own
  sandboxes.
- The computer needs `ssh`. A step that says "the viewer" needs a VNC viewer:
  the system's on a Mac, any installed one on Linux. A step that can be
  proved without a viewer says how.
- Record `cw version`, the workspace image digest the environment runs and
  the source the surface was running with every observation.

## `desktop-image-inert`: the image carries a desktop that does nothing

- **Entry points:** an environment created on the current workspace image.
- **States to exercise:** a fresh environment in which no desktop was ever
  started.
- **Driving it:**

  ```sh
  cw create --name desk-walk --no-file --ttl 2h
  cw exec --in desk-walk -- sh -c 'command -v Xvnc xfce4-session xdotool scrot'
  cw exec --in desk-walk -- sh -c 'ps -eo comm | grep -E "Xvnc|xfce|xfwm" || echo none'
  cw exec --in desk-walk -- ss -ltn
  cw ls desk-walk
  ```

- **Proof:** the four programs resolve; the process list prints `none`;
  `ss` shows no listener on 5901 or 6001; `cw ls` lists no
  `codewire-desktop` session; a command's environment has no `DISPLAY`
  (`cw exec --in desk-walk -- sh -c 'echo "${DISPLAY:-unset}"'` prints
  `unset`).
- **Gotchas:** an environment created before the image pin moved runs the
  previous image and proves nothing here; check its digest first.
- **Observed:** not yet observed.

## `desktop-cli`: `cw vnc` shows the desktop

- **Entry points:** `cw vnc [ENV]`, `cw vnc --in ENV`, with `--no-open`;
  `--local` and `--cloud`. No command yet (#3223).
- **States to exercise:**
  - a first start, which shows progress until the desktop runs;
  - a second `cw vnc` while the desktop runs, which starts nothing;
  - `--no-open`, which prints the address and opens nothing;
  - a computer with no registered viewer, which gets the address and a
    one-line hint.
- **Driving it:**

  ```sh
  cw vnc desk-walk --no-open
  ```

  It prints `vnc://127.0.0.1:PORT` and stays in the foreground. In a second
  terminal, with that PORT:

  ```sh
  head -c 11 < /dev/tcp/127.0.0.1/PORT
  cw vnc desk-walk --status
  cw ls desk-walk
  cw logs desk-walk --session codewire-desktop --tail 20
  ```

  Then, without `--no-open`, `cw vnc desk-walk` opens the viewer. Open the
  desktop's terminal from its panel and type a line.

- **Proof:**
  - the eleven bytes are `RFB 003.008`: the forward reaches the VNC server;
  - `--status` says the desktop is running and since when;
  - `cw ls` lists the session `codewire-desktop`, and its log shows `Xvnc`
    listening on port 5901;
  - the viewer shows an XFCE desktop with a panel, and the typed line
    appears in its terminal;
  - `cw vnc desk-walk --status` before and after the second `cw vnc` names
    the same start time.
- **Gotchas:** the `/dev/tcp` read needs `bash`. A viewer that connects is
  not proof that `cw vnc` chose the environment you meant; compare the host
  name the desktop's terminal prints with `cw info desk-walk`. The Mac
  walk records whether the system viewer connected without asking for a
  password (#3223's open point).
- **Observed:** not yet observed.

## `desktop-agent`: an agent draws on the desktop and reads it

- **Entry points:** `cw run --in ENV -- COMMAND`, `cw exec --in ENV --
  COMMAND`, `cw shell ENV`, and an agent started with `cw run` after the
  desktop.
- **States to exercise:**
  - a command started while the desktop runs;
  - a shell that was already open when the desktop started;
  - a command whose request sets its own `DISPLAY`;
  - a command started after the desktop stopped.
- **Driving it:** with the desktop running and a viewer open:

  ```sh
  cw run --in desk-walk -- sh -c 'echo $DISPLAY'
  cw exec --in desk-walk -- scrot /workspace/before.png
  cw run --in desk-walk -- sh -c 'xfce4-terminal --title desk-mark & sleep 3'
  cw exec --in desk-walk -- xdotool search --name desk-mark
  cw exec --in desk-walk -- sh -c 'xdotool search --name desk-mark windowactivate --sync type "echo drawn > /workspace/desk-mark"; xdotool key Return'
  cw exec --in desk-walk -- cat /workspace/desk-mark
  cw exec --in desk-walk -- scrot /workspace/after.png
  cw exec --in desk-walk -- sha256sum /workspace/before.png /workspace/after.png
  cw exec --in desk-walk -e DISPLAY=:7 -- sh -c 'echo $DISPLAY'
  ```

  Then start an agent with `cw run` in the environment and ask it to open a
  window on the desktop and type into it, while the viewer is open.

- **Proof:**
  - the first command prints `:1`;
  - `xdotool search` prints a window ID, and the viewer shows a terminal
    window titled `desk-mark` that nobody opened by hand;
  - `/workspace/desk-mark` holds `drawn`: keys sent by `xdotool` reached a
    program on the desktop;
  - the two pictures' checksums differ, and `after.png`, copied out with
    `cw cp desk-walk:/workspace/after.png ./after.png`, shows the same
    window the viewer shows;
  - the command with its own `DISPLAY` prints `:7`;
  - a shell opened before the desktop started still has no `DISPLAY`;
  - the agent's window and typing appear in the viewer as it works.
- **Gotchas:** a command that prints `:1` proves the variable, not the
  drawing; the window and the file are the proof. A picture taken with no
  viewer attached must still show the desktop: the desktop does not need a
  watcher.
- **Observed:** not yet observed.

## `desktop-lifetime`: the desktop outlives its viewers and ends with the environment

- **Entry points:** `cw vnc ENV`, `--status`, `--stop`; `cw stop` and
  `cw start`.
- **States to exercise:**
  - the viewer closed and `cw vnc` left with Ctrl-C;
  - a reattach;
  - the environment stopped while a viewer is attached;
  - the environment started again;
  - an explicit stop, and a stop of a desktop that is not running.
- **Driving it:**
  1. With the `desk-mark` window open, close the viewer and press Ctrl-C in
     `cw vnc`. `cw vnc desk-walk --status`; then `cw vnc desk-walk` again.
  2. With a viewer attached, `cw stop desk-walk` in a second terminal. Then
     `cw start desk-walk`, `cw vnc desk-walk --status` and `cw vnc
     desk-walk`.
  3. `cw vnc desk-walk --stop`, then:

     ```sh
     cw vnc desk-walk --status
     cw exec --in desk-walk -- ss -ltn
     cw exec --in desk-walk -- sh -c 'echo "${DISPLAY:-unset}"'
     cw vnc desk-walk --stop
     ```

- **Proof:**
  - after Ctrl-C, `--status` says running with the same start time, and the
    reattached viewer shows the `desk-mark` window as it was left;
  - on the stop, the viewer disconnects and `cw vnc` prints that the
    environment stopped, not an `ssh` exit status;
  - after the start, `--status` says stopped, and the next `cw vnc` shows a
    fresh desktop with no `desk-mark` window and a later start time;
  - after `--stop`, `--status` says stopped, nothing listens on 5901, a new
    command prints `unset`, the session `codewire-desktop` reads as ended in
    `cw ls desk-walk`, and the second `--stop` exits 0.
- **Gotchas:** a stop and start of a hosted Sandbox replaces its root
  filesystem but keeps `/workspace`; `/workspace/desk-mark` surviving says
  nothing about the desktop.
- **Observed:** not yet observed.

## `desktop-cli-refusals`: what `cw vnc` says when it cannot

- **Entry points:** `cw vnc ENV`, `--status`.
- **States to exercise:** each line below is one state.
- **Driving it and proof:** each refusal is one sentence naming the cause
  and the next command, exits non-zero, and starts no forward.
  - An environment on the previous workspace image: "this environment's
    image has no desktop", with the hint to recreate it on the current
    image. `--status` says unavailable, not stopped.
  - A stopped environment: names `cw start desk-walk`.
  - A hosted Sandbox whose `cw` predates the capability, and a local VM
    whose runtime does: each names the command that updates it, and the two
    differ.
  - `ssh` missing from `PATH` (run with a `PATH` that lacks it): one line
    naming OpenSSH.
  - The desktop stopped from a second terminal (`cw vnc desk-walk --stop`)
    while `cw vnc` holds a forward: `cw vnc` ends and says the desktop
    ended.
  - A forward that asks for another host, with plain OpenSSH
    (`ssh -N -L 5999:192.0.2.1:80 cw-cloud-ID`, then a connection to port
    5999): OpenSSH prints the refusal, which says forwarding reaches only
    the environment's own loopback.
- **Gotchas:** an image with no desktop and a runtime too old are different
  repairs; a walk that sees one sentence for both has found a bug.
- **Observed:** not yet observed.

## `desktop-loopback-only`: nothing new is reachable

- **Entry points:** the environment's network, from inside and outside.
- **States to exercise:** a running desktop with no `cw vnc` attached, and
  with one.
- **Driving it:**

  ```sh
  cw exec --in desk-walk -- ss -ltn
  cw ports desk-walk
  cw ports desk-walk --publish 5901
  cw ports desk-walk --publish 5902
  ```

  Then create an environment from a `codewire.yaml` whose ports list 5901.

  On Kind, from another Pod in the cluster, connect to the Sandbox Pod's
  address on 5901 and 6001. On a local VM, look for a listener on the
  computer with `ss -ltn` (Linux) or `lsof -iTCP -sTCP:LISTEN` (macOS)
  before and during `cw vnc`.

- **Proof:**
  - inside, 5901 is bound to `127.0.0.1` only, and no X listener is on TCP
    at all;
  - `cw ports` lists no port for the desktop, and no preview URL serves it;
  - publishing 5901 is refused with one sentence that says the port is the
    desktop's and names `cw vnc`, with the desktop running and with it
    stopped, in the cloud and on a local VM; publishing 5902 succeeds, and
    is removed afterwards; the create from the project file is refused with
    the same sentence;
  - the connection from another Pod is refused or times out on both ports;
  - on the computer, the only new listener while `cw vnc` runs is
    `127.0.0.1:PORT`, and it is gone after Ctrl-C.
- **Gotchas:** a check from the Sandbox itself proves nothing about the
  network; it must come from outside the Pod. An environment that published
  5901 before the reservation shipped is the case the refusal at use
  covers: on Kind, insert such a row into the disposable database and
  check that its preview URL answers with the refusal, not the desktop.
- **Observed:** not yet observed.

## `desktop-access`: who may open it

- **Entry points:** `cw vnc`, the dashboard's Desktop panel, and
  `EnvironmentDesktopService` with an API key.
- **States to exercise:**
  - the Sandbox's creator;
  - an organization admin who did not create it;
  - a member granted only viewer access to it;
  - a member of another organization;
  - an API key bound to another organization.
- **Driving it:** on Kind, with two more synthetic accounts in the
  creator's organization and one outside it. As each, run
  `cw vnc desk-walk --status` and `cw vnc desk-walk --no-open`, and open the
  Sandbox's page.
- **Proof:**
  - the creator and the admin both get a viewer, and each sees what the
    other types: it is one screen;
  - the viewer-only member is refused by `--status`, by a start and by the
    page, with the access refusal a terminal gives them, and the desktop's
    start time does not change;
  - the outsider and the foreign API key get the same answer as for an
    environment that does not exist.
- **Gotchas:** the admin seeing the creator's screen is the rule, not a
  finding; it is the terminal's rule.
- **Observed:** not yet observed.

## `desktop-dashboard`: the Desktop panel

- **Entry points:** a hosted Sandbox's page in the dashboard.
- **States to exercise:**
  - stopped, starting and running;
  - a second tab, and a fifth viewer;
  - leaving the page and coming back;
  - a Sandbox on the previous image;
  - a stopped Sandbox;
  - phone width.
- **Driving it:** on Kind, through the dashboard's own URL, signed in as the
  Sandbox's creator.
  1. Open the Sandbox's page. Press Start in the Desktop panel.
  2. Click into the desktop, open its terminal and type. Copy a marker on
     the computer and press "Paste to desktop"; select text in the desktop's
     terminal and press "Copy from desktop"; press "Release keyboard".
  3. Open the same page in a second tab, then in three more.
  4. Go to another dashboard page and come back.
  5. Open the page of a Sandbox on the previous image, and of a stopped one.
  6. Set the browser to 390 px wide.
- **Proof:**
  - the panel goes from stopped to starting to the desktop's picture, with
    no reload, and `cw vnc desk-walk --status` agrees it is running;
  - typed keys appear in the desktop's terminal; the pasted marker appears
    there; the copied text is on the computer's clipboard; after "Release
    keyboard" the Tab key moves focus through the page's controls;
  - a second tab shows the same desktop, and typing in one shows in the
    other; the fifth viewer is refused and the panel names the limit of
    four;
  - back on the page, the panel reports running and reconnects, and the
    start time `--status` prints has not changed;
  - the previous image shows the unavailable state with the recreate hint
    and no Start button; a stopped Sandbox shows no viewer;
  - at 390 px the picture scales to the panel with no horizontal scroll;
  - the browser spec reports zero content-security-policy violations, and
    every script and style on the page comes from the dashboard's origin.
- **Gotchas:** the limit of four holds in each orchestration process.
  Record how many replicas the surface ran: with more than one, a fifth
  viewer that lands on another replica is admitted, and that is correct.
  Nothing is copied from the desktop to the computer without the button:
  check the clipboard before pressing it.
- **Observed:** not yet observed.

## `desktop-dashboard-ends`: the viewer ends when it should

- **Entry points:** the Desktop panel with a viewer open.
- **States to exercise:**
  - the Sandbox stopped from its page;
  - the desktop stopped from the panel, and from `cw vnc --stop`;
  - a sign-out in another tab;
  - the account disabled;
  - an orchestration rollout.
- **Driving it:** with a viewer open in the panel, do each in turn, starting
  the desktop again between them. On Kind, disable the synthetic account as
  a platform admin, and replace orchestration as `sandbox-rollout` in
  [cloud-sandbox.md](cloud-sandbox.md) does.
- **Proof:**
  - on the Sandbox's stop, the panel says the environment stopped and Start
    is disabled until readiness returns; after a start, Start shows a fresh
    desktop;
  - on either desktop stop, the panel says the desktop ended and offers
    Start, in every open tab;
  - within 30 seconds of the sign-out, the viewer ends and says the session
    ended; after signing in again, Reconnect shows the same desktop;
  - within 30 seconds of the disable, the viewer ends, and the audit log
    holds a `stream.revoked` event naming the desktop stream and the
    environment;
  - across the rollout, the viewer reconnects by itself to the same
    desktop.
- **Gotchas:** removing a member from the organization does not end their
  open viewer yet, as it does not end an open terminal
  (`docs/dev/AUTH-POLICY.md`); do not record that as observed. Time the
  sign-out with a clock: "it ended eventually" is not the 30 second bound.
- **Observed:** not yet observed.
