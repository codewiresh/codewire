# An environment's desktop

This journey proves that a person can start, watch and control a graphical
desktop inside an environment, with `cw desktop` and in the dashboard, and that
an agent in the environment draws on it and drives it. `SPEC.md` describes
it in "7. Access paths" under "Desktop", and the contract is
`docs/dev/SANDBOX-DESKTOP.md`. Issue #3223. The format is in
[README.md](README.md).

Every step is written first, as the owner's rule of 2026-11-15 (#3013)
requires: a review refuses desktop code this file does not describe. Part of
the dashboard's Desktop panel does not exist until #3223's last pull request
lands. Every step reads "not yet observed" until it is walked.

## Where the journey stands

Updated 2026-11-23. The CLI and the dashboard viewer are announced together,
when both have been observed.

The 2026-11-22 walks ran `cw` built from a4a20f9d16e9 (#5853) against Dev at
source b99ac9991704 and against a Linux local VM whose runtime was built from
a4a20f9d16e9, on the default workspace image, whose digest was not recorded.
They are recorded on #3223 in that day's Dev and local VM walk comments, and
in the comment after them with the look and the listeners. The Desktop panel
was walked on Kind the same day, before review, at `43f5c10850`; that walk
is recorded on #3223 in its Kind walk comment. On Dev, the delivery walk
observed the panel's steps 1 to 3, all but "Release keyboard", in promote-dev
run 73498 at source 0b68dec2aa69 on 2026-11-23, recorded on #3223 in its Dev
panel comment.

| ID | Kind | Local VM | Dev | Production |
| --- | --- | --- | --- | --- |
| `desktop-image-inert` | not yet observed | observed on Linux | observed | not yet observed |
| `desktop-cli` | not yet observed | observed on Linux; macOS not yet observed | observed from Linux and macOS | not yet observed |
| `desktop-agent` | not yet observed | partly, on Linux | partly | not yet observed |
| `desktop-look` | not yet observed | partly, on Linux | partly | not yet observed |
| `desktop-browser` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-lifetime` | not yet observed | not yet observed | not yet observed | not yet observed |
| `desktop-cli-refusals` | not yet observed | partly, on Linux | partly | not yet observed |
| `desktop-loopback-only` | not yet observed | partly, on Linux | partly | not yet observed |
| `desktop-access` | not yet observed | does not apply: one owner | not yet observed | not yet observed |
| `desktop-dashboard` | partly | does not apply: no dashboard | partly | not yet observed |
| `desktop-dashboard-ends` | partly | does not apply: no dashboard | not yet observed | not yet observed |

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
  cw exec --in desk-walk -- sh -c 'command -v Xvnc xfce4-session xdotool scrot chromium'
  cw exec --in desk-walk -- sh -c 'ps -eo comm | grep -E "Xvnc|xfce|xfwm" || echo none'
  cw exec --in desk-walk -- ss -ltn
  cw ls desk-walk
  ```

- **Proof:** the five programs resolve; the process list prints `none`;
  `ss` shows no listener on 5901 or 6001; `cw ls` lists no
  `codewire-desktop` session; a command's environment has no `DISPLAY`
  (`cw exec --in desk-walk -- sh -c 'echo "${DISPLAY:-unset}"'` prints
  `unset`).
- **Gotchas:** an environment created before the image pin moved runs the
  previous image and proves nothing here; check its digest first.
- **Observed:** in the 2026-11-22 walks on Dev and a Linux local VM: the five
  programs resolve; no desktop process runs; nothing listens on 5901 or 6001;
  no session is listed; `DISPLAY` is unset.

## `desktop-cli`: `cw desktop` shows the desktop

- **Entry points:** `cw desktop [ENV]`, `cw desktop --in ENV`, with `--no-open`;
  `--local` and `--cloud`.
- **States to exercise:**
  - a first start, which shows progress until the desktop runs;
  - a second `cw desktop` while the desktop runs, which starts nothing;
  - `--no-open`, which prints the address and opens nothing;
  - a computer with no registered viewer, which gets the address and a
    one-line hint.
- **Driving it:**

  ```sh
  cw desktop desk-walk --no-open
  ```

  It prints `vnc://127.0.0.1:PORT` and stays in the foreground. In a second
  terminal, with that PORT:

  ```sh
  head -c 11 < /dev/tcp/127.0.0.1/PORT
  cw desktop desk-walk --status
  cw ls desk-walk
  cw logs desk-walk --session codewire-desktop --tail 20
  ```

  Then, without `--no-open`, `cw desktop desk-walk` opens the viewer. Open the
  desktop's terminal from its panel and type a line.

- **Proof:**
  - the eleven bytes are `RFB 003.008`: the forward reaches the VNC server;
  - `--status` says the desktop is running and since when;
  - `cw ls` lists the session `codewire-desktop`, and its log shows `Xvnc`
    listening on port 5901;
  - the viewer shows an XFCE desktop with a panel, and the typed line
    appears in its terminal;
  - `cw desktop desk-walk --status` before and after the second
    `cw desktop` names the same start time;
  - on a Mac the built-in viewer opens without asking for anything:
    `cw desktop` gave it the password. On Linux `cw desktop` prints the
    password under the address and the viewer asks for it once. With its
    output in a file (`cw desktop desk-walk > out`), the file holds the
    address and no password, and a note names `--no-open`. With
    `--no-open`, the printed password lets a viewer of your own connect, and
    a wrong one is refused by the VNC server;
  - the password is nowhere it should not be: `--status` does not print it;
    `cw logs desk-walk --session codewire-desktop` does not contain it;
    inside the environment, neither `ps -eo args` nor the environment of a
    command started there contains it; on the computer, `ps -eo args`
    taken again and again while the viewer opens shows no command line with
    it, and no file under the temporary directory holds it.
- **Gotchas:** the `/dev/tcp` read needs `bash`. A viewer that connects is
  not proof that `cw desktop` chose the environment you meant; compare the host
  name the desktop's terminal prints with `cw info desk-walk`. The password
  searches need the password: take it from `--no-open`, and search for the
  exact eight characters. On the owner's Mac the viewer is opened in a
  session the owner can watch, never over a bare remote command. A refusal
  that blames display :1 or port 5901 can be a denied launch (#6133); the
  session's status in the daemon says which, and a second start went
  through.
- **Observed:** from Linux, in the 2026-11-22 walks on Dev and a Linux local
  VM, with TigerVNC on a private X server as the viewer: every proof but the
  Mac's and a registered Linux viewer asking for the password. The forward's
  first bytes were `RFB 003.008`; `--status` named the start time, and a
  second `cw desktop` started nothing; the viewer showed the XFCE desktop and
  a line typed through it ran in its terminal; a wrong password was refused;
  with no `vnc://` handler registered, the automatic path printed the password
  at a terminal and, with its output in a file, printed none and named
  `--no-open`. The password was not in `--status`, the desktop's log, `ps -eo
  args` or a command's environment in the environment, about 340,000 sampled
  lines of `ps -eo args` on the computer, or a file written during the run.
  From macOS, on Dev on 2026-11-23, on the owner's Mac with its own login
  and keychain, `cw` built from 42306388f8 against Dev at the same source
  (recorded on #3223 in the macOS comment): the forward's first bytes were
  `RFB 003.008`; plain `cw desktop` opened Screen Sharing on the XFCE desktop
  without asking for anything and printed no password, and the VNC server
  accepted its authentication; a second `cw desktop` started nothing; the
  name Screen Sharing saved was the environment's host. The password was
  not in about 369,000 sampled lines of `ps -eo args`, the unified log,
  files written during the open, Screen Sharing's saved connections or a
  keychain password item for 127.0.0.1. A Linux viewer opened by `cw desktop` itself, and typing through
  the Mac's viewer, are not yet observed.

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
- **Observed:** partly, in the 2026-11-22 walks on Dev and a Linux local VM:
  `DISPLAY=:1`, and `:7` when the request set it; `xdotool` found the
  `desk-mark` window and its keys wrote `drawn`; the two pictures differ and
  the copied-out one shows the window. The shell opened before the desktop and
  an agent driving it are not yet observed.

## `desktop-look`: a started desktop looks like Codewire

- **Entry points:** any viewer of a desktop started for the first time in an
  environment.
- **States to exercise:**
  - a first start in a fresh environment;
  - a start after the user changed something (moved a panel item, set
    another wallpaper), stopped the desktop and started it again;
  - a viewer that resizes the desktop.
- **Driving it:** start the desktop and look, then:

  ```sh
  cw exec --in desk-walk -- scrot /workspace/look.png
  cw cp desk-walk:/workspace/look.png ./look.png
  cw exec --in desk-walk -- xdotool search --class xfce4-terminal
  ```

- **Proof:**
  - the picture shows the Codewire wordmark on a dark background, one dark
    panel along the top with the applications menu, a terminal, Chromium,
    the file manager and a clock, and one open terminal in the dashboard
    terminal's colours whose prompt is in `/workspace`; no desktop icons,
    no second panel;
  - the terminal was there without anyone opening it: `xdotool search`
    prints its window before any input was sent;
  - a window opened from the panel has a dark frame and dark controls;
  - after the user's change and a restart of the desktop, the change is
    still there: the home keeps it;
  - at another size the wallpaper still fills the screen and the wordmark
    is whole.
- **Gotchas:** an environment whose home already held a desktop's settings
  shows those, by design; walk the first-start state in a new environment.
- **Observed:** partly, a first start only, in the 2026-11-22 walks on Dev and
  a Linux local VM: the Codewire wordmark on a dark background, one dark panel
  along the top with the menu, a terminal, Chromium, the file manager and a
  clock, one terminal in `/workspace`, no desktop icons. The terminal's prompt
  is plain on Dev and coloured on the local VM; whether either matches the
  dashboard terminal's colours, the restart after a change and a resize are
  not yet observed.

## `desktop-browser`: Chromium runs sandboxed, and an agent can drive it

- **Entry points:** the panel's Chromium button; `chromium` in a terminal
  or from `cw run`; an agent's browser automation.
- **States to exercise:**
  - Chromium opened from the panel;
  - a launch with a debugging pipe, as an automation library makes;
  - a launch that asks for the debugging port;
  - a launch that asks for another debugging port, which is refused;
  - the debugging port published, which is refused;
  - an environment whose egress policy refuses the page asked for.
- **Driving it:** with the desktop running and a viewer open:

  ```sh
  cw exec --in desk-walk -- chromium --version
  cw run --in desk-walk -- sh -c 'chromium https://example.com & sleep 8'
  cw exec --in desk-walk -- sh -c 'ps -eo args | grep "[c]hromium" | grep -c -- --no-sandbox'
  cw exec --in desk-walk -- ss -ltn
  cw run --in desk-walk -- sh -c 'chromium --remote-debugging-port=9222 --user-data-dir=/tmp/agent-profile about:blank & sleep 8'
  cw exec --in desk-walk -- curl -s http://127.0.0.1:9222/json/version
  cw exec --in desk-walk -- chromium --remote-debugging-port=9333 --user-data-dir=/tmp/other-profile about:blank
  cw ports desk-walk --publish 9222
  ```

- **Proof:**
  - the version is the one the image pins, and the viewer shows Chromium's
    window, dark, with the page;
  - no Chromium process has `--no-sandbox`: the count is 0. Where an
    environment gives the workload no user namespaces, Chromium prints
    that it has no usable sandbox and no window opens, and that is the
    result to record, not a flag to add;
  - after the first launch `ss` shows no new listener: debugging is off;
  - after the launch that asked for it, `curl` inside the environment
    prints the browser's version document from `127.0.0.1:9222`, and `ss`
    shows that port on loopback only;
  - the launch that asked for port 9333 exits non-zero at once with a
    sentence that names 9222, and `ss` shows no listener on 9333;
  - publishing 9222 is refused with the sentence that names the reserved
    port, in the cloud and on a local VM, as 5901 is;
  - under an egress policy that refuses the site, the page shows the
    refusal and the policy's refusal log names the host.
- **Gotchas:** a debugging port without `--user-data-dir` is ignored by
  Chromium, so `curl` finding nothing may be the missing flag. Close the
  agent's browser before reusing the profile directory. Do not sign in to
  anything in a browser whose debugging is on.
- **Observed:** not yet observed.

## `desktop-lifetime`: the desktop outlives its viewers and ends with the environment

- **Entry points:** `cw desktop ENV`, `--status`, `--stop`; `cw stop` and
  `cw start`.
- **States to exercise:**
  - the viewer closed and `cw desktop` left with Ctrl-C;
  - a reattach;
  - the environment stopped while a viewer is attached;
  - the environment started again;
  - an explicit stop, and a stop of a desktop that is not running.
- **Driving it:**
  1. With the `desk-mark` window open, close the viewer and press Ctrl-C in
     `cw desktop`. `cw desktop desk-walk --status`; then `cw desktop desk-walk` again.
  2. With a viewer attached, `cw stop desk-walk` in a second terminal. Then
     `cw start desk-walk`, `cw desktop desk-walk --status` and `cw desktop
     desk-walk`.
  3. `cw desktop desk-walk --stop`, then:

     ```sh
     cw desktop desk-walk --status
     cw exec --in desk-walk -- ss -ltn
     cw exec --in desk-walk -- sh -c 'echo "${DISPLAY:-unset}"'
     cw desktop desk-walk --stop
     ```

- **Proof:**
  - after Ctrl-C, `--status` says running with the same start time, and the
    reattached viewer shows the `desk-mark` window as it was left;
  - on the stop, the viewer disconnects and `cw desktop` prints that the
    environment stopped, not an `ssh` exit status;
  - after the start, `--status` says stopped, and the next `cw desktop` shows a
    fresh desktop with no `desk-mark` window, a later start time and a new
    password; a viewer offering the earlier password is refused;
  - after `--stop`, `--status` says stopped, nothing listens on 5901, a new
    command prints `unset`, the session `codewire-desktop` reads as ended in
    `cw ls desk-walk`, and the second `--stop` exits 0.
- **Gotchas:** a stop and start of a hosted Sandbox replaces its root
  filesystem but keeps `/workspace`; `/workspace/desk-mark` surviving says
  nothing about the desktop.
- **Observed:** not yet observed.

## `desktop-cli-refusals`: what `cw desktop` says when it cannot

- **Entry points:** `cw desktop ENV`, `--status`.
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
  - Display `:1` or port 5901 already held by another process in the
    environment (start `nc -l 127.0.0.1 5901` there first): the start
    fails, names the display and the port, and `--status` says stopped,
    never running.
  - The desktop stopped from a second terminal (`cw desktop desk-walk --stop`)
    while `cw desktop` holds a forward: `cw desktop` ends and says the desktop
    ended.
  - A forward that asks for another host, with plain OpenSSH
    (`ssh -N -L 5999:192.0.2.1:80 cw-cloud-ID`, then a connection to port
    5999): OpenSSH prints the refusal, which says forwarding reaches only
    the environment's own loopback.
- **Gotchas:** an image with no desktop and a runtime too old are different
  repairs; a walk that sees one sentence for both has found a bug.
- **Observed:** partly, in the 2026-11-22 walks on Dev and a Linux local VM:
  no `ssh` on `PATH`; a forward to another host, refused by the environment's
  SSH server; the desktop stopped while a forward was held, which ended within
  10 s saying the desktop ended; port 5901 held, with `--status` saying
  stopped; a stopped environment, naming its start command. The previous image
  and a server, `cw` or local runtime too old for the desktop are not yet
  observed.

## `desktop-loopback-only`: nothing new is reachable

- **Entry points:** the environment's network, from inside and outside.
- **States to exercise:** a running desktop with no `cw desktop` attached, and
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
  before and during `cw desktop`.

- **Proof:**
  - inside, 5901 is bound to `127.0.0.1` and `::1` only, and no X listener
    is on TCP at all;
  - `cw ports` lists no port for the desktop, and no preview URL serves it;
  - publishing 5901 is refused with one sentence that says the port is the
    desktop's and names the way in (`cw desktop`, and the SSH local forward
    a viewer of one's own uses), with the desktop running and with it stopped, in
    the cloud and on a local VM; publishing 5902 succeeds, and is removed
    afterwards; the create from the project file is refused with the same
    sentence;
  - the connection from another Pod is refused or times out on both ports;
  - on the computer, the only new listener while `cw desktop` runs is
    `127.0.0.1:PORT`, and it is gone after Ctrl-C.
- **Gotchas:** a check from the Sandbox itself proves nothing about the
  network; it must come from outside the Pod. An environment that published
  5901 before the reservation shipped is the case the refusal at use
  covers: on Kind, insert such a row into the disposable database and
  check that its preview URL answers with the refusal, not the desktop.
- **Observed:** partly, in the 2026-11-22 walks on Dev and a Linux local VM:
  inside, 5901 listens on `127.0.0.1` (and `::1` on Dev) only, with no X
  listener on TCP; `cw ports` lists nothing; publishing 5901 is refused with
  the desktop running and stopped, with Dev's wording from before #5853 and
  the local VM's naming `cw desktop`; 5902 publishes and is removed; on the
  computer the only new listener is `127.0.0.1:PORT`, gone after the end. The
  check from another Pod, the project file with 5901 and the preview URL are
  not yet observed.

## `desktop-access`: who may open it

- **Entry points:** `cw desktop`, the dashboard's Desktop panel, and
  `EnvironmentDesktopService` with an API key.
- **States to exercise:**
  - the Sandbox's creator;
  - an organization admin who did not create it;
  - a member granted only viewer access to it;
  - a member of another organization;
  - an API key bound to another organization.
- **Driving it:** on Kind, with two more synthetic accounts in the
  creator's organization and one outside it. As each, run
  `cw desktop desk-walk --status` and `cw desktop desk-walk --no-open`, and open the
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
  1. Open the Sandbox's page, choose Desktop and press Start desktop.
  2. Click into the desktop, open its terminal and type. Copy a marker on
     the computer and press "Paste to desktop"; select text in the desktop's
     terminal and press "Copy from desktop"; press "Release keyboard".
  3. Open the same page in a second tab, then in three more.
  4. Go to another dashboard page and come back.
  5. Open the page of a Sandbox on the previous image, and of a stopped one.
  6. Set the browser to 390 px wide.

  On Dev every delivery walks steps 1 to 3 as the Dev smoke browser
  identity, on the walk's own Sandbox, in
  `apps/dashboard/scripts/dev-ux-walkthrough.ts`. Its dashboard terminal
  opens a terminal on the desktop and raises it, and afterwards reads back
  the files the viewer's typing and paste wrote there. The other pages are
  closed before it presses Stop desktop. The checks, in order, are
  `desktop-start`, `desktop-input`, `desktop-viewers`, `desktop-stop` and
  `desktop-reached`. Like the walk's other new checks, one that fails prints
  a `not-held` line and does not fail the acceptance. The five checks share
  a budget of 150 s; a check that begins after it prints `not-held
  expectation=in-time`. Dev runs one orchestration replica, so the fifth
  viewer is always refused there.
- **Proof:**
  - the panel goes from stopped to starting to the desktop's picture, with
    no reload, and `cw desktop desk-walk --status` agrees it is running;
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
  check the clipboard before pressing it. Keys typed straight after a paste
  land after the pasted text: the panel sends the text with its
  announcement, so the desktop's program has it at once.
- **Observed:** partly, on Kind on 2026-11-22, before review, with the
  dashboard at `43f5c10850` and the default workspace image (recorded on
  #3223 in the Kind walk comment): steps 1, 2, 3, 5 and 6. The panel went from
  stopped to starting to the desktop's picture in about a second, with no
  reload; typed keys, the pasted text and Copy from desktop all crossed;
  after "Release keyboard" keys no longer reached the desktop; tabs 2 to 4
  connected and the fifth was refused with "4 viewers already watch this
  desktop, the most it takes."; the image before the desktop showed the
  unavailable state with the recreate hint and no Start, and a stopped
  Sandbox asked for the Sandbox and showed no viewer; at 390 px there was no
  sideways scroll; no page checked had a content-security-policy violation.
  Partly, on Dev, in the delivery walk of promote-dev run 73498 (source
  0b68dec2aa69, 2026-11-23, as the Dev smoke browser identity, recorded on
  #3223 in the Dev panel comment): all five checks held. The panel went from
  stopped to the desktop's picture, filling the panel, in 4.9 s with no
  reload; typed keys and the pasted text reached the desktop's terminal, and
  Copy from desktop brought the terminal's printed line to the page; tabs 2
  to 4 connected and the fifth was refused with the limit of four named; Stop
  desktop left the panel stopped. Dev ran one orchestration replica.
  Not yet observed: step 4, `--status` and its start time, typing seen in a
  second tab, and, on Dev, "Release keyboard" and steps 4 to 6. The viewer's
  following of the Sandbox's readiness and of the tab's visibility came in
  review and is proven by the browser fixture spec only.

## `desktop-dashboard-ends`: the viewer ends when it should

- **Entry points:** the Desktop panel with a viewer open.
- **States to exercise:**
  - the Sandbox stopped from its page;
  - the desktop stopped from the panel, and from `cw desktop --stop`;
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
    desktop;
  - a viewer that cannot use its stream closes it and says the desktop's
    state is unknown; the panel never stays at "Connecting…" holding an
    open stream. A browser does not refuse its own WebSocket, so this is
    proven by the panel's browser fixture spec, which opens the view with
    a WebSocket noVNC refuses.
- **Gotchas:** removing a member from the organization does not end their
  open viewer yet, as it does not end an open terminal
  (`docs/dev/AUTH-POLICY.md`); do not record that as observed. Time the
  sign-out with a clock: "it ended eventually" is not the 30 second bound.
- **Observed:** partly, in the same Kind walk: on Stop desktop in the panel,
  the other open tab said "The desktop ended." and offered Start, and `Xvnc`
  was gone. The other states are not yet observed.
