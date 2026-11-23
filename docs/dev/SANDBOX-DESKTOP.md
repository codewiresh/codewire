# Environment desktop

Target, not shipped (#3223). This page is written before the code, as the
contract the code must make true; nothing here exists on `main` except what
"Already shipped" lists. The acceptance journey is
[../journeys/desktop.md](../journeys/desktop.md), and `SPEC.md` "7. Access
paths" has the summary.

An environment's desktop is a graphical session inside the workload that a
person watches and controls over VNC, and that an agent in the same
environment draws on and drives. It is for running a GUI test, an app with a
window or a headed browser where someone can see it. The image brings a
browser, Chromium, and the desktop has Codewire's look.

## Rules

- One desktop per environment, shared by everyone who may open a terminal
  there. It is a shared screen, not a private one.
- Nothing runs or listens until it is started. An environment that never
  starts a desktop behaves exactly as before.
- The VNC listener is on the workload's loopback only, port 5901 on
  `127.0.0.1` and `::1`. No Pod port, preview URL, published port or Mesh
  port ever serves it: guest port 5901 is reserved against publishing ("The
  reserved ports").
- A viewer reaches it only through a path that already admitted them: an SSH
  local forward, or orchestration's desktop stream. Neither adds a credential.
- The desktop delivers nothing to the workload. Provider credentials,
  application secrets and egress are what they were
  ([SECRETS-AND-CREDENTIALS.md](SECRETS-AND-CREDENTIALS.md)).
- A local VM accepts exactly what a hosted Sandbox accepts: the same image
  layer, the same daemon contract and the same loopback-only forward.

## Already shipped

The desktop is built on these, which are on `main`:

- SSH local forwards to the workload's loopback on both placements, with the
  platform's own listeners refused (`SPEC.md` "Port forwarding over SSH").
- The daemon's `ForwardTcp` (capability `forward.workload_loopback.v1`),
  which reaches only loopback and refuses the SSH server, the credential
  bridge and, on a hosted daemon, the daemon's own port.
- Durable sessions, which outlive their clients and are marked interrupted,
  never restarted, when the daemon restarts.
- The reservation of ports 5901 and 9222 ("The reserved ports", below) in the
  port API, the preview proxy, the tailnet and Mesh, and a local VM's
  published ports. The dashboard's own wording
  for the refusal comes with its viewer.
- The dashboard terminal's WebSocket admission
  ([BROWSER-TERMINALS.md](BROWSER-TERMINALS.md)) and the revocation fence
  that ends an admitted stream ([AUTH-POLICY.md](AUTH-POLICY.md)).
- The image's desktop layer, its launcher, Chromium and the look ("In the
  image", "The browser" and "The look", below), and the daemon's
  `desktop.vnc.v1` ("What the daemon does").
- The hosted service, `codewire.v1.EnvironmentDesktopService`, with its
  generated clients and the Rust, TypeScript, Go and Python SDK wrappers
  ("Starting and stopping"). It is reachable with an API key.
- The same service on a local VM's supervisor, to the VM's owner over its
  owner-only socket (supervisor protocol 25).
- `cw desktop` ("`cw desktop`", below).
- Orchestration's desktop stream and the dashboard's Desktop panel ("The
  dashboard viewer", below).

## In the image

The workspace image carries one more package layer, from the image's dated
Ubuntu snapshot: TigerVNC's `Xvnc` (one process that is both the X server and
the VNC server), an XFCE session (window manager, panel, desktop, settings,
file manager and terminal), `xdotool` to send input, `scrot` to capture the
screen, a font and an icon theme. A launcher under `/opt/codewire/desktop/`
starts them; it reads the viewer password from its standard input, writes
the server's password file with the VNC package's own tool, and refuses to
start without one. The VNC server and the session package are pinned to exact
versions, as the image's SSH server is.

The image also carries Chromium ("The browser") and the desktop's look
("The look"), and two small packages they need: one that draws SVG images,
and the Debian archive's keys.

The layer adds no service and no start-up hook. The built-image contract
checks that a container started from the image has no `Xvnc` or XFCE process
and nothing listening on 5901 or on an X display. It then runs the launcher
and checks that display `:1` and the XFCE panel come up, and that a stop
leaves no process of the launcher's session and no endpoint behind.

Sockets belong to a network namespace, which the containers of a Pod share,
so the contract also holds the desktop to a closed list of endpoints. While
it runs, the only ones it may add are:

- the VNC listener, TCP 5901 on `127.0.0.1` and `::1`;
- the X display's socket file. X clients have no TCP listener and no
  abstract socket;
- the session bus, a socket file in the launcher's private runtime
  directory, never the stock address under `/tmp`;
- the session manager's ICE socket, as a file and as an abstract socket. It
  admits only a holder of the cookie in the user's ICE authority file, and
  the session manager offers no way to turn the abstract one off.

Any other TCP listener, UDP socket or named Unix socket fails the image. So
does an SSH or GPG agent: the image's defaults for the session turn off the
agents an XFCE session would start, and the session's programs keep the
`SSH_AUTH_SOCK` they were given, so the desktop uses the workspace's agent
and adds no key store of its own. A user can turn them back on in their own
session settings.

The contract runs the launcher as the daemon does: the viewer password on
standard input, and a stop that kills the launcher alone and outright. The
launcher gives each program it starts a parent-death signal, and one
short-lived child removes the runtime directory, so nothing outlives it.
The image fails if the launcher starts without a password, if the server
does not ask for one, if the password is in any argument, environment or
printed line, or if the password file is readable by anyone else or is
still there after the stop.

Every placement is headless and renders in software: there is no GPU.

## The browser

The image has Chromium, because a desktop an agent drives is mostly driven
through a browser. It is on the panel and on `PATH` as `chromium`.

- **Source.** Ubuntu has no Chromium package of its own, only a stub for
  another packaging system that does not run here. The image takes Debian's
  open-source build: signed by the Debian archive, pinned to an exact
  version, from a dated snapshot of Debian's security archive. That archive
  is a package source for the one build step that installs Chromium, with
  every other Debian package pinned out, and is gone from the finished
  image. It is not Google Chrome and carries none of its terms.
- **How current.** As current as Debian ships it. The snapshot date and the
  version are bumped together, and a bump is proposed whenever Debian
  publishes a newer Chromium there. Debian's build follows upstream's stable
  release by days to a few weeks. If that gap grows, or Debian stops
  updating the release the image uses, another open-source source is chosen
  and this page changes first.
- **Its sandbox is never turned off.** The setuid helper Debian packages
  separately is not installed, so Chromium's sandbox is the kernel's
  unprivileged user namespaces. Where they are closed to the workload,
  Chromium says it has no usable sandbox and does not start. No default and
  no launcher of Codewire's passes `--no-sandbox`.
- **Defaults.** One file of flags, read by Chromium's own launcher script:
  it does not use `/dev/shm`, which is small in every placement; it keeps
  saved passwords in its profile, unencrypted, there being no desktop
  keyring, and the user documentation says so; and it shows no first-run
  pages. It follows the desktop's dark appearance.
- **Remote debugging is off** unless a launch asks for it. An agent that
  drives the browser starts it with a debugging pipe, which is how browser
  automation libraries start a browser of their own, and nothing listens.
  A launch that asks for a debugging port instead gets it on the workload's
  loopback, and must name a profile directory of its own, as Chromium
  requires. The debugging protocol has no authentication: whatever reaches
  the port controls that browser and reads its sessions. So guest port
  9222 is reserved against publishing exactly as 5901 is ("The reserved
  ports"), and it is the only debugging port the image's `chromium` opens:
  a launch that asks for any other port, or for the port Chromium picks
  itself, or for a debugging address that is not loopback, is refused
  before Chromium starts, with a sentence that names 9222. The refusal is
  in the defaults the image's `chromium` command reads. A user who runs
  Chromium's binary without that command, or installs another browser,
  runs their own program, as with any listener they start.

The built-image contract checks that Chromium runs, that nothing under its
directory is setuid, that its defaults do not turn the sandbox off, that the
Debian archive is no longer a package source, that a headless start either
renders a page or refuses for want of a sandbox, and that a launch asking
for a debugging port other than 9222 is refused.

## The look

A started desktop looks like Codewire: the wordmark on a dark background as
the wallpaper; one dark panel along the top with the applications menu, a
terminal, Chromium, the file manager, the open windows and a clock; dark
window frames and controls; and one terminal already open, in `/workspace`,
in the dashboard terminal's colours, titled "Terminal". There are no desktop
icons, no second panel and no log-out or workspace buttons. The wallpaper
fills the screen at any size, and the wordmark on it stays whole at every
shape from 4:3 to 21:9 (#6161).

These are defaults the image ships and the launcher puts first, not a
locked configuration. XFCE copies some of them into the home the first time
a desktop starts, the panel's layout among them, so a user's own changes
persist with the home, and a later image's defaults do not replace what a
home already holds. The assets are files in the image: nothing is fetched.

## What the daemon does

The capability is `desktop.vnc.v1`. A daemon that has these three RPCs
advertises it, whatever image the environment runs. A host daemon never does:
a desktop belongs to an environment.

| RPC | Result |
| --- | --- |
| `StartDesktop` | Starts the desktop and answers once the launcher has said its own server holds the display and the VNC listener accepts a connection, within 10 seconds; a desktop that is already running is returned, never restarted. |
| `GetDesktop` | The state: `unavailable`, `stopped`, `starting` or `running`. `running` carries the display (`:1`), the port (5901), when it started and the viewer password. |
| `StopDesktop` | Ends the launcher, and with it everything it started. Stopping a desktop that is not running succeeds. |

- `unavailable` means this environment's image has no desktop: `Xvnc` or the
  launcher is missing from the workload's filesystem. The state says which.
  It is a state and not a missing capability, so a client can tell "this
  image has no desktop" from "this runtime is too old to start one".
- The desktop is the non-PTY durable session `codewire-desktop`, run as the
  workload user with the environment a session gets. `cw ls ENV` lists it and
  `cw logs ENV --session codewire-desktop` shows what `Xvnc` and the session
  printed.
- That name is reserved. Launching a session called `codewire-desktop`
  through the session API is refused; stopping it there stops the desktop;
  restarting it there, or sending it input, is refused. A session that took
  the name before it was reserved is never started as the desktop: the start
  is refused until that session is removed.
- A start fails, and says so, when the launcher ends before it is ready. That
  is what happens when another process already holds display `:1` or port
  5901: the refusal names both. A listener on the port that is not the
  launcher's never reads as a running desktop.
- A start whose launch the environment refuses, as it can for a moment while
  orchestration hands over during a release, says that, not that the display
  or port is taken: the launcher never ran. A second start goes through
  (#6133).
- A start that is not ready within 10 seconds ends the launcher and fails.
- The daemon stops the desktop as it stops any session, by ending its one
  process. The launcher starts each of its programs so that they end with
  it, and the password file goes with them.
- The X server runs with `-localhost -nolisten tcp -nolisten local`, at 1600
  by 1000 and 24 bits, and lets a viewer resize it. X clients reach it
  through its socket file only. Several viewers share it; a second one never
  disconnects the first.
- Lifetime: the desktop belongs to one run of the environment. It survives
  every viewer leaving, so an agent keeps working unobserved. It ends when it
  is stopped or the environment stops. After a daemon restart it reads as
  interrupted and is started again only by `StartDesktop`.
- While the desktop runs, every process the daemon starts (a command, a
  shell, a durable session, an SSH session) gets `DISPLAY=:1`, unless its
  request sets `DISPLAY` itself. Processes already running are not changed,
  and nothing else is added to a process's environment. After a stop, new
  processes get no `DISPLAY`.

## The viewer password

The VNC server asks for a password, and the password protects nothing. It
exists because macOS's built-in viewer will not open a desktop without one:
measured on macOS 27.2 on 2026-11-18 (#3223), that viewer connects to a
server with no password and never starts the session, and with a password
in the address it goes straight to the picture. Every viewer uses the same
scheme, so there is one path to test.

It is not an access control. VNC's password scheme is a DES challenge over
at most eight characters, and every process in the workload can reach the X
server without it. What admits a viewer is still the transport, and guest
port 5901 stays reserved exactly as below.

- **Made** by the daemon each time `StartDesktop` launches a desktop: eight
  characters, lowercase letters and digits, from the system's random
  source. A desktop that is already running keeps its password. A stop ends
  it, and the next start makes a new one. Nothing rotates it while the
  desktop runs.
- **Held** in the daemon's memory for the desktop's lifetime, and nowhere
  durable: not in the session's record, its command, its environment or its
  output.
- **Given to the launcher** on its standard input, never as an argument or
  an environment variable. The launcher writes the VNC server's password
  file, readable by the workload user only, in its private runtime
  directory, and removes it with the directory at the stop. Neither the
  launcher nor the server prints it, so `cw logs` never shows it.
- **Returned** by `StartDesktop` and `GetDesktop` to a caller who may open
  the desktop, and by no other call. The field is marked for redaction in
  every contract that carries it, and no service logs it, audits it or puts
  it in an error.
- **`cw desktop`** keeps it in memory, uses it only once it has checked
  that it is eight lowercase letters or digits, and never puts it in a file
  or in an argument of a process it starts, where other users of the
  computer could read it. The check is made where the address is built,
  because the value comes from the environment, which the computer has no
  reason to trust, and on macOS it becomes script text. On macOS it writes
  the address with the password to the standard input of
  `/usr/bin/osascript`, the system's script runner, which opens it, so the
  built-in viewer opens without asking. If the script runner cannot start,
  fails or takes longer than 10 s, `cw desktop` does what it does on other
  systems, never an opener with the password in an argument. On other systems a
  registered viewer is started with the address as an argument, so
  `cw desktop` opens the address without the password and prints the
  password for the user to type. It prints it only when its output is a
  terminal, so a run whose output is logged does not record it, and
  otherwise says that `--no-open` prints it. With `--no-open` it prints the
  address and the password, for a viewer of the user's own. `--status` never
  prints it.
- **The dashboard** receives it in the answer to the panel's own state
  read, keeps it in the page's memory and hands it to the viewer. It is
  never in a URL, in browser storage or in the page's markup. The desktop
  stream carries the VNC handshake as bytes; orchestration does not read
  the password out of it.

## The reserved ports

The viewer password is no boundary, so the only ways to the VNC listener
must be the two that admit a viewer. Guest port 5901 is therefore reserved
on every placement, whether or not a desktop runs. So is guest port 9222,
the browser's debugging port, which has no authentication at all. For each
of the two:

- **Hosted.** The port API refuses to publish it with `port_reserved`, as
  it refuses the daemon's SSH port, so no preview URL and no Mesh port can
  name it. A project file that lists it is refused the same way at create.
- **Local.** A host-port binding and a Mesh ingress refuse it, as they
  refuse the daemon's port, so `cw ports ENV --publish 5901` and a local
  HTTPS hostname cannot name it.
- **At use, not only at publication.** The preview proxy, the host-port
  forward and Mesh ingress refuse to open a connection to it, so a port
  published before this rule existed is not served either.
- `cw` and the dashboard show the server's refusal, which names `cw desktop`
  and the SSH local forward a viewer of one's own uses.

SSH local forwards and orchestration's desktop stream are the two paths
that still reach 5901, and an SSH local forward is the one path that reaches
9222 from outside the environment. A program a user runs inside the workload
to relay the desktop or the browser to another port is their own choice, as
a web server they start is; what they publish then is that program's port
and its protection.

Both ports are reserved on `main`.

## Starting and stopping

**Hosted.** `codewire.v1.EnvironmentDesktopService` has `StartDesktop`,
`GetDesktop` and `StopDesktop`, each naming an organization and an
environment. A caller needs operator access to the environment (its creator,
an organization owner or admin, or a member granted operator), as launching a
terminal does, and the Sandbox must be running, current and claimed.
Orchestration calls the daemon with the bound Pod's credential. The service
ships with its generated clients and the Rust, TypeScript, Go and Python SDK
wrappers.

None of the three is marked as a read without side effects, `GetDesktop`
included: its answer carries the viewer password, so it is never served as a
cacheable GET, and like every authenticated answer of this API it is sent
`no-store`. A daemon without the capability is refused with the repair.

A hosted Sandbox's daemon can be replaced by whoever has a shell in the
Sandbox, so the control plane treats everything it answers as the workload's
own text, and none of that text reaches a caller or a log:

- A refusal is told in the control plane's own sentences, chosen by the
  daemon's status code and, after a refused start, by the state read next:
  the image has no desktop (create the environment again on the current
  image); the desktop did not start (a held display or port, or a session in
  the way); it was not ready in time. The log line carries the code alone.
- An answer is passed on only in the shape the real daemon gives it: a
  known state; when unavailable, the control plane's sentence in place of
  the daemon's reason; when running, display `:1`, port 5901, a password of
  eight lowercase letters or digits, and a start time a client can format,
  or none. Any other answer is an upstream error and no part of it is kept.

**Local.** The supervisor serves the same service,
`codewire.v1.EnvironmentDesktopService`, to the VM's owner over its
owner-only socket, as it serves the session, exec and file services, and
calls the guest daemon; `cw` never holds the guest daemon's credential. It
vets the daemon's answer exactly as the hosted control plane does and tells
a refusal in its own sentences. A VM whose runtime predates the capability
is refused with the command that moves it onto the installed runtime. A
supervisor started by an older `cw` has no such service; it says so by its
protocol, and `cw desktop` names `cw upgrade --vms`.

## `cw desktop`

```text
cw desktop [ENV]             start the desktop if needed, forward it, open a viewer
cw desktop [ENV] --no-open   the same, printing the address and the password
cw desktop [ENV] --status    say whether the desktop is running
cw desktop [ENV] --stop      stop the desktop
```

`ENV` and `--in ENV` select the environment as on every flat command, and
`--local` and `--cloud` choose the placement.

`cw desktop` starts the desktop, brings the managed OpenSSH block up to date as
`cw vscode` does, picks a free port on the computer's loopback and runs
OpenSSH with one local forward from that port to `127.0.0.1:5901` through
the environment's managed alias. It prints `vnc://127.0.0.1:PORT`, opens
that address in the system's viewer where one is registered, and holds the
forward until Ctrl-C. On macOS the viewer is given the password and opens
without asking; elsewhere `cw desktop` prints the password under the address,
for the viewer's prompt ("The viewer password"). Leaving `cw desktop` closes
the forward and leaves the desktop running.

When the forward ends by itself, `cw desktop` asks the control plane why and
says "the environment stopped" or "the desktop ended", never OpenSSH's exit
status alone. Each refusal names its repair: an image with no desktop
(recreate the environment on the current image), a stopped environment
(`cw start`), a runtime too old for the capability (the update command for
that placement), and no `ssh` on the computer.

Someone who prefers their own viewer needs the alias and the password:
`ssh -L 5901:127.0.0.1:5901 cw-cloud-ID`, after `cw desktop ENV --no-open` has
started the desktop and printed it.

## The dashboard viewer

A hosted Sandbox's page has a Desktop panel beside its terminals, chosen
with the page's Terminal and Desktop switch: Start, the viewer, Stop, and
the states unavailable (with the recreate hint and no Start), stopped,
starting, running, disconnected (Reconnect) and ended. Paste and copy are
explicit buttons, "Paste to desktop" and "Copy from desktop"; the clipboard
never syncs by itself in either direction. Paste to desktop sends the text
with its announcement, so the desktop holds it and a program's paste takes
it at once, ahead of any key typed after it. "Release keyboard" returns the
keyboard to the page. Start and Stop pass the checks the terminal's New and
Close pass: CSRF, the exact dashboard origin and two-factor eligibility.

The panel reads the desktop's state when the page loads, after its own Start
and Stop, and from the reason a stream closed with. It polls nothing. Losing
Sandbox readiness pauses the viewer as it pauses the terminals.

The viewer is noVNC 1.7.0, vendored and served from the dashboard's own
origin as one self-contained ES module. esbuild 0.28.2, pinned in the
lockfile, builds it from upstream's files inside an image pinned by digest,
with no network. Every input's size and digest, the bundle's, and every
build pin are in `.supplychain/vendor-bundles.json`; the licences are npm
entries in `.supplychain/vendor-artifacts.json`, beside the bundle. The page
loads it with an integrity attribute. In CI,
`scripts/checks/security/check-novnc-bundle.sh` rebuilds it and fails unless
the result is byte-equal, or if the bundle holds an import, an export,
`eval`, `Function`, a worker or a `blob:` URL. No CDN, no worker, no `blob:`
source; the page's content security policy changes only by the terminal
page's existing `connect-src` entry for the WebSocket origin, and
`script-src` has neither `'unsafe-eval'` nor `'wasm-unsafe-eval'`.

### The desktop stream

`GET /api/v1/organizations/{org}/environments/{env}/desktop-stream`, with
the one subprotocol `codewire.desktop-stream.v1` and the page's account as
the one query parameter, `account_id`. Binary frames carry the VNC (RFB)
bytes unchanged in each direction; there are no text frames.

Admission is the durable terminal's, in the same order and inside the same
15 second budget: no `Authorization` header; exactly one `Origin`, equal to
the dashboard's; exactly one session cookie; the account in the request
equal to the cookie's; two-factor eligibility; operator access to a running,
current Sandbox; the claim ready. A request that fails any of them is
refused before the upgrade, and nothing is dialed.

Orchestration then upgrades the request, counts it against the viewer
limit and opens the daemon's `ForwardTcp` to `127.0.0.1:5901` with the bound
Pod's credential. It never connects to the Pod's address. A stream over the
limit, or whose desktop is not running, closes right after the upgrade, so
the page can say why; the first dials nothing.

| Bound | Value |
| --- | --- |
| WebSocket message | 64 KiB at most; a larger one ends the stream |
| Chunk towards the browser | 32 KiB at most |
| Queues | bounded in both directions; a full queue waits, it never grows |
| Stall | 5 seconds without progress on a write, either way, ends the stream |
| Viewers | 4 streams per environment in one orchestration process; the next is refused and the page names the limit |
| Pings | The server pings the browser every 30 seconds, so a still desktop is never silent on the wire and no proxy's idle timeout closes it (#6100) |

An open stream ends when:

- its user is disabled or the browser session that admitted it is deleted,
  within 30 seconds, through the revocation fence that ends an attach stream;
- the desktop stops, or the Sandbox stops or is replaced;
- orchestration drains for a rollout (the viewer reconnects).

It closes with 1000 when the viewer left, 1012 on a drain and 1008
otherwise, with a reason the page shows: the desktop ended or is not
running, the viewer limit, a stall, a frame that is not desktop bytes, a
Sandbox too old for the stream or one that could not be reached, or access
revoked. It writes the `stream.revoked` audit event when the fence ended
it. Removing a member from an organization does not end an open stream yet,
on this surface or any other ([AUTH-POLICY.md](AUTH-POLICY.md)); the next
admission refuses them.

## What this does not protect

- **The workload sees the desktop.** Every process in an environment is the
  same user as the X server. It can watch the screen, read what is typed or
  pasted, and draw a window that looks like something else. This is the
  terminal's posture. Do not type or paste a secret into an environment's
  desktop that you would not put in its terminal.
- **Signing in inside the desktop leaves that sign-in in the environment.** A
  browser a user runs there keeps its cookies in the workload's files, as a
  provider's own login command run in a terminal would. It uses the
  environment's egress policy and no other.
- **Whoever may open a terminal may watch.** An organization owner or admin
  can open a Sandbox's desktop and sees what its creator sees.
- **The viewer password is not a secret worth keeping.** Anything in the
  workload can read the server's password file and the screen itself.
- **A browser with debugging on belongs to the whole workload.** Any
  process there can attach to it, drive it and read every session it holds.
  Turn debugging on for a browser an agent drives, not for one you are
  signed in with.
- **A relay the user runs is theirs.** Publishing a port that a program in
  the workload bridges to the desktop exposes the desktop to whoever may
  reach that port. Codewire reserves 5901 and 9222; it does not inspect what
  other ports carry.

What a viewer's computer receives is the picture and, only on an explicit
copy, text from the desktop's clipboard. VNC here has no file transfer,
audio, printing or device redirection.

## Placements

| Placement | Desktop | `cw desktop` | Dashboard |
| --- | --- | --- | --- |
| Hosted Sandbox | In the workspace container, as the workspace user | Forward through `cw-cloud-ID` | Desktop panel |
| Hosted confidential Sandbox | The same image and daemon | The same | The same; not in the first journey |
| Linux local VM | In the workload container | Forward through `cw-local-ID` | None: local VMs are not in the dashboard |
| macOS local VM | The same guest; the VM stays headless | The same; the address opens in the system viewer | None |

A local VM's supervisor admits 8 SSH streams per environment; a `cw desktop`
forward is one of them.

The image's Chromium is set not to use `/dev/shm`, which every placement
keeps small. A browser a user installs themselves needs
`--disable-dev-shm-usage` for the same reason.
