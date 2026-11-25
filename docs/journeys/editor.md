# A sandbox in a desktop editor

This journey proves that a user can work in a cloud sandbox from a desktop
editor over Remote-SSH, as `SPEC.md` describes in "7. Access paths". There are
two entry points: `cw vscode`, and the editor's own Remote-SSH reaching a
`cw-cloud-*` host through the section `cw setup ssh` writes. Both go through
`cw shell --stdio` as the ProxyCommand. Issue #4641; the automated check is
#4642. The format is in [README.md](README.md).

## Where the journey stands

Updated 2026-11-24.

| ID | Owner | Dev | Production |
| --- | --- | --- | --- |
| `editor-connect` | cw-cli | observed 2026-11-14, with `ssh` and with the editor (#4641) | not yet observed |
| `editor-server` | cw-cli | observed 2026-11-14 (#4641) | not yet observed |
| `editor-edit` | cw-cli | observed 2026-11-14, with sftp and with the editor (#4641) | not yet observed |
| `editor-reconnect` | cw-cli | observed 2026-11-14: the timed ending with `ssh`, and the editor's reconnect after a sleep (#4641); the lost-connection line and the durable shell's reattach after a 90 s network cut on Dev 2026-11-24 (#6101) | not yet observed |
| `editor-failures` | cw-cli | observed 2026-11-14 with `ssh`; the stopped and signed-out messages are fixed by #4643, not yet on Dev | not yet observed |

## Before the walk

- Use one running cloud sandbox for every step. The examples call it
  `editor-walk`.
- On Dev, `scripts/runtime/dev/with-dev-smoke-auth.sh -- COMMAND` runs one
  command as the synthetic Dev identity. Never use a person's sign-in.
- The computer needs a desktop editor with a Remote-SSH extension, and an
  `ssh` new enough for `%n` (OpenSSH 9.6 or later, or a build with the
  CVE-2023-51385 fix; see `cw setup ssh --help`).
- Record `cw version` and the source the surface was running with every
  observation.

## `editor-connect`: the editor reaches the sandbox

**Entry points:** `cw vscode [ENV] [--folder PATH]`; the editor's Remote-SSH
host list after `cw setup ssh`.

**States to exercise:** a first connection, with no host key known; a second
connection; a section `cw doctor` reports as outdated, which `cw vscode`
rewrites before it opens the editor.

**Driving it:**

1. `cw setup ssh`. It prints the section it wrote, which starts the SSH config
   file.
2. `cw vscode editor-walk`. It rewrites the section silently, keeping any
   `-o` options given to `cw setup ssh`, prints
   `→ Opening VS Code for editor-walk · /workspace`, and opens the editor's
   `ssh-remote+cw-cloud-<ID>` link for `/workspace`.
3. Or, in the editor, connect to the host `cw-cloud-editor-walk` from the
   Remote-SSH host list.

**Proof:** the editor connects with no host-key prompt. The key comes from
`cw ssh known-hosts` through `KnownHostsCommand`. From a terminal,
`ssh -T cw-cloud-editor-walk 'cat /etc/hostname'` prints the sandbox's host
name. A connection with `ssh` doesn't prove the editor's: each is observed
on its own.

**Gotchas:** a host-key prompt means the editor isn't using the managed
section. Look for a second SSH config file named in the editor's settings.

## `editor-server`: the editor's server installs and the folder opens

**Driving it:** after `editor-connect`, the editor downloads and starts its
server in the sandbox, then opens `/workspace` (or the `--folder` given).

**Proof:** the editor's explorer lists `/workspace`'s files, and
`cw exec --in editor-walk -- ls -d ~/.vscode-server` shows the server in the
sandbox.

**Gotchas:** the server is downloaded from the editor vendor's servers by the
sandbox or by the computer, depending on the extension's settings. Egress
rules that block that host fail this step, not `cw`.

## `editor-edit`: an edit saved in the editor is in the sandbox

**Driving it:** open a file under `/workspace` in the editor, add a line with
a fresh marker (a timestamp), and save.

**Proof:** `cw exec --in editor-walk -- grep MARKER /workspace/FILE` prints
the line.

## `editor-reconnect`: a session that died ends, and the editor reconnects

**States to exercise:** the computer sleeps, or its network changes, while the
editor is connected and idle. A network cut of about 90 s while a plain
`ssh` shell and a `cw shell --durable` shell are open (#6101). Over the WebSocket fallback
(`CW_SSH_TRANSPORT=websocket`), also: the connection sits idle for 90 minutes;
and Codewire's server restarts, as at a Dev rollout (#6100).

**Driving it:** connect, leave the editor idle, put the computer to sleep for
five minutes, and wake it.

**Proof:**

- The dead connection ends within about two and a half minutes of the wake, because of
  the section's `ServerAliveInterval 30` and `ServerAliveCountMax 4`.
- The editor reconnects to the same sandbox. The edit from `editor-edit` is
  still there.

Without a keepalive, ssh waits on the dead connection with no end. The
terminal stand-in, run on Dev:

1. `ssh -T cw-cloud-editor-walk 'sleep 900'`;
2. freeze the ProxyCommand with `kill -STOP`, so no bytes cross;
3. time how long ssh takes to give up.

Over the WebSocket fallback:

- An idle `ssh -T cw-cloud-editor-walk` with no output for 90 minutes still
  answers its next command (infra#2986).
- At a rollout, `ssh -T cw-cloud-editor-walk 'sleep 900'` ends within about
  270 s of the orchestration replica's SIGTERM, and its terminal shows
  `the connection ended: server restarting; connect again`. The editor then
  reconnects.

After a network cut of about 90 s (#6101):

- The plain `ssh cw-cloud-editor-walk` shell ends, and its terminal shows,
  just before OpenSSH's own `Connection to … closed by remote host.`:

  ```text
  ✗ Lost the connection to editor-walk: SSH sessions end after about a minute offline, and their processes stop
  → for work that must keep running, use cw shell --durable editor-walk or cw run --detach
  ```

  A `sleep 900 &` started in that shell is gone afterwards.
- `cw shell --durable editor-walk` reattaches by itself, and its shell still
  has what was typed before the cut.
- A shell left with `exit` and no cut prints nothing from `cw`.

The cut is `nmcli networking off` and `on`, or, on a shared machine,
`IPAddressDeny=any` on the systemd scope that `ssh` and `cw` run in.

**Gotchas:** a keepalive in the user's own `Host *` entry doesn't apply to
`cw-*` hosts, because the managed section comes first. Set one with
`cw setup ssh -o 'ServerAliveInterval 60'`.

## `editor-failures`: what the user sees when it can't connect

Each failure names the next step, in the editor's Remote-SSH output or from
`cw`:

| State | Driving it | What must be seen |
| --- | --- | --- |
| Not signed in | `cw logout`, then connect | today `not logged in (set CODEWIRE_API_KEY, run 'cw setup', or run 'cw login')`; expected "not signed in" with `cw login` (#4643) |
| The sandbox is stopped | `cw stop editor-walk`, then connect | today `connect SSH WebSocket proxy: HTTP error: 400 Bad Request`, and `cw vscode` opens the editor anyway; expected the stopped state with `cw start editor-walk` (#4643) |
| The sandbox is removed | `cw rm editor-walk`, then connect | `no cloud environment matches "editor-walk" (from cw-cloud-editor-walk); cw --cloud ls lists yours`; `cw vscode` exits 1 with `environment "editor-walk" not found` |
| No managed section | `cw setup ssh remove`, then connect from the editor | the editor can't resolve `cw-cloud-editor-walk`; `cw doctor` names `cw setup ssh` |
| An outdated section | a section without the keepalive | `cw doctor`: "outdated or not first; run `cw setup ssh`" |

## Observed

- Dev, 2026-11-14 (cw-cli): Dev had been promoted to source 9664662dd at
  11:07Z, and the rollout was not checked. Only the server side of the
  failure states depends on it. `cw` was built from the `cw setup ssh`
  keepalive branch, with OpenSSH 10.6. No editor was run. Evidence: #4641.
  - `editor-connect`: `cw setup ssh -o 'ConnectTimeout 20'` wrote the
    section and `cw doctor` reported it ok. `ssh -T cw-cloud-<name>` printed
    the sandbox's host name with no host-key prompt.
  - `editor-edit`: a file put over sftp read back with
    `cw exec --in <name> -- cat` and carried the same timestamp marker.
  - `cw vscode`: with the keepalive lines removed, `cw doctor` reported the
    section outdated. `cw vscode` rewrote it with the keepalive and kept
    `ConnectTimeout 20` (the `-o` given before), then `cw doctor` reported it
    ok. It opened
    `vscode://vscode-remote/ssh-remote+cw-cloud-<ID>//workspace`.
  - `editor-reconnect`, with the ProxyCommand frozen while the session was
    idle:
    - the section v0.4.17 writes: still waiting after 360 s;
    - the branch's defaults: `Timeout, server ... not responding` after 149 s;
    - `-o 'ServerAliveInterval 10'`: the same message after 49 s.
  - `editor-failures`: as in the table. The stopped and signed-out messages
    are #4643.
- Dev, 2026-11-14 (the owner, at their own editor with its Remote-SSH
  extension): walked the steps of #4641's checklist with the released `cw`.
  The section was written with `cw setup ssh -o 'ServerAliveInterval 30'
  -o 'ServerAliveCountMax 4'`, the lines this branch writes by default.
  - `cw --cloud vscode` opened the editor on `/workspace`, with no host-key
    or password prompt.
  - The editor's server installed.
  - A file saved in the editor was read back with `cw exec`.
  - The host connected from the editor's host list by name.
  - After a laptop sleep, the editor reconnected and came back to the file.
  - After a stop and a start, the editor reconnected.

  The owner's result: "the editor walk works 100%". No timings or editor
  messages were recorded. Evidence: #4641.
- Dev, 2026-11-24 (#6101), `editor-reconnect` after a network cut, with
  `cw` built from main at 013f98d865 and OpenSSH 10.6, as the Dev smoke
  identity, in a test Sandbox removed by name afterwards. Dev's desired
  source moved from c4ff29d60b to 013f98d865 at 21:08:27Z, 4 s into the
  walk, and the rollout was not checked; both have #6208, and the lines
  below are the client's. The section was written with `cw setup ssh
  --ssh-config-file` into a private file, which `ssh -F` read. The cut was
  `IPAddressDeny=any` on the systemd scope that `ssh` and `cw` ran in, from
  21:08:44.820 to 21:10:14.865Z (90 s).
  - A session left with `exit` and no cut printed nothing from `cw`.
  - The plain `ssh` shell, with `sleep 900 &` started in it, ended at
    21:10:18.182, 3.3 s after the network came back. Its terminal showed
    "✗ Lost the connection to w6101-editor: SSH sessions end after about a
    minute offline, and their processes stop" and "→ for work that must keep
    running, use cw shell --durable w6101-editor or cw run --detach", then
    OpenSSH's "Connection to cw-cloud-w6101-editor closed by remote host."
    The `sleep` was gone afterwards (`cw exec … kill -0` failed).
  - `cw shell --durable w6101-editor`, via direct UDP, printed "[cw]
    connection lost; reconnecting to the same session" and answered the
    next command with a variable set before the cut, 5 s after the network
    came back.
- Production: not yet observed.
