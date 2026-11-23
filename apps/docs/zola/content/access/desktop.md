---
title: Desktop
description: Watch and control a graphical desktop inside an environment with cw desktop or the Sandbox page's Desktop panel, and let agents draw on it and drive it.
updated: 2026-11-23
weight: 6
---

Every environment on the current workspace image can run a graphical desktop:
an XFCE session with a terminal, a file manager and Chromium. Use it to run a
GUI test, an app with a window or a headed browser where you can see it, and
to watch an agent work. Nothing runs or listens until you start it.

There is one desktop per environment, and it is a shared screen: everyone who
may open a terminal in the environment may watch and control it. It keeps
running when every viewer leaves, and ends when you stop it or the
environment stops.

## From the terminal: cw desktop

```sh
cw desktop [ENV]             # start the desktop if needed, forward it, open a viewer
cw desktop [ENV] --no-open   # the same, printing the address and the password
cw desktop [ENV] --status    # say whether the desktop is running
cw desktop [ENV] --stop      # stop the desktop and the programs on it
```

`ENV` (or `--in ENV`) is a name or ID and defaults to the environment selected
with `cw use`; `--local` and `--cloud` choose the placement, as on every
command.

`cw desktop` starts the desktop, forwards it over SSH to a free port on your
computer's `127.0.0.1`, prints the `vnc://127.0.0.1:PORT` address and opens it
in your system's VNC viewer. The forward lasts until you press Ctrl-C; leaving
closes the forward and leaves the desktop running.

- **On macOS** the built-in Screen Sharing opens straight to the desktop.
- **Elsewhere** a registered VNC viewer opens the address and asks for the
  password, which `cw desktop` prints under it. It prints the password only to
  a terminal, so a logged run does not record it.

The password is made fresh each time the desktop starts. It is there because
some viewers will not connect without one, not to keep anyone out: what
admits you is your sign-in and the SSH forward. `--status` never prints it.

If the forward ends by itself, `cw desktop` says whether the environment
stopped or the desktop ended. Each refusal names its repair: an image with no
desktop (create the environment again on the current image), a stopped
environment (`cw start ENV`), a server or local VM runtime too old for the
desktop (for local VMs, `cw upgrade --vms`), and no `ssh` on your computer.

## In the dashboard: the Desktop panel

A hosted sandbox's page has a **Terminal | Desktop** switch. Choose
**Desktop**, then **Start desktop**; the panel connects without a reload.

- **Keyboard and mouse** go to the desktop once you click into it.
  **Release keyboard** gives the keyboard back to the page, so Tab moves
  through its controls again.
- **The clipboard moves only when you ask.** **Paste to desktop** sends your
  computer's clipboard to the desktop's; **Copy from desktop** brings the
  desktop's clipboard to yours. Nothing syncs by itself.
- **Up to four dashboard viewers** can watch one desktop at a time, in any
  mix of tabs and people; a fifth is told the limit. Viewers through
  `cw desktop` are not counted.
- **Stop desktop** ends it for every viewer; each open panel says the desktop
  ended and offers Start again.

On a stopped sandbox the panel asks you to start the sandbox first. A
sandbox created before the desktop was in the image says it has none, with no
Start: create it again on the current image.

## Agents on the desktop

While the desktop runs, every command, shell and session started in the
environment gets `DISPLAY=:1`, so an agent started with `cw run` draws on the
desktop with no setup. The image has the tools to drive and read it:

```sh
cw run --in my-app -- sh -c 'xdotool search --sync --class xfce4-terminal windowactivate --sync type "hello"'
cw exec --in my-app -- scrot /tmp/screen.png
```

Processes already running when the desktop starts keep their environment; a
new one started after a stop gets no `DISPLAY`.

## Chromium

The image's Chromium is Debian's open-source build, on the panel and on
`PATH` as `chromium`.

- **Its sandbox stays on.** Chromium uses the kernel's user namespaces; where
  they are closed, it says so and does not start. Codewire never passes
  `--no-sandbox`.
- **Shared memory.** It is set not to use `/dev/shm`, which is small in every
  environment. A browser you install yourself needs
  `--disable-dev-shm-usage` for the same reason.
- **Saved passwords are stored unencrypted** in its profile in the
  environment, since the desktop has no keyring.
- **Remote debugging** is off unless a launch asks for it. An automation
  library that starts its own browser uses a debugging pipe, and nothing
  listens. A launch that asks for a debugging port gets it only on port 9222
  of the environment's loopback, with a profile directory of its own; any
  other port or address is refused.

## Your own viewer

Any VNC client works. `cw desktop ENV --no-open` starts the desktop and prints
the address and the password without opening anything. To forward it
yourself instead, use the environment's SSH alias, which `cw desktop` keeps
up to date:

```sh
ssh -L 5901:127.0.0.1:5901 cw-cloud-ID   # cw-local-ID for a local VM
```

Then connect your viewer to `127.0.0.1:5901` with the password `--no-open`
printed.

Ports 5901 and 9222 are reserved: they cannot be published as a preview URL or
a host port, so the desktop and the browser's debugging port are reached only
through your SSH forward or the dashboard.

## What it does not protect

- **The environment sees the desktop.** Every process there runs as the same
  user as the desktop. It can watch the screen, read what you type or paste,
  and draw a window that looks like something else, as it can in a terminal.
  Do not type or paste a secret into the desktop that you would not put in
  the environment's terminal.
- **A sign-in inside the desktop stays in the environment.** A browser there
  keeps its cookies in the environment's files and uses its egress policy.
- **Whoever may open a terminal may watch.** An organization owner or admin
  can open a sandbox's desktop and sees what its creator sees.
- **A browser with debugging on belongs to the whole environment.** Any
  process there can drive it and read its sessions. Turn debugging on for a
  browser an agent drives, not one you are signed in with.

Your computer receives the picture and, only when you press Copy from desktop
or copy in your own viewer, text from the desktop's clipboard. There is no
file transfer, audio, printing or device redirection.
