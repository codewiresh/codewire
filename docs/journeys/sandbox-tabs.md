# Sandbox tabs and agent workspace

This journey proves that a hosted Sandbox's page presents one unified tab bar
for Agent, Terminal, and Desktop tabs, opens a Tab Home Page when no tabs are
open or when `+` is clicked, and lets the user launch, switch, reattach, and
close tabs cleanly. `docs/dev/SANDBOX-DESKTOP.md` covers the Desktop viewer and
`docs/dev/BROWSER-TERMINALS.md` covers durable terminals. The format is in
[README.md](README.md).

Every step is written first and reads **not yet observed** until walked on a
running surface.

## Where the journey stands

Updated 2026-11-27. Written first; every step is **not yet observed**.

| ID | Kind | Dev | Production |
| --- | --- | --- | --- |
| `sandbox-tabs-home` | not yet observed | not yet observed | not yet observed |
| `sandbox-tabs-desktop` | not yet observed | not yet observed | not yet observed |
| `sandbox-tabs-agent-composer` | not yet observed | not yet observed | not yet observed |

## `sandbox-tabs-home`: Tab Home Page on empty Sandbox and `+`

- **Entry points:** a running hosted Sandbox's page in the dashboard.
- **States to exercise:**
  - a fresh ready Sandbox with 0 running sessions (Tab Home Page opens by default);
  - a Sandbox with live terminal sessions (restores/reattaches open tabs; clicking `+` opens a Tab Home Page tab);
  - a Sandbox with detached live sessions (`Running in this Sandbox` lists them so one click reattaches);
  - a stopped or setting-up Sandbox (shows Sandbox status notice instead of interactive tab choices);
  - light and dark themes at desktop (1440 px) and mobile (390 px) widths.
- **Driving it:**
  1. Open a fresh running Sandbox in the dashboard.
  2. Verify the header has no separate `Terminal | Desktop` switch.
  3. Verify the default tab is `New tab` showing **Agent**, **Terminal**, and **Desktop** on one line with icon + title and a plain description, with no static `VNC`, `agy`, or `Durable PTY` badges.
  4. Click **Terminal** to launch a durable terminal in that tab.
  5. Click `+` (`New tab`) in the tab bar to open another Tab Home Page tab, and switch between tabs with mouse and keyboard (`ArrowLeft`/`ArrowRight`).
- **Proof:**
  - the Tab Home Page opens without auto-launching an unused shell on an empty Sandbox;
  - clicking **Terminal** launches a durable PTY session (`/_actions/terminal-sessions/launch`) and attaches xterm in the tab;
  - detached live sessions appear under `Running in this Sandbox` (sentence case) and reattach on click;
  - zero horizontal scroll at 390 px and zero CSP violations.
- **Gotchas:** a Sandbox with an already-running terminal session reattaches that session on arrival; test the empty-Sandbox default on a Sandbox with 0 live sessions.
- **Observed:** not yet observed.

## `sandbox-tabs-desktop`: Desktop as a tab with Close confirmation

- **Entry points:** Tab Home Page → **Desktop**, and the `Desktop` tab's close button (`×`).
- **States to exercise:**
  - opening **Desktop** when stopped, starting, or already running;
  - clicking **Desktop** a second time from another Tab Home Page (focuses the existing Desktop tab rather than duplicating it);
  - clicking `×` on a running Desktop tab and choosing Cancel, Keep running, or Stop desktop;
  - clicking `×` on a stopped Desktop tab (removes immediately without prompting).
- **Driving it:**
  1. From the Tab Home Page, click **Desktop**.
  2. Start the desktop and wait for the noVNC canvas to connect.
  3. Click `×` on the `Desktop` tab; verify the native `<dialog>` **Close Desktop tab?** opens with `Cancel`, `Keep running`, and `Stop desktop`.
  4. Choose `Keep running`, verify the tab closes and the desktop stays running (reopening **Desktop** reconnects without restarting).
  5. Click `×` again and choose `Stop desktop`; verify the desktop stops (`/_actions/desktop/stop`) and the tab closes.
- **Proof:**
  - at most one `Desktop` tab exists in the tab bar at a time;
  - `Keep running` closes the WebSocket viewer without calling `/_actions/desktop/stop`;
  - `Stop desktop` calls `/_actions/desktop/stop` and leaves the desktop stopped.
- **Gotchas:** switching away from the `Desktop` tab to a `Terminal` tab pauses the VNC WebSocket so hidden tabs hold no viewer slot.
- **Observed:** not yet observed.

## `sandbox-tabs-agent-composer`: Agent tab composer and cascading agent/model menu

- **Entry points:** Tab Home Page → **Agent**.
- **States to exercise:**
  - opening an Agent tab from the Tab Home Page;
  - opening the Agent/Model/Effort dropdown from the composer pill;
  - hovering Level 1 (`Agent` / `Effort`) → Level 2 (agent list with search filter or effort options) → Level 3 (models for the hovered agent);
  - selecting a model and effort level and closing the menu with Escape or outside click;
  - light and dark themes, desktop and mobile widths.
- **Driving it:**
  1. From the Tab Home Page, click **Agent**.
  2. Verify the centred `Start an agent session` heading sits above the rounded composer bar with equal left, right, and bottom padding around the bottom pill bar and normal placeholder text (`What would you like to work on?`).
  3. Click the agent/model pill to open Level 1 (`Agent` and `Effort`). Verify Level 1 stays anchored above the pill and does not shift when hovering `Agent` or `Effort`.
  4. Verify hovering `Agent` opens only Level 2 (agent list with real brand icons for Antigravity, Claude Code, Codex, and Pi) and hovering an agent opens Level 3 (models for that agent).
  5. Select a model and verify the trigger pill updates with the agent's icon and chosen model name.
- **Proof:**
  - Level 1's viewport bounding box stays fixed while Level 2 and Level 3 open and close;
  - Level 3 does not open until an agent row in Level 2 is hovered or focused;
  - every provider mark uses its real vector icon from `icons.svg` (never generic keys or letter badges).
- **Gotchas:** Slice 1 delivers the Agent tab shell, composer, and cascading picker; live managed agent execution and SSE token streaming land in Slice 2.
- **Observed:** not yet observed.
