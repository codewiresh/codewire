# Agent-friendly first sandbox

The homepage offers a copyable install prompt above its manual install command.
It preserves the registration marks, grid and frosted surface. The supported
agent marks use the foreground color with muted 1px circular outlines in both
themes; Codex uses the OpenAI knot. Agent names sit below the marks, with the
no-account note to their right.
Read the install prompt sits under Copy install prompt. Text actions use pills.

The quickstart begins with plain prompt text and a Copy prompt button in its
upper right. A complete human walkthrough follows: install, optional Git
credential, create, build and run, open the app, stop and remove. The public
React, TanStack Router and Vite repository is `codewiresh/example`. Its dev
server runs inside the sandbox as a named session on port 3000. Neither the
public clone nor a local VM requires an account or credential. Private Git
access uses an explicitly selected profile; credentials never appear in the
example source or copied prompts.

| Step | Expected behavior | Observation |
| --- | --- | --- |
| Read the headline, then copy the install prompt | “Sandboxes for” and “agents and humans.” occupy one line each. The prompt installs the CLI, verifies it, and asks where to run the first sandbox | Chromium on the editable fixture at 320, 390, 760, 901, 1024 and 1440 pixels in both themes. Each headline line fits, the subhead gap is one em, and both copy controls write the expected text, 2026-11-23 |
| Inspect the overlapping agent icon outlines in both themes | Each icon keeps its foreground color with a muted 1px outline in light and dark mode | Local Rust homepage: all seven borders measure 1px at 35% opacity, while icon color and opacity remain unchanged in both themes, 2026-11-17 |
| Open homepage at desktop and mobile widths in both themes | Grid, registration marks and frost remain; readable agent marks; no horizontal overflow | Observed in the local Rust application, Chromium, 1440px and 390px, light and dark, 2026-11-17 |
| Copy setup prompt and install command | Exact text reaches clipboard; control shows Copied then returns to its normal label; failure remains retryable | Exact clipboard text and Copied observed on both pages; fallback, failure, retry and label reset also observed at 320px, 2026-11-17 |
| Switch Independent/Mesh and pricing selections | Pill track and inset selection stay readable and keyboard accessible | Independent/Mesh switched in the local application; homepage and pricing contrast, focus and overflow checks passed at desktop/mobile in both themes, 2026-11-17 |
| Open quickstart and copy its prompt and commands | Prompt precedes human steps; small copy glyphs are 12px; copied states remain visible | Observed in the local application at both widths and themes; Markdown export retains prompts, 2026-11-17 |
| Clone codewiresh/example and follow local walkthrough | Install/build run inside VM; counter, navigation and route refresh work through published port | Published example revision 8640876 installed and built inside a fresh local VM; counter, navigation and refresh observed through its published port, 2026-11-17 |
| Stop and start local VM | Disk and port mapping remain; a new named dev session restores the app | Stop/start and a fresh dev session succeeded without a profile, 2026-11-17 |
| Add optional task-only SSH profile | Profile selection is explained; observed attachment failures are recorded separately, never presented as successful | Attachment restart failed on Linux cw v0.4.21; recorded on Program #3013, tracked by #5220. Successful credential attachment remains unverified |
| Follow hosted walkthrough | Create, install, build and private preview work; stop and remove touch only task resources | Dedicated Production smoke identity created its own sandbox, installed/built/served the published repository, registered creator access, stopped and removed it, 2026-11-17. Signed-in private-preview browser access was not exercised |

These observations are local source and CLI checks. The site changes have not
been delivered to Dev or Production. The retained Kind ingress was unavailable;
the homepage and docs were reviewed through the actual Rust web server with
`make web` instead.
