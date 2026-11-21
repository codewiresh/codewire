# Keyboard focus in the dashboard

This walk proves that a keyboard user is never sent back to the top of a
dashboard page: the Create Sandbox drawer is a modal that gives focus back
to whatever opened it (#4531), and a control waiting on its own request
keeps focus (#4533). The rules are in the `codewire-design` skill, section
"Keyboard focus". The format is in [README.md](README.md).

## `drawer-modal`: the Create Sandbox drawer is modal

Issue: #4531. Code: `packages/codewire-design/dashboard.js`.

- **Entry points:** Create Sandbox in the sidebar, on the Sandboxes page
  and in its empty state; the `/ORG/sandboxes/new/` URL opened directly;
  Edit sources on a Sandbox, which opens the same drawer.
- **States to exercise:**
  - opened from a trigger, by keyboard and by pointer;
  - opened at page load from its URL;
  - closed with Escape, with its close button and with the backdrop;
  - closed with a dirty form, which asks first, then cancelled and then
    discarded;
  - a field-help popover and the discard dialog open above it;
  - desktop 1440 and phone 390.
- **Driving it:** on Kind or Dev, sign in, open the Sandboxes page and tab to
  Create Sandbox, press Enter, then:
  1. Tab and Shift+Tab around the drawer for more than one lap.
  2. Open a field-help popover and close it.
  3. Press Escape.
  4. Open the drawer again with the pointer, type a name, and click the
     backdrop; cancel the discard dialog, then click the backdrop again and
     discard.
  5. Open `/ORG/sandboxes/new/` directly, close it with its close button.
  6. With a screen reader, list landmarks while the drawer is open.
- **Proof:**
  - Tab never leaves the drawer: no stop is a sidebar link, the page header
    or a row of the Sandboxes list.
  - The sidebar, header and list can't be clicked or focused while the
    drawer is open; the popover and the discard dialog work above it.
  - After each close, `document.activeElement` is the Create Sandbox
    control that opened it; after step 5, it is the page's Create Sandbox
    button.
  - The screen reader lists only the drawer's dialog.
  - Fixture spec: `apps/dashboard/e2e/ssr-dashboard.creation-disclosure.ssr.ts`,
    "the Create drawer is modal and returns focus to its opener".
- **Gotchas:** the focus walk must start after the page's first frame, as
  the design-contract walk does (#4529); before it, focus may still be
  moving to Name.
- **Observed:** not yet observed.

## `pending-keeps-focus`: a control waiting on its request keeps focus

Issue: #4533. Code: `packages/codewire-design/preview-ports.js`,
`packages/codewire-design/sandbox-resize.js`,
`packages/codewire-design/dashboard.js`,
`packages/codewire-design/durable-terminal.js`,
`packages/codewire-design/environments.js`.

- **Entry points:** each control below, reached with Tab and pressed with
  Enter or Space:
  - Copy preview URL, in a Sandbox's Ports dialog;
  - Review resize, Apply and Check status, in the Resize dialog;
  - Connect, in a Credentials device sign-in dialog;
  - Retry, Refresh sessions, Rename's Save and a tab's Remove, on the
    Sandbox page;
  - Restore draft, in Create Sandbox.
- **States to exercise:** a slow request (held about 3 s), then its success;
  a slow request, then its failure; a second press while it waits.
- **Driving it:** on Kind, open each control's page, hold its request with
  the browser's network throttling, and press the control from the keyboard.
- **Proof:**
  - While the request runs, the control keeps its focus ring, reads as
    unavailable (dimmed, `aria-disabled="true"`), and a second press sends no
    second request.
  - When it ends, focus is still on the control, or, where the step
    replaces it (Review resize moves to Back, Restore draft to Name), on
    that next control, never on `<body>`.
  - Retry hides while it re-lists, so focus moves to its status line
    ("Opening a terminal…"), then to the terminal's tab when it opens, or
    back to Retry if it fails again.
  - Connect hides with the sign-in form, so focus moves into the view that
    replaces it: the "Requesting a sign-in code…" status, then the code's
    Open link, or Try again after a failure, which returns focus to the
    form.
  - Fixture specs, each with a held request, at 1440 and 390 where the
    control exists at both:
    - `apps/dashboard/e2e/ssr-dashboard.preview-ports.ssr.ts`, "Copy URL
      keeps keyboard focus while it copies and after";
    - `apps/dashboard/e2e/ssr-dashboard.resize.ssr.ts`, "Review resize keeps
      keyboard focus while its plan is pending, on success and refusal";
    - `apps/dashboard/e2e/ssr-dashboard.credential-dialogs.ssr.ts`, "device
      sign-in moves focus into each view it shows";
    - `apps/dashboard/e2e/ssr-dashboard.durable-terminal.ssr.ts`, "Retry
      hands focus to its status line while it re-lists, then to the terminal
      it opens";
    - `apps/dashboard/e2e/ssr-dashboard.creation-disclosure.ssr.ts`,
      "Restore saved draft keeps keyboard focus while it restores, then hands
      focus to Name".
  - Apply, Check status, Refresh sessions, Rename's Save and a tab's Remove
    use the same change as the controls above, with no test of their own
    yet; the Kind walk covers them.
- **Gotchas:** Chromium drops focus from a button the moment it becomes
  `disabled`; a check that refocuses the control afterwards hides the bug.
  Read `document.activeElement` without focusing anything first.
- **Observed:** not yet observed.
