# Homepage Safety section

Spec: `packages/codewire-design/README.md`, "Safety panels". The public
homepage shows how the credential proxy keeps an API key outside the VM and
how network egress control decides where an agent may connect. It is a
picture of existing behaviour and changes none of it: the behaviour itself is
proved by [local-vm-credentials-smoke.md](local-vm-credentials-smoke.md) and
[network-and-egress.md](network-and-egress.md).

## safety-01: the two panels explain themselves

- **Entry point:** the homepage, "Choose what your agent can access.",
  between the hero and Compatible tools.
- **States to exercise:** light and dark themes; 1440, 1024, 901, 768, 390
  and 320 pixels wide; reduced motion; JavaScript disabled.
- **Driving it:** serve the real homepage with `make web` and open it at each
  width in both themes. Watch one full loop of about 23 seconds. Press the
  "Your agent" button. Turn on reduced motion and reload. Disable JavaScript
  and reload.

| Step | Expected behavior | Observation |
| --- | --- | --- |
| Watch the credential proxy panel | Requests move down from "Your agent, inside the VM" to "OpenAI, destination", one about every three seconds. Above the VM boundary each reads `Bearer cw-demo-agent-7f2a`; below it, `Bearer sk-demo-9K2mP7vR4t`. Requests stay inside their column and never touch each other or the labels. A request at rest has the boundary in the gap between two of its lines, never through or against its text | Local Rust server, headless Chromium, 2026-11-18: at all six widths in both themes, sampled at 13 points of the loop, requests stayed inside their column, at least 20 pixels apart and clear of the labels; the value read the stand-in above the line and the API key below it. 2026-11-19, design fixture at three times scale: before the fix the resting boundary sat 0.7 pixels inside the text box of the line above and met its descenders; after it, 2.5 pixels below that box and 4 above the credential's at 1440, and on the boundary between the two lines at 390; the local Rust homepage measured the same at 1440 |
| Watch the network egress control panel for one loop | A band moves down rows 1 to 5, one at a time; rows not reached are dim. After the check the band, "Allowed", the rule and the later wires are green. Then `pastebin.com:443` is refused: the band stops on row 2 in red with `Refused: pastebin.com:443 by npm-only rev 1 (name not allowed)`, row 3 reads "Not opened", and rows 3 to 5 and the Internet participant stay dim. Row heights never change between the two runs | Same run: the current row was 1, 2, 2 green, 3, 4, 5, then 1, 2, 2 red; the band matched the current row within a pixel at every sample; the refusal line, "Not opened" and the dimmed rows appeared as described; row heights were identical at every sample |
| Compare the panels at desktop widths, then narrow the window | Both panels are the same height above 900 pixels and stack below; no horizontal scrolling at any width; no clipped label | Same run: equal panel heights at 1440, 1024 and 901; stacked at 768, 390 and 320; no horizontal scrolling and no clipped label at any width or sample |
| Wait, then press the "Your agent" button | The agent mark changes about every three seconds in both panels and the button names it; pressing the button moves to the next agent | Same server, real time: the mark changed in both panels and the button named Claude, Codex, then Cursor, 3.4 to 4.1 seconds apart on a heavily loaded workstation (frames were slow); Enter on the focused button moved Kimi to Pi |
| Scroll the section off screen and back | The animation continues from where it was; nothing runs while it is off screen | Same server: with the section off screen nothing changed over 2.5 seconds; back on screen the requests moved again |
| Turn on reduced motion and reload | Nothing moves: three requests at rest, one across the boundary, and the allowed run finished with all five rows readable. The button still changes the agent | Same server with reduced motion, six widths, both themes: three requests at rest, the allowed run finished, all five rows at full strength; the button moved Claude to Codex |
| Disable JavaScript and reload | One request above the boundary with the stand-in and one below with the API key; the five steps as a list reading the allowed run; no button | Same server with JavaScript disabled, six widths, both themes: one request in each half, the allowed run's text, no wires and no button; equal panel heights above 900 pixels; no horizontal scrolling |

- **Gotchas:** the hosts, the policy name `npm-only` and both credential
  strings are made up. The refusal line follows `cw policy check` in the
  [egress policies](../../apps/docs/zola/content/networking/egress.md)
  documentation; if that wording changes, this section changes with it. The
  caption identifies the local example and points readers to `cw info NAME`
  for a hosted sandbox’s policy and enforcement status.

These are observations of the real Rust homepage served locally with the
`make web` settings, driven by headless Chromium, plus the design fixture's
contract test (contrast, focus and type scale at desktop and phone widths in
both themes). No page or console errors were raised, including under the
page's Content-Security-Policy. The section has not been observed on Dev or in
Production.
