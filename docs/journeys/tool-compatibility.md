# Compatible tools and plugins

Spec: `packages/codewire-design/README.md`, “Compatible tools”. The public
homepage introduces the existing Rex and Orca plugins, agent terminal sessions,
and pi-durable composition. It links to the existing setup guides, with the
same marks and setup instructions in the documentation.

## tools-01: homepage to a working setup guide

- **Entry points:** homepage “Compatible with your tools”; documentation
  Integrations index; Rex and Orca guides.
- **States to exercise:** light and dark themes; desktop, tablet and phone;
  JavaScript disabled; automatic agent rotation, manual selection, pause and
  reduced motion.
- **Driving it:** build the docs with `apps/docs/zola/build.sh`, serve the real
  Rust homepage and docs with `make web`, and open the homepage at 1440, 900,
  390 and 320 pixels wide. Follow both plugin links and check their install
  sections. Navigate and pause the agent examples, then enable reduced motion.
- **Proof:** all four cards in a row have the same height and their actions
  align; no horizontal overflow; Rex and Orca retain their official artwork
  and remain readable in both themes; Pi has sharp square edges. Plugin links
  reach the existing guides, the Rex guide shows `cw setup rex`, and the Orca
  guide explains loading `integrations/orca` and approving it in Orca. Agent
  rotation stops when paused, when manually selected, and under reduced motion.
  With JavaScript disabled, the first agent and all setup links remain usable.
- **Gotchas:** Pi and pi-durable are composition examples, not Codewire plugins.
  This change does not alter or requalify the plugins' existing runtime behavior.
- **Observed (2026-11-18):** the Rust `make web` homepage and built docs
  passed browser checks at 1440, 390 and 320 pixels in both themes; the
  design fixture also passed at 900 pixels. All cards align within each
  row, both plugin links open their local guides and load the official marks,
  and manual agent selection and reduced motion work without page errors.
  Automatic rotation and the JavaScript-disabled fallback were also exercised.
  The existing plugin runtime behavior was outside this presentation check.
