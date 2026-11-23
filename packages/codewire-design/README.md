# Codewire design system

This directory is the framework-neutral, source-owned visual contract for the
server-rendered web application. Production CSS, JavaScript, vectors, and fonts
are compiled into the Rust binary without a package build or browser download.

## Layers

- `styles.css` owns Kernel Dark tokens, reset, shell, navigation, buttons,
  cards, and form primitives.
- `components.css` owns reusable layout, table, dialog, loading, empty, and
  status primitives. Product lanes extend these components instead of adding a
  framework-specific component library.
- `routes/*.css` owns styles that are meaningful to only one route family.
  Full-page templates opt into a route sheet explicitly; fragments rely on the
  sheet already loaded by their containing page.
- `assets/logo.svg` and `assets/icons.svg` are reviewed local vectors. The icon
  sprite is referenced with same-origin `<use>` elements and never from a CDN.
- `dashboard.js`, route scripts, and HTMX are narrowly scoped progressive-
  enhancement adapters. No-JavaScript forms and links remain the functional
  baseline.
- `reference/source/` preserves the editable HTML authoring handoff. These
  files are visual source material, not production templates. Their local
  `runtime.js` accepts authoring-host React, ReactDOM, and optional Babel only
  through explicit same-origin `window.__resources` entries; it never falls
  back to a package CDN.
- `reference/fixtures/` exercises production CSS and components without a
  running backend. Use these pages for token, component, and state review
  before translating a change into the Askama templates.

Run `make design-system`, then open
`http://127.0.0.1:4174/reference/fixtures/`. The static server binds only to
loopback, maps the production font asset URLs to their checked-in font
files, and does not modify generated or production assets. Open files beneath
`reference/source/` in the design authoring host when editing the original
handoff; use the fixtures for the repository-owned, fully offline preview.

`make design-check` runs the fixture browser specs against these pages at desktop
and mobile widths, with the pinned Chromium. The `web` verification gate runs the
same check.

## Conventions

Use the `cw-` prefix for public classes and the documented custom properties
for color, spacing, radius, content width, and overlay shadow. Prefer semantic
HTML and native controls; a class supplies presentation, not application state.
State exposed to CSS uses `aria-*` or `data-*` attributes.

Text action buttons use the pill radius in both the dashboard and the public
site. The public site's segmented controls use a pill track with a small inset
and fully rounded selection buttons. The selected segment is identified by
`aria-pressed`, with the inverse foreground and background colors; rounding
does not change selection or keyboard behavior. Standalone icon controls retain
their existing presentation. The public-site scale owns its radius and segment
inset tokens in `routes/public.css`.

The review and verification steps are in
[`docs/journeys/public-controls.md`](../../docs/journeys/public-controls.md).

`python3 scripts/checks/repo_checks.py design-tokens` enforces these
conventions in Policy, locally and in CI. Literal font sizes, line heights,
colors, radii, shadows, and spacing live only in the `:root` token block of
`styles.css` (and of `routes/public.css`, which resolves against its own
tokens); route sheets and fixtures reference `var(--token)` without fallbacks.
The guard also rejects `!important`, removed focus outlines, route-level
overrides of core primitives, undefined tokens and `cw-` classes, native
controls without their primitive class, inline styles, and core primitives
missing from `reference/fixtures/components.html`. There is no baseline of
exceptions: every violation fails. `--self-test` proves each rule on in-memory
fixtures.

Route modules keep public page URLs clean. Mutations live under `_actions`,
partial HTML under `_fragments`, and event streams under `_events`. Route-local
JavaScript and CSS must be registered as immutable same-origin assets by the
Rust adapter. Do not add inline scripts, eval-dependent HTMX features, dynamic
package runners, package-CDN references, or install-time generation.

The homepage template and `reference/fixtures/home.html`
share `routes/public.css` and `public.js`. Fonts are vendored under
`crates/codewire-dashboard-web/assets/fonts/` and recorded in `.supplychain/vendor-artifacts.json`. The Rust
asset tests verify homepage parity after resolving fixture asset paths.
Sign-in, sign-up and the other account pages sit on plain black
(`--bg-auth`). The auth template and `reference/fixtures/login.html`,
`reference/fixtures/login-preview.html` and `reference/fixtures/signup.html`
share `routes/auth.css`. `login-preview.html` is the same sign-in reached from
the private-preview redirect: only its title and one fixed context line differ.

## Homepage opening

The opening headline reads “Sandboxes for agents and humans.” The line break
after “for” holds at phone and desktop widths. The subhead follows one
subhead em below. The install prompt verifies the CLI, then lets the reader
choose a local or hosted sandbox. The homepage labels hosted signup “Request
cloud access”. The acceptance journey is `docs/journeys/agent-quickstart.md`.

## Compatible tools

The homepage's “Compatible with your tools” section links to the existing Rex
and Orca plugin guides, running an agent in a persistent session, and the
upstream pi-durable runtime. Four frosted cards share the public grid,
registration marks and pill actions, with equal heights within each row.
The agent card shows the supported tools' marks at the same size as the other
cards, rotates while visible, and supports manual selection and pause.
Reduced motion keeps it still. Rex and Orca documentation uses the same artwork.
The acceptance journey is `docs/journeys/tool-compatibility.md`.

## Safety panels

The homepage's Safety section, "Choose what your agent can access.",
sits between the install prompt and Compatible tools. Two frosted panels share one row grid, so they are the
same height side by side, and stack at 900 pixels and below. All values shown
are made up.

- **Credential proxy.** Example requests stream from the agent inside the VM,
  across the VM boundary, to the destination. Each request is drawn twice, one
  copy clipped above the boundary and one below it, so its `Authorization`
  value changes from a stand-in to the API key exactly on the line.
- **Network egress control.** Five steps run twice: a destination the example
  policy allows, then one it refuses at the check, in the words
  `cw policy check` prints. One band steps down the rows and the steps not yet
  reached stay dim. Allowed is green and refused is red (`--ok` and `--no`,
  the code samples' green and red). The refused run stops at the check.
- The example agent's mark changes every three seconds in both panels, and a
  button steps it by hand. The marks are the ones in the get-started box.
- The panels draw only while they are on screen. With reduced motion they
  hold one picture: three requests at rest and the allowed run finished.
  Without JavaScript the same markup is a still picture: one request before
  and after the boundary, and the five steps as a list.
- The copy follows the documentation: a local VM enforces its network policy,
  a hosted sandbox reports its enforcement status in `cw info`, and keeping a key
  outside the VM is a different guarantee from egress control.

`public.js` reads the section's markup; `cargo test -p codewire-dashboard-web`
pins what it reads. The acceptance journey is
`docs/journeys/homepage-safety.md`.
