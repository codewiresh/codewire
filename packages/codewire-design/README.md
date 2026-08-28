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
loopback, maps the production IBM Plex Mono asset URLs to their checked-in font
files, and does not modify generated or production assets. Open files beneath
`reference/source/` in the design authoring host when editing the original
handoff; use the fixtures for the repository-owned, fully offline preview.

## Conventions

Use the `cw-` prefix for public classes and the documented custom properties
for color, spacing, radius, content width, and overlay shadow. Prefer semantic
HTML and native controls; a class supplies presentation, not application state.
State exposed to CSS uses `aria-*` or `data-*` attributes.

Route modules keep public page URLs clean. Mutations live under `_actions`,
partial HTML under `_fragments`, and event streams under `_events`. Route-local
JavaScript and CSS must be registered as immutable same-origin assets by the
Rust adapter. Do not add inline scripts, eval-dependent HTMX features, dynamic
package runners, package-CDN references, or install-time generation.
