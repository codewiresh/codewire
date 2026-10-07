---
name: codewire-design
description: Codewire dashboard design and frontend patterns, with the proof each needs. Use for any change to dashboard UI, Askama templates in crates/codewire-dashboard-web/templates, design fixtures or CSS in packages/codewire-design, or the browser scripts there, including layout, alignment, loading, failure and retry states, status pills and action labels. Do not use for backend-only, CLI or infrastructure work.
---

# Codewire Design

`AGENTS.md` "HTML and frontend" is authoritative: semantic HTML, links navigate
and buttons act, containers own gutters, repeated controls share one inset,
production and fixture parity, no diagnostic JavaScript in tracked markup, and
the UI iteration checkpoint. Read it first. This skill names the concrete
patterns and proofs that keep those rules true; do not restate them elsewhere.

## Where things live

- Tokens: the `:root` block of `packages/codewire-design/styles.css`.
  Primitives: `styles.css` and `components.css`, each shown in
  `packages/codewire-design/reference/fixtures/components.html`.
- Route CSS: `packages/codewire-design/routes/*.css`, served to production by
  `crates/codewire-dashboard-web/src/assets.rs` and linked by the fixtures.
- Markup: `crates/codewire-dashboard-web/templates/` (production) and
  `packages/codewire-design/reference/fixtures/` (editable fixtures).
- Behaviour: `packages/codewire-design/*.js`, loaded by both.

## 1. Centre trailing actions on the control line

- A row of fields with a trailing action (remove ×, menu, inline button) is a
  `.cw-field-row` (`components.css`). Every `.cw-field` in it spans two lines
  with `grid-template-rows: subgrid`: labels share the first line, controls the
  second. The `.cw-button` or `.cw-icon-button` action sits on the second line
  in the last column, `align-self: center`. A `.cw-field-error` takes a third
  line, so an error or a wrapped label never moves a control off the line.
- Markup adds the route class beside the primitive, for example
  `class="cw-field-row cw-app-port-row"`. Route CSS sets only the columns and
  the narrow layout: see `.cw-repository-row`, `.cw-app-port-row` and
  `.cw-port-form` in `routes/environments.css`.
- Never align with margins, negative offsets, transforms, transparent borders
  or pixel nudges. Never centre an action across the label stack, and never rely
  on `align-items: end` with equal heights; both break when a label wraps or an
  error appears.
- At `max-width: 48rem`, keep the action beside the first control
  (`grid-template-columns: minmax(0, 1fr) auto`, other fields
  `grid-column: 1 / -1`) or move it after the fields on purpose
  (`grid-row: auto`, as `.cw-port-form` does for Add port). No overlap and no
  horizontal scroll.
- Prove it with a spec that compares the action's centre with each control's
  centre (within 1 px) at 1440 and 390, including an error state:
  `expectActionOnControlLine` in
  `apps/dashboard/e2e/ssr-dashboard.repository-picker.ssr.ts`. Run it against
  the previous CSS once and see it fail before trusting it.

## 2. Status and visibility pills

- Use `.cw-badge`: a rounded pill whose text names the state (Private, Public,
  Archived, Unavailable). Colour only reinforces it.
- `data-tone` is `success`, `warning`, `danger` or `info` for statuses, `purple`
  or `orange` for categories, or absent for neutral. GitHub rows use Private
  `purple`, Public neutral, Archived `warning`, Unavailable neutral, grouped in
  `.cw-github-repository-badges`.
- When a pill qualifies a control, keep it inside the control so it is part of
  the accessible name.

## 3. Action labels follow real state

- Derive a label from its source of truth on every change; never keep a second
  flag that can drift. `syncRepositoryActions` in `environments.js` reads the
  form's repository rows (keyed by `repositoryKey`) after input,
  `codewire:form-structure-edited`, each rendered page, search and draft
  restore, and sets "+ Add" or "− Remove".
- Keep one `<button>` per choice whose name starts with the verb: a
  `.cw-sr-only` verb, the name and pills, and an `aria-hidden` visible
  "+ Add"/"− Remove". Do not add `aria-pressed` to a button whose label changes.
- At a limit, disable the actions that would exceed it and say why in visible
  text. Take the limit from the server's constant through the template, as
  `data-repository-limit` does.

## 4. Async regions

- A hidden drawer or dialog must never drop a response silently. Defer the
  request until it is visible (`draftIsOpen`), keep a cancelled request pending,
  and start it again when the container opens (a `MutationObserver` on `hidden`
  and `data-open`, see `resumeRepositories`) or the page returns on `pageshow`
  with `persisted`.
- While loading: `aria-busy="true"` on the region, `.cw-spinner` beside a
  `role="status"` message, `.cw-row-skeleton` rows of `.cw-skeleton` bars while
  nothing is shown, and a "Still loading…" message after about 5 seconds.
- Retry transient failures (no response, timeout, 5xx, 429) twice, after 1 s and
  then 3 s (`transientRetryDelays`), saying "Retrying (n of 2)…". Then show the
  error and a real `<button>` Retry. Show definite failures (a 4xx with a server
  message, an invalid response, reconnect required) at once.
- Keep the existing guards: same-origin endpoints, content type, no `<script>`
  in fragments, sequence numbers with `AbortController`, size and time bounds.
- Animations stop under `prefers-reduced-motion` in `components.css`; add any
  new animation to that block.

## 5. Parity and primitives

- Change a production template and its fixture in the same commit, with the same
  classes, data hooks and route CSS.
- A reusable class goes in `components.css` and is shown in
  `reference/fixtures/components.html`. Use tokens only.
- `python3 scripts/checks/repo_checks.py design-tokens --self-test` fails on:
  - literals outside token files;
  - visual overrides of primitives in route CSS;
  - classes used in templates, fixtures or scripts that no stylesheet defines;
  - primitives missing from the gallery.
  Policy: `scripts/checks/contracts/design-token-policy.json`.

## 6. Semantics

Follow `AGENTS.md`. In short:

- buttons act and links navigate;
- repeated rows are `ul`/`li`;
- every control has a label and every section a heading or name;
- decorative glyphs are `aria-hidden`;
- a `div` only for layout;
- toggle with the `hidden` attribute (the global `[hidden]` rule wins).

## 7. Verification loop

1. Iterate on fixtures with `make design-system`. List new fixture spec files in
   `apps/dashboard/e2e/helpers/design-fixtures.ts`.
2. Gate with `scripts/ci/verify/run-design-fixtures.sh`. It runs desktop 1440
   and mobile 390, and fails on any skip.
3. Pin markup the scripts depend on with `cargo test -p codewire-dashboard-web`.
4. Review in the product on the retained Kind cluster: `make kind-status`, then
   `make kind-watch` (http://nj.example.invalid:4174/, or
   `KIND_WATCH_SOURCE_ROOT=<worktree>`). Walk the empty, loading, failure and
   recovery states. Never recreate the cluster.
5. When visible text, control names or counts change, update
   `apps/dashboard/scripts/dev-ux-walkthrough.ts`, which pins them on Dev.
6. Before landing, run `scripts/dev/preflight.sh --explain` and
   `git diff --check`.
7. Diagnose from specs or scratch scripts under the gitignored `.tmp/`. Never
   add probes, logging or temporary attributes to tracked templates or fixtures.
