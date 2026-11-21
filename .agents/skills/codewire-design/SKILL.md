---
name: codewire-design
description: Codewire dashboard design and frontend patterns, with the proof each needs. Use for any change to dashboard UI, Askama templates in crates/codewire-dashboard-web/templates, design fixtures or CSS in packages/codewire-design, or the browser scripts there, including layout, alignment, loading, failure and retry states, status pills and action labels. Do not use for backend-only, CLI or infrastructure work.
---

# Codewire Design

This skill is the one home of the dashboard rules; `AGENTS.md` keeps only the
UI iteration checkpoint, which gates landing. Do not restate these elsewhere.

- Never inject disposable diagnostic JavaScript, inline browser probes,
  temporary data attributes, console logging, forced scrolling or similar
  instrumentation into tracked product templates or editable design fixtures,
  even to remove it before handoff. Diagnose from external browser or
  repository-owned test tooling; if that is unavailable, use static evidence
  and existing checks or report the verification gap. Tracked JavaScript
  implements intentional product behaviour or a durable repository-owned test.
- Use native semantic HTML throughout the product and editable design
  fixtures. Landmarks, headings, sections, navigation, lists, tables, forms,
  labels, links and buttons describe their actual purpose; a `div` or `span`
  only when no native element conveys meaning and the element is strictly for
  layout or text styling. Links navigate; buttons perform actions. Navigation
  collections and repeated rows use lists. Every section has a real heading or
  an accessible name, every form control has a label, and table headers declare
  their scope. Prefer native semantics over recreating them with ARIA.
- A container owns its outside gutter. Repeated controls own one shared inside
  padding through a reusable row primitive. Align related content with that
  common inset, never per-element margins, negative offsets, transparent border
  compensation or independent wrappers.
- Keep production templates and editable `packages/codewire-design` fixtures
  on the same tokens, components and route CSS. A fidelity change is incomplete
  when only the fixture or only the production template changes.
- During active iteration use `make kind-watch` against the retained local
  cluster; use `make design-system` only for fixture-only work. Image rebuilds
  need no separate approval. Run `scripts/dev/preflight.sh --explain` before
  the landing gate; if a UI-only change is unclassified or selects integration,
  Kind or full verification only because classification is missing, repair the
  classifier or split the unrelated change. Stop the Kind-backed dashboard
  watcher before Kind verification so its exit handler releases the forwards.
  Reuse existing visual coverage and add only the smallest behavioural or
  accessibility assertion that protects a real regression.

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

### Text inside single-line controls

- Single-line controls carry no leading. `line-height: var(--leading-none)` is
  set on `.cw-button`, `.cw-icon-button`, `.cw-badge`, `.cw-status--pill`,
  `.cw-toggle-chip > span`, `.cw-field-help-trigger` and
  `.cw-github-repository-action`.
- Size them with `min-height` and padding, never with the line box. A pill's
  `min-height` is one UI line plus its border.
- Centre the capitals, not a line box. Where
  `text-box: trim-both cap alphabetic` is supported (the block at the end of
  `styles.css`):
  - a text-only `.cw-button`, `.cw-badge` or chip becomes a one-line block,
    centred with `align-content: center`;
  - a `<span>` label inside a `.cw-button` is trimmed.
- The trim cannot reach a bare text node beside an icon. A `.cw-button` (a
  `button`, link or `summary`) that holds an icon, a spinner, a `.cw-sr-only`
  name or any other element keeps its visible label in a plain `<span>`:
  `<a class="cw-button" href="new/"><svg class="cw-icon" aria-hidden="true">…</svg><span>Create Sandbox</span></a>`
  and `<button class="cw-button"><span>Reconnect</span><span class="cw-sr-only"> Work Codex</span></button>`.
  The accessible name does not change. A text-only button needs no span.
- Guards: the `markup` rule of
  `python3 scripts/checks/repo_checks.py design-tokens` rejects a bare label
  beside an element in templates and fixtures, and the per-fixture spec in
  `apps/dashboard/e2e/ssr-dashboard.design-system.ssr.ts` rejects it in the
  rendered fixtures, including hidden dialogs and `<template>` content.
- Prove centring with `capitalsOffset` in the same spec: it measures the
  capitals' centre against the control's padding box and must be within
  0.75 px at 1440 and 390. "buttons with an icon centre their label's
  capitals" covers Create Sandbox, Add custom Git URL, Reconnect and Back.

## 2. Anchor lines

Owner, 2026-11-10: "there should be a grid, gutters, standard spacing that
just works for this. that is methodical. left and right both have these
anchoring vertical". On the Sandbox page: "just make sure that the plus sign
and the arrow … and the banners are all left aligned on the same line …
simple." Don't over-tune: no optical offsets for text.

- **The sidebar** (`routes/dashboard.css`) is a grid: a leading mark column,
  the text and a trailing mark column. The centre of each mark column is an
  anchor line, `gutter + row padding + mark / 2` from the edge.
  - Marks centre on it: the logo's c, the badges, the create plus, the sort
    icon, the rail's dots, the footer icons, and on the right the chevrons,
    the collapse and view-all icons and the region labels.
  - A row with no mark, such as the Admin label and links, starts on the left
    line.
  - The phone's drawer is the same sidebar.
- **A page column** has one left line, its gutter. Boxes such as notices and
  banners start on it. A leading icon button (back, new) starts before it by
  its inset around the icon plus `--icon-glyph-inset`, so the visible glyph
  meets the line: `--cw-workspace-icon-start` in `routes/terminal.css`.
- **Derive every line from tokens.** A row reaches its line through padding
  or the primitive's hook, such as `--nav-link-padding-start`. To move
  everything, change the gutter, never one element.
- **Prove it** with `expectOnAnchorLines`
  (`apps/dashboard/e2e/helpers/anchor-lines.ts`), within 1 px, at 1440 and 390:
  - the sidebar and drawer in `ssr-dashboard.anchor-lines.ssr.ts`;
  - the Sandbox page in `ssr-dashboard.durable-terminal.ssr.ts`.

  A new mark, row or column of chrome adds its check there. Run the check
  against the previous CSS once and see it fail.

## 3. Status and visibility pills

- Use `.cw-badge`: a rounded pill whose text names the state (Private, Public,
  Archived, Unavailable). Colour only reinforces it.
- `data-tone` is `success`, `warning`, `danger` or `info` for statuses, `purple`
  or `orange` for categories, or absent for neutral. GitHub rows use Private
  `purple`, Public neutral, Archived `warning`, Unavailable neutral, grouped in
  `.cw-github-repository-badges`.
- When a pill qualifies a control, keep it inside the control so it is part of
  the accessible name.

## 4. Action labels follow real state

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

## 5. Async regions

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

## 6. Parity and primitives

- Change a production template and its fixture in the same commit, with the same
  classes, data hooks and route CSS.
- A reusable class goes in `components.css` and is shown in
  `reference/fixtures/components.html`. Use tokens only.
- An empty state is `.cw-empty`: a title, its copy, at most one action, then
  at most one `.cw-empty-hint` (such as the `cw` command that does the same).
  The space between them comes from the primitives and `--empty-state-gap`,
  never from margins on the page (owner, 2026-11-16, #5112).
- A page header whose title and primary action must stay on one line, with
  the description below, is `.cw-page-header--stacked`: a
  `.cw-page-header-row` holding the title and the action, then the
  description. On a phone the title steps down a size; the action never
  wraps under it (owner, 2026-11-16, #5113). Whether an existing page adopts
  it is the owner's call.
- Both are measured in `ssr-dashboard.design-system.ssr.ts` ("an empty
  state's hint sits one token below its action…") at 1440 and 390.
- `python3 scripts/checks/repo_checks.py design-tokens --self-test` fails on:
  - literals outside token files;
  - visual overrides of primitives in route CSS;
  - classes used in templates, fixtures or scripts that no stylesheet defines;
  - primitives missing from the gallery.
  Policy: `scripts/checks/contracts/design-token-policy.json`.

Credentials and profiles on screen use the words in `docs/GLOSSARY.md`,
"Words users see: credentials".

## 7. Semantics

The semantic HTML rule at the top of this skill, in short:

- buttons act and links navigate;
- repeated rows are `ul`/`li`;
- every control has a label and every section a heading or name;
- decorative glyphs are `aria-hidden`;
- a `div` only for layout;
- toggle with the `hidden` attribute (the global `[hidden]` rule wins).

## 8. Verification loop

1. Iterate on fixtures with `make design-system`. List new fixture spec files in
   `apps/dashboard/e2e/helpers/design-fixtures.ts` and in the fixture case of
   `scripts/ci/select/select-verification.sh`.
2. Gate with `scripts/ci/verify/run-design-fixtures.sh`. It runs desktop 1440
   and mobile 390, and fails on any skip.
3. Pin markup the scripts depend on with `cargo test -p codewire-dashboard-web`.
4. Review in the product on the retained Kind cluster: `make kind-status`, then
   `make kind-watch` (http://localhost:4174/, or
   `KIND_WATCH_SOURCE_ROOT=<worktree>`). Walk the empty, loading, failure and
   recovery states. Never recreate the cluster.
5. When visible text, control names or counts change, update
   `apps/dashboard/scripts/dev-ux-walkthrough.ts`, which pins them on Dev.
6. Before landing, run `scripts/dev/preflight.sh --explain`,
   `python3 scripts/checks/repo_checks.py live-state` and `git diff --check`.
7. Diagnose from specs or scratch scripts under the gitignored `.tmp/`. Never
   add probes, logging or temporary attributes to tracked templates or fixtures.

## 9. Live state

Owner, 2026-11-14 (codewire#3013): Server-Sent Events are the default for
live state, and pages don't poll for it. Design: private-docs
`designs/live-updates.md`; build: codewire#4762.

- A page learns that state changed from the shared stream: `live.js` opens
  `/_events/live` once per page. A live region subscribes to its kind and
  re-fetches its own fragment, for example
  `hx-trigger="codewire:live:sandbox from:body"`, and refreshes on
  `codewire:live:resync`. Events carry ids only; the fragment request
  authorizes as usual.
- Never poll for state the server knows: no htmx `every`, no `setInterval`, no
  `setTimeout` loop that fetches. If the stream has no event for your state,
  add the database notification and the event, not a timer.
- Allowed timers:
  - `live.js`'s own fallback when the stream is busy or unavailable;
  - client-only timers that fetch nothing, such as an elapsed-time display or
    an animation;
  - retries with backoff after a failed request (section 5). A retry is not a
    poll.
- Setup progress keeps its own per-Sandbox stream (`setup-progress.js`); a page
  opens it on `codewire:live:setup`.
- Until the stream lands, a region that must update live waits for it. A poll
  that can't wait goes on the allow-list under its issue.
- **Guard:** `python3 scripts/checks/repo_checks.py live-state` fails on an
  htmx `every` trigger, a `setInterval(`, or a `setTimeout(` that schedules
  the function it is written in, in templates, the dashboard's Rust sources
  and `packages/codewire-design`, unless it is listed in
  `scripts/checks/contracts/live-state-allowlist.json`. A poll's entry names
  its issue and the step that removes it; a client-only timer or a bounded
  self-rescheduling retry says why. The list only shrinks.
- **Review checklist:** this change adds no periodic request; every live
  region subscribes to a `codewire:live:*` event, refreshes on `resync`, and
  still shows the right state after the stream reconnects.

## 10. Keyboard focus

Journey: `docs/journeys/dashboard-keyboard.md`.

- **A drawer is modal.** While a `[data-drawer]` is open, everything outside
  it is `inert`, except native dialogs and popovers that open above it. Tab
  and Shift+Tab stay inside the panel, and its first field takes focus on
  the first frame unless focus is already inside. Escape, the close button
  and the backdrop close it, and focus returns to the control that opened it.
  Opened at page load, there is no opener, so focus goes to the page's
  Create Sandbox trigger (#4531).
- **A control waiting on its own request keeps focus.** While the request
  runs, mark the control `aria-disabled="true"` and have its handler ignore
  presses; never set `disabled` mid-interaction, because a focused control
  that becomes disabled sends focus to `<body>`. Keep `disabled` for a
  control that does not apply at all. `.cw-button`, menu items and terminal
  tab buttons style `aria-disabled` the same as
  `:disabled` (#4533).
- **Prove it** with a held request in a fixture spec: activate the control by
  keyboard, hold its response, and assert that `document.activeElement` is
  still the control while the request runs and after it ends, on success and
  on failure.
