# Dashboard end-to-end testing

The dashboard Playwright suite validates the server-rendered Rust application
against the real Rust control plane. Kind is the canonical full-stack test
topology because environment creation needs ingress, the sandbox controller,
Temporal, Kubernetes resources, and the same service boundaries used by the
shipped application.

Local verification is the development loop. Reproduce and fix product and
integration failures locally; hosted CI confirms the merged tree afterwards.

## Canonical commands

Run the complete isolated product gate, including the full Playwright suite:

```bash
make e2e-kind
```

This creates and removes a dedicated cluster. For bounded diagnosis only, use
a unique `KIND_CLUSTER_NAME` with `KEEP_KIND_CLUSTER=1`.

To test an already deployed interactive `kind-codewire` stack:

```bash
make up
make seed-e2e-users
make test-ui-kind
```

The seed command creates the documented manual-login identities in a new local
database. The final command does not rebuild the stack. It verifies the
dashboard, IdP, and orchestration rollouts, checks that the dashboard public
origin is `http://127.0.0.1:8080`, manages the Kind Postgres forward, and runs
every browser test through that origin.

For a focused interactive-Kind rerun, pass Playwright selectors directly to
the underlying script:

```bash
scripts/dev/kind/test-dashboard-kind.sh \
  apps/dashboard/e2e/ssr-dashboard.auth.ssr.ts

scripts/dev/kind/test-dashboard-kind.sh \
  apps/dashboard/e2e/ssr-dashboard.environment-lifecycle.ssr.ts
```

The gate requires the repository-pinned Chromium version that matches
Playwright. CI provisions it before the test and passes it in
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH`. Without that variable, the Kind browser
suite and the design-fixture runner use the pinned build already unpacked in
this checkout's `.tmp/`, or install it there with the checksum-verifying
`scripts/ci/install-pinned-playwright-chromium.sh`. The verified archive is
cached in `~/.cache/codewire/chrome-for-testing/`, so a new worktree unpacks it
without downloading again.

Visual baselines are renderer-specific. An ordinary local run uses the
automatic `linux` snapshot suffix. The `ubuntu24-cft145` suffix is reserved for
the pinned Ubuntu 24.04 CI renderer; the browser preflight verifies its OS,
Fontconfig/FreeType packages, Fontconfig configuration, and font inventory
before Playwright starts. Generate or update that baseline only inside the
runner-equivalent image. Never copy a locally rendered image into the Ubuntu
baseline merely because the pixels look similar.

The Playwright browser itself is DNS-isolated to `localhost` and
`127.0.0.1`. Provision browser binaries and other immutable inputs before the
suite starts; a browser test must not fetch public dependencies or generate
background Internet traffic.

Do not add a browser download to the test path. Install the frozen JavaScript
dependencies without lifecycle scripts:

```bash
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  bun install --frozen-lockfile --ignore-scripts
```

The integrated Kind gate requires at least 1 GiB from a short writable temp
root before building or importing images. If `TMPDIR` is unset and `/tmp` is
too full, it selects `XDG_RUNTIME_DIR` or `/dev/shm`; an explicitly configured
`TMPDIR` fails closed instead of being replaced. The browser then uses
`/dev/shm` when it has at least 1 GiB free. These preflights keep a saturated
host `/tmp` from surfacing as misleading image-import, renderer, or network
failures.

## Test projects

`apps/dashboard/playwright.config.ts` defines these projects:

| Project | Purpose |
|---|---|
| `setup` | Performs a real Rust form login and proves the dashboard and scoped HttpOnly session cookie |
| `dashboard-ssr-desktop` | Runs the complete server-rendered behavior suite at desktop size |
| `dashboard-ssr-mobile` | Runs the specs that check the mobile layout, listed in `e2e/helpers/mobile-layout.ts`; their desktop-only secret and lifecycle mutations are explicitly skipped |
| `design-fixtures-desktop`, `design-fixtures-mobile` | Run the editable design-fixture specs at 1440 and 390 pixels; defined only when `CODEWIRE_DESIGN_ORIGIN` is set, as `make design-check` does |

No project depends on `setup`: every spec signs in as its own worker identity,
so nothing waits for the shared login. A spec belongs in the mobile project
when one of its tests checks the mobile layout; `e2e/helpers/mobile-layout.test.ts`
fails when a spec with a mobile check is missing from the list, or a listed
spec no longer has one. There are no `chromium`, `lifecycle`, `signup`,
`billing`, or `oidc` projects; those were names from the retired React suite.

Every run writes a JSON report, with each test's duration, retries and
outcome, to `apps/dashboard/test-report/results.json`. The CI dashboard leg
uploads it from every run, green or red.

## Parallel workers and identity isolation

The config keeps `workers: 1` for direct runs; `--workers=N` opts in, with 4 as
the ceiling (sandbox pods contend on a small Kind cluster). The CI dashboard
leg and `make kind-test` run four workers; `CODEWIRE_KIND_DASHBOARD_WORKERS`
sets another count, and the full local gate keeps one. The real Sandbox
lifecycle (`ssr-dashboard.environment-lifecycle.ssr.ts`) has its own spec and
organization, so it runs on one worker while the serial Create checks run on
another.

Each Playwright worker process acts as its own master-class seeded identity,
`e2e-worker-<workerIndex>@codewire.sh`. Global setup seeds identities up to the
ceiling (4); a higher `--workers` count self-seeds lazily. Specs that drive the
browser as the seeded account import `test` from `e2e/helpers/test.ts` instead
of `@playwright/test`: the worker-scoped `workerStorageState` fixture issues a
real session for the worker identity (two-factor bypassed like the other
synthetic specs, no UI round-trip) and supplies it as the test's storage state,
including to no-JavaScript contexts that accept the `workerStorageState`
fixture explicitly. The `setup` project still performs the single real form
login as the shared `e2e-master` smoke proof.

Isolation rules for new and edited specs:

- Never mutate the shared seeded identities (`USERS.master`, `USERS.admin`,
  `USERS.outsider`, …). Resolve the owning identity with
  `ensureWorkerIdentity(testInfo.workerIndex)` in hooks, or seed a disposable
  `e2e-<purpose>-<run id>` user like the admission and picker specs do.
- Organization slugs must be unique per project run
  (`<purpose>-${Date.now()}-<random>`). A fixed slug lets one worker delete an
  organization another worker is still testing; global setup only wipes
  `e2e-%` slugs at run start.
- Personal secret stores, API key inventories, and Git identity belong to the
  worker identity, so spec-created rows must use run-unique keys/names and be
  removed by the spec that created them.
- Design-fixture specs keep their empty `storageState` override and never
  touch the seeded stack.

## Required behavior coverage

The suite under `apps/dashboard/e2e/` covers:

- real signup, 2FA setup, sign-out, fresh login, and 2FA challenge;
- password reset with the token moved from the URL to a scoped HttpOnly
  cookie;
- OIDC discovery and published Ed25519 keys, browser PKCE, CLI device
  authorization, refresh, revocation, UserInfo, and a bearer-authenticated
  product RPC;
- dashboard shell, public/auth routes, homepage motion, responsive behavior,
  and no-JavaScript form fallbacks;
- organization creation, members, invitations, roles, assignments, and API
  key lifecycle;
- organization, user, and project secrets plus environment presets;
- Git identity settings and manual repository URL, branch, and mount entry;
- billing and admin rendering through server-side clients; and
- direct environment creation, including typed rejection of an unknown
  repository-only configuration, plus real Kind running state, terminal,
  exposed port, stop, restart, and destruction.

The real environment lifecycle is mandatory in the desktop gate. It must not
be hidden behind an opt-in environment variable.

## Full-stack invariants

- `PLAYWRIGHT_BASE_URL`, `SERVER_URL`, the dashboard public origin, and the IdP
  frontend/issuer origin must describe one coherent Kind edge. Mixing
  `localhost` and `127.0.0.1`, or combining a standalone dashboard with an
  absent API on port 8080, is not a valid full-stack result.
- Login setup must observe `POST /login/_actions/sign-in`, require its redirect,
  render the authenticated dashboard, and prove `codewire.session_token` is
  HttpOnly. Merely reaching `/dashboard` is insufficient.
- Product mutations go through the Rust page actions and server-side service
  clients. Browser request observers assert that pages do not quietly restore
  direct Connect/REST ownership.
- Database helpers may seed, verify, inspect, and clean deterministic fixtures;
  they do not replace the user-visible mutation being tested.
- Tests that handle one-time API keys, secret values, credentials, TOTP seeds,
  or OAuth tokens disable screenshots and traces so artifacts do not become a
  second secret store.
- Environment images are immutable digest references. Do not introduce a
  floating registry tag into lifecycle evidence.

## Static users and setup

`apps/dashboard/e2e/global-setup.ts` seeds the following local fixtures through
`POST /api/auth/sign-up`, verifies them in the test database, assigns the admin
flag where required, clears rate limits, removes stale `e2e-` organizations,
and removes stale sandbox fixtures.

| Role | Email | Admin |
|---|---|---|
| master | `e2e-master@codewire.sh` | no |
| owner | `e2e-owner@codewire.sh` | no |
| member | `e2e-member@codewire.sh` | no |
| outsider | `e2e-outsider@codewire.sh` | no |
| admin | `e2e-admin@codewire.sh` | yes |
| billing | `e2e-billing@codewire.sh` | no |

The synthetic password and roster live in
`apps/dashboard/e2e/helpers/seed.ts`. The generated authenticated storage file
under `apps/dashboard/playwright/.auth/` and Playwright reports are ignored by
Git.

## Design fixture browser specs

`make design-check` runs every spec listed in
`apps/dashboard/e2e/helpers/design-fixtures.ts` against the editable fixtures in
`packages/codewire-design/reference/fixtures/`, at 1440 and 390 pixels, with the
pinned Chromium. It needs no dashboard, database or Kind cluster. It serves the
fixtures on the first free loopback port from 4180 to 4199, so it does not
collide with `make design-system` on 4174 or with checks in other worktrees. The same runner is part of the `web` verification. It fails when
a test fails or is skipped, or when either viewport runs nothing.

Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` to a pinned Chromium to reuse it.
Otherwise the runner resolves the pinned Chromium as the Kind browser suite
does (above).
A new spec that reads `CODEWIRE_DESIGN_ORIGIN` must be added to that list; the
`test:fixtures` unit test enforces this.

## Focused static gates

Before paying the cost of Kind, run the wiring guards and enumerate the suite:

```bash
scripts/ci/tests/test-dashboard-browser-gate.sh
scripts/ci/tests/test-kind-e2e-suites.sh
bun run --cwd apps/dashboard typecheck
./apps/dashboard/node_modules/.bin/playwright test \
  --config apps/dashboard/playwright.config.ts --list
make scan-supply-chain
```

These checks catch missing suite wiring, opt-in lifecycle regressions, stale
Kind ordering, invalid Playwright discovery, and dependency/source-policy
violations. They do not prove login or environment creation; only execution
against the coherent full stack does that.

## Browser assertions

Browser tests assert behavior, state and accessible structure, not pixels:
there are no screenshot goldens. A layout regression that matters gets a
specific behavioral assertion (for example no page overflow or a visible
control), not a full-page image comparison.

## Helpers

- `helpers/seed.ts` — static user roster and synthetic password
- `helpers/db.ts` — deterministic database setup, inspection, and cleanup
- `helpers/org.ts` — organization fixtures and cleanup
- `helpers/environment.ts` — sandbox lifecycle waits and cleanup
- `helpers/topology.ts` — proof that the server and direct test connection use
  the same database
- `helpers/terminal-websocket.ts` — terminal edge URL construction
