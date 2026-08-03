# Dashboard end-to-end testing

The dashboard Playwright suite validates the server-rendered Rust application
against the real Rust control plane. Kind is the canonical full-stack test
topology because environment creation needs ingress, the sandbox controller,
Temporal, Kubernetes resources, and the same service boundaries used by the
shipped application.

Local verification is the development loop. Reproduce and fix product and
integration failures locally; use the exact-head Gitea run as merge
attestation after the local gate is green.

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
  apps/dashboard/e2e/ssr-dashboard.environments.ssr.ts \
  --grep 'creates, runs, exposes a port'
```

The gate uses a trusted system Chromium. Set
`PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` when it is not available as `chromium`,
`google-chrome`, or `google-chrome-stable`. Do not add a browser download to
the test path. Install the frozen JavaScript dependencies without lifecycle
scripts:

```bash
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
  bun install --frozen-lockfile --ignore-scripts
```

## Test projects

`apps/dashboard/playwright.config.ts` defines three projects:

| Project | Purpose |
|---|---|
| `setup` | Performs a real Rust form login, proves the dashboard and scoped HttpOnly session cookie, then writes local storage state |
| `dashboard-ssr-desktop` | Runs the complete server-rendered behavior suite at desktop size |
| `dashboard-ssr-mobile` | Runs the responsive behavior and visual contracts; desktop-only secret and lifecycle mutations are explicitly skipped |

The desktop and mobile projects depend on `setup`. There are no `chromium`,
`lifecycle`, `signup`, `billing`, or `oidc` projects; those were names from the
retired React suite.

## Required behavior coverage

The suite under `apps/dashboard/e2e/` covers:

- real signup, mandatory 2FA setup, sign-out, fresh login, and 2FA challenge;
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
- Git credentials, Git identity, and SSH-key settings;
- billing and admin rendering through server-side clients; and
- real Kind environment preparation, creation, running state, terminal,
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

## Helpers

- `helpers/seed.ts` — static user roster and synthetic password
- `helpers/db.ts` — deterministic database setup, inspection, and cleanup
- `helpers/org.ts` — organization fixtures and cleanup
- `helpers/environment.ts` — sandbox lifecycle waits and cleanup
- `helpers/topology.ts` — proof that the server and direct test connection use
  the same database
- `helpers/terminal-websocket.ts` — terminal edge URL construction
