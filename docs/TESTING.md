# E2E Testing Guide

## Overview

E2E tests use Playwright with **static test users** seeded via a `globalSetup` script. Users are permanent fixtures in the database; only transient data (orgs, resources, invitations) is created and cleaned up per test run.

## Static User Roster

| Role | Email | Name | is_admin | Used By |
|------|-------|------|----------|---------|
| master | `e2e-master@codewire.sh` | E2E Master | false | `auth.setup.ts` (storageState for chromium project) |
| owner | `e2e-owner@codewire.sh` | E2E Owner | false | `lifecycle.spec.ts` — creates orgs, resources, invites |
| member | `e2e-member@codewire.sh` | E2E Member | false | `lifecycle.spec.ts` — invited, role changes, removal |
| outsider | `e2e-outsider@codewire.sh` | E2E Outsider | false | `lifecycle.spec.ts` — cross-org isolation |
| admin | `e2e-admin@codewire.sh` | E2E Admin | true | `admin.spec.ts` |
| billing | `e2e-billing@codewire.sh` | E2E Billing | false | `billing.spec.ts` |

All use password: `SecureTestPass9#`

Constants are defined in `apps/dashboard/e2e/helpers/seed.ts`.

## How Seeding Works

`apps/dashboard/e2e/global-setup.ts` runs before any test project:

1. Clears `rate_limit` table (Better Auth enforces `{ window: 300, max: 3 }` on `/sign-up/email`)
2. For each user: checks if exists → if not, creates via `POST /api/auth/sign-up/email`
3. Sets `email_verified = true` and `is_admin` flag via direct DB updates
4. Cleans up transient org data from previous runs (orgs with `e2e-` prefix slugs)
5. Clears rate limits again for `signup.spec.ts`

## Running Tests

### Prerequisites

**For E2E tests (recommended):** use the local KIND stack so tests exercise
the Rust control-plane services through ingress:

```bash
make e2e-kind
```

This creates and removes its own isolated cluster. Use `bun run up` separately
when you want the interactive `kind-codewire` development stack.

For dashboard-only development, `make dev` starts local Postgres and
`make web` starts Vite. Set `DASHBOARD_API_PROXY_TARGET` when the dashboard
should proxy to a non-default Rust/KIND API origin.

### Run All Tests

```bash
cd apps/dashboard
DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable" \
  npx playwright test
```

### Run Specific Projects

```bash
# Lifecycle tests (org creation, resources, members, roles, permissions)
DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable" \
  npx playwright test --project=lifecycle --reporter=list

# Auth setup + chromium tests (dashboard, admin, etc.)
DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable" \
  npx playwright test --project=setup --project=chromium --reporter=list

# Signup UI test
DATABASE_URL="postgres://codewire:codewire@localhost:54320/codewire?sslmode=disable" \
  npx playwright test --project=signup --reporter=list
```

## Playwright Projects

| Project | Test Match | Dependencies | Description |
|---------|-----------|--------------|-------------|
| `setup` | `*.setup.ts` | none | Logs in master user, saves storageState |
| `chromium` | all except lifecycle, membership, oidc, signup | setup | Main tests using saved auth |
| `lifecycle` | `lifecycle.spec.ts` | none | Full org lifecycle (owner/member/outsider) |
| `membership` | `membership.spec.ts` | none | Legacy tenant membership flow |
| `signup` | `signup.spec.ts` | none | Signup UI validation |
| `oidc` | `oidc.spec.ts` | none | OIDC/SSO tests |

## Lifecycle Test Phases (37 tests)

1. **Owner login + org creation** (6 tests): Login, empty dashboard, navigate to create page, slug validation, create org, empty environments state
2. **Environment creation** (8 tests): Preset picker, name/slug fields, environment runtime, Mesh access, wait for provision, dashboard shows environments, metrics, environment card navigation
3. **Environment detail pages** (5 tests): Detail page, access details, quick actions, back link, relay detail
4. **Member management** (3 tests): Navigate to members, owner shown, invite member
5. **Member login + invitation** (5 tests): Member login, accept invite, see resources, permissions check, resource detail permissions
6. **Cross-org isolation** (3 tests): Outsider org, can't see other orgs, can't access members
7. **Invitation + role management** (5 tests): Invite+revoke, member count, change role, admin controls, revert role
8. **Member removal** (2 tests): Remove member, verify removed

## Testing Patterns

### React Forms — `pressSequentially` over `fill()`

Vite/React controlled inputs need character-by-character input:

```typescript
const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};
```

### Vite HMR — `waitUntil: "commit"`

Vite HMR keeps the page in a loading state. Use `"commit"` instead of `"load"`:

```typescript
await page.goto(url, { waitUntil: "commit" });
await page.waitForLoadState("domcontentloaded");
```

### Email Verification — DB Bypass

Bypass email verification by directly updating the database:

```typescript
await sql`UPDATE users SET email_verified = true WHERE email = ${email}`;
```

### Org Invitations — DB Accept

The accept-invite UI still references tenant invitations. Accept org invitations via DB helper:

```typescript
const result = await acceptOrgInvitationViaDb(memberEmail);
```

## Dev Domain Setup

E2E tests that trigger real provisioning (not `DRY_RUN`) create DNS records on `codewire-dev.sh`, not the production `codewire.sh` domain. This is controlled by `BASE_DOMAIN` in docker-compose.

If stale DNS records accumulate on either zone, clean them up:

```bash
# List lc-* records on the dev zone
infisical run --env=local -- bash -c '
  curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "https://api.cloudflare.com/client/v4/zones/$CLOUDFLARE_ZONE_ID/dns_records?per_page=100" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data.get(\"result\", []):
    if r[\"name\"].startswith(\"lc-\") or r[\"name\"].startswith(\"*.lc-\"):
        print(f\"{r[\"id\"]}  {r[\"type\"]:6}  {r[\"name\"]}\")
"'
```

## Test Helpers

- `apps/dashboard/e2e/helpers/seed.ts` — User roster constants (`USERS`, `TEST_PASSWORD`)
- `apps/dashboard/e2e/helpers/db.ts` — Database utilities (verify email, cleanup, invitation helpers)
- `apps/dashboard/e2e/helpers/org.ts` — Organization utilities (create org, add member, cleanup)
- `apps/dashboard/e2e/billing.spec.ts` — Billing/subscription tests
- `apps/dashboard/e2e/helpers/stripe.ts` — Stripe test utilities
