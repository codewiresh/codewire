// covers: src/admin_connect.rs src/billing_connect.rs src/raw_auth.rs src/routes/admin.rs
// covers: src/routes/authentication.rs src/routes/billing.rs templates/admin-audit.html
// covers: templates/admin-billing.html templates/admin-overview.html
// covers: templates/admin-plan-fields-new.html templates/admin-plan-fields-row.html
// covers: templates/admin-price-fields-new.html templates/admin-price-fields-row.html
// covers: templates/auth-form.html templates/organization-billing.html
// covers: templates/organization-settings-nav.html templates/settings-navigation.html
import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
import { fillField } from "./helpers/auth-flow";
import {
  bypassTwoFactor,
  cleanupUser,
  clearRateLimits,
  disableTwoFactor,
  seedSyntheticUser,
} from "./helpers/db";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { ACCOUNT_HOME, cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { TEST_PASSWORD } from "./helpers/seed";
import postgres from "postgres";

const sql = postgres(process.env.DATABASE_URL!);

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const slug = `ssr-billing-${Date.now()}`;
// Suite-scoped administrator: the shared seeded admin stays untouched so
// sibling specs may enroll, bypass, or sign in with their own identities.
const adminEmail = `e2e-admin-billing-${Date.now()}-${crypto.randomUUID().slice(0, 8)}@codewire.sh`;

async function loginAsAdmin(page: Page) {
  await clearRateLimits();
  await disableTwoFactor(adminEmail);
  await page.context().clearCookies();
  await page.goto("/login");
  await fillField(page, "#email", adminEmail);
  await fillField(page, "#password", TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL((url) => url.pathname.startsWith("/setup-2fa") || ACCOUNT_HOME.test(url.pathname), { timeout: 15_000 });
  // This suite verifies admin authorization, not enrollment. Keep setup
  // material out of traces and let the seeded identity satisfy the 2FA gate.
  await bypassTwoFactor(adminEmail);
}

async function followAdminNavigation(page: Page, isMobile: boolean | undefined, name: string) {
  if (isMobile) {
    await page.getByRole("button", { name: "Toggle sidebar" }).click();
    const link = page.locator(".cw-mobile-drawer").getByRole("link", { name });
    await expect(link).toBeVisible();
    await link.evaluate((element: HTMLAnchorElement) => element.click());
  } else {
    await page.getByRole("link", { name }).click();
  }
}

test.describe.serial("server-rendered billing and administration", () => {
  test.beforeAll(async ({}, testInfo) => {
    const ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    await ensureTestOrg("SSR Billing", slug, ownerId);
    await seedSyntheticUser(adminEmail, "E2E Admin", true);
  });

  test.afterAll(async () => {
    await sql`UPDATE billing_catalog_settings SET int_value = 0 WHERE setting_key = 'signup_credit_cents'`;
    await cleanupTestOrg(`${slug}-credit-on`);
    await cleanupTestOrg(`${slug}-credit-off`);
    await cleanupTestOrg(slug);
    await cleanupUser(adminEmail);
    await sql.end();
  });

  test("renders organization billing without browser-side service calls", { tag: "@smoke" }, async ({ page, isMobile }) => {
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(request.url()));

    const response = await page.goto(`/${slug}/billing/`);
    expect(response?.status()).toBe(200);
    await expect(page.locator(".cw-org-switcher-label").first()).toHaveText("SSR Billing");
    await expect(page.getByLabel("Organization navigation").getByRole("link", {
      name: "Billing",
      exact: true,
    })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await expect(page.getByRole("heading", { name: "Compute credit" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Sandbox Usage" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Invoices" })).toBeVisible();
    expect(browserRequests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
    expect(browserRequests.some((url) => new URL(url).pathname.includes("BillingService"))).toBe(false);

  });

  test("redirects a non-admin before rendering privileged pages", async ({ page }) => {
    await page.goto("/admin/");
    await expect(page).toHaveURL(ACCOUNT_HOME);
  });

  test("renders the admin overview, audit log, and catalog from server-side Connect clients", async ({
    page,
    isMobile,
  }) => {
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(request.url()));
    await loginAsAdmin(page);

    await page.goto("/admin/");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByText("Total Sandboxes")).toBeVisible();

    await followAdminNavigation(page, isMobile, "Audit Log");
    await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
    await expect(page.getByLabel("Action")).toBeVisible();
    await expect(page.getByLabel("Severity")).toBeVisible();

    await followAdminNavigation(page, isMobile, "Billing Catalog");
    await expect(page.getByRole("heading", { name: "Billing Catalog" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Subscription Migrations" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Plans" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Billing Settings" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Stripe Price IDs" })).toBeVisible();
    expect(browserRequests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
    expect(browserRequests.some((url) => new URL(url).pathname.startsWith("/codewire."))).toBe(false);
  });

  // Owner, 2026-11-10 (#3381): an admin sets the sign-up credit; each new
  // organization gets the amount current at its creation, once.
  test("an admin's sign-up credit reaches organizations created after it, once", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "the setting and the grant do not depend on width");
    await loginAsAdmin(page);
    const setCredit = async (cents: string) => {
      await page.goto("/admin/billing/");
      const field = page.getByLabel(/Sign-up credit, in euro cents/);
      await field.fill(cents);
      await page.locator("form.cw-setting-row", { has: field }).getByRole("button", { name: "Save" }).click();
      await expect(page.getByText("Billing setting saved.")).toBeVisible();
      await expect(page.getByLabel(/Sign-up credit, in euro cents/)).toHaveValue(cents);
    };
    const createOrganization = async (name: string, orgSlug: string) => {
      await page.goto("/organizations/new/");
      await page.getByLabel("Organization Name").fill(name);
      await page.getByLabel("Slug").fill(orgSlug);
      await page.getByRole("button", { name: "Create Organization" }).click();
      await expect(page).toHaveURL(`${ssrUrl}/${orgSlug}/`);
    };
    const grants = (orgSlug: string) => sql`
      SELECT l.amount_nano_eur::text AS amount, l.idempotency_key AS key
        FROM billing_credit_ledger l JOIN organizations o ON o.id = l.organization_id
       WHERE o.slug = ${orgSlug} AND l.entry_kind = 'grant'`;

    await setCredit("1000");
    const [audit] = await sql`
      SELECT a.metadata FROM audit_logs a JOIN users u ON u.id = a.user_id
       WHERE u.email = ${adminEmail} AND a.action = 'admin.billing.catalog.setting_updated'
       ORDER BY a.timestamp DESC LIMIT 1`;
    expect(audit.metadata).toMatchObject({ setting_key: "signup_credit_cents", value: 1000 });

    await createOrganization("Credit On", `${slug}-credit-on`);
    expect(await grants(`${slug}-credit-on`)).toEqual([{ amount: "10000000000", key: "signup_credit" }]);
    await page.goto(`/${slug}-credit-on/billing/`);
    await expect(page.locator(".cw-stat", { hasText: "Balance" }).locator("dd")).toHaveText("€10.00");

    await setCredit("0");
    await createOrganization("Credit Off", `${slug}-credit-off`);
    expect(await grants(`${slug}-credit-off`)).toEqual([]);
    // The earlier organization keeps exactly its one grant.
    expect(await grants(`${slug}-credit-on`)).toHaveLength(1);
  });
});

