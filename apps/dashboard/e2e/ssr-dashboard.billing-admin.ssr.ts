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
    await cleanupTestOrg(slug);
    await cleanupUser(adminEmail);
  });

  test("renders organization billing without browser-side service calls", async ({ page, isMobile }) => {
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
    await expect(page.getByRole("heading", { name: "Plan" })).toBeVisible();
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
});
