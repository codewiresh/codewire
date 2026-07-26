import { test, expect, Page } from "@playwright/test";
import { AdminService } from "@codewire/proto-ts/gen/codewire/admin/v1/admin_pb";
import { BillingCatalogService } from "@codewire/proto-ts/gen/codewire/admin/v1/billing_catalog_pb";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { clearRateLimits, disableTwoFactor } from "./helpers/db";
import { completeTwoFactorSetupFromSession } from "./helpers/auth-flow";

test.describe.configure({ mode: "serial" });

// Use "commit" waitUntil because Vite HMR keeps page in loading state
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

const connectRoute = (
  service: { typeName: string },
  method: { name: string },
) => `/${service.typeName}/${method.name}`;

// Helper to fill a form field (React controlled inputs need pressSequentially)
const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.click();
  await field.pressSequentially(value, { delay: 20 });
};

// Helper: login as the static admin user
async function loginAsAdmin(page: Page) {
  await clearRateLimits();
  await disableTwoFactor(USERS.admin.email);
  await goto(page, "/login");
  await page.waitForSelector('button:has-text("Sign in")');
  await fillField(page, "#email", USERS.admin.email);
  await fillField(page, "#password", TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15000 });
  await completeTwoFactorSetupFromSession(page);
}

test.describe("Admin Overview", () => {
  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("admin can view overview dashboard", async ({ page }) => {
    await loginAsAdmin(page);

    const getStats = page.waitForResponse(
      (response) =>
        response.request().method() === "GET" &&
        response.url().includes(connectRoute(AdminService, AdminService.method.getStats)),
    );
    await goto(page, "/admin");
    expect((await getStats).status()).toBe(200);

    await expect(page.getByRole("heading", { name: /overview/i })).toBeVisible({
      timeout: 10000,
    });
    // Verify stat cards are present
    await expect(page.getByText(/total environments/i)).toBeVisible();
    await expect(page.getByText(/cpu hours/i).first()).toBeVisible();
  });

  test("non-admin redirected to dashboard", async ({ page }) => {
    await clearRateLimits();
    await disableTwoFactor(USERS.outsider.email);
    await goto(page, "/login");
    await page.waitForSelector('button:has-text("Sign in")');
    await fillField(page, "#email", USERS.outsider.email);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15000 });
    await completeTwoFactorSetupFromSession(page);

    // Try to access admin page
    await goto(page, "/admin");

    // Should be redirected to dashboard (not admin)
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });

    const denied = await page.evaluate(
      async ({ service, method }) => {
        const response = await fetch(`/${service}/${method}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Connect-Protocol-Version": "1",
          },
          body: "{}",
        });
        return { status: response.status, body: await response.json() };
      },
      {
        service: AdminService.typeName,
        method: AdminService.method.getStats.name,
      },
    );
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ code: "permission_denied" });
  });
});

test.describe("Admin Sidebar Navigation", () => {
  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("admin sidebar navigation works", async ({ page }) => {
    await loginAsAdmin(page);

    await goto(page, "/admin");
    await expect(page.getByRole("heading", { name: /overview/i })).toBeVisible({
      timeout: 10000,
    });

    // Click Billing Catalog nav link
    await page.getByRole("link", { name: /billing catalog/i }).click();
    await expect(page).toHaveURL(/\/admin\/billing/);
    await expect(page.getByRole("heading", { name: /billing catalog/i }))
      .toBeVisible({ timeout: 10000 });

    // Click Audit Log nav link
    await page.getByRole("link", { name: /audit log/i }).click();
    await expect(page).toHaveURL(/\/admin\/audit/);
    await expect(page.getByText(/audit log/i).first()).toBeVisible({ timeout: 10000 });

    // Click Overview nav link
    await page.getByRole("link", { name: /overview/i }).click();
    await expect(page).toHaveURL(/\/admin$/);
  });
});

test.describe("Admin Audit Log", () => {
  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("admin can view audit log page", async ({ page }) => {
    await loginAsAdmin(page);

    const listAuditLogs = page.waitForResponse(
      (response) =>
        response.request().method() === "GET" &&
        response
          .url()
          .includes(connectRoute(AdminService, AdminService.method.listAuditLogs)),
    );
    await goto(page, "/admin/audit");
    expect((await listAuditLogs).status()).toBe(200);

    await expect(page.getByText(/audit log/i).first()).toBeVisible({
      timeout: 10000,
    });

    // Should have filter inputs
    await expect(page.getByPlaceholder(/filter by action/i)).toBeVisible();

    // Table should exist with headers
    await expect(page.getByText("Timestamp").first()).toBeVisible();
    await expect(page.getByText("Action").first()).toBeVisible();
    await expect(page.getByText("Severity").first()).toBeVisible();
  });
});

test.describe("Admin Billing Catalog", () => {
  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("admin can view the billing catalog editor", async ({ page }) => {
    await loginAsAdmin(page);

    const getCatalog = page.waitForResponse(
      (response) =>
        response.request().method() === "GET" &&
        response
          .url()
          .includes(
            connectRoute(
              BillingCatalogService,
              BillingCatalogService.method.getCatalog,
            ),
          ),
    );
    await goto(page, "/admin/billing");
    expect((await getCatalog).status()).toBe(200);

    await expect(
      page.getByRole("heading", { name: /billing catalog/i }),
    ).toBeVisible({ timeout: 10000 });
    await expect(
      page.getByRole("heading", { name: "Subscription Migrations" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Billing Settings" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Stripe Price IDs" }),
    ).toBeVisible();
  });
});
