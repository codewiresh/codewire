import { test, expect } from "./fixtures";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const ORG_SLUG = `e2e-billing-connect-${Date.now()}`;
const BILLING_SERVICE_PATH = "/codewire.console.v1.BillingService/";

function captureBillingTraffic(
  page: Parameters<typeof test>[0]["page"],
  orgId: string,
) {
  const connectRequests: string[] = [];
  const restRequests: string[] = [];

  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith(BILLING_SERVICE_PATH)) {
      connectRequests.push(path);
    }
    if (
      path.startsWith(`/api/v1/organizations/${orgId}/billing`) ||
      path === `/api/v1/organizations/${orgId}/environments/usage`
    ) {
      restRequests.push(path);
    }
  });

  return { connectRequests, restRequests };
}

test.describe.serial("Billing Connect", () => {
  let orgId: string;

  test.beforeAll(async () => {
    const userId = await getUserId(USERS.master.email);
    if (!userId) throw new Error("E2E master user was not seeded");
    orgId = await ensureTestOrg("E2E Billing Connect", ORG_SLUG, userId);
  });

  test.afterAll(async () => {
    await cleanupTestOrg(ORG_SLUG);
  });

  test("billing overview, usage, invoices, and events use console Connect", async ({ page }) => {
    const { connectRequests, restRequests } = captureBillingTraffic(page, orgId);
    await page.goto(`/dashboard/orgs/${ORG_SLUG}/billing`, {
      waitUntil: "commit",
    });
    await expect(page.getByRole("heading", { name: "Plan" })).toBeVisible({
      timeout: 10000,
    });

    for (const method of [
      "GetBillingOverview",
      "GetEnvironmentUsage",
      "ListInvoices",
      "ListBillingEvents",
    ]) {
      await expect.poll(
        () => connectRequests.includes(`${BILLING_SERVICE_PATH}${method}`),
        { timeout: 10000 },
      ).toBe(true);
    }
    expect(restRequests).toEqual([]);
  });

  test("billing portal redirect uses console Connect", async ({ page }) => {
    const { connectRequests, restRequests } = captureBillingTraffic(page, orgId);
    await page.route(`**${BILLING_SERVICE_PATH}GetBillingOverview**`, (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          billingEnabled: true,
          hasPaymentMethod: true,
          planDisplayName: "E2E plan",
          status: "active",
        }),
      }),
    );
    await page.route(`**${BILLING_SERVICE_PATH}CreatePortalSession`, (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ portalUrl: page.url() }),
      }),
    );

    await page.goto(`/dashboard/orgs/${ORG_SLUG}/billing`, {
      waitUntil: "commit",
    });
    await expect(page.getByRole("button", { name: /manage in stripe/i })).toBeVisible({
      timeout: 10000,
    });

    const portalRequest = page.waitForRequest(
      (request) =>
        new URL(request.url()).pathname ===
        `${BILLING_SERVICE_PATH}CreatePortalSession`,
    );
    await page.getByRole("button", { name: /manage in stripe/i }).click();
    await portalRequest;

    expect(connectRequests).toContain(
      `${BILLING_SERVICE_PATH}CreatePortalSession`,
    );
    expect(restRequests).toEqual([]);
  });

  test("billing setup redirect uses console Connect", async ({ page }) => {
    const { connectRequests, restRequests } = captureBillingTraffic(page, orgId);
    await page.route(`**${BILLING_SERVICE_PATH}GetBillingOverview**`, (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          billingEnabled: true,
          hasPaymentMethod: false,
          planDisplayName: "E2E plan",
          status: "active",
        }),
      }),
    );
    await page.route(`**${BILLING_SERVICE_PATH}CreateSetupSession`, (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ checkoutUrl: page.url() }),
      }),
    );

    await page.goto(`/dashboard/orgs/${ORG_SLUG}/billing`, {
      waitUntil: "commit",
    });
    await expect(page.getByRole("button", { name: /add payment method/i })).toBeVisible({
      timeout: 10000,
    });

    const setupRequest = page.waitForRequest(
      (request) =>
        new URL(request.url()).pathname ===
        `${BILLING_SERVICE_PATH}CreateSetupSession`,
    );
    await page.getByRole("button", { name: /add payment method/i }).click();
    await setupRequest;

    expect(connectRequests).toContain(
      `${BILLING_SERVICE_PATH}CreateSetupSession`,
    );
    expect(restRequests).toEqual([]);
  });
});
