import { test, expect } from "./fixtures";
import { cleanupTestOrg, getOrgInvitationToken } from "./helpers/org";

const timestamp = Date.now();
const TEST_ORG_NAME = `E2E Test Org ${timestamp}`;
const TEST_ORG_SLUG = `e2e-test-org-${timestamp}`;

function captureOrganizationTraffic(page: Parameters<typeof test>[0]["page"]) {
  const connectRequests: string[] = [];
  const restRequests: string[] = [];

  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes("/codewire.v1.OrganizationService/")) {
      connectRequests.push(path);
    }
    if (
      path === "/api/v1/organizations" ||
      path.startsWith("/api/v1/organizations/") ||
      path.startsWith("/api/v1/invitations")
    ) {
      restRequests.push(path);
    }
  });

  return { connectRequests, restRequests };
}

/**
 * Organization lifecycle tests — uses authenticated state from fixtures.
 * Must be serial because later tests depend on earlier ones (create org, then verify, etc.).
 */
test.describe.serial("Organization Lifecycle", () => {
  test.afterAll(async () => {
    await cleanupTestOrg(TEST_ORG_SLUG);
  });

  test("should display dashboard with org-grouped view", async ({ page }) => {
    await page.goto("/dashboard", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    // New dashboard shows "Dashboard" heading
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
      timeout: 10000,
    });
    // Should have "New Organization" button/link
    await expect(
      page.getByRole("link", { name: /new organization/i }).first()
    ).toBeVisible({ timeout: 10000 });
  });

  test("should navigate to create organization page", async ({ page }) => {
    await page.goto("/dashboard", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    await page.getByRole("link", { name: /new organization/i }).click();

    await expect(page).toHaveURL("/dashboard/orgs/new");
    await expect(
      page.getByRole("heading", { name: /create organization/i })
    ).toBeVisible();
  });

  test("should validate slug on create organization", async ({ page }) => {
    await page.goto("/dashboard/orgs/new", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    // Fill name
    const nameField = page.getByLabel("Organization Name");
    await nameField.click();
    await nameField.pressSequentially("Test", { delay: 20 });

    // Set invalid slug
    const slugField = page.getByLabel("Slug");
    await slugField.click();
    await slugField.fill("");
    await slugField.pressSequentially("ab", { delay: 20 }); // too short

    await page.getByRole("button", { name: /create organization/i }).click();

    // Should show error (slug too short)
    await expect(
      page.getByText(/slug must be between 3 and 48/i)
    ).toBeVisible({ timeout: 5000 });
  });

  test("should render typed Connect validation for a missing organization name", async ({ page }) => {
    const { connectRequests, restRequests } = captureOrganizationTraffic(page);

    await page.goto("/dashboard/orgs/new", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    const nameField = page.getByLabel("Organization Name");
    await nameField.evaluate((input) => input.removeAttribute("required"));
    await page.getByLabel("Slug").fill(`missing-name-${timestamp}`);
    await page.getByRole("button", { name: /create organization/i }).click();

    await expect(page.getByRole("alert")).toContainText(/name is required/i);
    expect(connectRequests).toContain("/codewire.v1.OrganizationService/CreateOrganization");
    expect(restRequests).toEqual([]);
  });

  test("should create a new organization", async ({ page }) => {
    const { connectRequests, restRequests } = captureOrganizationTraffic(page);

    await page.goto("/dashboard/orgs/new", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    // Fill name
    const nameField = page.getByLabel("Organization Name");
    await nameField.click();
    await nameField.pressSequentially(TEST_ORG_NAME, { delay: 20 });

    // Fill slug
    const slugField = page.getByLabel("Slug");
    await slugField.click();
    await slugField.fill(""); // clear auto-generated slug
    await slugField.pressSequentially(TEST_ORG_SLUG, { delay: 20 });

    // Submit
    await page.getByRole("button", { name: /create organization/i }).click();

    // Should redirect to dashboard
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });

    // Should see the new org in the dashboard (scoped to main to avoid sidebar match)
    await expect(page.getByRole("main").getByText(TEST_ORG_NAME).first()).toBeVisible({ timeout: 10000 });
    expect(connectRequests).toContain("/codewire.v1.OrganizationService/CreateOrganization");
    expect(restRequests).toEqual([]);
  });

  test("should show org with empty environments", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/environments`, { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    await expect(page.getByRole("heading", { name: TEST_ORG_NAME })).toBeVisible({
      timeout: 10000,
    });

    await expect(
      page.getByText(/no environments found/i)
    ).toBeVisible();

    await expect(
      page.getByRole("button", { name: /^create$/i }).first()
    ).toBeVisible();
  });

  test("should navigate to members page", async ({ page }) => {
    await page.goto("/dashboard", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    await page
      .getByRole("link", { name: new RegExp(TEST_ORG_NAME) })
      .first()
      .click();
    await page.waitForURL(new RegExp(`/dashboard/orgs/${TEST_ORG_SLUG}/environments`));

    await page.getByRole("link", { name: /^members$/i }).click();

    // Should be on members page
    await expect(page).toHaveURL(new RegExp(`/dashboard/orgs/${TEST_ORG_SLUG}/members`));
    await expect(
      page.getByRole("heading", { name: TEST_ORG_NAME })
    ).toBeVisible();
  });

  test("should show owner in members list", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/members`, {
      waitUntil: "commit",
    });
    await page.waitForLoadState("domcontentloaded");

    // Should show at least 1 member (the owner)
    await expect(page.getByText("Members (1)")).toBeVisible({ timeout: 10000 });
    // Should show owner badge
    await expect(page.getByText("owner").first()).toBeVisible();
  });

  test("should invite a member", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/members`, {
      waitUntil: "commit",
    });
    await page.waitForLoadState("domcontentloaded");

    // Click invite button
    await page.getByRole("button", { name: /invite member/i }).click();

    // Fill invite form
    const emailField = page.getByPlaceholder("colleague@example.com");
    await emailField.click();
    await emailField.pressSequentially("invited@example.com", { delay: 20 });

    // Submit
    await page.getByRole("button", { name: /send invite/i }).click();

    // Should see the pending invitation
    await expect(
      page.getByText("Pending Invitations (1)")
    ).toBeVisible({ timeout: 10000 });
    await expect(page.getByText("invited@example.com")).toBeVisible();
  });

  test("should load an invitation through public Connect lookup", async ({ page }) => {
    const token = await getOrgInvitationToken("invited@example.com");
    expect(token).not.toBeNull();

    const browser = page.context().browser();
    if (!browser) {
      throw new Error("Playwright browser is unavailable");
    }

    const context = await browser.newContext();
    await context.clearCookies();
    const publicPage = await context.newPage();
    const { connectRequests, restRequests } = captureOrganizationTraffic(publicPage);

    try {
      const baseURL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:5173";
      const invitationResponse = publicPage.waitForResponse(
        (response) =>
          new URL(response.url()).pathname ===
          "/codewire.v1.OrganizationService/GetInvitationByToken",
      );
      await publicPage.goto(
        `${baseURL}/accept-invite?token=${encodeURIComponent(token!)}`,
        { waitUntil: "commit" },
      );

      expect((await invitationResponse).status()).toBe(200);
      await expect(
        publicPage.getByRole("heading", { name: /you've been invited/i }),
      ).toBeVisible({ timeout: 10000 });
      expect(connectRequests).toContain(
        "/codewire.v1.OrganizationService/GetInvitationByToken",
      );
      expect(restRequests).toEqual([]);
    } finally {
      await context.close();
    }
  });

  test("should revoke an invitation", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/members`, {
      waitUntil: "commit",
    });
    await page.waitForLoadState("domcontentloaded");

    // Wait for invitations to load
    await expect(page.getByText("invited@example.com")).toBeVisible({
      timeout: 10000,
    });

    // Click revoke button (X icon next to the invitation)
    // Use has: filter (not hasText:) to find the row containing both email and button
    const invitationRow = page
      .locator("div")
      .filter({ has: page.getByText("invited@example.com", { exact: true }) })
      .filter({ has: page.getByRole("button") })
      .last();
    await invitationRow.getByRole("button").last().click();

    // Invitation should disappear
    await expect(page.getByText("invited@example.com")).not.toBeVisible({
      timeout: 10000,
    });
  });

  test("should open the environment create form", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/environments`, { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    await page.getByRole("button", { name: /^create$/i }).click();

    await expect(
      page.getByText("Create Environment")
    ).toBeVisible();
  });
});
