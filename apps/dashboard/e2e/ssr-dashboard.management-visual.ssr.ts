import { expect, test, type Page } from "@playwright/test";
import { fillField } from "./helpers/auth-flow";
import {
  bypassTwoFactor,
  clearRateLimits,
  cleanupUser,
  createAuthenticatedSession,
  disableTwoFactor,
  getUserId,
  seedSyntheticUser,
  stabilizeSyntheticAccountVisual,
} from "./helpers/db";
import { ensureTestSandboxPreset } from "./helpers/environment";
import { addOrgMember, cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { TEST_PASSWORD, USERS } from "./helpers/seed";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const slug = "e2e-management-visual";
const accountVisualEmail = `e2e-account-visual-${crypto.randomUUID()}@codewire.sh`;
let accountVisualSession = { id: "", token: "" };
let managementOrgId = "";

async function expectNoPageOverflow(page: Page) {
  expect(await page.evaluate(() => ({
    viewport: window.innerWidth,
    page: document.documentElement.scrollWidth,
  }))).toEqual(expect.objectContaining({ page: expect.any(Number) }));
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
}

async function loginAsAdmin(page: Page) {
  await clearRateLimits();
  await disableTwoFactor(USERS.admin.email);
  await page.context().clearCookies();
  await page.goto("/login");
  await fillField(page, "#email", USERS.admin.email);
  await fillField(page, "#password", TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15_000 });
  await bypassTwoFactor(USERS.admin.email);
}

test.describe.serial("rounded management interface", () => {
  test.beforeAll(async () => {
    const ownerId = await getUserId(USERS.master.email);
    if (!ownerId) throw new Error("E2E master user was not seeded");
    const orgId = await ensureTestOrg("Management Visual", slug, ownerId);
    managementOrgId = orgId;
    const adminId = await getUserId(USERS.admin.email);
    if (!adminId) throw new Error("E2E admin user was not seeded");
    await addOrgMember(orgId, adminId, "admin");
    await ensureTestSandboxPreset(orgId, "visual-default");
  });

  test.afterAll(async () => {
    try { await cleanupTestOrg(slug); }
    finally { await cleanupUser(accountVisualEmail); }
  });

  test("renders every organization management surface without page overflow", async ({
    page,
    isMobile,
  }) => {
    for (const [path, heading, snapshot] of [
      ["presets", "Presets", "management-presets"],
      ["secrets", "Secrets", "management-secrets"],
      ["secrets/organization", "Organization Secrets", "management-secret-bucket"],
      ["api-keys", "API Keys", "management-api-keys"],
      ["members", "Members", "management-members"],
      ["billing", "Billing", "management-billing"],
    ] as const) {
      const response = await page.goto(`/${slug}/${path}/`);
      expect(response?.status()).toBe(200);
      await expect(page.locator(".cw-org-switcher-label").first()).toHaveText("Management Visual");
      await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });

  test("renders account, security, and session surfaces in the selected context", async ({
    page,
    isMobile,
  }) => {
    // Add this owner only after the organization/Members screenshots. Binding
    // the byte-lowest ID as actor also makes current/other row ordering stable.
    await seedSyntheticUser(accountVisualEmail, "Account visual owner");
    await bypassTwoFactor(accountVisualEmail);
    const accountVisualId = await getUserId(accountVisualEmail);
    if (!accountVisualId) throw new Error("Isolated Account visual owner missing");
    await addOrgMember(managementOrgId, accountVisualId, "member");
    const sessions = await Promise.all([
      createAuthenticatedSession(accountVisualEmail), createAuthenticatedSession(accountVisualEmail),
    ]);
    sessions.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0);
    accountVisualSession = sessions[0];
    await stabilizeSyntheticAccountVisual(accountVisualEmail, sessions.map((session) => session.id));
    await page.context().clearCookies();
    await page.context().addCookies([{ name: "codewire.session_token", value: accountVisualSession.token, url: ssrUrl }]);
    for (const [path, heading, snapshot] of [
      ["/settings/", "Account", "management-settings"],
      ["/settings/security/", "Security", "management-security"],
      ["/settings/sessions/", "Active sessions", "management-sessions"],
    ] as const) {
      const response = await page.goto(`${path}?org=${slug}`);
      expect(response?.status()).toBe(200);
      await expect(page).toHaveURL(`/settings/?org=${slug}${path === "/settings/" ? "" : path.includes("security") ? "#security" : "#sessions"}`);
      await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
      await expect(page.locator(".cw-account-session")).toHaveCount(2);
      await expect(page.locator("#account-details dd").first()).toHaveText("Account visual owner");
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
        "Management Visual",
      );
      await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });

  test("renders admin audit and catalog surfaces in the selected context", async ({
    page,
    isMobile,
  }) => {
    await loginAsAdmin(page);
    for (const [path, heading, snapshot] of [
      ["/admin/audit/", "Audit Log", "management-admin-audit"],
      ["/admin/billing/", "Billing Catalog", "management-admin-billing"],
    ] as const) {
      const contextQuery = path === "/admin/audit/"
        ? `?org=${slug}&action=visual.none`
        : `?org=${slug}`;
      const response = await page.goto(`${path}${contextQuery}`);
      expect(response?.status()).toBe(200);
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
        "Management Visual",
      );
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
      await expectNoPageOverflow(page);
    }
  });
});
