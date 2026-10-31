// covers: src/admin_connect.rs src/billing_connect.rs src/organization_connect.rs src/raw_auth.rs
// covers: src/routes/admin.rs src/routes/authentication.rs src/routes/billing.rs
// covers: src/routes/secrets_presets.rs src/routes/settings.rs src/secrets_presets_connect.rs
// covers: templates/admin-audit.html templates/admin-billing.html
// covers: templates/admin-plan-fields-new.html templates/admin-plan-fields-row.html
// covers: templates/admin-price-fields-new.html templates/admin-price-fields-row.html
// covers: templates/auth-form.html templates/organization-api-keys-content.html
// covers: templates/organization-api-keys.html templates/organization-billing.html
// covers: templates/organization-members-content.html templates/organization-members.html
// covers: templates/organization-presets-content.html templates/organization-presets.html
// covers: templates/organization-secret-bucket-content.html
// covers: templates/organization-secret-bucket.html templates/organization-secrets-content.html
// covers: templates/organization-secrets.html templates/settings.html
import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
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
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { ensureTestSandboxPreset } from "./helpers/environment";
import { addOrgMember, cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { TEST_PASSWORD } from "./helpers/seed";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
// Per-project-run slug: desktop and mobile workers may run this file at the
// same time, and each must own the organization it creates and deletes.
const slug = `e2e-management-visual-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const accountVisualEmail = `e2e-account-visual-${crypto.randomUUID()}@codewire.sh`;
// Suite-scoped administrator: the shared seeded admin stays untouched so
// sibling specs may enroll, bypass, or sign in with their own identities.
const adminEmail = `e2e-admin-visual-${crypto.randomUUID().slice(0, 8)}@codewire.sh`;
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
  await disableTwoFactor(adminEmail);
  await page.context().clearCookies();
  await page.goto("/login");
  await fillField(page, "#email", adminEmail);
  await fillField(page, "#password", TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15_000 });
  await bypassTwoFactor(adminEmail);
}

test.describe.serial("rounded management interface", () => {
  test.beforeAll(async ({}, testInfo) => {
    const ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    const orgId = await ensureTestOrg("Management Visual", slug, ownerId);
    managementOrgId = orgId;
    await seedSyntheticUser(adminEmail, "E2E Admin", true);
    const adminId = await getUserId(adminEmail);
    if (!adminId) throw new Error("Suite-scoped admin user was not seeded");
    await addOrgMember(orgId, adminId, "admin");
    await ensureTestSandboxPreset(orgId, "visual-default");
  });

  test.afterAll(async () => {
    try { await cleanupTestOrg(slug); }
    finally { await Promise.all([cleanupUser(accountVisualEmail), cleanupUser(adminEmail)]); }
  });

  test("renders every organization management surface without page overflow", async ({
    page,
    isMobile,
  }) => {
    for (const [path, heading, snapshot] of [
      ["presets", "Presets", "management-presets"],
      ["secrets", "Secrets", "management-secrets"],
      ["secrets/organization", "Organization Secrets", "management-secret-bucket"],
      ["api-keys", "API keys", "management-api-keys"],
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
      await expect(page).toHaveURL(`/settings/${path === "/settings/" ? "" : path.includes("security") ? "#security" : "#sessions"}`);
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

  test("renders the admin organizations list and opens an organization from anywhere on its row", async ({
    page,
  }) => {
    await loginAsAdmin(page);
    const response = await page.goto(`/admin/organizations/?org=${slug}`);
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Organizations", exact: true })).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Defaults for organizations without their own quota" }),
    ).toBeVisible();
    await expect(page.getByLabel("Concurrent sandboxes")).toHaveAttribute("min", "-1");
    await expectNoPageOverflow(page);

    // A click on the row's slug cell, not its name, opens the organization;
    // the name link stays the row's only focusable element. The link's overlay
    // covers the row by design, so the pointer lands on it at the slug's position.
    const row = page.locator("tbody tr").filter({ has: page.locator("code", { hasText: slug }) });
    await expect(row.locator("a, button, input, [tabindex]")).toHaveCount(1);
    await row.locator("code", { hasText: slug }).click({ force: true });
    await expect(page).toHaveURL(/\/admin\/organizations\/[A-Za-z0-9_-]+\/$/);
    await expect(page.getByRole("heading", { name: "Management Visual", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Environment quota and usage" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Billing" })).toBeVisible();
    const settings = page.getByRole("list", { name: "Organization settings" });
    await expect(settings.getByRole("listitem")).toHaveCount(2);
    await expect(settings.getByRole("button", { name: "Opt in to confidential environments" })).toBeVisible();
    await expect(settings.getByRole("button", { name: "Give dedicated CPU" })).toBeVisible();
    await expect(page.getByLabel("Memory (MiB)")).toBeVisible();
    await expectNoPageOverflow(page);
  });
});
