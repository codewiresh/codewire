import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { cleanupUser, clearRateLimits, disableTwoFactor, getUserId, seedSyntheticUser } from "./helpers/db";
import { fillField } from "./helpers/auth-flow";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import {
  addOrgMember,
  cleanupTestOrg,
  ensureTestOrg,
} from "./helpers/org";
import { TEST_PASSWORD, USERS } from "./helpers/seed";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const slug = `ssr-governance-${Date.now()}`;
const invitationEmail = `invited-${Date.now()}@example.com`;
// Suite-scoped invitee: the shared seeded outsider stays untouched so sibling
// specs may hold sessions, bypass, or disable two-factor on their own users.
const outsiderEmail = `e2e-governance-outsider-${Date.now()}-${crypto.randomUUID().slice(0, 8)}@codewire.sh`;

// This file reaches the one-time API-key reveal. Capturing a screenshot or
// trace here would turn a test artifact into a secret store.
test.use({ screenshot: "off", trace: "off" });

async function oneTimeInvitationUrl(page: Page): Promise<string> {
  await expect(page.getByRole("heading", { name: "Invitation created", exact: true }))
    .toBeVisible();
  await expect(page.getByText("Share this link now. It will not be shown again.", { exact: true }))
    .toBeVisible();
  const invitationUrl = (await page
    .locator('[data-secret-kind="invitation-url"]')
    .textContent())?.trim();
  expect(invitationUrl).toBeTruthy();
  return invitationUrl!;
}

test.describe.serial("server-rendered organization governance", () => {
  test.beforeAll(async ({}, testInfo) => {
    const ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    const memberId = await getUserId(USERS.member.email);
    if (!memberId) throw new Error("E2E users were not seeded");
    const orgId = await ensureTestOrg("SSR Governance", slug, ownerId);
    await addOrgMember(orgId, memberId, "member");
    await seedSyntheticUser(outsiderEmail, "E2E Governance Outsider");
  });

  test.afterAll(async () => {
    await cleanupTestOrg(slug);
    await cleanupUser(outsiderEmail);
  });

  test("manages members and invitations through server-side Connect clients", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop mutation contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(new URL(request.url()).pathname));

    const response = await page.goto(`/${slug}/members/`);
    expect(response?.status()).toBe(200);
    await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
      "SSR Governance",
    );
    await expect(page.getByText("Members (2)")).toBeVisible();
    await expect(
      page.getByLabel("Organization navigation").getByRole("link", { name: "Members" }),
    ).toHaveAttribute("aria-current", "page");

    const member = page.locator(".cw-list-row", { hasText: USERS.member.email });
    await member.getByLabel("Role").selectOption("admin");
    await member.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Member role updated");

    const updatedMember = page.locator(".cw-list-row", { hasText: USERS.member.email });
    await updatedMember.getByText("Assignments", { exact: true }).click();
    await updatedMember.getByLabel("Developer").check();
    await updatedMember.getByRole("button", { name: "Save assignments" }).click();
    await expect(page.getByRole("status")).toContainText("Member assignments updated");
    await expect(
      page
        .locator(".cw-list-row", { hasText: USERS.member.email })
        .locator(".cw-person-assignments")
        .getByText("Developer"),
    ).toBeVisible();

    await page.getByText("Invite Member", { exact: true }).first().click();
    await page.getByLabel("Email").fill(invitationEmail);
    await page.getByRole("button", { name: "Send Invite" }).click();
    await oneTimeInvitationUrl(page);
    const invitation = page.locator(".cw-list-row", { hasText: invitationEmail });
    await expect(invitation).toBeVisible();
    await invitation.getByRole("button", { name: `Revoke invitation for ${invitationEmail}` }).click();
    await expect(page.getByRole("status")).toContainText("Invitation revoked");
    await expect(page.locator(".cw-list-row", { hasText: invitationEmail })).toHaveCount(0);

    const removable = page.locator(".cw-list-row", { hasText: USERS.member.email });
    await removable.getByRole("button", { name: `Remove ${USERS.member.name}` }).click();
    await expect(page.getByRole("status")).toContainText("Member removed");
    await expect(page.locator(".cw-list-row", { hasText: USERS.member.email })).toHaveCount(0);

    expect(browserRequests.some((request) => request.includes("/codewire.v1."))).toBe(false);
    expect(browserRequests.some((request) => request.startsWith("/api/v1/organizations"))).toBe(false);
  });

  test("creates, reveals once, disables, and deletes an API key without artifact capture", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop secret lifecycle contract");
    const keyName = "SSR Connect API Key";
    await page.goto(`/${slug}/api-keys/`);
    await expect(page.getByText("No API keys yet. Create one for programmatic access.")).toBeVisible();
    const csrf = await page.locator('input[name="_csrf"]').first().inputValue();
    const createResponse = await page.request.post(
      `/${slug}/api-keys/_actions/create`,
      {
        form: { _csrf: csrf, name: keyName, expiration: "never" },
        headers: {
          Origin: ssrUrl,
          "HX-Request": "true",
          "HX-Current-URL": `${ssrUrl}/${slug}/api-keys/`,
        },
      },
    );
    expect(createResponse.status()).toBe(200);
    let fragment = await createResponse.text();
    const hasValidShape = /data-secret-kind="api-key">cw_[A-Za-z0-9_-]+<\/code>/.test(fragment);
    const isFragment = !fragment.includes("<!doctype html>");
    fragment = "";
    expect(hasValidShape).toBe(true);
    expect(isFragment).toBe(true);
    await page.goto(`/${slug}/api-keys/`);
    await expect(page.locator('[data-secret-kind="api-key"]')).toHaveCount(0);

    await expect(page.locator(".cw-page-title-row .cw-badge")).toHaveText("1 key");
    let keyRow = page.getByRole("row").filter({ hasText: keyName });
    await expect(keyRow).toBeVisible();
    await keyRow.locator("details.cw-menu > summary").click();
    await keyRow.getByRole("button", { name: "Disable", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("API key status updated");
    keyRow = page.getByRole("row").filter({ hasText: keyName });
    await expect(keyRow.getByText("Disabled")).toBeVisible();

    await keyRow.locator("details.cw-menu > summary").click();
    await keyRow.getByRole("button", { name: "Delete", exact: true }).click();
    const deletion = page.getByRole("dialog", { name: `Delete ${keyName}?`, exact: true });
    await deletion.getByRole("button", { name: "Delete key", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("API key deleted");
    await expect(page.getByRole("row").filter({ hasText: keyName })).toHaveCount(0);
  });

  test("keeps an invitation attached through login, 2FA enrollment, and acceptance", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop invitation acceptance contract");
    test.setTimeout(90_000);
    await clearRateLimits();
    await disableTwoFactor(outsiderEmail);

    try {
      await page.goto(`/${slug}/members/`);
      await page.getByText("Invite Member", { exact: true }).first().click();
      await page.getByLabel("Email").fill(outsiderEmail);
      await page.getByRole("button", { name: "Send Invite" }).click();

      const invitationUrl = await oneTimeInvitationUrl(page);
      const token = new URL(invitationUrl).searchParams.get("token");
      expect(token).toBeTruthy();
      await page.context().clearCookies();
      await page.goto(`/accept-invite?token=${token}`);
      await expect(page.getByRole("heading", { name: "Join SSR Governance" })).toBeVisible();
      await page.getByRole("link", { name: "Sign in", exact: true }).click();
      expect(new URL(page.url()).searchParams.get("return_to")).toBe(
        `/accept-invite?token=${token}`,
      );

      await fillField(page, "#email", outsiderEmail);
      await fillField(page, "#password", TEST_PASSWORD);
      await page.getByRole("button", { name: /sign in/i }).click();
      await expect(page).toHaveURL(/\/setup-2fa\?return_to=/);

      const secret = (await page.getByTestId("totp-secret").textContent())?.trim();
      expect(secret).toBeTruthy();
      await fillField(page, "#code", new OTPAuth.TOTP({ secret: secret! }).generate());
      await page.getByRole("button", { name: /enable two-factor authentication/i }).click();
      await expect(page.getByRole("heading", { name: /two-factor authentication enabled/i }))
        .toBeVisible();
      await expect(page.getByTestId("recovery-code")).toHaveCount(10);
      await page.getByRole("link", { name: /continue to codewire/i }).click();
      await expect(page).toHaveURL(new RegExp(`/accept-invite\\?token=${token}`));

      await page.getByRole("button", { name: "Accept invitation" }).click();
      await expect(page.getByRole("heading", { name: "Welcome to the team" })).toBeVisible();
      await page.getByRole("link", { name: "Go to dashboard" }).click();
      await page.locator(".cw-sidebar-slot .cw-org-switcher summary").click();
      await expect(
        page.locator(`.cw-sidebar-slot .cw-org-menu a[href="?org=${slug}"]`),
      ).toBeVisible();
    } finally {
      await disableTwoFactor(outsiderEmail);
    }
  });

  test("normal form responses work without HTMX and keep one-time key material out of URLs", async ({ browser, isMobile, workerStorageState }) => {
    test.skip(!!isMobile, "desktop no-JavaScript contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: workerStorageState,
    });
    const page = await context.newPage();
    await page.goto(`/${slug}/api-keys/`);
    const csrf = await page.locator('input[name="_csrf"]').first().inputValue();
    const actionUrl = `/${slug}/api-keys/_actions/create`;
    const actionResponse = await context.request.post(actionUrl, {
      form: { _csrf: csrf, name: "No JavaScript Key", expiration: "never" },
      headers: { Origin: ssrUrl },
    });
    expect(actionResponse.status()).toBe(200);
    let body = await actionResponse.text();
    const completePage = body.includes("<!doctype html>");
    const hasValidSecret = /data-secret-kind="api-key">cw_[A-Za-z0-9_-]+<\/code>/.test(body);
    body = "";
    expect(completePage).toBe(true);
    expect(hasValidSecret).toBe(true);
    expect(actionResponse.url()).not.toContain("cw_");
    await context.close();
  });

  test("organization tabs and actions remain usable on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile responsive contract");
    await page.goto(`/${slug}/api-keys/`);
    await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
      "SSR Governance",
    );
    await expect(page.getByRole("navigation", { name: "Organization navigation" })).toBeVisible();
    // The header's Create key disclosure; its form's submit shares the name.
    await expect(page.locator(".cw-page-header summary").filter({ hasText: "Create key" })).toBeInViewport();
  });
});
