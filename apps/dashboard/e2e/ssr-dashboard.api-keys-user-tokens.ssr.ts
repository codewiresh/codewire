// covers: src/account_user_tokens.rs src/routes/user_tokens.rs src/routes/personal_api_keys.rs
// covers: templates/settings-api-keys.html
import { expect, test } from "@playwright/test";
import {
  bypassTwoFactor, cleanupUser, createAuthenticatedSession, createUserToken, getUserId, seedSyntheticUser,
  userTokenIds,
} from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

// The API keys page's User tokens group (#5688) on the real IdP, dashboard and
// database, with synthetic owners. The tokens are stored rows; no value exists
// outside the helper that made them.
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const email = `e2e-account-user-tokens-${runId}@codewire.sh`;
const foreignEmail = `e2e-account-user-tokens-foreign-${runId}@codewire.sh`;
const slug = `account-user-tokens-${runId}`;
const origin = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
let accountId = "";
let current = { id: "", token: "" };
let expiring = "";
let forever = "";
let foreignToken = "";

test.use({ storageState: { cookies: [], origins: [] }, trace: "off", screenshot: "off" });

test.describe.serial("API keys page user token controls", () => {
  test.beforeAll(async ({}, info) => {
    test.skip(info.project.name !== "dashboard-ssr-desktop", "one managed Account proof");
    await seedSyntheticUser(email, "User token owner");
    await seedSyntheticUser(foreignEmail, "Foreign user token owner");
    await bypassTwoFactor(email);
    accountId = (await getUserId(email))!;
    expect(accountId).toBeTruthy();
    await ensureTestOrg("API keys user token controls", slug, accountId);
    current = await createAuthenticatedSession(email);
    expiring = await createUserToken(email, { expiresInDays: 30, used: true });
    forever = await createUserToken(email, { expiresInDays: null, used: false });
    foreignToken = await createUserToken(foreignEmail, { expiresInDays: 30, used: false });
  });

  test.afterAll(async () => {
    try { if (accountId) await cleanupTestOrg(slug); }
    finally { await Promise.all([cleanupUser(email), cleanupUser(foreignEmail)]); }
  });

  test("lists only the account's live tokens and marks the one that never expires", async ({ page }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/api-keys/?org=${slug}`);
    await expect(page.getByRole("heading", { name: "User tokens", exact: true })).toBeVisible();
    const rows = page.locator(".cw-user-token");
    await expect(rows).toHaveCount(2);
    expect(new Set(await rows.locator("header > code").allTextContents())).toEqual(new Set([expiring, forever]));
    const foreverRow = rows.filter({ hasText: forever });
    await expect(foreverRow.getByText("Never expires", { exact: true })).toBeVisible();
    await expect(foreverRow).toContainText("Never used");
    const expiringRow = rows.filter({ hasText: expiring });
    await expect(expiringRow).toContainText("Expires");
    await expect(expiringRow).toContainText("Last used");
    await expect(expiringRow.getByText("Never expires", { exact: true })).toHaveCount(0);
    expect(await page.content()).not.toContain(foreignToken);
  });

  test("a foreign token can't be revoked from this account", async ({ page }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/api-keys/?org=${slug}`);
    const csrf = await page.locator('#user-tokens [name="_csrf"]').first().inputValue({ timeout: 5_000 });
    const post = (form: Record<string, string>, headers: Record<string, string>) => page.context().request.post(`/settings/api-keys/_actions/user-tokens/revoke`, { form, headers, maxRedirects: 0 });
    const form = { _csrf: csrf, account_id: accountId, token_id: foreignToken };
    expect((await post(form, { Origin: "https://foreign.example.test" })).status()).toBe(403);
    expect((await post({ ...form, _csrf: "invalid" }, { Origin: origin })).status()).toBe(403);
    const foreignTarget = await post(form, { Origin: origin });
    expect(foreignTarget.status()).toBe(303);
    expect(foreignTarget.headers().location).toContain("error=user-token-no-longer-available#user-tokens");
    expect(await userTokenIds(foreignEmail)).toEqual([foreignToken]);
    expect(new Set(await userTokenIds(email))).toEqual(new Set([expiring, forever]));
  });

  test("Cancel sends nothing; a confirmed revoke deletes the token", async ({ page }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/api-keys/?org=${slug}`);
    const target = page.locator(".cw-user-token").filter({ hasText: forever });
    const requests: string[] = [];
    page.on("request", (request) => { if (request.url().includes("/_actions/user-tokens/revoke")) requests.push(request.method()); });
    await target.getByRole("button", { name: "Revoke", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Revoke user token?", exact: true });
    await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(requests).toEqual([]);
    await target.getByRole("button", { name: "Revoke", exact: true }).click();
    await dialog.getByRole("button", { name: "Revoke token", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "User token revoked." })).toBeVisible();
    expect(requests).toEqual(["POST"]);
    await expect(page.locator(".cw-user-token")).toHaveCount(1);
    expect(await userTokenIds(email)).toEqual([expiring]);
  });
});
