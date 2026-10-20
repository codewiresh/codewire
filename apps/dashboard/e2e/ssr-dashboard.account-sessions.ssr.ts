// covers: src/raw_auth.rs src/routes/authentication.rs src/routes/settings.rs
// covers: templates/settings.html
import { expect, test, type Page } from "@playwright/test";
import {
  bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser,
} from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

// Real checked-in IdP/dashboard/database topology, synthetic isolated owners.
// Fixture dialog tests are not a substitute for these cookie/auth assertions.
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const email = `e2e-account-sessions-${runId}@codewire.sh`;
const foreignEmail = `e2e-account-foreign-${runId}@codewire.sh`;
const slug = `account-sessions-${runId}`;
const origin = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
let accountId = "";
let current = { id: "", token: "" };
let foreign = { id: "", token: "" };
const sessions: { id: string; token: string }[] = [];

async function allOwnerIds(page: Page) {
  await page.goto(`/settings/?org=${slug}`);
  const ids: string[] = [];
  for (let count = 0; count < 3; count++) {
    ids.push(...await page.locator(".cw-account-session > header > code").allTextContents());
    const next = page.getByRole("link", { name: "Next page", exact: true });
    if (await next.count() === 0) return ids;
    await next.click();
  }
  throw new Error("Account pagination did not finish within its fixture bound");
}

test.use({ storageState: { cookies: [], origins: [] }, trace: "off", screenshot: "off" });

test.describe.serial("cookie-owned Account session controls", () => {
  test.beforeAll(async ({}, info) => {
    test.skip(info.project.name !== "dashboard-ssr-desktop", "one managed Account proof");
    await seedSyntheticUser(email, "Account session owner");
    await seedSyntheticUser(foreignEmail, "Foreign session owner");
    await bypassTwoFactor(email);
    await bypassTwoFactor(foreignEmail);
    accountId = (await getUserId(email))!;
    expect(accountId).toBeTruthy();
    await ensureTestOrg("Account session controls", slug, accountId);
    current = await createAuthenticatedSession(email);
    foreign = await createAuthenticatedSession(foreignEmail);
    sessions.push(...await Promise.all(Array.from({ length: 52 }, () => createAuthenticatedSession(email))));
  });

  test.afterAll(async () => {
    try { if (accountId) await cleanupTestOrg(slug); }
    finally { await Promise.all([cleanupUser(email), cleanupUser(foreignEmail)]); }
  });

  test("lists every active session through pagination and keeps legacy links on Account", async ({ page }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/?org=${slug}`);
    for (const name of ["Account details", "Security", "Active sessions"]) {
      await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
    }
    await expect(page.locator(".cw-account-session")).toHaveCount(50);
    const ids = await page.locator(".cw-account-session > header > code").allTextContents();
    await page.getByRole("link", { name: "Next page", exact: true }).click();
    await expect(page.locator(".cw-account-session")).toHaveCount(3);
    ids.push(...await page.locator(".cw-account-session > header > code").allTextContents());
    expect(new Set(ids).size).toBe(53);
    expect(new Set(ids)).toEqual(new Set([current.id, ...sessions.map((session) => session.id)]));
    for (const section of ["security", "sessions"]) {
      await page.goto(`/settings/${section}/?org=${slug}`);
      await expect(page).toHaveURL(`/settings/#${section}`);
      await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    }
    expect(await page.content()).not.toContain(current.token);
    expect(await page.content()).not.toContain(foreign.id);
  });

  test("rejects changed account, CSRF, Origin, duplicate cookies and foreign targets", async ({ page }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/?org=${slug}`);
    const csrf = await page.locator('#sign-out [name="_csrf"]').inputValue();
    const form = { _csrf: csrf, account_id: accountId, session_id: sessions[0].id };
    const post = (formData: Record<string, string>, headers: Record<string, string>) => page.context().request.post(`/settings/_actions/sessions/revoke?org=${slug}`, { form: formData, headers, maxRedirects: 0 });
    expect((await post(form, { Origin: "https://foreign.example.test" })).status()).toBe(403);
    expect((await post({ ...form, _csrf: "invalid" }, { Origin: origin })).status()).toBe(403);
    const changed = await post({ ...form, account_id: "another-account" }, { Origin: origin });
    expect(changed.status()).toBe(303);
    expect(changed.headers().location).toContain("error=account-changed");
    const switched = await post(form, { Origin: origin, Cookie: `codewire.session_token=${foreign.token}; codewire_ssr_csrf=${csrf}` });
    expect(switched.status()).toBe(303);
    expect(switched.headers().location).toContain("error=account-changed");
    const duplicate = await post(form, { Origin: origin, Cookie: `codewire.session_token=${current.token}; codewire.session_token=${foreign.token}; codewire_ssr_csrf=${csrf}` });
    expect(duplicate.status()).toBe(303);
    expect(duplicate.headers().location).toContain("/login");
    const foreignTarget = await post({ ...form, session_id: foreign.id }, { Origin: origin });
    expect(foreignTarget.status()).toBe(303);
    expect(foreignTarget.headers().location).toContain("error=session-no-longer-available");
    expect(foreignTarget.headers()["set-cookie"]).toBeUndefined();
    const unchanged = await allOwnerIds(page);
    expect(unchanged).toHaveLength(53);
    expect(new Set(unchanged)).toEqual(new Set([current.id, ...sessions.map((session) => session.id)]));
    const stillAuthorized = await page.context().request.get(`${origin}/settings/`, { headers: { Cookie: `codewire.session_token=${foreign.token}` }, maxRedirects: 0 });
    expect(stillAuthorized.status()).toBe(200);
    expect(await stillAuthorized.text()).toContain(foreign.id);
  });

  test("Cancel sends no mutation; confirmed other-session revoke keeps this browser signed in", async ({ page, browser }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/?org=${slug}`);
    const target = page.locator(".cw-account-session").filter({ has: page.getByRole("heading", { name: "Browser session", exact: true }) }).first();
    const id = await target.locator("header > code").textContent();
    const token = sessions.find((session) => session.id === id)!.token;
    const requests: string[] = [];
    page.on("request", (request) => { if (request.url().includes("/_actions/sessions/revoke")) requests.push(request.method()); });
    await target.getByRole("button", { name: "Sign out session", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Sign out session?", exact: true });
    await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(requests).toEqual([]);
    await target.getByRole("button", { name: "Sign out session", exact: true }).click();
    await dialog.getByRole("button", { name: "Sign out session", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Session signed out");
    expect(requests).toEqual(["POST"]);
    await expect(page.locator(`.cw-account-session > header > code`).filter({ hasText: id! })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    const other = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      await other.addCookies([{ name: "codewire.session_token", value: token, url: origin }]);
      const rejected = await other.request.get(`${origin}/settings/`, { maxRedirects: 0 });
      expect(rejected.status()).toBe(303);
      expect(rejected.headers().location).toContain("/login");
    } finally { await other.close(); }
  });

  test("this browser's row signs it out, clears its cookie and invalidates the saved token", async ({ page, browser }) => {
    await page.context().addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
    await page.goto(`/settings/?org=${slug}`);
    const thisBrowser = page.locator(".cw-account-session").filter({ has: page.getByRole("heading", { name: "This browser", exact: true }) });
    if (await thisBrowser.count() === 0) await page.getByRole("link", { name: "Next page", exact: true }).click();
    await expect(thisBrowser.locator("header > code")).toHaveText(current.id);
    // Signing out this browser needs no confirmation, as in the sidebar.
    await thisBrowser.getByRole("button", { name: "Sign out of this browser", exact: true }).click();
    await expect(page).toHaveURL(/\/login$/);
    expect((await page.context().cookies()).some((cookie) => cookie.name === "codewire.session_token")).toBe(false);
    const other = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    try {
      await other.addCookies([{ name: "codewire.session_token", value: current.token, url: origin }]);
      const rejected = await other.request.get(`${origin}/settings/`, { maxRedirects: 0 });
      expect(rejected.status()).toBe(303);
      expect(rejected.headers().location).toContain("/login");
    } finally { await other.close(); }
  });
});
