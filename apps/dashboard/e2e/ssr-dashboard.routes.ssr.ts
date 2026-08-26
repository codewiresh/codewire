import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const cleanRoutesOrgSlug = "e2e-clean-routes";

test.describe("server-rendered public, auth, and account routes", () => {
  test.beforeAll(async ({}, testInfo) => {
    if (testInfo.project.use.isMobile) return;
    const ownerId = await getUserId(USERS.master.email);
    if (!ownerId) throw new Error(`Missing clean-routes fixture owner ${USERS.master.email}`);
    await ensureTestOrg("Clean Routes Organization", cleanRoutesOrgSlug, ownerId);
  });

  test.afterAll(async ({}, testInfo) => {
    if (!testInfo.project.use.isMobile) await cleanupTestOrg(cleanRoutesOrgSlug);
  });

  test("homepage and sign-in stay on the Rust origin", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop route and supply-chain contract");
    const requests: string[] = [];
    page.on("request", (request) => requests.push(request.url()));

    const home = await page.goto("/");
    expect(home?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: /Give every AI agent/i })).toBeVisible();
    await page.getByRole("link", { name: "Sign in" }).first().click();
    await expect(page).toHaveURL(`${ssrUrl}/login`);
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await expect(page.getByLabel("Email")).toHaveAttribute("autocomplete", "email");
    await expect(page.getByLabel("Password")).toHaveAttribute("autocomplete", "current-password");

    await page.goto("/signup");
    await expect(page.getByLabel("Invite code")).toBeVisible();

    expect(requests.length).toBeGreaterThan(0);
    expect(requests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
  });

  test("homepage preserves the complete landing page and motion contract", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop landing-page motion contract");
    await page.goto("/");

    for (const heading of [
      "Your AI tools are stuck on one machine.",
      "AI agents write and run code you haven't reviewed. They need real isolation.",
      "What you get",
      "Up and running in 3 commands",
      "No seat tax on AI agents",
      "Ready to multiply your stack?",
    ]) {
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
    }

    const currentTask = page.locator("[data-current-task]");
    await expect(currentTask).toHaveAttribute("data-active-task", "0");
    await expect.poll(() => currentTask.getAttribute("data-active-task"), { timeout: 4000 }).not.toBe("0");
    expect(await page.locator(".cw-workspace").first().evaluate((element) => (
      getComputedStyle(element.querySelector("b")!).animationName
    ))).toBe("cw-fill-progress");
    await expect(page.locator("script[src='/assets/codewire/public-v1.js']")).toHaveCount(1);
    await expect(page.getByRole("link", { name: "Documentation", exact: true })).toHaveAttribute("href", "/docs");
  });

  test("password-reset token is moved to a scoped HttpOnly cookie and removed from the URL", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop security contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    const token = "opaque-reset-token-for-browser-proof";
    await page.goto(`/reset-password?token=${token}`);
    await expect(page).toHaveURL(`${ssrUrl}/reset-password`);
    await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
    expect(await page.content()).not.toContain(token);
    const resetCookie = (await context.cookies()).find((cookie) => cookie.name === "codewire_password_reset");
    expect(resetCookie).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/reset-password" });
    await context.close();
  });

  test("unauthenticated device approval keeps a local continuation", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop redirect contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    await page.goto("/device?user_code=ABCD-1234");
    await expect(page).toHaveURL(
      `${ssrUrl}/login?return_to=%2Fdevice%3Fuser_code%3DABCD-1234`,
    );
    await context.close();
  });

  test("settings render the current typed integrations and no-JS forms", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop settings contract");
    const response = await page.goto("/settings/");
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Account", exact: true }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "GitHub", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Git authentication" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Git identity" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "SSH key" })).toBeVisible();
    await expect(page.locator('form[action="/settings/_actions/sign-out"]')).toHaveCount(1);
    await expect(page.locator('input[name="_csrf"]')).not.toHaveCount(0);
  });

  test("clean console routes redirect canonically and legacy paths stay retired", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop clean-route contract");
    await page.goto("/dashboard/");
    const snapshotsHref = await page
      .locator(".cw-sidebar-slot")
      .getByRole("link", { name: /Snapshots/ })
      .getAttribute("href");
    expect(snapshotsHref).toMatch(/^\/[a-z0-9-]+\/snapshots\/$/);
    const organizationRoot = snapshotsHref!.replace(/snapshots\/$/, "");

    for (const canonical of ["/dashboard/", snapshotsHref!]) {
      const response = await page.request.get(canonical.slice(0, -1), { maxRedirects: 0 });
      expect(response.status()).toBe(308);
      expect(response.headers().location).toBe(canonical);
    }

    for (const legacy of [
      "/dashboard/settings",
      "/dashboard/orgs/legacy/environments",
      "/terminal/legacy/environment",
      "/favicon.ico",
    ]) {
      expect((await page.request.get(legacy)).status()).toBe(404);
    }
    expect((await page.request.get(`${organizationRoot}not-a-uuid/`)).status()).toBe(404);
    expect((await page.request.get("/dashboard/?org=not-a-member")).status()).toBe(404);

    const snapshots = await page.goto(snapshotsHref!);
    expect(snapshots?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Snapshots", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Create Snapshot" })).toBeDisabled();
    await expect(page.getByText("No snapshots yet", { exact: true })).toBeVisible();
  });

  test("account placeholders preserve the current authenticated product behavior", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop account contract");
    for (const [route, heading] of [
      ["/settings/", "Account"],
      ["/settings/security/", "Security settings"],
      ["/settings/sessions/", "Active sessions"],
    ] as const) {
      const response = await page.goto(route);
      expect(response?.status()).toBe(200);
      await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
    }
  });

  test("global routes preserve only an accessible organization context", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop global-context contract");

    for (const route of ["/settings/", "/settings/security/", "/settings/sessions/"]) {
      const response = await page.goto(`${route}?org=${cleanRoutesOrgSlug}`);
      expect(response?.status()).toBe(200);
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
        "Clean Routes Organization",
      );
      await expect(page.locator(".cw-sidebar-slot").getByRole("link", { name: "Settings" }))
        .toHaveAttribute("href", `/settings/?org=${cleanRoutesOrgSlug}`);
    }

    const adminRedirect = await page.request.get(`/admin/?org=${cleanRoutesOrgSlug}`, {
      maxRedirects: 0,
    });
    expect(adminRedirect.status()).toBe(303);
    expect(adminRedirect.headers().location).toBe(`/dashboard/?org=${cleanRoutesOrgSlug}`);

    for (const route of [
      "/settings/?org=not-a-member",
      "/settings/security/?org=not-a-member",
      "/settings/sessions/?org=not-a-member",
      "/admin/?org=not-a-member",
      "/admin/billing/?org=not-a-member",
      "/admin/audit/?org=not-a-member",
    ]) {
      expect((await page.request.get(route)).status()).toBe(404);
    }
  });

  test("public and auth layout remains responsive on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile visual contract");
    await page.goto("/");
    await expect(page.getByRole("heading", { name: /Give every AI agent/i })).toBeVisible();
    await page.getByRole("button", { name: "Toggle menu" }).click();
    await expect(page.locator("#landing-menu")).toHaveClass(/is-open/);
    await expect(page.getByRole("link", { name: "Docs", exact: true })).toBeVisible();
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
    await expect(page.locator(".cw-auth-card")).toBeInViewport();
  });
});

test.describe("server-rendered no-JavaScript auth", () => {
  test.use({ storageState: authState });

  test("wrong credentials return a safe complete HTML page without reflecting secrets", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "desktop no-JavaScript contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    await page.goto("/login");
    const password = "NeverReflectThisPassword9!";
    await page.getByLabel("Email").fill("not-a-real-user@example.test");
    await page.getByLabel("Password").fill(password);
    const responsePromise = page.waitForResponse((response) => (
      response.url().endsWith("/login/_actions/sign-in")
      && response.request().method() === "POST"
    ));
    await page.getByLabel("Password").press("Enter");
    const response = await responsePromise;
    expect(response.status()).toBe(401);
    await expect(page.getByRole("alert")).toContainText("Email or password is incorrect");
    expect(await page.content()).not.toContain(password);
    await context.close();
  });
});
