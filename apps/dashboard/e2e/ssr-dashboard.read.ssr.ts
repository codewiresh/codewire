// covers: src/routes/environments.rs templates/dashboard.html
// covers: templates/environment-create-form.html templates/environment-list.html
// covers: templates/environment-source-fields.html
// covers: templates/organization-environments-content.html
// covers: templates/organization-environments.html
import { expect, test } from "./helpers/test";
import {
  bypassTwoFactor,
  createAuthenticatedSession,
  deleteSession,
  disableTwoFactor,
} from "./helpers/db";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
// Per-project-run slug: parallel workers may run this file at the same time,
// and each must own the organization it creates and deletes.
const dashboardOrgSlug = `e2e-dashboard-read-${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

test.describe("server-rendered dashboard", () => {
  test.beforeAll(async ({}, testInfo) => {
    if (testInfo.project.use.isMobile) return;
    await ensureTestOrg("Dashboard Read Organization", dashboardOrgSlug, await ensureWorkerIdentity(testInfo.workerIndex));
  });

  test.afterAll(async ({}, testInfo) => {
    if (!testInfo.project.use.isMobile) await cleanupTestOrg(dashboardOrgSlug);
  });

  test("opens the organization home in the shared console shell", { tag: "@smoke" }, async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop visual contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(request.url()));

    // The account home is the remembered or first organization's home.
    const response = await page.goto("/dashboard/");
    expect(response?.status()).toBe(200);
    await expect(page).toHaveURL(/\/[a-z0-9-]+\/$/);
    await expect(page.getByRole("heading", { name: "Sandboxes", exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main navigation" }).first()).toBeVisible();
    const sandboxNavigation = page.locator(".cw-sidebar-slot").getByRole("region", {
      name: "Sandboxes",
    });
    await expect(sandboxNavigation.getByRole("link", { name: "Create Sandbox" })).toBeVisible();
    await expect(sandboxNavigation.getByRole("link", { name: "View all sandboxes" })).toBeVisible();
    await expect(page.locator('.cw-org-menu a[href="/organizations/new/"]').first()).toHaveAttribute(
      "href",
      "/organizations/new/",
    );

    // One token source: the console palette lives in the core stylesheet.
    const style = await page.request.get("/assets/codewire/design-v1.css");
    expect(style.status()).toBe(200);
    expect(await style.text()).toMatch(/--bg-primary:\s*[^;]+;/);
    const routeStyle = await page.request.get("/assets/codewire/routes/dashboard-v1.css");
    expect(await routeStyle.text()).not.toContain("--bg-primary:");

    const shellGeometry = await page.evaluate(() => {
      const sidebar = document.querySelector(".cw-sidebar-slot")?.getBoundingClientRect();
      const header = document.querySelector(".cw-console-header")?.getBoundingClientRect();
      const heading = document.querySelector(".cw-page-title");
      const headingStyle = heading ? getComputedStyle(heading) : null;
      return {
        sidebarWidth: sidebar?.width,
        headerHeight: header?.height,
        headingFont: headingStyle?.fontFamily,
        headingSize: headingStyle?.fontSize,
        headingLineHeight: headingStyle?.lineHeight,
        headingLetterSpacing: headingStyle?.letterSpacing,
        headingTransform: headingStyle?.textTransform,
        headingWeight: headingStyle?.fontWeight,
      };
    });
    expect(shellGeometry.sidebarWidth).toBeGreaterThan(0);
    expect(shellGeometry.sidebarWidth).toBeLessThan((page.viewportSize()?.width ?? 0) / 2);
    expect(shellGeometry.headerHeight).toBeGreaterThan(0);
    expect(shellGeometry.headerHeight).toBeLessThan((page.viewportSize()?.height ?? 0) / 4);
    // Page titles are sentence-case sans headings, not small mono labels.
    expect(shellGeometry.headingFont).not.toContain("IBM Plex Mono");
    expect(Number.parseFloat(shellGeometry.headingSize ?? "0")).toBeGreaterThanOrEqual(24);
    expect(shellGeometry.headingTransform).toBe("none");
    expect(Number(shellGeometry.headingWeight)).toBeGreaterThanOrEqual(600);
    expect(shellGeometry.headingLetterSpacing).toBe("normal");

    await expect(page.locator('[data-quick-search-results] a[data-search-text*="snapshots"]')).toHaveCount(0);
    const searchResults = page.locator(".cw-sidebar-slot [data-quick-search-results]");
    await expect(searchResults.getByRole("link", { name: "Credentials", exact: true, includeHidden: true })).toHaveAttribute("href", "/settings/credentials/");
    await expect(searchResults.getByRole("link", { name: "Account", exact: true, includeHidden: true })).toHaveAttribute("href", "/settings/");
    await expect(searchResults.getByRole("link", { name: "Personal application secrets", exact: true, includeHidden: true })).toHaveAttribute("href", "/settings/secrets/");
    await expect(searchResults.getByRole("link", { name: "Organization application secrets", exact: true, includeHidden: true })).toHaveAttribute("href", /\/secrets\/organization\/$/);
    await page.keyboard.press("/");
    await expect(page.locator(".cw-sidebar-slot [data-quick-search]")).toBeVisible();
    await page.locator(".cw-sidebar-slot [data-quick-search-input]").fill("settings");
    await expect(
      page.locator(".cw-sidebar-slot [data-quick-search-results]").getByRole("link", {
        name: "Settings",
      }),
    ).toBeVisible();
    await page.keyboard.press("Escape");

    expect(browserRequests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
  });

  test("sends an unauthenticated visitor to the local server-rendered login", { tag: "@smoke" }, async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop adapter contract");
    const context = await browser.newContext();
    await context.clearCookies();
    const page = await context.newPage();
    await page.goto(`${ssrUrl}/dashboard/`);
    await expect(page).toHaveURL(
      `${ssrUrl}/login?return_to=%2Fdashboard%2F`,
    );
    await context.close();
  });

  test("mobile shell opens and closes the shared sidebar", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile visual contract");
    const session = await createAuthenticatedSession(USERS.outsider.email);
    try {
      await bypassTwoFactor(USERS.outsider.email);
      await page.context().clearCookies();
      await page.context().addCookies([{
        name: "codewire.session_token",
        value: session.token,
        url: ssrUrl,
        httpOnly: true,
        sameSite: "Lax",
      }]);
      // Without an organization the account home stays here; with one it is
      // that organization's home. Both render the shared sidebar.
      await page.goto("/dashboard/");
      await expect(page).toHaveURL(/\/[a-z0-9-]+\/$/);
      await page.getByRole("button", { name: "Toggle sidebar" }).click();
      await expect(page.locator("[data-dashboard-app]")).toHaveAttribute("data-mobile-open", "true");
      await expect(page.locator(".cw-mobile-drawer")).toBeVisible();
      await page.getByRole("button", { name: "Close sidebar" }).click({ position: { x: 300, y: 400 } });
      await expect(page.locator("[data-dashboard-app]")).toHaveAttribute("data-mobile-open", "false");
    } finally {
      await Promise.all([
        deleteSession(session.id),
        disableTwoFactor(USERS.outsider.email),
      ]);
    }
  });
});
