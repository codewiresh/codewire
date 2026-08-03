import { expect, test } from "@playwright/test";
import {
  bypassTwoFactor,
  createAuthenticatedSession,
  deleteSession,
  disableTwoFactor,
} from "./helpers/db";
import { USERS } from "./helpers/seed";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

test.describe("server-rendered dashboard", () => {
  test("renders the shared shell and refreshes its organization fragment", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop visual contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(request.url()));

    const response = await page.goto("/dashboard");
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Main navigation" }).first()).toBeVisible();
    await expect(page.getByRole("link", { name: "New Organization" }).first()).toHaveAttribute(
      "href",
      "/dashboard/orgs/new",
    );

    const style = await page.request.get("/assets/codewire/design-v1.css");
    expect(style.status()).toBe(200);
    expect(await style.text()).toContain("--bg-primary: #08090a");

    const fragment = page.waitForResponse((candidate) => (
      candidate.url().endsWith("/dashboard/_fragments/organizations")
      && candidate.request().method() === "GET"
    ));
    await page.evaluate(() => {
      document.body.dispatchEvent(new CustomEvent("dashboard:refresh", { bubbles: true }));
    });
    const fragmentResponse = await fragment;
    expect(fragmentResponse.status()).toBe(200);
    expect(fragmentResponse.request().headers()["hx-request"]).toBe("true");
    await expect(page.locator("#organization-list")).toBeVisible();

    expect(browserRequests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
    await expect(page).toHaveScreenshot("dashboard-desktop.png", { fullPage: true });
  });

  test("sends an unauthenticated visitor to the local server-rendered login", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop adapter contract");
    const context = await browser.newContext();
    await context.clearCookies();
    const page = await context.newPage();
    await page.goto(`${ssrUrl}/dashboard`);
    await expect(page).toHaveURL(
      `${ssrUrl}/login?return_to=%2Fdashboard`,
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
      await page.goto("/dashboard");
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page).toHaveScreenshot("dashboard-mobile.png", { fullPage: true });
      await page.getByRole("button", { name: "Toggle sidebar" }).click();
      await expect(page.locator("[data-dashboard-app]")).toHaveAttribute("data-mobile-open", "true");
      await expect(page.locator(".cw-mobile-drawer")).toBeVisible();
      await expect(page).toHaveScreenshot("dashboard-mobile-drawer.png", { fullPage: true });
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
