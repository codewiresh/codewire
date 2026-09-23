import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cleanupTestOrg } from "./helpers/org";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const slugPrefix = `ssr-create-${Date.now()}`;

test.describe("server-rendered organization creation", () => {
  test.afterAll(async () => {
    await cleanupTestOrg(slugPrefix);
  });

  test("renders the desktop organization form and suggests a slug", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop visual contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(request.url()));
    const response = await page.goto("/organizations/new/");
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Create Organization" })).toBeVisible();
    await page.getByLabel("Organization Name").fill("A Useful Team");
    await expect(page.getByLabel("Slug")).toHaveValue("a-useful-team");
    expect(browserRequests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
  });

  test("creates an organization through HTMX and returns to the dashboard", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop interaction contract");
    const slug = `${slugPrefix}-htmx`;
    await page.goto("/organizations/new/");
    await page.getByLabel("Organization Name").fill("SSR HTMX Organization");
    await page.getByLabel("Slug").fill(slug);

    const post = page.waitForResponse((response) => (
      response.url().endsWith("/organizations/_actions/create")
      && response.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Organization" }).click();
    const response = await post;
    expect(response.status()).toBe(200);
    expect(response.headers()["hx-redirect"]).toBe("/dashboard/");

    await expect(page).toHaveURL(`${ssrUrl}/dashboard/`);
    await page.locator(".cw-sidebar-slot .cw-org-switcher > summary").click();
    const organization = page.locator(".cw-sidebar-slot .cw-org-menu a", { hasText: "SSR HTMX Organization" });
    await expect(organization).toBeVisible();
    await expect(organization).toContainText("Owner");
  });

  test("creates an organization with a legacy dashboard-scoped CSRF cookie present", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop upgrade regression contract");
    const slug = `${slugPrefix}-legacy-csrf`;
    const origin = new URL(ssrUrl);
    await page.context().addCookies([{
      name: "codewire_csrf",
      value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      domain: origin.hostname,
      path: "/dashboard",
      httpOnly: true,
      secure: origin.protocol === "https:",
      sameSite: "Strict",
    }]);
    expect((await page.context().cookies()).some((cookie) => (
      cookie.name === "codewire_csrf" && cookie.path === "/dashboard"
    ))).toBe(true);

    await page.goto("/organizations/new/");
    expect((await page.context().cookies()).filter((cookie) => (
      cookie.name === "codewire_csrf"
    ))).toHaveLength(0);
    await page.getByLabel("Organization Name").fill("SSR Legacy Cookie Organization");
    await page.getByLabel("Slug").fill(slug);

    const post = page.waitForResponse((response) => (
      response.url().endsWith("/organizations/_actions/create")
      && response.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Organization" }).click();
    const response = await post;
    expect(response.status()).toBe(200);
    expect(response.headers()["hx-redirect"]).toBe("/dashboard/");
    await expect(page).toHaveURL(`${ssrUrl}/dashboard/`);
    await expect(page.locator(".cw-sidebar-slot .cw-org-menu a", {
      hasText: "SSR Legacy Cookie Organization",
    })).toContainText("Owner");
  });

  test("returns an HTMX validation fragment and preserves submitted values", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop interaction contract");
    await page.goto("/organizations/new/");
    await page.getByLabel("Organization Name").fill("Preserved Organization");
    await page.getByLabel("Slug").evaluate((input) => {
      input.removeAttribute("minlength");
      input.removeAttribute("pattern");
    });
    await page.getByLabel("Slug").fill("ab");

    const post = page.waitForResponse((response) => (
      response.url().endsWith("/organizations/_actions/create")
      && response.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Organization" }).click();
    const response = await post;
    expect(response.status()).toBe(422);
    expect(await response.text()).not.toContain("<!doctype html>");
    await expect(page.getByLabel("Organization Name")).toHaveValue("Preserved Organization");
    await expect(page.getByLabel("Slug")).toHaveValue("ab");
    await expect(page.getByText("Slug must be between 3 and 48 characters")).toBeVisible();
  });

  test("returns a complete validation page to a normal form post", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop no-JavaScript contract");
    await page.goto("/organizations/new/");
    const csrf = await page.locator('input[name="_csrf"]').inputValue();
    const response = await page.request.post("/organizations/_actions/create", {
      form: {
        name: "Normal Validation Organization",
        slug: "ab",
        _csrf: csrf,
      },
      headers: { Origin: ssrUrl },
    });
    expect(response.status()).toBe(422);
    const body = await response.text();
    expect(body).toContain("<!doctype html>");
    expect(body).toContain("Normal Validation Organization");
    expect(body).toContain("Slug must be between 3 and 48 characters");
  });

  test("maps a duplicate organization slug to the slug field", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop interaction contract");
    const slug = `${slugPrefix}-duplicate`;
    await page.goto("/organizations/new/");
    await page.getByLabel("Organization Name").fill("First Organization");
    await page.getByLabel("Slug").fill(slug);
    await page.getByRole("button", { name: "Create Organization" }).click();
    await expect(page).toHaveURL(`${ssrUrl}/dashboard/`);

    await page.goto("/organizations/new/");
    await page.getByLabel("Organization Name").fill("Duplicate Organization");
    await page.getByLabel("Slug").fill(slug);
    const post = page.waitForResponse((response) => (
      response.url().endsWith("/organizations/_actions/create")
      && response.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Organization" }).click();
    expect((await post).status()).toBe(422);
    await expect(page.getByLabel("Organization Name")).toHaveValue("Duplicate Organization");
    await expect(page.getByLabel("Slug")).toHaveValue(slug);
    await expect(page.getByText("An organization with this slug already exists")).toBeVisible();
  });

  test("creates an organization with JavaScript disabled and a normal redirect", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop no-JavaScript contract");
    const slug = `${slugPrefix}-no-js`;
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: authState,
    });
    const page = await context.newPage();
    await page.goto("/organizations/new/");
    await page.getByLabel("Organization Name").fill("SSR No JavaScript Organization");
    await page.getByLabel("Slug").fill(slug);
    const post = page.waitForResponse((response) => (
      response.url().endsWith("/organizations/_actions/create")
      && response.request().method() === "POST"
    ));
    await page.getByLabel("Slug").press("Enter");
    const response = await post;
    expect(response.status()).toBe(303);
    expect(response.headers().location).toBe("/dashboard/");
    await expect(page).toHaveURL(`${ssrUrl}/dashboard/`);
    await expect(page.locator(".cw-sidebar-slot .cw-org-menu a", { hasText: "SSR No JavaScript Organization" })).toContainText("Owner");
    await context.close();
  });

  test("rejects a form post without the double-submit token", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop security contract");
    await page.goto("/organizations/new/");
    const response = await page.request.post("/organizations/_actions/create", {
      form: {
        name: "Missing Token",
        slug: `${slugPrefix}-missing-token`,
        _csrf: "",
      },
      headers: { Origin: ssrUrl },
    });
    expect(response.status()).toBe(403);
    expect(await response.text()).toContain("The form expired or came from another site");
  });

  test("mobile organization form matches the responsive shell", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile visual contract");
    await page.goto("/organizations/new/");
    await expect(page.getByRole("heading", { name: "Create Organization" })).toBeVisible();
  });
});
