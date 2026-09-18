import { expect, test, type Page } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const origin = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const slug = `ssr-personal-keys-${Date.now()}`;
let organizationId = "";

// These tests mint disposable synthetic keys on the checked-in E2E stack.
// Never capture a one-time credential in a trace, video or screenshot.
test.use({ screenshot: "off", trace: "off", video: "off" });

async function checkReveal(page: Page) {
  await expect(page.getByRole("heading", { name: "Save your API key", exact: true })).toBeVisible();
  const value = page.locator("[data-one-time-api-key]");
  await expect(value).toHaveCount(1);
  expect(await value.evaluate((node) => /^cw_[a-f0-9]{64}$/.test(node.textContent || ""))).toBe(true);
  await expect(page.locator(".cw-personal-api-key-row")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create key", exact: true })).toHaveCount(0);
  await expect(page.locator("body")).toHaveAttribute("hx-history", "false");
}

test.describe.serial("personal Codewire API keys through the managed app", () => {
  test.beforeAll(async () => {
    test.skip(!!process.env.CODEWIRE_DESIGN_ORIGIN, "Authenticated managed-app journey, not an editable fixture");
    const owner = await getUserId(USERS.master.email);
    if (!owner) throw new Error("Synthetic owner was not seeded");
    organizationId = await ensureTestOrg("AAA Personal API Keys", slug, owner);
  });

  test.afterAll(async () => {
    if (organizationId) await cleanupTestOrg(slug);
  });

  test("creates once and manages a scoped key using native browser forms", async ({ page, isMobile }) => {
    const name = `Personal browser key ${isMobile ? "mobile" : "desktop"}`;
    const response = await page.goto("/settings/api-keys/");
    expect(response?.status()).toBe(200);
    expect(response?.headers()["referrer-policy"]).toBe("same-origin");
    const personal = page.getByRole("list", { name: "Personal", exact: true });
    await expect(personal.getByRole("link", { name: "API Keys", exact: true })).toHaveAttribute("aria-current", "page");
    await page.getByRole("button", { name: "Create key", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Create API key", exact: true });
    await dialog.getByLabel("Organization", { exact: true }).selectOption(organizationId);
    await dialog.getByLabel("Name", { exact: true }).fill(name);
    await dialog.getByLabel("Expiration", { exact: true }).selectOption("30");
    const submitted = page.waitForRequest((request) => request.method() === "POST"
      && new URL(request.url()).pathname === "/settings/api-keys/_actions/create");
    await dialog.getByRole("button", { name: "Create key", exact: true }).click();
    expect(await (await submitted).headerValue("origin")).toBe(origin);
    await checkReveal(page);
    await page.getByRole("link", { name: "Done", exact: true }).click();
    await expect(page.locator("[data-one-time-api-key]")).toHaveCount(0);
    const row = page.locator(".cw-personal-api-key-row").filter({ has: page.getByRole("heading", { name, exact: true }) });
    await expect(row).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await row.getByRole("button", { name: "Disable", exact: true }).click();
    await expect(row.getByText("Disabled", { exact: true })).toBeVisible();
    await row.getByRole("button", { name: "Enable", exact: true }).click();
    await expect(row.getByText("Active", { exact: true })).toBeVisible();
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    const deletion = page.getByRole("dialog", { name: `Delete ${name}?`, exact: true });
    await expect(deletion.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await deletion.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(row).toBeVisible();
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await deletion.getByRole("button", { name: "Delete key", exact: true }).click();
    await expect(row).toHaveCount(0);
  });

  test("keeps Create and Delete usable without JavaScript or raw-key readback", async ({ browser, isMobile }) => {
    const context = await browser.newContext({
      javaScriptEnabled: false, storageState: authState, baseURL: origin,
      viewport: isMobile ? { width: 390, height: 844 } : { width: 1440, height: 900 },
    });
    const page = await context.newPage();
    try {
      const name = `Personal native key ${isMobile ? "mobile" : "desktop"}`;
      await page.goto("/settings/api-keys/");
      const form = page.locator("#fallback-create-personal-api-key-form");
      await form.getByLabel("Organization", { exact: true }).selectOption(organizationId);
      await form.getByLabel("Name", { exact: true }).fill(name);
      await form.getByRole("button", { name: "Create key", exact: true }).click();
      await checkReveal(page);
      await page.getByRole("link", { name: "Done", exact: true }).click();
      await expect(page.locator("[data-one-time-api-key]")).toHaveCount(0);
      const row = page.locator(".cw-personal-api-key-row").filter({ has: page.getByRole("heading", { name, exact: true }) });
      const confirmation = row.locator('details[id^="fallback-api-key-"]');
      await confirmation.locator("summary").click();
      await expect(confirmation).toContainText("permanently removes the key");
      await confirmation.getByRole("button", { name: "Delete key", exact: true }).click();
      await expect(row).toHaveCount(0);
    } finally {
      await context.close();
    }
  });
});
