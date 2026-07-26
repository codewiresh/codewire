import { test as setup, expect, Page } from "@playwright/test";
import * as path from "path";
import { fileURLToPath } from "url";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import * as OTPAuth from "otpauth";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const authFile = path.join(__dirname, "../playwright/.auth/user.json");

// Use "commit" waitUntil because Vite HMR keeps page in loading state
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

// Helper to fill a form field (React controlled inputs need pressSequentially)
const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};

const completeTwoFactorSetup = async (page: Page) => {
  await expect(page.getByRole("heading", { name: /set up two-factor authentication/i }))
    .toBeVisible({ timeout: 15000 });

  const secret = (await page
    .locator("p")
    .filter({ hasText: /^[A-Z2-7]{16,}$/ })
    .first()
    .textContent())?.trim();
  if (!secret) throw new Error("2FA setup secret was not visible");

  const code = new OTPAuth.TOTP({ secret }).generate();
  await fillField(page, "#code", code);
  await page.getByRole("button", { name: /verify & enable/i }).click();
  await page.getByRole("button", { name: /continue to dashboard/i })
    .click({ timeout: 15000 });
  await page.waitForURL(/\/dashboard/, { timeout: 15000 });
};

setup("authenticate", async ({ page }) => {
  // globalSetup guarantees the master user exists — just log in
  await goto(page, "/login");
  await page.waitForSelector('button:has-text("Sign in")');

  await fillField(page, "#email", USERS.master.email);
  await fillField(page, "#password", TEST_PASSWORD);

  await page.getByRole("button", { name: /sign in/i }).click();

  await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15000 });
  await page.waitForTimeout(1000);
  if (page.url().includes("/setup-2fa")) {
    await completeTwoFactorSetup(page);
  }
  console.log("Login successful — master user authenticated");

  // Verify we're logged in
  await expect(page).toHaveURL(/\/dashboard/);

  // Save authentication state
  await page.context().storageState({ path: authFile });
  console.log("Auth state saved to:", authFile);
});
