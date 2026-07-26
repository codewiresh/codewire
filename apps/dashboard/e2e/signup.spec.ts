import { test, expect, Page } from "@playwright/test";
import { verifyUserEmail, cleanupUser } from "./helpers/db";
import { completeTwoFactorSetupFromSession } from "./helpers/auth-flow";

/**
 * Signup UI Test
 *
 * Isolated test for the signup form. Creates a throwaway user with a
 * timestamp-based email, verifies the form works end-to-end, and
 * cleans up the user in afterAll.
 */

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

const timestamp = Date.now();
const throwawayEmail = `e2e-signup-${timestamp}@codewire.sh`;
const throwawayName = "E2E Signup Test";
const throwawayPassword = "SecureTestPass9#";

test.describe("Signup UI", () => {
  test.afterAll(async () => {
    await cleanupUser(throwawayEmail);
  });

  test("signup form creates account and login works after email verification", async ({
    page,
  }) => {
    // Navigate to signup page
    await goto(page, "/signup");
    await page.waitForSelector('button:has-text("Create Account")');
    await page.waitForTimeout(1000); // Wait for React hydration

    // Fill all fields (INVITE_CODES=BETA-001,BETA-002,BETA-003 in docker)
    await fillField(page, "#invite-code", "BETA-001");
    await fillField(page, "#name", throwawayName);
    await fillField(page, "#email", throwawayEmail);
    await fillField(page, "#password", throwawayPassword);

    // Submit the form
    await page.getByRole("button", { name: /create account/i }).click();

    await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15000 });
    await completeTwoFactorSetupFromSession(page);
    await expect(
      page.getByRole("heading", { name: "Dashboard" })
    ).toBeVisible({ timeout: 10000 });
  });
});
