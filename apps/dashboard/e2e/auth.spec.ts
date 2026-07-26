import { test, expect, Page } from "@playwright/test";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { clearRateLimits, disableTwoFactor } from "./helpers/db";
import { completeTwoFactorSetup, fillField } from "./helpers/auth-flow";

// Use "commit" waitUntil because Vite HMR keeps page in loading state
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

/**
 * Authentication tests - these run WITHOUT pre-authenticated state
 * to test the actual login flow.
 */
test.describe("Authentication", () => {
  test("should show login page", async ({ page }) => {
    await goto(page, "/login");

    await expect(
      page.getByRole("heading", { name: /welcome back/i })
    ).toBeVisible();
    await expect(page.getByLabel("Email")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /sign in/i })
    ).toBeVisible();
  });

  test("should login successfully with valid credentials", async ({ page }) => {
    await disableTwoFactor(USERS.billing.email);
    await clearRateLimits();

    await goto(page, "/login");
    await page.waitForSelector('button:has-text("Sign in")');

    await fillField(page, "#email", USERS.billing.email);
    await fillField(page, "#password", TEST_PASSWORD);

    await page.getByRole("button", { name: /sign in/i }).click();

    await page.waitForURL(/\/(dashboard|setup-2fa)/, { timeout: 15000 });
    const dashboardHeading = page.getByRole("heading", { name: "Dashboard" });
    const setupHeading = page.getByRole("heading", {
      name: /set up two-factor authentication/i,
    });
    const destination = await Promise.any([
      dashboardHeading
        .waitFor({ state: "visible", timeout: 15000 })
        .then(() => "dashboard"),
      setupHeading
        .waitFor({ state: "visible", timeout: 15000 })
        .then(() => "setup"),
    ]);
    if (destination === "setup") {
      await completeTwoFactorSetup(page);
    }

    await expect(dashboardHeading).toBeVisible({ timeout: 15000 });
  });

  test("should show error on invalid credentials", async ({ page }) => {
    await goto(page, "/login");
    await page.waitForSelector('button:has-text("Sign in")');

    await fillField(page, "#email", "invalid@example.com");
    await fillField(page, "#password", "wrongpassword");

    await page.getByRole("button", { name: /sign in/i }).click();

    // Should stay on login page (error case)
    await page.waitForTimeout(2000);
    await expect(page).toHaveURL(/\/login/);
  });

  test("should redirect unauthenticated users to login", async ({ page }) => {
    // Try to access dashboard without auth
    await page.goto("/dashboard");

    // Should redirect to login
    await expect(page).toHaveURL(/\/login/);
  });

  test("should have link to signup page", async ({ page }) => {
    await goto(page, "/login");

    const signupLink = page.getByRole("link", { name: /sign up/i });
    await expect(signupLink).toBeVisible();
    await signupLink.click();

    await expect(page).toHaveURL(/\/signup/);
  });
});
