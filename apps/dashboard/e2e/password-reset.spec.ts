import { test, expect, Page } from "@playwright/test";

/**
 * Password reset tests - run WITHOUT pre-authenticated state.
 * Tests forgot-password and reset-password page UI states.
 */

// Use "commit" waitUntil because Vite HMR keeps page in loading state
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

// Helper to fill a form field (React controlled inputs need pressSequentially)
const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.click();
  await field.pressSequentially(value, { delay: 20 });
};

test.describe("Password Reset", () => {
  test("shows forgot password form", async ({ page }) => {
    await goto(page, "/forgot-password");

    await expect(
      page.getByRole("heading", { name: /forgot password/i })
    ).toBeVisible();
    await expect(page.locator("#email")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /send reset link/i })
    ).toBeVisible();
  });

  test("login page links to forgot password", async ({ page }) => {
    await goto(page, "/login");

    const forgotLink = page.getByRole("link", { name: /forgot password/i });
    await expect(forgotLink).toBeVisible();
    await forgotLink.click();

    await expect(page).toHaveURL(/\/forgot-password/);
  });

  test('shows "Check your email" after submit', async ({ page }) => {
    await goto(page, "/forgot-password");
    await page.waitForSelector('button:has-text("Send reset link")');

    await fillField(page, "#email", "test@codewire.sh");
    await page.getByRole("button", { name: /send reset link/i }).click();

    // Should show check your email message
    await expect(page.getByText(/check your email/i)).toBeVisible({
      timeout: 10000,
    });
  });

  test("shows invalid link page without token", async ({ page }) => {
    await goto(page, "/reset-password");

    // Without a token, should show invalid/expired link message
    await expect(page.getByText(/invalid or expired link/i)).toBeVisible({
      timeout: 10000,
    });
  });

  test("shows invalid link page for INVALID_TOKEN error", async ({ page }) => {
    await goto(page, "/reset-password?error=INVALID_TOKEN");

    await expect(page.getByText(/invalid or expired link/i)).toBeVisible({
      timeout: 10000,
    });
  });

  test("shows reset form when token present", async ({ page }) => {
    await goto(page, "/reset-password?token=test");

    await expect(
      page.getByRole("heading", { name: /reset your password/i })
    ).toBeVisible();
    await expect(page.locator("#password")).toBeVisible();
    await expect(page.locator("#confirmPassword")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /reset password/i })
    ).toBeVisible();
  });
});
