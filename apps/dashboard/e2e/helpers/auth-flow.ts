import { expect, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";

export const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};

export const completeTwoFactorSetup = async (page: Page) => {
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

export const completeSetupIfRequired = async (page: Page) => {
  const setupHeading = page.getByRole("heading", {
    name: /set up two-factor authentication/i,
  });
  if (await setupHeading.isVisible({ timeout: 15000 }).catch(() => false)) {
    await completeTwoFactorSetup(page);
  }
};

export const completeTwoFactorSetupFromSession = async (page: Page) => {
  await page.goto("/setup-2fa", { waitUntil: "commit" });
  await completeTwoFactorSetup(page);
};
