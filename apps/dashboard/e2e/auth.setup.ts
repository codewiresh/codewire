import { test as setup, expect, Page } from "@playwright/test";
import * as path from "path";
import { fileURLToPath } from "url";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { ACCOUNT_HOME } from "./helpers/org";
import * as OTPAuth from "otpauth";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const authFile = path.join(__dirname, "../playwright/.auth/user.json");

// Use an explicit commit wait so authentication redirects are observed.
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

// Fill fields through the same keyboard path users exercise.
const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};

// Retries share this worker, so a secret enrolled by an earlier attempt
// stays available when a later sign-in receives the challenge instead.
let enrolledTotpSecret: string | undefined;

const completeTwoFactorSetup = async (page: Page) => {
  await expect(page.getByRole("heading", { name: /secure your account/i }))
    .toBeVisible({ timeout: 15000 });

  const secret = (await page.getByTestId("totp-secret").textContent())?.trim();
  if (!secret) throw new Error("2FA setup secret was not visible");
  enrolledTotpSecret = secret;

  const code = new OTPAuth.TOTP({ secret }).generate();
  await fillField(page, "#code", code);
  await page.getByRole("button", { name: /enable two-factor authentication/i }).click();
  await expect(page.getByRole("heading", { name: /two-factor authentication enabled/i }))
    .toBeVisible({ timeout: 15000 });
  await expect(page.getByTestId("recovery-code")).toHaveCount(10);
  await page.getByRole("link", { name: /continue to codewire/i }).click();
  await page.waitForURL(ACCOUNT_HOME, { timeout: 15000 });
};

const completeTwoFactorChallenge = async (page: Page) => {
  if (!enrolledTotpSecret) {
    throw new Error("two-factor challenge arrived before this worker enrolled 2FA");
  }
  await expect(page.getByRole("heading", { name: /^two-factor authentication$/i }))
    .toBeVisible({ timeout: 15000 });

  const code = new OTPAuth.TOTP({ secret: enrolledTotpSecret }).generate();
  await fillField(page, "#code", code);
  await page.getByRole("button", { name: /^verify$/i }).click();
  await page.waitForURL(ACCOUNT_HOME, { timeout: 15000 });
};

setup("authenticate", async ({ page }) => {
  // globalSetup guarantees the master user exists — just log in
  await goto(page, "/login");
  await page.waitForSelector('button:has-text("Sign in")');

  await fillField(page, "#email", USERS.master.email);
  await fillField(page, "#password", TEST_PASSWORD);

  const signInResponse = page.waitForResponse((response) => (
    response.url().endsWith("/login/_actions/sign-in")
      && response.request().method() === "POST"
  ));
  await page.getByRole("button", { name: /sign in/i }).click();
  const response = await signInResponse;
  expect(response.status()).toBe(303);
  expect(response.headers().location).toMatch(/^\/(dashboard|setup-2fa|two-factor)/);

  await page.waitForURL(/\/(dashboard|setup-2fa|two-factor)/, { timeout: 15000 });
  await page.waitForTimeout(1000);
  if (page.url().includes("/setup-2fa")) {
    await completeTwoFactorSetup(page);
  } else if (page.url().includes("/two-factor")) {
    await completeTwoFactorChallenge(page);
  }
  console.log("Login successful — master user authenticated");

  // Verify we're logged in
  // The account home is the Dashboard without an organization, or the
  // organization's Sandboxes home with one; either proves the signed-in shell.
  // Match the page title only: the sidebar also labels its Sandboxes region.
  await expect(page).toHaveURL(ACCOUNT_HOME);
  await expect(
    page.getByRole("heading", { level: 1, name: "Dashboard", exact: true })
      .or(page.getByRole("heading", { level: 1, name: "Sandboxes", exact: true })),
  ).toBeVisible();
  const session = (await page.context().cookies()).find((cookie) => (
    cookie.name === "codewire.session_token"
  ));
  expect(session).toMatchObject({ httpOnly: true, sameSite: "Lax" });

  // Save authentication state
  await page.context().storageState({ path: authFile });
  console.log("Auth state saved to:", authFile);
});
