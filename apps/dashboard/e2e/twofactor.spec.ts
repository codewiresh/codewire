import { test, expect, Page } from "@playwright/test";
import { clearRateLimits, cleanupUser } from "./helpers/db";
import { TEST_PASSWORD } from "./helpers/seed";
import * as OTPAuth from "otpauth";

/**
 * Two-Factor Authentication Test Suite
 *
 * Tests the mandatory 2FA flow:
 *   1. Sign up a fresh user -> gets session (no 2FA yet)
 *   2. Enable 2FA via /setup-2fa -> scan QR + verify code
 *   3. Sign out -> sign in again -> 2FA challenge (no session cookie)
 *   4. Enter TOTP code -> session created -> redirect to dashboard
 *   5. Security: validate endpoint rejects invalid/expired tokens
 *
 * This test does NOT rely on SKIP_2FA_SETUP — it tests the real flow.
 */

const SERVER_URL = process.env.SERVER_URL || "http://localhost:8080";
const E2E_2FA_EMAIL = "e2e-2fa-test@codewire.sh";

type DeviceAuthorization = {
  device_code: string;
  user_code: string;
  verification_uri_complete: string;
};

type TokenSet = {
  access_token: string;
  token_type: string;
  scope: string;
};

// Use "commit" waitUntil because Vite HMR keeps page in loading state
const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};

test.describe.serial("Two-Factor Authentication", () => {
  let totpSecret: string;

  test.beforeAll(async () => {
    // Clean up from any previous run
    await cleanupUser(E2E_2FA_EMAIL);
    await clearRateLimits();

    // Create user via API (faster than UI)
    const res = await fetch(`${SERVER_URL}/api/auth/sign-up`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: E2E_2FA_EMAIL,
        password: TEST_PASSWORD,
        name: "E2E 2FA Test",
        invite_code: "BETA-001",
      }),
    });
    if (!res.ok && res.status !== 409) {
      throw new Error(`Failed to create user: ${res.status} ${await res.text()}`);
    }
    await clearRateLimits();
  });

  test.afterAll(async () => {
    await cleanupUser(E2E_2FA_EMAIL);
  });

  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("sign-in without 2FA returns session (SKIP_2FA_SETUP=true)", async () => {
    // Without 2FA enabled, sign-in should return a normal session
    const res = await fetch(`${SERVER_URL}/api/auth/sign-in`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: E2E_2FA_EMAIL, password: TEST_PASSWORD }),
    });
    expect(res.ok).toBe(true);
    const data = await res.json();
    expect(data.user).toBeDefined();
    expect(data.session).toBeDefined();
    expect(data.twoFactorRequired).toBeUndefined();
  });

  test("enable 2FA via API and verify TOTP code", async () => {
    // Sign in first to get session
    const signInRes = await fetch(`${SERVER_URL}/api/auth/sign-in`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: E2E_2FA_EMAIL, password: TEST_PASSWORD }),
    });
    const signInData = await signInRes.json();
    const sessionToken = signInData.session.token;

    // Enable 2FA
    const enableRes = await fetch(`${SERVER_URL}/api/auth/two-factor/enable`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `codewire.session_token=${sessionToken}`,
      },
    });
    expect(enableRes.ok).toBe(true);
    const enableData = await enableRes.json();
    expect(enableData.totpUri).toBeDefined();
    expect(enableData.secret).toBeDefined();
    expect(enableData.backupCodes).toHaveLength(10);

    totpSecret = enableData.secret;

    // Verify with a valid TOTP code
    const totp = new OTPAuth.TOTP({ secret: totpSecret });
    const code = totp.generate();

    const verifyRes = await fetch(`${SERVER_URL}/api/auth/two-factor/verify`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `codewire.session_token=${sessionToken}`,
      },
      body: JSON.stringify({ code }),
    });
    expect(verifyRes.ok).toBe(true);
    const verifyData = await verifyRes.json();
    expect(verifyData.enabled).toBe(true);
  });

  test("sign-in with 2FA returns challenge (no session)", async () => {
    // Now that 2FA is enabled, sign-in should NOT return a session
    const res = await fetch(`${SERVER_URL}/api/auth/sign-in`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: E2E_2FA_EMAIL, password: TEST_PASSWORD }),
    });
    expect(res.ok).toBe(true);
    const data = await res.json();
    expect(data.twoFactorRequired).toBe(true);
    expect(data.twoFactorToken).toBeDefined();
    // Should NOT have session or user
    expect(data.session).toBeUndefined();
    expect(data.user).toBeUndefined();
  });

  test("validate TOTP with token creates session", async () => {
    // Sign in to get challenge token
    const signInRes = await fetch(`${SERVER_URL}/api/auth/sign-in`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: E2E_2FA_EMAIL, password: TEST_PASSWORD }),
    });
    const challenge = await signInRes.json();
    expect(challenge.twoFactorRequired).toBe(true);

    // Generate TOTP code
    const totp = new OTPAuth.TOTP({ secret: totpSecret });
    const code = totp.generate();

    // Validate with token
    const validateRes = await fetch(`${SERVER_URL}/api/auth/two-factor/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, token: challenge.twoFactorToken }),
    });
    expect(validateRes.ok).toBe(true);
    const data = await validateRes.json();
    expect(data.user).toBeDefined();
    expect(data.user.email).toBe(E2E_2FA_EMAIL);
    expect(data.user.two_factor_enabled).toBe(true);
    expect(data.session).toBeDefined();
  });

  test("validate rejects invalid token", async () => {
    const totp = new OTPAuth.TOTP({ secret: totpSecret });
    const code = totp.generate();

    const res = await fetch(`${SERVER_URL}/api/auth/two-factor/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, token: "bogus-token-that-does-not-exist" }),
    });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error ?? data.detail).toMatch(/invalid(_token)?|Invalid or expired 2FA token/);
  });

  test("validate rejects wrong TOTP code", async () => {
    // Get a valid challenge token
    const signInRes = await fetch(`${SERVER_URL}/api/auth/sign-in`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: E2E_2FA_EMAIL, password: TEST_PASSWORD }),
    });
    const challenge = await signInRes.json();

    // Use a wrong code
    const res = await fetch(`${SERVER_URL}/api/auth/two-factor/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: "000000", token: challenge.twoFactorToken }),
    });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error ?? data.detail).toMatch(/invalid(_code)?|Invalid/);
  });

  test("full browser flow: sign in -> 2FA challenge -> verify -> dashboard", async ({
    page,
  }) => {
    // Navigate to login
    await goto(page, "/login");
    await page.waitForSelector('button:has-text("Sign in")', { timeout: 10000 });
    await page.waitForTimeout(500);

    // Fill credentials
    await fillField(page, "#email", E2E_2FA_EMAIL);
    await fillField(page, "#password", TEST_PASSWORD);

    // Submit
    await page.getByRole("button", { name: /sign in/i }).click();

    // Should redirect to /two-factor with token param
    await page.waitForURL(/\/two-factor\?token=/, { timeout: 10000 });
    expect(page.url()).toContain("/two-factor?token=");

    // Generate TOTP code and enter it
    const totp = new OTPAuth.TOTP({ secret: totpSecret });
    const code = totp.generate();

    await fillField(page, "#code", code);
    await page.getByRole("button", { name: /verify/i }).click();

    // Should redirect to dashboard
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    expect(page.url()).toContain("/dashboard");
  });

  test("OAuth device login returns through 2FA to device approval", async ({
    page,
    request,
  }) => {
    const requestedScope = "openid profile email offline_access codewire.api";
    const deviceResponse = await request.post(
      `${SERVER_URL}/api/oauth/device_authorization`,
      {
        form: {
          client_id: "codewire-cli",
          scope: requestedScope,
        },
      },
    );
    expect(deviceResponse.ok()).toBe(true);
    const device = await deviceResponse.json() as DeviceAuthorization;

    await goto(page, device.verification_uri_complete);
    await expect(page).toHaveURL(/\/login\?return_to=/);
    expect(new URL(page.url()).searchParams.get("return_to")).toBe(
      `/device?user_code=${device.user_code}`,
    );

    await fillField(page, "#email", E2E_2FA_EMAIL);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/\/two-factor\?/, { timeout: 10000 });
    expect(new URL(page.url()).searchParams.get("return_to")).toBe(
      `/device?user_code=${device.user_code}`,
    );

    const code = new OTPAuth.TOTP({ secret: totpSecret }).generate();
    await fillField(page, "#code", code);
    await page.getByRole("button", { name: /verify/i }).click();
    await page.waitForURL(/\/device\?user_code=/, { timeout: 10000 });
    await expect(page.getByPlaceholder("ABCD-1234")).toHaveValue(
      device.user_code,
    );

    await page.getByRole("button", { name: "Authorize CLI Access" }).click();
    await expect(page.getByText("CLI Authorized")).toBeVisible();

    const exchange = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
      },
    });
    expect(exchange.ok()).toBe(true);
    const tokens = await exchange.json() as TokenSet;
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.scope.split(" ")).toEqual(
      expect.arrayContaining(requestedScope.split(" ")),
    );

    const userinfo = await request.get(`${SERVER_URL}/api/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.ok()).toBe(true);
    expect((await userinfo.json()).email).toBe(E2E_2FA_EMAIL);

    const productRpc = await request.post(
      `${SERVER_URL}/codewire.v1.OrganizationService/ListOrganizations`,
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/json",
        },
        data: {},
      },
    );
    expect(productRpc.ok()).toBe(true);
  });
});
