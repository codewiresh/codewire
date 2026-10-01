import { expect, request as playwrightRequest, test, type Page, type Response } from "@playwright/test";
import * as OTPAuth from "otpauth";
import {
  accountSecurityState, cleanupUser, clearRateLimits, createAuthenticatedSession, seedSyntheticUser,
} from "./helpers/db";
import { fillField } from "./helpers/auth-flow";
import { TEST_PASSWORD } from "./helpers/seed";

// Real checked-in IdP, dashboard and database topology with one synthetic
// owner. The editable fixture spec proves presentation; this journey proves
// the fresh proof, the swap, session revocation and cookie rotation.
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const email = `e2e-account-two-factor-${runId}@codewire.sh`;
const origin = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

// Identity journeys handle TOTP seeds and recovery codes. A failed retry must
// not promote them into screenshots or traces.
test.use({ storageState: { cookies: [], origins: [] }, trace: "off", screenshot: "off" });

let secret = "";
let lastCode = "";
let recoveryCodes: string[] = [];

/** A code from a later time step than any the IdP has accepted. */
async function freshCode(seed: string): Promise<string> {
  const generate = () => new OTPAuth.TOTP({ secret: seed }).generate();
  if (lastCode) {
    await expect.poll(generate, { timeout: 35_000, intervals: [1_000] }).not.toBe(lastCode);
  }
  lastCode = generate();
  return lastCode;
}

async function submit(page: Page, path: string, owner: ReturnType<Page["getByRole"]>, button: string): Promise<Response> {
  const response = page.waitForResponse((candidate) => (
    new URL(candidate.url()).pathname === path && candidate.request().method() === "POST"
  ), { timeout: 15_000 });
  await owner.getByRole("button", { name: button, exact: true }).click();
  return response;
}

async function sessionCookie(page: Page): Promise<string> {
  const cookie = (await page.context().cookies()).find((candidate) => candidate.name === "codewire.session_token");
  expect(cookie).toMatchObject({ httpOnly: true, sameSite: "Lax", path: "/" });
  return cookie!.value;
}

async function signIn(page: Page, code: string): Promise<number> {
  await page.goto("/login");
  await fillField(page, "#email", email);
  await fillField(page, "#password", TEST_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/two-factor(?:\?|$)/);
  await fillField(page, "#code", code);
  const response = page.waitForResponse((candidate) => (
    new URL(candidate.url()).pathname === "/two-factor/_actions/validate" && candidate.request().method() === "POST"
  ), { timeout: 15_000 });
  await page.getByRole("button", { name: /verify/i }).click();
  return (await response).status();
}

function assertPrivate(response: Response, secrets: string[]) {
  expect(response.headers()["cache-control"]).toBe("no-store");
  const location = response.headers().location || "";
  for (const value of secrets.filter(Boolean)) expect(location).not.toContain(value);
}

test.describe.serial("Account › Security replaces the authenticator after a fresh proof", () => {
  test.beforeAll(async ({}, info) => {
    test.skip(info.project.name !== "dashboard-ssr-desktop", "one managed two-factor proof");
    await clearRateLimits();
    await seedSyntheticUser(email, "Two-factor owner");
  });

  test.afterAll(async () => {
    await cleanupUser(email);
  });

  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("enrolls through the real setup flow", async ({ page }) => {
    await page.goto("/login");
    await fillField(page, "#email", email);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await expect(page.getByRole("heading", { name: "Secure your account" })).toBeVisible();
    secret = (await page.getByTestId("totp-secret").textContent())?.trim() || "";
    expect(secret).not.toBe("");
    await fillField(page, "#code", await freshCode(secret));
    await page.getByRole("button", { name: /enable two-factor authentication/i }).click();
    await expect(page.getByTestId("recovery-code")).toHaveCount(10);
    recoveryCodes = (await page.getByTestId("recovery-code").allTextContents()).map((code) => code.trim());
  });

  test("a wrong proof says what still works and counts one failure", async ({ page }) => {
    expect(await signIn(page, await freshCode(secret))).toBe(303);
    await page.goto("/settings/");
    const security = page.getByRole("region", { name: "Security", exact: true });
    await expect(security).toContainText("Sign-in asks for a code from your authenticator app. Recovery codes each work once.");
    await security.getByRole("button", { name: "Replace authenticator", exact: true }).click();
    const proof = page.getByRole("dialog", { name: "Replace authenticator", exact: true });
    await proof.getByLabel("Password", { exact: true }).fill(TEST_PASSWORD);
    await proof.getByLabel("Current code or recovery code", { exact: true }).fill("ffffffffff");
    const rejected = await submit(page, "/settings/_actions/two-factor/replace/start", proof, "Continue");
    expect(rejected.status()).toBe(422);
    assertPrivate(rejected, [TEST_PASSWORD]);
    await expect(page.getByRole("dialog", { name: "Replace authenticator", exact: true }).getByRole("alert"))
      .toHaveText("The password or code didn't match. Nothing changed: your current authenticator and recovery codes still work.");
    expect(await page.content()).not.toContain(TEST_PASSWORD);
    expect((await accountSecurityState(email)).failures).toBe(1);
  });

  test("regenerating with a recovery code replaces every code and keeps the session", async ({ page }) => {
    expect(await signIn(page, await freshCode(secret))).toBe(303);
    const before = await sessionCookie(page);
    await page.goto("/settings/#security");
    await page.getByRole("button", { name: "Regenerate recovery codes", exact: true }).click();
    const proof = page.getByRole("dialog", { name: "Regenerate recovery codes", exact: true });
    await proof.getByLabel("Password", { exact: true }).fill(TEST_PASSWORD);
    await proof.getByLabel("Current code or recovery code", { exact: true }).fill(recoveryCodes[0]);
    const regenerated = await submit(page, "/settings/_actions/two-factor/recovery-codes/regenerate", proof, "Regenerate codes");
    expect(regenerated.status()).toBe(200);
    assertPrivate(regenerated, [TEST_PASSWORD, recoveryCodes[0]]);
    const done = page.getByRole("dialog", { name: "New recovery codes", exact: true });
    await expect(done.getByTestId("recovery-code")).toHaveCount(10);
    const fresh = (await done.getByTestId("recovery-code").allTextContents()).map((code) => code.trim());
    expect(fresh.some((code) => recoveryCodes.includes(code))).toBe(false);
    expect(await sessionCookie(page)).toBe(before);
    await done.getByRole("link", { name: "Done", exact: true }).click();
    await expect(page).toHaveURL(/\/settings\/#security$/);
    expect(await page.content()).not.toContain(fresh[0]);
    recoveryCodes = fresh;
  });

  test("replacing swaps the factor, signs out other browsers and rotates this one", async ({ page }) => {
    expect(await signIn(page, await freshCode(secret))).toBe(303);
    const other = await createAuthenticatedSession(email);
    const before = await sessionCookie(page);
    expect((await accountSecurityState(email)).sessions).toBeGreaterThanOrEqual(2);

    await page.goto("/settings/#security");
    await page.getByRole("button", { name: "Replace authenticator", exact: true }).click();
    const proof = page.getByRole("dialog", { name: "Replace authenticator", exact: true });
    await proof.getByLabel("Password", { exact: true }).fill(TEST_PASSWORD);
    await proof.getByLabel("Current code or recovery code", { exact: true }).fill(await freshCode(secret));
    const started = await submit(page, "/settings/_actions/two-factor/replace/start", proof, "Continue");
    expect(started.status()).toBe(200);
    const confirm = page.getByRole("dialog", { name: "Add your new authenticator", exact: true });
    await expect(confirm.getByRole("img", { name: "QR code for your new authenticator" })).toBeVisible();
    const replacement = (await confirm.getByTestId("replacement-totp-secret").textContent())?.trim() || "";
    expect(replacement).toMatch(/^[A-Z2-7]{32}$/);
    expect(replacement).not.toBe(secret);
    assertPrivate(started, [TEST_PASSWORD, replacement]);
    expect(page.url()).not.toContain(replacement);

    // The old authenticator keeps working while the replacement is pending.
    const wrong = String((Number(new OTPAuth.TOTP({ secret: replacement }).generate()) + 500_000) % 1_000_000).padStart(6, "0");
    await confirm.getByLabel("Code from your new authenticator", { exact: true }).fill(wrong);
    const refused = await submit(page, "/settings/_actions/two-factor/replace/confirm", confirm, "Replace authenticator");
    expect(refused.status()).toBe(422);
    assertPrivate(refused, [replacement]);
    const retry = page.getByRole("dialog", { name: "Add your new authenticator", exact: true });
    await expect(retry.getByRole("alert")).toContainText("Your current authenticator still works.");
    await expect(retry.getByTestId("replacement-totp-secret")).toHaveCount(0);
    expect(await page.content()).not.toContain(replacement);

    await retry.getByLabel("Code from your new authenticator", { exact: true })
      .fill(new OTPAuth.TOTP({ secret: replacement }).generate());
    const replaced = await submit(page, "/settings/_actions/two-factor/replace/confirm", retry, "Replace authenticator");
    expect(replaced.status()).toBe(200);
    assertPrivate(replaced, [replacement]);
    const done = page.getByRole("dialog", { name: "Authenticator replaced", exact: true });
    await expect(done.getByRole("status")).toContainText(
      "Your old authenticator and recovery codes no longer work, and your other browsers were signed out.",
    );
    await expect(done.getByTestId("recovery-code")).toHaveCount(10);
    const replacedCodes = (await done.getByTestId("recovery-code").allTextContents()).map((code) => code.trim());
    const rotated = await sessionCookie(page);
    expect(rotated).not.toBe(before);
    expect(await accountSecurityState(email)).toEqual({ sessions: 1, failures: 0 });

    // Both old cookies are refused; the rotated one opens Account.
    const api = await playwrightRequest.newContext({ baseURL: origin });
    try {
      for (const token of [before, other.token]) {
        const stale = await api.get("/settings/", {
          headers: { cookie: `codewire.session_token=${token}` }, maxRedirects: 0,
        });
        expect(stale.status()).toBe(303);
        expect(stale.headers().location).toMatch(/^\/login/);
      }
    } finally {
      await api.dispose();
    }
    await done.getByRole("link", { name: "Done", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    await expect(page.locator(".cw-account-session")).toHaveCount(1);

    // Sign-in now needs the new authenticator; the old one and its codes fail.
    await page.context().clearCookies();
    expect(await signIn(page, new OTPAuth.TOTP({ secret }).generate())).toBe(401);
    await expect(page.getByRole("alert")).toHaveText("The verification code is invalid.");
    await page.context().clearCookies();
    expect(await signIn(page, recoveryCodes[1])).toBe(401);
    await page.context().clearCookies();
    expect(await signIn(page, new OTPAuth.TOTP({ secret: replacement }).generate())).toBe(303);
    await page.context().clearCookies();
    expect(await signIn(page, replacedCodes[0])).toBe(303);
    secret = replacement;
  });
});
