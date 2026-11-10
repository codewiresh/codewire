// covers: src/raw_auth.rs src/routes/authentication.rs src/routes/device.rs src/routes/settings.rs
// covers: templates/auth-form.html templates/auth-status.html templates/dashboard.html
// covers: templates/device.html templates/settings.html templates/setup-two-factor.html
// covers: templates/two-factor-recovery.html
import { expect, test, type Page } from "@playwright/test";
import { createPublicKey, verify } from "node:crypto";
import * as OTPAuth from "otpauth";
import {
  bindSyntheticPasswordResetToken,
  cleanupUser,
  clearRateLimits,
  getUserId,
  seedSyntheticUser,
} from "./helpers/db";
import { fillField } from "./helpers/auth-flow";
import { TEST_PASSWORD } from "./helpers/seed";

const serverUrl = process.env.SERVER_URL || "http://127.0.0.1:8080";
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const authEmail = `e2e-ssr-auth-${runId}@codewire.sh`;
const enrollmentEmail = `e2e-ssr-enrollment-${runId}@codewire.sh`;
const skipSetupEmail = `e2e-ssr-skip-setup-${runId}@codewire.sh`;
const resetEmail = `e2e-ssr-reset-${runId}@codewire.sh`;
const signupSafetyEmail = `e2e-ssr-signup-${runId}@codewire.sh`;
const replacementPassword = "ReplacementPass8!";

let totpSecret = "";
let lastTotpCode = "";

// Identity tests handle TOTP seeds and short-lived OAuth tokens. A failed
// retry must not promote those values into screenshots or trace artifacts.
test.use({ screenshot: "off", trace: "off" });

type PublishedJwk = {
  kty: string;
  crv: string;
  x: string;
  use: string;
  alg: string;
  kid: string;
};

type PublishedJwks = { keys: PublishedJwk[] };

function verifyIdTokenAgainstPublishedJwks(
  idToken: string,
  jwks: PublishedJwks,
): boolean {
  const [encodedHeader, encodedClaims, encodedSignature, extra] = idToken.split(".");
  expect(extra).toBeUndefined();
  const header = JSON.parse(
    Buffer.from(encodedHeader, "base64url").toString("utf8"),
  ) as { alg?: string; kid?: string };
  expect(header).toMatchObject({ alg: "EdDSA", kid: expect.any(String) });

  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  expect(jwk).toMatchObject({
    kty: "OKP",
    crv: "Ed25519",
    use: "sig",
    alg: "EdDSA",
  });
  if (!jwk) return false;

  const key = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: jwk.x },
    format: "jwk",
  });
  return verify(
    null,
    Buffer.from(`${encodedHeader}.${encodedClaims}`),
    key,
    Buffer.from(encodedSignature, "base64url"),
  );
}

async function freshTotpCode(): Promise<string> {
  const generate = () => new OTPAuth.TOTP({ secret: totpSecret }).generate();
  if (lastTotpCode) {
    await expect.poll(generate, { timeout: 35_000, intervals: [1_000] })
      .not.toBe(lastTotpCode);
  }
  lastTotpCode = generate();
  return lastTotpCode;
}

async function submitAndCapture(page: Page, path: string, button: RegExp) {
  const response = page.waitForResponse((candidate) => (
    new URL(candidate.url()).pathname === path
      && candidate.request().method() === "POST"
  ), { timeout: 15_000 });
  const owner = path === "/settings/_actions/sign-out"
    ? page.locator("form#sign-out")
    : page;
  await owner.getByRole("button", { name: button }).click();
  return response;
}

async function signInThroughRust(
  page: Page,
  email: string,
  password: string,
  navigate = true,
) {
  if (navigate) await page.goto("/login");
  await fillField(page, "#email", email);
  await fillField(page, "#password", password);
  return submitAndCapture(page, "/login/_actions/sign-in", /sign in/i);
}

async function finishTwoFactorChallenge(
  page: Page,
  destination: RegExp = /\/dashboard/,
) {
  await expect(page).toHaveURL(/\/two-factor(?:\?|$)/);
  expect(new URL(page.url()).searchParams.has("token")).toBe(false);
  const challenge = (await page.context().cookies()).find((cookie) => (
    cookie.name === "codewire_2fa_challenge"
  ));
  expect(challenge).toMatchObject({
    httpOnly: true,
    sameSite: "Strict",
    path: "/two-factor",
  });
  await fillField(
    page,
    "#code",
    await freshTotpCode(),
  );
  const response = await submitAndCapture(
    page,
    "/two-factor/_actions/validate",
    /verify/i,
  );
  expect(response.status()).toBe(303);
  await expect(page).toHaveURL(destination);
  if (destination.source.includes("dashboard")) {
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  }
}

test.describe.serial("server-rendered identity flows", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test.beforeAll(async () => {
    await cleanupUser(authEmail);
    await cleanupUser(enrollmentEmail);
    await cleanupUser(resetEmail);
    await cleanupUser(signupSafetyEmail);
    await clearRateLimits();
  });

  test.afterAll(async () => {
    await cleanupUser(authEmail);
    await cleanupUser(enrollmentEmail);
    await cleanupUser(resetEmail);
    await cleanupUser(signupSafetyEmail);
  });

  test.beforeEach(async () => {
    await clearRateLimits();
  });

  test("publishes a usable OIDC discovery document and Ed25519 key", { tag: "@smoke" }, async ({ request, isMobile }) => {
    test.skip(!!isMobile, "desktop identity provider contract");

    const discoveryResponse = await request.get(
      `${serverUrl}/.well-known/openid-configuration`,
    );
    expect(discoveryResponse.ok(), await discoveryResponse.text()).toBe(true);
    const discovery = await discoveryResponse.json() as {
      issuer: string;
      authorization_endpoint: string;
      token_endpoint: string;
      userinfo_endpoint: string;
      jwks_uri: string;
      id_token_signing_alg_values_supported: string[];
      code_challenge_methods_supported: string[];
    };
    expect(discovery).toMatchObject({
      issuer: expect.any(String),
      authorization_endpoint: expect.stringContaining("/api/oauth/authorize"),
      token_endpoint: expect.stringContaining("/api/oauth/token"),
      userinfo_endpoint: expect.stringContaining("/api/oauth/userinfo"),
      jwks_uri: expect.stringContaining("/.well-known/jwks.json"),
      id_token_signing_alg_values_supported: expect.arrayContaining(["EdDSA"]),
      code_challenge_methods_supported: expect.arrayContaining(["S256"]),
    });

    const jwksResponse = await request.get(`${serverUrl}/.well-known/jwks.json`);
    expect(jwksResponse.ok(), await jwksResponse.text()).toBe(true);
    const jwks = await jwksResponse.json() as PublishedJwks;
    expect(jwks.keys).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kty: "OKP",
        crv: "Ed25519",
        alg: "EdDSA",
        use: "sig",
        kid: expect.any(String),
        x: expect.any(String),
      }),
    ]));
  });

  test("fails closed when public signup has no human-verification authority", async ({ request, isMobile }) => {
    test.skip(!!isMobile, "desktop identity provider contract");

    const response = await request.post(`${serverUrl}/api/auth/sign-up`, {
      data: {
        email: signupSafetyEmail,
        password: TEST_PASSWORD,
        name: "SSR Signup Safety Probe",
        invite_code: "BETA-001",
        reason: "Verify the deployed signup safety boundary",
      },
    });
    expect(response.status()).toBe(503);
    expect(await response.text()).toContain(
      "Human verification is temporarily unavailable",
    );
    expect(await getUserId(signupSafetyEmail)).toBeNull();
  });

  test("enrolls a seeded login in 2FA and reveals recovery codes only after verification", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop manual-enrollment contract");

    await seedSyntheticUser(enrollmentEmail, "SSR Manual Enrollment");
    await clearRateLimits();
    await page.context().clearCookies();

    const login = await signInThroughRust(page, enrollmentEmail, TEST_PASSWORD);
    expect(login.status()).toBe(303);
    expect(login.headers().location).toMatch(/^\/setup-2fa/);
    await expect(page).toHaveURL(/\/setup-2fa(?:\?|$)/);
    await expect(page.getByRole("heading", { name: "Secure your account" })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);

    expect(await page.getByRole("heading", { name: /save recovery codes/i }).count())
      .toBe(0);
    expect(await page.getByTestId("recovery-code").count()).toBe(0);

    const secret = (await page.getByTestId("totp-secret").textContent())?.trim() || "";
    expect(secret).not.toBe("");
    const currentCode = new OTPAuth.TOTP({ secret }).generate();
    const invalidCode = currentCode === "000000" ? "000001" : "000000";
    await fillField(page, "#code", invalidCode);
    const rejected = await submitAndCapture(
      page,
      "/setup-2fa/_actions/verify",
      /enable two-factor authentication/i,
    );
    expect(rejected.status()).toBe(400);
    await page.waitForLoadState("domcontentloaded");
    expect(await page.getByRole("alert").count()).toBe(1);
    const secretAfterRejection =
      (await page.getByTestId("totp-secret").textContent())?.trim() || "";
    expect(secretAfterRejection === secret).toBe(true);
    expect(await page.getByTestId("recovery-code").count()).toBe(0);

    await fillField(
      page,
      "#code",
      new OTPAuth.TOTP({ secret: secretAfterRejection || secret }).generate(),
    );
    const setup = await submitAndCapture(
      page,
      "/setup-2fa/_actions/verify",
      /enable two-factor authentication/i,
    );
    expect(setup.status()).toBe(200);
    await page.waitForLoadState("domcontentloaded");
    expect(await page.getByRole("heading", {
      name: /two-factor authentication enabled/i,
    }).count()).toBe(1);
    expect(await page.getByTestId("recovery-code").count()).toBe(10);
    const continueLink = page.getByRole("link", { name: /continue to codewire/i });
    if (await continueLink.count()) await continueLink.click();
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
  });

  test("skips 2FA setup for this session only and asks again at the next sign-in", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop setup-skip contract");

    await seedSyntheticUser(skipSetupEmail, "SSR Setup Skip");
    await clearRateLimits();
    await page.context().clearCookies();

    const login = await signInThroughRust(page, skipSetupEmail, TEST_PASSWORD);
    expect(login.headers().location).toMatch(/^\/setup-2fa/);
    await expect(page.getByRole("heading", { name: "Secure your account" })).toBeVisible();
    const skipped = await submitAndCapture(page, "/setup-2fa/_actions/skip", /set up later/i);
    expect(skipped.status()).toBe(303);
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();

    await page.context().clearCookies();
    const again = await signInThroughRust(page, skipSetupEmail, TEST_PASSWORD);
    expect(again.headers().location).toMatch(/^\/setup-2fa/);
    await expect(page.getByRole("heading", { name: "Secure your account" })).toBeVisible();
  });

  test("enables 2FA for a seeded login, signs out, and completes a fresh login", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop identity mutation contract");
    test.setTimeout(90_000);

    await seedSyntheticUser(authEmail, "SSR Identity User");
    const login = await signInThroughRust(page, authEmail, TEST_PASSWORD);
    expect(login.status()).toBe(303);
    expect(login.headers().location).toMatch(/^\/setup-2fa/);

    await expect(page.getByRole("heading", { name: "Secure your account" })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
    totpSecret = (await page.getByTestId("totp-secret").textContent())?.trim() || "";
    expect(totpSecret).not.toBe("");
    const setupCode = new OTPAuth.TOTP({ secret: totpSecret }).generate();
    lastTotpCode = setupCode;
    await fillField(page, "#code", setupCode);
    const setup = await submitAndCapture(
      page,
      "/setup-2fa/_actions/verify",
      /enable two-factor authentication/i,
    );
    expect(setup.status()).toBe(200);
    await expect(page.getByRole("heading", { name: /two-factor authentication enabled/i }))
      .toBeVisible();
    await expect(page.getByTestId("recovery-code")).toHaveCount(10);
    await page.getByRole("link", { name: /continue to codewire/i }).click();
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();

    const session = (await page.context().cookies()).find((cookie) => (
      cookie.name === "codewire.session_token"
    ));
    expect(session).toMatchObject({ httpOnly: true, sameSite: "Lax", path: "/" });

    await page.goto("/settings/");
    const signOut = await submitAndCapture(
      page,
      "/settings/_actions/sign-out",
      /sign out/i,
    );
    expect(signOut.status()).toBe(303);
    await expect(page).toHaveURL(/\/login/);
    expect((await page.context().cookies()).some((cookie) => (
      cookie.name === "codewire.session_token"
    ))).toBe(false);

    const freshLogin = await signInThroughRust(page, authEmail, TEST_PASSWORD);
    expect(freshLogin.status()).toBe(303);
    expect(freshLogin.headers().location).toMatch(/^\/two-factor/);
    await finishTwoFactorChallenge(page);

    // A page loaded in another tab must not invalidate this tab's navigation.
    const otherTab = await page.context().newPage();
    await otherTab.goto("/settings/");
    await otherTab.close();
    const navigationSignOut = page.waitForResponse((candidate) => (
      new URL(candidate.url()).pathname === "/settings/_actions/sign-out"
        && candidate.request().method() === "POST"
    ), { timeout: 15_000 });
    // Sign Out is in the account menu at the foot of the sidebar.
    await page.locator(".cw-sidebar-slot .cw-account-menu > summary").click();
    await page.locator(".cw-sidebar-slot form[data-sign-out]")
      .getByRole("button", { name: "Sign Out", exact: true })
      .click();
    expect((await navigationSignOut).status()).toBe(303);
    await expect(page).toHaveURL(/\/login/);
    expect((await page.context().cookies()).some((cookie) => (
      cookie.name === "codewire.session_token"
    ))).toBe(false);
    await page.goto("/dashboard/");
    await expect(page).toHaveURL(/\/login/);
  });

  test("resets a password through the clean-URL HttpOnly token flow", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop password-reset mutation contract");

    await seedSyntheticUser(resetEmail, "SSR Password Reset");
    await clearRateLimits();

    await page.goto("/forgot-password");
    await fillField(page, "#email", resetEmail);
    const request = await submitAndCapture(
      page,
      "/forgot-password/_actions/request",
      /send reset link/i,
    );
    expect(request.status(), await request.text()).toBe(200);
    await expect(page.getByRole("heading", { name: "Check your email" })).toBeVisible();

    const token = await bindSyntheticPasswordResetToken(resetEmail);
    expect(token).toBeTruthy();
    await page.goto(`/reset-password?token=${token}`);
    await expect(page).toHaveURL(/\/reset-password$/);
    expect(await page.content()).not.toContain(token!);
    const resetCookie = (await page.context().cookies()).find((cookie) => (
      cookie.name === "codewire_password_reset"
    ));
    expect(resetCookie).toMatchObject({
      httpOnly: true,
      sameSite: "Strict",
      path: "/reset-password",
    });

    await fillField(page, "#password", replacementPassword);
    await fillField(page, "#confirm-password", replacementPassword);
    const reset = await submitAndCapture(
      page,
      "/reset-password/_actions/reset",
      /reset password/i,
    );
    expect(reset.status(), await reset.text()).toBe(200);
    await expect(page.getByRole("heading", { name: "Password reset" })).toBeVisible();
    expect((await page.context().cookies()).some((cookie) => (
      cookie.name === "codewire_password_reset"
    ))).toBe(false);

    const login = await signInThroughRust(page, resetEmail, replacementPassword);
    expect(login.status()).toBe(303);
    expect(login.headers().location).toMatch(/^\/setup-2fa/);
  });

  test("returns an OAuth device grant through 2FA and a scoped product RPC", async ({ page, request, isMobile }) => {
    test.skip(!!isMobile, "desktop device-authorization contract");
    test.setTimeout(90_000);

    const requestedScope = "openid profile email offline_access codewire.api";
    const authorization = await request.post(`${serverUrl}/api/oauth/device_authorization`, {
      form: { client_id: "codewire-cli", scope: requestedScope },
    });
    expect(authorization.ok(), await authorization.text()).toBe(true);
    const device = await authorization.json() as {
      device_code: string;
      user_code: string;
      verification_uri_complete: string;
    };

    await page.goto(device.verification_uri_complete);
    await expect(page).toHaveURL(/\/login\?return_to=/);
    expect(new URL(page.url()).searchParams.get("return_to")).toBe(
      `/device?user_code=${device.user_code}`,
    );

    const login = await signInThroughRust(page, authEmail, TEST_PASSWORD, false);
    expect(login.status()).toBe(303);
    await finishTwoFactorChallenge(
      page,
      new RegExp(`/device\\?user_code=${device.user_code}`),
    );
    const deviceCode = page.getByRole("group", { name: "Device code" });
    const deviceCodeSlots = deviceCode.getByRole("textbox");
    const deviceCodeValues = () => deviceCodeSlots.evaluateAll((inputs) => inputs.map((input) => (
      input instanceof HTMLInputElement ? input.value : ""
    )));
    await expect(deviceCodeSlots).toHaveCount(8);
    expect(await deviceCodeValues()).toEqual(device.user_code.replace("-", "").split(""));

    // Exercise the compact form accepted by both one-time-code autofill and
    // the server boundary instead of resubmitting the prefilled representation.
    await deviceCodeSlots.first().fill(device.user_code.replace("-", "").toLowerCase());
    expect(await deviceCodeValues()).toEqual(device.user_code.replace("-", "").split(""));

    const approval = await submitAndCapture(
      page,
      "/device/_actions/approve",
      /approve device/i,
    );
    expect(approval.status(), await approval.text()).toBe(200);
    await expect(page.getByRole("status")).toContainText("Device approved");

    const exchange = await request.post(`${serverUrl}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
      },
    });
    expect(exchange.ok(), await exchange.text()).toBe(true);
    const tokens = await exchange.json() as {
      access_token: string;
      refresh_token: string;
      token_type: string;
      scope: string;
    };
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.scope.split(" ")).toEqual(
      expect.arrayContaining(requestedScope.split(" ")),
    );

    const userinfo = await request.get(`${serverUrl}/api/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.ok(), await userinfo.text()).toBe(true);
    expect((await userinfo.json()).email).toBe(authEmail);

    const organizations = await request.post(
      `${serverUrl}/codewire.v1.OrganizationService/ListOrganizations`,
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/json",
        },
        data: {},
      },
    );
    expect(organizations.ok(), await organizations.text()).toBe(true);

    const refresh = await request.post(`${serverUrl}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "refresh_token",
        refresh_token: tokens.refresh_token,
      },
    });
    expect(refresh.ok(), await refresh.text()).toBe(true);
    const refreshed = await refresh.json() as {
      access_token: string;
      refresh_token: string;
    };
    expect(refreshed.access_token).not.toBe(tokens.access_token);

    const revoke = await request.post(`${serverUrl}/api/oauth/revoke`, {
      form: {
        client_id: "codewire-cli",
        token: refreshed.refresh_token,
        token_type_hint: "refresh_token",
      },
    });
    expect(revoke.ok(), await revoke.text()).toBe(true);

    const rejectedRefresh = await request.post(`${serverUrl}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "refresh_token",
        refresh_token: refreshed.refresh_token,
      },
    });
    expect(rejectedRefresh.ok()).toBe(false);
  });

  test("completes browser OIDC PKCE and verifies the issued ID token", { tag: "@kind-heavy" }, async ({ page, request, isMobile }) => {
    test.skip(!!isMobile, "desktop browser OIDC contract");
    test.setTimeout(90_000);

    const jwksResponse = await request.get(`${serverUrl}/.well-known/jwks.json`);
    expect(jwksResponse.ok(), await jwksResponse.text()).toBe(true);
    const publishedJwks = await jwksResponse.json() as PublishedJwks;

    const requestedScope = "openid profile email offline_access codewire.api";
    const authorize = new URL("/api/oauth/authorize", serverUrl);
    authorize.search = new URLSearchParams({
      client_id: "codewire-desktop",
      response_type: "code",
      redirect_uri: "http://localhost:9876/callback",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      scope: requestedScope,
      state: "ssr-browser-state",
    }).toString();
    await page.goto(authorize.toString(), { waitUntil: "commit" });
    await expect(page).toHaveURL(/\/login\?authRequestID=/);

    const login = await signInThroughRust(page, authEmail, TEST_PASSWORD, false);
    expect(login.status()).toBe(303);
    expect(login.headers().location).toMatch(/^\/two-factor/);
    await expect(page).toHaveURL(/\/two-factor\?authRequestID=/);
    await fillField(page, "#code", await freshTotpCode());
    const validationForm = await page.locator("form").evaluate((form) => (
      Object.fromEntries(new FormData(form as HTMLFormElement).entries())
    )) as Record<string, string>;
    const validation = await page.request.post(
      `${serverUrl}/two-factor/_actions/validate`,
      {
        form: validationForm,
        headers: {
          origin: serverUrl,
          referer: page.url(),
        },
        maxRedirects: 0,
      },
    );
    expect(validation.status(), await validation.text()).toBe(303);
    const completionPath = validation.headers().location;
    expect(completionPath).toMatch(/^\/api\/oidc\/callback\?id=/);

    const oidcCompletion = await page.request.get(
      new URL(completionPath, serverUrl).toString(),
      { maxRedirects: 0 },
    );
    expect(oidcCompletion.status(), await oidcCompletion.text()).toBe(302);
    const callback = new URL(oidcCompletion.headers().location);
    expect(callback.origin).toBe("http://localhost:9876");
    expect(callback.pathname).toBe("/callback");
    expect(callback.searchParams.get("state")).toBe("ssr-browser-state");
    const code = callback.searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenResponse = await request.post(`${serverUrl}/api/oauth/token`, {
      form: {
        grant_type: "authorization_code",
        code: code!,
        client_id: "codewire-desktop",
        redirect_uri: "http://localhost:9876/callback",
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      },
    });
    expect(tokenResponse.ok(), await tokenResponse.text()).toBe(true);
    const tokens = await tokenResponse.json() as {
      access_token: string;
      id_token: string;
      scope: string;
    };
    expect(tokens.scope.split(" ")).toEqual(
      expect.arrayContaining(requestedScope.split(" ")),
    );
    expect(verifyIdTokenAgainstPublishedJwks(tokens.id_token, publishedJwks)).toBe(true);

    const organizations = await request.post(
      `${serverUrl}/codewire.v1.OrganizationService/ListOrganizations`,
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          "content-type": "application/json",
        },
        data: {},
      },
    );
    expect(organizations.ok(), await organizations.text()).toBe(true);
  });
});
