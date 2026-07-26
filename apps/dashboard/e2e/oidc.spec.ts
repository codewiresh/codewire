import { test, expect, Page } from "@playwright/test";
import { createPublicKey, verify } from "node:crypto";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { clearRateLimits, disableTwoFactor } from "./helpers/db";

const SERVER_URL = process.env.SERVER_URL || "http://localhost:8080";

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

type PublishedJwk = {
  kty: string;
  crv: string;
  x: string;
  use: string;
  alg: string;
  kid: string;
};

type PublishedJwks = { keys: PublishedJwk[] };

type DeviceAuthorization = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
};

type TokenSet = {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

function verifyIdTokenAgainstPublishedJwks(
  idToken: string,
  jwks: PublishedJwks,
): boolean {
  const parts = idToken.split(".");
  expect(parts).toHaveLength(3);
  const [encodedHeader, encodedClaims, encodedSignature] = parts;
  const header = JSON.parse(
    Buffer.from(encodedHeader, "base64url").toString("utf8"),
  ) as { alg?: string; kid?: string };
  expect(header.alg).toBe("EdDSA");
  expect(header.kid).toBeTruthy();

  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  expect(jwk).toBeTruthy();
  if (!jwk) return false;
  expect(jwk).toMatchObject({
    kty: "OKP",
    crv: "Ed25519",
    use: "sig",
    alg: "EdDSA",
  });

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

test.describe("OIDC Provider", () => {
  test.beforeEach(async () => {
    await clearRateLimits();
    await disableTwoFactor(USERS.member.email);
  });

  test("OIDC discovery endpoint returns correct configuration", async ({
    request,
  }) => {
    const res = await request.get(
      `${SERVER_URL}/.well-known/openid-configuration`
    );
    expect(res.ok()).toBeTruthy();

    const config = await res.json();
    expect(config.issuer).toBeTruthy();
    expect(config.authorization_endpoint).toContain("/api/oauth/authorize");
    expect(config.token_endpoint).toContain("/api/oauth/token");
    expect(config.userinfo_endpoint).toContain("/api/oauth/userinfo");
    expect(config.jwks_uri).toContain("/.well-known/jwks.json");
    expect(config.id_token_signing_alg_values_supported).toContain("EdDSA");
    expect(config.code_challenge_methods_supported).toContain("S256");
    expect(config.response_types_supported).toContain("code");
  });

  test("JWKS endpoint returns usable Ed25519 signing keys", async ({ request }) => {
    const res = await request.get(`${SERVER_URL}/.well-known/jwks.json`);
    expect(res.ok()).toBeTruthy();

    const jwks = (await res.json()) as PublishedJwks;
    expect(jwks.keys.length).toBeGreaterThan(0);
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

  test("authorize endpoint redirects unauthenticated user to login with authRequestID", async ({
    page,
  }) => {
    // Hit the authorize endpoint directly (no session)
    const authorizeUrl = `${SERVER_URL}/api/oauth/authorize?client_id=codewire-desktop&response_type=code&redirect_uri=http://localhost:9876/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid+profile+email&state=teststate`;

    await page.goto(authorizeUrl, { waitUntil: "commit" });

    // Should be redirected to login page with authRequestID
    await expect(page).toHaveURL(/\/login\?authRequestID=/);

    // The login form should be visible
    await expect(page.locator("#email")).toBeVisible();
    await expect(page.locator("#password")).toBeVisible();
  });

  test("full OIDC PKCE flow: published JWKS → authorize → login → exchange → verified ID token", async ({
    page,
    request,
  }) => {
    // Step 1: fetch the issuer key before the authorization code exists. A
    // relying party may cache this document before the first user logs in.
    const jwksResponse = await request.get(`${SERVER_URL}/.well-known/jwks.json`);
    expect(jwksResponse.ok()).toBeTruthy();
    const publishedJwks = (await jwksResponse.json()) as PublishedJwks;
    expect(publishedJwks.keys.length).toBeGreaterThan(0);

    // Step 2: Hit authorize endpoint (unauthenticated)
    const authorizeUrl = `${SERVER_URL}/api/oauth/authorize?client_id=codewire-desktop&response_type=code&redirect_uri=http://localhost:9876/callback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&scope=openid+profile+email&state=teststate`;

    await page.goto(authorizeUrl, { waitUntil: "commit" });

    // Step 3: Should be on login page with authRequestID
    await expect(page).toHaveURL(/\/login\?authRequestID=/);

    // Step 4: Capture the redirect to localhost:9876 via request events.
    // Nothing listens there so the navigation will fail, but we can capture
    // the URL from the failed request to verify the authorization code.
    const callbackPromise = new Promise<string>((resolve) => {
      page.on("requestfailed", (req) => {
        if (req.url().includes("localhost:9876/callback")) {
          resolve(req.url());
        }
      });
    });

    // Step 5: Sign in
    await fillField(page, "#email", USERS.member.email);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();

    // Step 6: After sign-in, the OIDC flow completes and redirects to the
    // client's redirect_uri with an authorization code.
    const callbackUrl = await Promise.race([
      callbackPromise,
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error("Timed out waiting for callback redirect")), 15000)
      ),
    ]);

    expect(callbackUrl).toContain("localhost:9876/callback");
    const code = new URL(callbackUrl).searchParams.get("code");
    expect(code).toBeTruthy();

    // Step 7: The public client exchanges the actual browser-issued code.
    const tokenResponse = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        grant_type: "authorization_code",
        code: code!,
        client_id: "codewire-desktop",
        redirect_uri: "http://localhost:9876/callback",
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
      },
    });
    expect(tokenResponse.ok()).toBeTruthy();
    const tokens = await tokenResponse.json() as { id_token?: string };
    expect(tokens.id_token).toBeTruthy();
    expect(verifyIdTokenAgainstPublishedJwks(tokens.id_token!, publishedJwks)).toBeTruthy();
  });

  test("CLI device grant uses browser approval, refresh, UserInfo, and a scoped product RPC", async ({
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
    expect(deviceResponse.ok()).toBeTruthy();
    const device = await deviceResponse.json() as DeviceAuthorization;
    expect(device.verification_uri).toContain("/device");
    expect(device.verification_uri_complete).toContain(device.user_code);
    expect(device.expires_in).toBeGreaterThan(0);
    expect(device.interval).toBeGreaterThan(0);

    // The browser remains the only password owner. The native side has only
    // the user code and cannot complete this step itself.
    await page.goto(device.verification_uri, { waitUntil: "commit" });
    await expect(page).toHaveURL(/\/login\?return_to=/);
    await fillField(page, "#email", USERS.member.email);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/\/device/, { timeout: 15000 });
    await page.getByPlaceholder("ABCD-1234").fill(device.user_code);
    await page.getByRole("button", { name: "Authorize CLI Access" }).click();
    await expect(page.getByText("CLI Authorized")).toBeVisible();

    const exchange = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: device.device_code,
      },
    });
    expect(exchange.ok()).toBeTruthy();
    const initialTokens = await exchange.json() as TokenSet;
    expect(initialTokens.token_type).toBe("Bearer");
    expect(initialTokens.scope.split(" ")).toEqual(
      expect.arrayContaining(requestedScope.split(" ")),
    );

    const userinfo = await request.get(`${SERVER_URL}/api/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${initialTokens.access_token}` },
    });
    expect(userinfo.ok()).toBeTruthy();
    expect((await userinfo.json()).email).toBe(USERS.member.email);

    // This is the product plane, not an IdP endpoint: the issued
    // `codewire.api` token must traverse the real Connect auth layer.
    const productRpc = await request.post(
      `${SERVER_URL}/codewire.v1.OrganizationService/ListOrganizations`,
      {
        headers: {
          Authorization: `Bearer ${initialTokens.access_token}`,
          "content-type": "application/json",
        },
        data: {},
      },
    );
    expect(productRpc.ok()).toBeTruthy();

    const refresh = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "refresh_token",
        refresh_token: initialTokens.refresh_token,
      },
    });
    expect(refresh.ok()).toBeTruthy();
    const refreshedTokens = await refresh.json() as TokenSet;
    expect(refreshedTokens.access_token).not.toBe(initialTokens.access_token);

    const revoke = await request.post(`${SERVER_URL}/api/oauth/revoke`, {
      form: {
        client_id: "codewire-cli",
        token: refreshedTokens.refresh_token,
        token_type_hint: "refresh_token",
      },
    });
    expect(revoke.ok()).toBeTruthy();

    const revokedRefresh = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        client_id: "codewire-cli",
        grant_type: "refresh_token",
        refresh_token: refreshedTokens.refresh_token,
      },
    });
    expect(revokedRefresh.ok()).toBeFalsy();
  });

  test("authorize rejects unknown client_id", async ({ request }) => {
    const res = await request.get(
      `${SERVER_URL}/api/oauth/authorize?client_id=unknown-client&response_type=code&redirect_uri=http://localhost:9876/callback&scope=openid&state=test`,
      { maxRedirects: 0 }
    );
    // Rust returns 401 JSON; ZITADEL-compatible flows may redirect or 400.
    const status = res.status();
    expect([302, 400, 401]).toContain(status);
  });

  test("token endpoint rejects invalid grant", async ({ request }) => {
    const res = await request.post(`${SERVER_URL}/api/oauth/token`, {
      form: {
        grant_type: "authorization_code",
        code: "invalid-code",
        client_id: "codewire-desktop",
        redirect_uri: "http://localhost:9876/callback",
        code_verifier: "test-verifier",
      },
    });
    expect(res.ok()).toBeFalsy();
  });

  test("login page carries authRequestID through to OIDC callback", async ({
    page,
  }) => {
    // Navigate to login with an authRequestID (simulating OIDC redirect)
    await goto(page, "/login?authRequestID=test-fake-id");

    // Login form should be visible
    await expect(page.locator("#email")).toBeVisible();

    // Sign in
    await fillField(page, "#email", USERS.member.email);
    await fillField(page, "#password", TEST_PASSWORD);
    await page.getByRole("button", { name: /sign in/i }).click();

    // After sign-in, should redirect to /api/oidc/callback?id=test-fake-id
    // This will fail because the authRequestID is fake, but the redirect proves
    // the login page correctly carries the ID through
    await page.waitForURL(/\/api\/oidc\/callback\?id=test-fake-id/, {
      timeout: 10000,
    }).catch(() => {});

    // Even if the callback fails (invalid ID), the important thing is
    // the login page sent us there
    const url = page.url();
    expect(url).toContain("oidc/callback");
  });
});
