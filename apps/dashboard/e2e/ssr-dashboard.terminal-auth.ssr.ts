import { expect, test, type APIRequestContext } from "@playwright/test";
import {
  bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser,
} from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

// Existing managed identity/database topology, with a distinct synthetic owner.
// No real sandbox is needed: every rejection must precede session dispatch.
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const email = `e2e-terminal-auth-${runId}@codewire.sh`;
const slug = `terminal-auth-${runId}`;
const environmentId = crypto.randomUUID();
const sessionId = `session-${crypto.randomUUID()}`;
const dashboard = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const server = (process.env.SERVER_URL || "http://127.0.0.1:8080").replace(/\/$/, "");
const base = `/${slug}/${environmentId}`;
let accountId = "";
let orgId = "";
let token = "";

test.use({ storageState: { cookies: [], origins: [] }, trace: "off", screenshot: "off" });

async function rawRequest(
  request: APIRequestContext, query: string, overrides: Record<string, string> = {},
  requestedOrg = orgId,
) {
  return request.get(
    `${server}/api/v1/organizations/${requestedOrg}/environments/${environmentId}/terminal?${query}`,
    {
      headers: {
        Connection: "Upgrade", Upgrade: "websocket",
        "Sec-WebSocket-Key": Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("base64"),
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Protocol": "codewire.durable-terminal.v1",
        Origin: dashboard,
        Cookie: `codewire.session_token=${token}`,
        ...overrides,
      },
      maxRedirects: 0,
    },
  );
}

test.describe.serial("durable terminal browser admission", () => {
  test.beforeAll(async ({}, testInfo) => {
    test.skip(testInfo.project.name !== "dashboard-ssr-desktop", "one managed admission proof");
    await seedSyntheticUser(email, "Terminal admission");
    accountId = (await getUserId(email))!;
    expect(accountId).toBeTruthy();
    orgId = await ensureTestOrg("Terminal admission", slug, accountId);
    token = (await createAuthenticatedSession(email)).token;
  });

  test.afterAll(async () => {
    if (!accountId) return;
    await cleanupTestOrg(slug);
    await cleanupUser(email);
  });

  test("both browser routes enforce sign-in and mandatory two-factor before runtime lookup", async ({ request }) => {
    const anonymous = await request.get(`${base}/_fragments/terminal-sessions`);
    expect(anonymous.status()).toBe(401);
    expect(await anonymous.json()).toEqual({ error: "sign-in-required" });
    const anonymousStatus = await request.get(`${base}/_fragments/terminal-readiness`, { maxRedirects: 0 });
    expect(anonymousStatus.status()).toBe(401);
    expect(await anonymousStatus.json()).toEqual({ error: "terminal-readiness-unavailable" });
    expect(anonymousStatus.headers()["cache-control"]).toBe("no-store");
    expect(anonymousStatus.headers()["location"]).toBeUndefined();
    expect(anonymousStatus.headers()["set-cookie"]).toBeUndefined();
    const missingFactor = await request.get(`${base}/_fragments/terminal-sessions`, {
      headers: { Cookie: `codewire.session_token=${token}` },
    });
    expect(missingFactor.status()).toBe(403);
    expect(await missingFactor.json()).toEqual({ error: "two-factor-required" });
    const missingFactorStatus = await request.get(`${base}/_fragments/terminal-readiness`, {
      headers: { Cookie: `codewire.session_token=${token}` }, maxRedirects: 0,
    });
    // Background status never follows the page's factor-setup redirect.
    expect(missingFactorStatus.status()).toBe(401);
    expect(await missingFactorStatus.json()).toEqual({ error: "terminal-readiness-unavailable" });
    const raw = await rawRequest(request, `account_id=${accountId}&session_id=${sessionId}&output_offset=0`);
    expect(raw.status()).toBe(403);
    // This is the existing synthetic fixture helper, not a product auth bypass.
    await bypassTwoFactor(email);
    const authorizedButMissing = await request.get(`${base}/_fragments/terminal-sessions`, {
      headers: { Cookie: `codewire.session_token=${token}` },
    });
    // The existing environment-access policy hides missing targets as forbidden.
    expect(authorizedButMissing.status()).toBe(403);
    expect(await authorizedButMissing.json()).toEqual({ error: "not-authorized" });
    const missingStatus = await request.get(`${base}/_fragments/terminal-readiness`, {
      headers: { Cookie: `codewire.session_token=${token}` }, maxRedirects: 0,
    });
    expect(missingStatus.status()).toBe(403);
    expect(await missingStatus.json()).toEqual({ error: "terminal-readiness-unavailable" });
    // A missing organization is distinguishable from the earlier 2FA rejection:
    // its ordinary membership lookup returns 404 after factor setup is complete.
    expect((await rawRequest(request, `account_id=${accountId}&session_id=${sessionId}&output_offset=0`, {},
      crypto.randomUUID())).status()).toBe(404);
  });

  test("durable reconnect rejects protocol downgrade and noncanonical browser authority", async ({ request }) => {
    const coordinates = `account_id=${accountId}&session_id=${sessionId}&output_offset=0`;
    for (const [query, headers] of [
      [coordinates, { "Sec-WebSocket-Protocol": "terminal" }],
      [coordinates, { "Sec-WebSocket-Protocol": "terminal, codewire.durable-terminal.v1" }],
      [coordinates, { "Sec-WebSocket-Protocol": "codewire.durable-terminal.v2" }],
      [`${coordinates}&output_offset=1`, {}],
      [`${coordinates}&session_id=${sessionId}`, {}],
      [`session_id=${sessionId}&output_offset=01`, {}],
      [`${coordinates}&ticket=synthetic-rejected-ticket`, {}],
    ] as [string, Record<string, string>][]) {
      expect((await rawRequest(request, query, headers)).status()).toBe(400);
    }
    for (const headers of [
      { Origin: "https://foreign.example.test" },
      { Origin: "null" },
      { Authorization: "Bearer synthetic-rejected-token" },
      { Cookie: `codewire.session_token=${token}; codewire.session_token=${token}` },
    ] as Array<Record<string, string>>) {
      expect((await rawRequest(request, coordinates, headers)).status()).toBe(403);
    }
    // Preserve the existing forbidden response for a missing environment.
    expect((await rawRequest(request, coordinates)).status()).toBe(403);
    // Same synthetic cookie, fresh expected identity: a missing organization
    // reaches membership lookup only when the inventory account still matches.
    const missingOrg = crypto.randomUUID();
    expect((await rawRequest(request, coordinates, {}, missingOrg)).status()).toBe(404);
    const staleCoordinates = `account_id=other-account&session_id=${sessionId}&output_offset=0`;
    expect((await rawRequest(request, staleCoordinates, {}, missingOrg)).status()).toBe(403);
  });

  test("session mutations reject stale account context, foreign origin and caller commands", async ({ page }) => {
    await page.context().addCookies([{
      name: "codewire.session_token", value: token, url: dashboard,
      httpOnly: true, sameSite: "Lax", secure: dashboard.startsWith("https:"),
    }]);
    const response = await page.goto(`/settings/?org=${slug}`);
    expect(response?.status()).toBe(200);
    const csrf = await page.locator('input[name="_csrf"]').first().inputValue();
    for (const action of ["launch", "stop"]) {
      const url = `${base}/_actions/terminal-sessions/${action}`;
      const form = { _csrf: csrf, account_id: accountId,
        ...(action === "stop" ? { session_id: sessionId } : {}) };
      for (const [origin, submitted] of [
        ["https://foreign.example.test", csrf], [dashboard, "invalid-csrf"],
      ]) {
        const rejected = await page.request.post(url, {
          headers: { Origin: origin }, form: { ...form, _csrf: submitted },
        });
        expect(rejected.status()).toBe(403);
        expect(await rejected.json()).toEqual({ error: "request-rejected" });
      }
      const stale = await page.request.post(url, {
        headers: { Origin: dashboard }, form: { ...form, account_id: "other-account" },
      });
      expect(stale.status()).toBe(409);
      expect(stale.headers()["cache-control"]).toBe("no-store");
      expect(stale.headers()["set-cookie"]).toBeUndefined();
      expect(await stale.json()).toEqual({ error: "account-changed" });
      const arbitrary = await page.request.post(url, {
        headers: { Origin: dashboard }, form: { ...form, command: "must-not-execute" },
      });
      expect(arbitrary.status()).toBe(422);
    }
  });
});
