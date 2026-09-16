import { randomBytes, randomUUID } from "node:crypto";
import { expect, test, type APIRequestContext, type APIResponse } from "@playwright/test";
import {
  bypassTwoFactor, cleanupUser, createAuthenticatedSession, deleteSession, getUserId, seedSyntheticUser,
} from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

// Managed private-route admission proof, with a distinct synthetic identity.
// Missing targets and rejected authority must never dispatch a Resize.
const run = `${Date.now()}-${randomUUID().slice(0, 8)}`;
const email = `e2e-resize-auth-${run}@codewire.sh`;
const slug = `resize-auth-${run}`;
const environment = randomUUID();
const requestId = randomUUID().replaceAll("-", "");
const operationId = randomUUID().replaceAll("-", "");
const origin = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const base = `/${slug}/${environment}`;
let account = "";
let token = "";
let session = "";
const csrf = randomBytes(32).toString("base64url");

test.use({ storageState: { cookies: [], origins: [] }, trace: "off", screenshot: "off" });

async function closed(response: APIResponse, status: number, error: string) {
  const body = await response.json();
  const code = typeof body.error === "string" && /^[a-z-]{1,48}$/.test(body.error)
    ? body.error : "unrecognized-resize-response";
  expect(response.status(), code).toBe(status);
  expect(body).toEqual({ error });
  expect(response.headers()["cache-control"]).toBe("no-store");
  expect(response.headers().vary).toBe("Cookie");
  expect(response.headers().location).toBeUndefined();
  expect(response.headers()["set-cookie"]).toBeUndefined();
}

function headers(cookie = `codewire.session_token=${token}`) {
  return { Origin: origin, Cookie: `${cookie}; codewire_ssr_csrf=${csrf}` };
}

async function action(request: APIRequestContext, name: "plan" | "apply", options: {
  cookie?: string; origin?: string; account?: string; csrf?: string; extra?: Record<string, string>;
  authorization?: string;
} = {}) {
  return request.post(`${base}/_actions/resize/${name}`, {
    maxRedirects: 0,
    headers: { ...headers(options.cookie), Origin: options.origin ?? origin,
      ...(options.authorization ? { Authorization: options.authorization } : {}) },
    form: { _csrf: options.csrf ?? csrf, account_id: options.account ?? account,
      cpu_millicores: "1000", memory_mb: "2048", disk_gb: "10",
      ...(name === "apply" ? { request_id: requestId, allow_restart: "false", force: "false" } : {}),
      ...options.extra },
  });
}

test.describe.serial("private Resize browser admission", () => {
  test.beforeAll(async ({}, info) => {
    test.skip(info.project.name !== "dashboard-ssr-desktop", "one managed admission proof");
    await seedSyntheticUser(email, "Resize admission");
    account = (await getUserId(email))!;
    expect(account).toBeTruthy();
    await ensureTestOrg("Resize admission", slug, account);
    const issued = await createAuthenticatedSession(email);
    token = issued.token;
    session = issued.id;
  });

  test.afterAll(async () => {
    if (!account) return;
    await cleanupTestOrg(slug);
    await cleanupUser(email);
  });

  test("sign-in and mandatory two-factor precede Resize lookup without redirects or cookie rotation", async ({ request }) => {
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      params: { account_id: account, operation_id: operationId }, maxRedirects: 0,
    }), 401, "sign-in-required");
    for (const name of ["plan", "apply"] as const) {
      await closed(await action(request, name, { cookie: "" }), 401, "sign-in-required");
      await closed(await action(request, name), 403, "two-factor-required");
    }
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      headers: headers(), params: { account_id: account, operation_id: operationId }, maxRedirects: 0,
    }), 403, "two-factor-required");
    await bypassTwoFactor(email);
  });

  test("actions reject stale actor, mixed cookies, foreign Origin, invalid CSRF and unknown inputs", async ({ request }) => {
    for (const name of ["plan", "apply"] as const) {
      await closed(await action(request, name, { origin: "https://foreign.example.test" }), 403, "request-rejected");
      await closed(await action(request, name, { csrf: "invalid-csrf" }), 403, "request-rejected");
      await closed(await action(request, name, { account: "stale-account" }), 409, "account-changed");
      await closed(await action(request, name, {
        cookie: `codewire.session_token=${token}; codewire.session_token=${token}`,
      }), 401, "sign-in-required");
      await closed(await action(request, name, { authorization: "Bearer synthetic-rejected-token" }), 401, "sign-in-required");
      await closed(await action(request, name, { extra: { command: "must-not-execute" } }), 400, "invalid-request");
    }
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      headers: headers(), params: { account_id: "stale-account", operation_id: operationId }, maxRedirects: 0,
    }), 409, "account-changed");
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      headers: headers(`codewire.session_token=${token}; codewire.session_token=${token}`),
      params: { account_id: account, operation_id: operationId }, maxRedirects: 0,
    }), 401, "sign-in-required");
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      headers: headers(), params: { account_id: account, operation_id: "noncanonical" }, maxRedirects: 0,
    }), 400, "invalid-request");
    const foreign = `/${slug}-foreign/${environment}/_fragments/resize-operation`;
    await closed(await request.get(foreign, {
      headers: headers(), params: { account_id: account, operation_id: operationId }, maxRedirects: 0,
    }), 404, "not-found");
  });

  test("revoked synthetic sessions fail closed before Resize dispatch", async ({ request }) => {
    await deleteSession(session);
    for (const name of ["plan", "apply"] as const) {
      await closed(await action(request, name), 401, "sign-in-required");
    }
    await closed(await request.get(`${base}/_fragments/resize-operation`, {
      headers: headers(), params: { account_id: account, operation_id: operationId }, maxRedirects: 0,
    }), 401, "sign-in-required");
  });
});
