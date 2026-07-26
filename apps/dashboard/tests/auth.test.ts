import { afterEach, describe, expect, test } from "bun:test";
import {
  clearSessionCache,
  getSession,
  signIn,
} from "../src/lib/auth";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  clearSessionCache();
});

describe("raw identity client", () => {
  test("keeps auth requests same-origin and credentialed", async () => {
    let request: { input: RequestInfo | URL; init?: RequestInit } | undefined;
    globalThis.fetch = (async (input, init) => {
      request = { input, init };
      return Response.json({ twoFactorRequired: true, twoFactorToken: "challenge" });
    }) as typeof fetch;

    const response = await signIn("user@example.com", "password");

    expect(response.twoFactorRequired).toBe(true);
    expect(request?.input).toBe("/api/auth/sign-in");
    expect(request?.init?.credentials).toBe("include");
    expect(request?.init?.headers).toEqual({ "Content-Type": "application/json" });
  });

  test("caches a valid session and preserves null-on-failure behavior", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls += 1;
      return Response.json({
        user: { id: "user-1" },
        session: { id: "session-1" },
      });
    }) as typeof fetch;

    expect((await getSession())?.user.id).toBe("user-1");
    expect((await getSession())?.session.id).toBe("session-1");
    expect(calls).toBe(1);

    clearSessionCache();
    globalThis.fetch = (async () => new Response("unavailable", { status: 503 })) as typeof fetch;
    expect(await getSession()).toBeNull();
  });
});
