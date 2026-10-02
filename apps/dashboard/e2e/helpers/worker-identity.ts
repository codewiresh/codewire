import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Browser } from "@playwright/test";
import {
  bypassTwoFactor,
  createAuthenticatedSession,
  getUserId,
  seedSyntheticUser,
} from "./db";
import { workerIdentityEmail, workerIdentityName } from "./synthetic-users";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

export const workerAuthStatePath = (index: number) => (
  path.join(dashboardDir, "playwright/.auth", `worker-${index}.json`)
);

/** The worker's master-class identity, seeded on demand; safe to call from hooks. */
export async function ensureWorkerIdentity(index: number): Promise<string> {
  const email = workerIdentityEmail(index);
  const existing = await getUserId(email);
  if (existing) return existing;
  await seedSyntheticUser(email, workerIdentityName(index));
  const id = await getUserId(email);
  if (!id) throw new Error(`Worker identity ${email} was not seeded`);
  return id;
}

/**
 * Authenticate this worker's identity without a UI round-trip: bypass the
 * two-factor gate like the other synthetic specs, issue a real session row,
 * and persist the cookie as the worker's storage state.
 */
export async function createWorkerAuthState(
  browser: Browser,
  index: number,
): Promise<{ file: string; sessionId: string }> {
  const email = workerIdentityEmail(index);
  await ensureWorkerIdentity(index);
  await bypassTwoFactor(email);
  const session = await createAuthenticatedSession(email);
  const context = await browser.newContext();
  try {
    await context.addCookies([{
      name: "codewire.session_token",
      value: session.token,
      url: ssrUrl,
      httpOnly: true,
      sameSite: "Lax",
    }]);
    const file = workerAuthStatePath(index);
    await context.storageState({ path: file });
    return { file, sessionId: session.id };
  } finally {
    await context.close();
  }
}
