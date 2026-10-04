import { test as base } from "@playwright/test";
import { deleteSession } from "./db";
import { createWorkerAuthState } from "./worker-identity";

// Base test for specs that run the browser as the seeded account. Each worker
// process gets its own master-class identity (e2e-worker-<index>) and its own
// storage state, so org and personal-store mutations stay inside one worker.
// Specs that use disposable or design-fixture identities keep importing
// @playwright/test directly and override storageState themselves.
export const test = base.extend<object, { workerStorageState: string }>({
  storageState: async ({ workerStorageState }, use) => {
    await use(workerStorageState);
  },
  workerStorageState: [async ({ browser }, use, workerInfo) => {
    const { file, sessionId } = await createWorkerAuthState(browser, workerInfo.workerIndex);
    await use(file);
    await deleteSession(sessionId).catch(() => {});
  }, { scope: "worker" }],
});

export { expect } from "@playwright/test";
