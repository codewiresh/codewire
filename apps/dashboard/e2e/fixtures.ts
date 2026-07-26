import { test as base, expect } from "@playwright/test";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Extended test fixture with pre-authenticated state.
 * Use this for tests that require a logged-in user.
 */
export const test = base.extend({
  storageState: path.join(__dirname, "../playwright/.auth/user.json"),
});

export { expect };
