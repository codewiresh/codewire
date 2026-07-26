import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dashboardDir = path.dirname(fileURLToPath(import.meta.url));
const sourceViteUrl = "http://127.0.0.1:5173";

export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",

  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL || sourceViteUrl,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [
    // Auth setup project - runs first to save auth state
    { name: "setup", testMatch: /.*\.setup\.ts/ },

    // Main tests depend on auth setup (exclude tests that handle their own auth)
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
      testIgnore: [
        /admin\.spec\.ts/,
        /oidc\.spec\.ts/,
        /signup\.spec\.ts/,
        /twofactor\.spec\.ts/,
        /environments\.spec\.ts/,
      ],
    },

    // Signup UI test - isolated, handles its own auth
    {
      name: "signup",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /signup\.spec\.ts/,
    },

    // Two-factor auth tests - isolated, handles its own auth
    {
      name: "twofactor",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /twofactor\.spec\.ts/,
    },

    // Admin panel tests - isolated, handles its own auth
    {
      name: "admin",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /admin\.spec\.ts/,
    },

    // OIDC provider tests - isolated, handles its own auth
    {
      name: "oidc",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /oidc\.spec\.ts/,
    },

    // Environments E2E tests - isolated, handles its own auth
    {
      name: "environments",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /environments\.spec\.ts/,
    },
  ],

  // Start the current-worktree Vite server before tests (if not already running).
  // A deployed-dashboard test can set PLAYWRIGHT_BASE_URL to skip auto-start.
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: "bun run dev -- --host 127.0.0.1",
    cwd: dashboardDir,
    url: sourceViteUrl,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
