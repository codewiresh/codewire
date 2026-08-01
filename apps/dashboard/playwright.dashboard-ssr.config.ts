import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dashboardDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(dashboardDir, "../..");
const legacyUrl = "http://127.0.0.1:5173";
const ssrUrl = "http://127.0.0.1:5174";
const apiOrigin = process.env.CODEWIRE_API_ORIGIN
  || process.env.SERVER_URL
  || "http://127.0.0.1:8080";
const authState = path.join(dashboardDir, "playwright/.auth/user.json");

// Kept separate from the React suite: only the explicit SSR target starts the
// Rust adapter and takes the side-by-side visual baselines.
export default defineConfig({
  testDir: repoRoot,
  globalSetup: path.join(dashboardDir, "e2e/global-setup.ts"),
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: "html",
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.015 },
  },

  projects: [
    {
      name: "setup",
      testMatch: /apps\/dashboard\/e2e\/auth\.setup\.ts/,
      use: { baseURL: legacyUrl },
    },
    {
      name: "dashboard-ssr-desktop",
      testMatch: /apps\/dashboard\/e2e\/ssr-dashboard\..*\.ssr\.ts/,
      dependencies: ["setup"],
      use: {
        ...devices["Desktop Chrome"],
        baseURL: ssrUrl,
        storageState: authState,
        viewport: { width: 1440, height: 900 },
        trace: "on-first-retry",
        screenshot: "only-on-failure",
      },
    },
    {
      name: "dashboard-ssr-mobile",
      testMatch: /apps\/dashboard\/e2e\/ssr-dashboard\..*\.ssr\.ts/,
      dependencies: ["setup"],
      use: {
        ...devices["Pixel 5"],
        baseURL: ssrUrl,
        storageState: authState,
        viewport: { width: 390, height: 844 },
        trace: "on-first-retry",
      },
    },
  ],

  webServer: [
    {
      command: "bun run dev -- --host 127.0.0.1",
      cwd: dashboardDir,
      url: legacyUrl,
      reuseExistingServer: !process.env.CI,
      timeout: 120000,
    },
    {
      command: 'CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)" cargo run --locked -p codewire-dashboard-web',
      cwd: repoRoot,
      env: {
        ...process.env,
        CODEWIRE_DASHBOARD_LISTEN_ADDR: "127.0.0.1:5174",
        CODEWIRE_PUBLIC_ORIGIN: ssrUrl,
        CODEWIRE_API_ORIGIN: apiOrigin,
        CODEWIRE_LEGACY_UI_ORIGIN: legacyUrl,
      },
      url: `${ssrUrl}/healthz`,
      reuseExistingServer: !process.env.CI,
      timeout: 120000,
    },
  ],
});
