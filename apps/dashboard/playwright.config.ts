import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dashboardDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(dashboardDir, "../..");
const dashboardUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const apiOrigin = process.env.CODEWIRE_API_ORIGIN
  || process.env.SERVER_URL
  || "http://127.0.0.1:8080";
const identityOrigin = process.env.CODEWIRE_IDENTITY_ORIGIN || apiOrigin;
const billingOrigin = process.env.CODEWIRE_BILLING_ORIGIN || "http://127.0.0.1:8081";
const browserApiOrigin = process.env.CODEWIRE_BROWSER_API_ORIGIN || apiOrigin;
const chromiumExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
const useDevShm = process.env.CODEWIRE_PLAYWRIGHT_USE_DEV_SHM === "1";
const snapshotEnvironment = process.env.CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV || "{platform}";
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const skipSharedSetup = process.env.PLAYWRIGHT_SKIP_SHARED_SETUP === "1";
const localOnlyResolverRule = "--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1";

export default defineConfig({
  testDir: repoRoot,
  globalSetup: skipSharedSetup ? undefined : path.join(dashboardDir, "e2e/global-setup.ts"),
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: "html",
  snapshotPathTemplate: `{testDir}/{testFilePath}-snapshots/{arg}-{projectName}-${snapshotEnvironment}{ext}`,
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.015 },
  },
  use: {
    launchOptions: {
      args: [localOnlyResolverRule],
      executablePath: chromiumExecutable,
      ignoreDefaultArgs: useDevShm ? ["--disable-dev-shm-usage"] : undefined,
    },
  },
  projects: [
    {
      name: "setup",
      testMatch: /apps\/dashboard\/e2e\/auth\.setup\.ts/,
      use: { baseURL: dashboardUrl },
    },
    {
      name: "dashboard-ssr-desktop",
      testMatch: /apps\/dashboard\/e2e\/ssr-dashboard\..*\.ssr\.ts/,
      dependencies: skipSharedSetup ? [] : ["setup"],
      use: {
        ...devices["Desktop Chrome"],
        baseURL: dashboardUrl,
        storageState: authState,
        viewport: { width: 1440, height: 900 },
        trace: "on-first-retry",
        screenshot: "only-on-failure",
      },
    },
    {
      name: "dashboard-ssr-mobile",
      testMatch: /apps\/dashboard\/e2e\/ssr-dashboard\..*\.ssr\.ts/,
      dependencies: skipSharedSetup ? [] : ["setup"],
      use: {
        ...devices["Pixel 5"],
        baseURL: dashboardUrl,
        storageState: authState,
        viewport: { width: 390, height: 844 },
        trace: "on-first-retry",
      },
    },
  ],
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: 'CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)" cargo run --locked -p codewire-dashboard-web',
    cwd: repoRoot,
    env: {
      ...process.env,
      CODEWIRE_DASHBOARD_LISTEN_ADDR: "127.0.0.1:5173",
      CODEWIRE_PUBLIC_ORIGIN: dashboardUrl,
      CODEWIRE_API_ORIGIN: apiOrigin,
      CODEWIRE_IDENTITY_ORIGIN: identityOrigin,
      CODEWIRE_BILLING_ORIGIN: billingOrigin,
      CODEWIRE_BROWSER_API_ORIGIN: browserApiOrigin,
    },
    url: `${dashboardUrl}/healthz`,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
