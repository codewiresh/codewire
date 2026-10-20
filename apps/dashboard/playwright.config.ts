import { defineConfig, devices } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { designFixtureSpecPattern } from "./e2e/helpers/design-fixtures";
import { mobileLayoutSpecPattern } from "./e2e/helpers/mobile-layout";

const dashboardDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(dashboardDir, "../..");
const dashboardUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const designOrigin = (process.env.CODEWIRE_DESIGN_ORIGIN || "http://127.0.0.1:4174").replace(/\/$/, "");
const apiOrigin = process.env.CODEWIRE_API_ORIGIN
  || process.env.SERVER_URL
  || "http://127.0.0.1:8080";
const identityOrigin = process.env.CODEWIRE_IDENTITY_ORIGIN || apiOrigin;
const billingOrigin = process.env.CODEWIRE_BILLING_ORIGIN || "http://127.0.0.1:8081";
const browserApiOrigin = process.env.CODEWIRE_BROWSER_API_ORIGIN || apiOrigin;
const chromiumExecutable = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
const useDevShm = process.env.CODEWIRE_PLAYWRIGHT_USE_DEV_SHM === "1";
const snapshotEnvironment = process.env.CODEWIRE_PLAYWRIGHT_SNAPSHOT_ENV || "{platform}";
const skipSharedSetup = process.env.PLAYWRIGHT_SKIP_SHARED_SETUP === "1";
const localOnlyResolverRule = "--host-resolver-rules=MAP * ^NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1";
// Keep the browser off the host GPU. Hardware video acceleration is the only
// path from its GPU process to a host GPU driver: on a workstation with an
// NVIDIA card it loads the VA-API driver, which opens /dev/nvidia* and a CUDA
// context. When that driver blocks, the GPU process stops producing frames,
// and every click waits out its timeout for a stable element while the page
// itself still answers (#3019). No spec plays video, and CI runners have no
// GPU, so every browser renders the same way. The browser runtime spec in
// e2e/ssr-dashboard.design-system.ssr.ts checks the GPU process holds no
// host GPU device.
const hostGpuIsolation = ["--disable-accelerated-video-decode", "--disable-accelerated-video-encode"];
const designFixtureProjects = [
  {
    name: "design-fixtures-desktop",
    testMatch: designFixtureSpecPattern,
    use: {
      ...devices["Desktop Chrome"],
      baseURL: designOrigin,
      viewport: { width: 1440, height: 900 },
      trace: "on-first-retry" as const,
      screenshot: "only-on-failure" as const,
    },
  },
  {
    name: "design-fixtures-mobile",
    testMatch: designFixtureSpecPattern,
    use: {
      ...devices["Pixel 5"],
      baseURL: designOrigin,
      viewport: { width: 390, height: 844 },
      trace: "on-first-retry" as const,
    },
  },
];

export default defineConfig({
  testDir: repoRoot,
  globalSetup: skipSharedSetup ? undefined : path.join(dashboardDir, "e2e/global-setup.ts"),
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  // One retry in CI: a second retry mostly spent minutes rerunning a flaky
  // test (#2975). A test that needs more goes to the quarantine lane
  // (e2e/helpers/quarantine.ts) with its issue and last day.
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  // The JSON report records every test's duration, retries and outcome. CI
  // uploads it from every dashboard run, green or red (#2974).
  reporter: [["html"], ["json", { outputFile: path.join(dashboardDir, "test-report/results.json") }]],
  snapshotPathTemplate: `{testDir}/{testFilePath}-snapshots/{arg}-{projectName}-${snapshotEnvironment}{ext}`,
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.015 },
  },
  use: {
    launchOptions: {
      args: [localOnlyResolverRule, ...hostGpuIsolation],
      executablePath: chromiumExecutable,
      ignoreDefaultArgs: useDevShm ? ["--disable-dev-shm-usage"] : undefined,
    },
  },
  projects: [
    // The seeded login's form sign-in and two-factor proof. Specs sign in as
    // their own per-worker identities (e2e/helpers/test.ts), so nothing waits
    // for this project or reads a session from it.
    {
      name: "setup",
      testMatch: /apps\/dashboard\/e2e\/auth\.setup\.ts/,
      use: { baseURL: dashboardUrl },
    },
    {
      name: "dashboard-ssr-desktop",
      testMatch: /apps\/dashboard\/e2e\/ssr-dashboard\..*\.ssr\.ts/,
      testIgnore: designFixtureSpecPattern,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: dashboardUrl,
        viewport: { width: 1440, height: 900 },
        trace: "on-first-retry",
        screenshot: "only-on-failure",
      },
    },
    // Only the specs that check the mobile layout (e2e/helpers/mobile-layout.ts).
    {
      name: "dashboard-ssr-mobile",
      testMatch: mobileLayoutSpecPattern,
      use: {
        ...devices["Pixel 5"],
        baseURL: dashboardUrl,
        viewport: { width: 390, height: 844 },
        trace: "on-first-retry",
      },
    },
    // Editable design fixtures need no dashboard, identity or shared setup.
    // scripts/ci/verify/run-design-fixtures.sh serves them, sets the origin and
    // owns this gate; without an origin these projects are not defined at all.
    ...(process.env.CODEWIRE_DESIGN_ORIGIN ? designFixtureProjects : []),
  ],
  webServer: process.env.PLAYWRIGHT_BASE_URL ? undefined : {
    command: 'CARGO_TARGET_DIR="$(scripts/ci/verify/resolve-cargo-target-dir.sh)" cargo run --locked -p codewire-dashboard-web',
    cwd: repoRoot,
    env: {
      ...process.env,
      CODEWIRE_DASHBOARD_LISTEN_ADDR: "127.0.0.1:5173",
      CODEWIRE_PUBLIC_ORIGIN: dashboardUrl,
      CODEWIRE_API_ORIGIN: apiOrigin,
      CODEWIRE_CREDENTIAL_ORIGIN: apiOrigin,
      CODEWIRE_IDENTITY_ORIGIN: identityOrigin,
      CODEWIRE_BILLING_ORIGIN: billingOrigin,
      CODEWIRE_BROWSER_API_ORIGIN: browserApiOrigin,
    },
    url: `${dashboardUrl}/healthz`,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
