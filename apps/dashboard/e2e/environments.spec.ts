import { test, expect, Page } from "@playwright/test";
import { cleanupOrgs, clearRateLimits, insertEnvBillingEvents, cleanupEnvBilling } from "./helpers/db";
import { ensureTestOrg } from "./helpers/org";
import {
  ensureTestSandboxPreset,
  ensureSystemPreset,
  waitForEnvironmentState,
  cleanupEnvironments,
  cleanupSystemPresets,
} from "./helpers/environment";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import postgres from "postgres";
import * as OTPAuth from "otpauth";
import { terminalWebSocketUrl } from "./helpers/terminal-websocket";

const sql = postgres(process.env.DATABASE_URL!);
const SERVER_URL = process.env.SERVER_URL || "http://127.0.0.1:8080";
const totpSecrets = new Map<string, string>();

const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "commit" });
  await page.waitForLoadState("domcontentloaded");
};

const assertEnvironmentCreateConnectSource = async (page: Page) => {
  const response = await page.request.get("/src/components/env-create-form.tsx");
  expect(
    response.ok(),
    "environment create E2E requires the current source Vite server",
  ).toBeTruthy();
  const source = await response.text();
  expect(source).toContain("EnvironmentSetupService.method.getEnvironmentCreateOptions");
  expect(source).toContain("GitHubService.method.listGitHubRepos");
};

const fillField = async (page: Page, selector: string, value: string) => {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.click();
  await field.fill("");
  await field.pressSequentially(value, { delay: 20 });
};

const connectEnvelope = (flags: number, message: unknown): Buffer => {
  const payload = Buffer.from(JSON.stringify(message));
  const header = Buffer.alloc(5);
  header.writeUInt8(flags, 0);
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
};

const connectJsonStream = (...messages: unknown[]): Buffer => Buffer.concat([
  ...messages.map((message) => connectEnvelope(0, message)),
  connectEnvelope(0b10, {}),
]);

async function issueTerminalTicket(page: Page): Promise<string> {
  const response = await page.request.post(
    "/codewire.console.v1.EnvironmentSetupService/IssueTerminalTicket",
    {
      headers: {
        "content-type": "application/json",
      },
      data: {},
    },
  );
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("application/json");
  const { ticket } = await response.json();
  return ticket;
}

const openPresetSelector = async (page: Page) => {
  await page
    .getByRole("combobox")
    .filter({ hasText: /select a preset/i })
    .click();
};

const completeTwoFactorSetup = async (page: Page, email: string) => {
  await expect(page.getByRole("heading", { name: /set up two-factor authentication/i }))
    .toBeVisible({ timeout: 15000 });

  const secret = (await page
    .locator("p")
    .filter({ hasText: /^[A-Z2-7]{16,}$/ })
    .first()
    .textContent())?.trim();
  if (!secret) throw new Error("2FA setup secret was not visible");

  totpSecrets.set(email, secret);
  const code = new OTPAuth.TOTP({ secret }).generate();
  await fillField(page, "#code", code);
  await page.getByRole("button", { name: /verify & enable/i }).click();
  await page.getByRole("button", { name: /continue to dashboard/i })
    .click({ timeout: 15000 });
  await page.waitForURL(/\/dashboard/, { timeout: 15000 });
};

const completeTwoFactorChallenge = async (page: Page, email: string) => {
  const secret = totpSecrets.get(email);
  if (!secret) throw new Error(`No TOTP secret recorded for ${email}`);

  await expect(page.getByRole("heading", { name: "Two-Factor Authentication" }))
    .toBeVisible({ timeout: 15000 });
  const code = new OTPAuth.TOTP({ secret }).generate();
  await fillField(page, "#code", code);
  await page.getByRole("button", { name: /^verify$/i }).click();
  await page.waitForURL(/\/dashboard/, { timeout: 15000 });
};

const login = async (page: Page, email: string, pw: string) => {
  for (let attempt = 0; attempt < 2; attempt++) {
    await goto(page, "/login");
    await page.waitForSelector('button:has-text("Sign in")');
    await page.waitForTimeout(500);
    await fillField(page, "#email", email);
    await fillField(page, "#password", pw);
    const emailValue = await page.locator("#email").inputValue();
    if (!emailValue.includes("@")) continue;
    await page.getByRole("button", { name: /sign in/i }).click();
    try {
      await page.waitForURL(/\/(dashboard|setup-2fa|two-factor)/, { timeout: 15000 });
      await page.waitForTimeout(1000);
      if (page.url().includes("/setup-2fa")) {
        await completeTwoFactorSetup(page, email);
      } else if (page.url().includes("/two-factor")) {
        await completeTwoFactorChallenge(page, email);
      }
      return;
    } catch {
      if (attempt === 1) throw new Error(`Login failed for ${email} after 2 attempts`);
    }
  }
};

const runId = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
const orgName = `Env Test Org ${runId}`;
const orgSlug = `e2e-envtest-${runId}`;

let orgId: string;
let presetId: string;
let systemPresetId: string;
let userId: string;
let runningEnvironment: { envId: string; envName: string } | null = null;
const cancelledStreamRepoUrl = `https://example.test/e2e-stream-cancel-${runId}.git`;
const streamRepoUrl = `https://example.test/e2e-stream-${runId}.git`;

const createRunningEnvironment = async (page: Page) => {
  const createResp = await page.request.post(
    `/api/v1/organizations/${orgId}/environments`,
    { data: { preset_id: presetId } },
  );
  expect(createResp.ok()).toBeTruthy();
  const { id: envId } = await createResp.json();
  await waitForEnvironmentState(envId, ["running"], 300_000);
  const [envRow] = await sql`SELECT name FROM environments WHERE id = ${envId}`;
  runningEnvironment = { envId, envName: envRow.name as string };
  return runningEnvironment;
};

const ensureRunningEnvironment = async (page: Page) => {
  if (runningEnvironment) {
    const [current] = await sql`
      SELECT state FROM environments WHERE id = ${runningEnvironment.envId}
    `;
    if (current?.state === "running") return runningEnvironment;
    if (current && current.state !== "destroyed" && current.state !== "destroying") {
      await waitForEnvironmentState(runningEnvironment.envId, ["running"], 300_000);
      return runningEnvironment;
    }
    runningEnvironment = null;
  }

  const [existing] = await sql`
    SELECT id, name FROM environments
    WHERE org_id = ${orgId} AND state = 'running'
    ORDER BY created_at ASC
    LIMIT 1
  `;
  if (existing) {
    runningEnvironment = { envId: existing.id, envName: existing.name as string };
    return runningEnvironment;
  }

  return createRunningEnvironment(page);
};

test.describe.serial("Environments", () => {
  test.beforeAll(async () => {
    await clearRateLimits();
    // Get owner user ID
    const [user] = await sql`SELECT id FROM users WHERE email = ${USERS.owner.email}`;
    userId = user.id;
    // Create test org
    orgId = await ensureTestOrg(orgName, orgSlug, userId);
    // Seed org preset and system preset
    presetId = await ensureTestSandboxPreset(orgId);
    systemPresetId = await ensureSystemPreset();
  });

  test.afterAll(async () => {
    await cleanupEnvBilling("e2e-envtest-");
    await cleanupEnvironments("e2e-envtest-");
    await cleanupOrgs("e2e-envtest-");
    await cleanupSystemPresets();
  });

  test("create environment from preset and see it in table", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Open create form
    await page.getByRole("button", { name: /^create$/i }).click();
    await page.waitForSelector("text=Create Environment");

    // Switch to "From Image" tab
    await page.getByText("From Image").click();

    // Open the preset selector (Radix Select)
    await openPresetSelector(page);

    // Select the org preset
    await page.getByRole("option", { name: "e2e-sandbox-preset" }).click();

    // Should show the selected preset bar
    await expect(page.getByText("e2e-sandbox-preset")).toBeVisible();

    // Submit
    await page.getByRole("button", { name: /create environment/i }).click();

    // Should see the environment appear in the table
    await expect(
      page.locator("text=pending").or(page.locator("text=creating")),
    ).toBeVisible({ timeout: 10000 });
  });

  test("environment create options and repository picker use console Connect", async ({ page }) => {
    const connectRequests: string[] = [];
    const restRequests: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path.includes("/codewire.console.v1.EnvironmentSetupService/") || path.includes("/codewire.console.v1.GitHubService/")) {
        connectRequests.push(path);
      }
      if (
        path === `/api/v1/organizations/${orgId}/environment-create/options` ||
        path === "/api/v1/github/repos"
      ) {
        restRequests.push(path);
      }
    });

    await page.route("**/codewire.console.v1.EnvironmentSetupService/GetEnvironmentCreateOptions**", (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ githubStatus: { connected: true, username: "octocat" } }),
      }),
    );
    await page.route("**/codewire.console.v1.GitHubService/ListGitHubRepos**", (route) =>
      route.fulfill({
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          repos: [{
            fullName: "codewire/example",
            htmlUrl: "https://github.com/codewire/example",
            cloneUrl: "https://github.com/codewire/example.git",
            defaultBranch: "main",
          }],
        }),
      }),
    );

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);
    await assertEnvironmentCreateConnectSource(page);
    await page.getByRole("button", { name: /^create$/i }).click();

    await expect.poll(() => connectRequests).toContain(
      "/codewire.console.v1.EnvironmentSetupService/GetEnvironmentCreateOptions",
    );
    await expect.poll(() => connectRequests).toContain(
      "/codewire.console.v1.GitHubService/ListGitHubRepos",
    );
    await expect(page.getByText("GitHub connected as @octocat")).toBeVisible();
    await expect(page.getByText("codewire/example", { exact: true })).toBeVisible();
    expect(connectRequests).toContain(
      "/codewire.console.v1.EnvironmentSetupService/GetEnvironmentCreateOptions",
    );
    expect(connectRequests).toContain("/codewire.console.v1.GitHubService/ListGitHubRepos");
    expect(restRequests).toEqual([]);
  });

  test("preset selector shows system and user presets", async ({ page }) => {
    const connectRequests: string[] = [];
    const restPresetRequests: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path.includes("/codewire.v1.PresetService/")) connectRequests.push(path);
      if (path.startsWith(`/api/v1/organizations/${orgId}/presets`)) {
        restPresetRequests.push(path);
      }
    });

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Open create form
    await page.getByRole("button", { name: /^create$/i }).click();
    await page.waitForSelector("text=Create Environment");

    // Switch to "From Image" tab
    await page.getByText("From Image").click();

    // Open the preset selector
    await openPresetSelector(page);

    // Verify system presets group is visible
    await expect(page.getByText("System", { exact: true })).toBeVisible();
    await expect(page.getByRole("option", { name: "e2e-system-preset" })).toBeVisible();

    // Verify user presets group is visible
    await expect(page.getByText("Your Presets")).toBeVisible();
    await expect(page.getByRole("option", { name: "e2e-sandbox-preset" })).toBeVisible();

    // Close dropdown by pressing Escape
    await page.keyboard.press("Escape");

    expect(connectRequests).toContain("/codewire.v1.PresetService/ListPresets");
    expect(restPresetRequests).toEqual([]);
  });

  test("preset page lists presets through Connect", async ({ page }) => {
    const connectRequests: string[] = [];
    const restPresetRequests: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path.includes("/codewire.v1.PresetService/")) connectRequests.push(path);
      if (path.startsWith(`/api/v1/organizations/${orgId}/presets`)) {
        restPresetRequests.push(path);
      }
    });

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/presets`);

    await expect(page.getByRole("heading", { name: "Presets" })).toBeVisible();
    await expect(page.getByText("e2e-sandbox-preset", { exact: true })).toBeVisible();
    expect(connectRequests).toContain("/codewire.v1.PresetService/ListPresets");
    expect(restPresetRequests).toEqual([]);
  });

  test("selecting a preset pre-fills resource defaults", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Open create form
    await page.getByRole("button", { name: /^create$/i }).click();
    await page.waitForSelector("text=Create Environment");

    // Switch to "From Image" tab and select the system preset
    await page.getByText("From Image").click();
    await openPresetSelector(page);
    await page.getByRole("option", { name: "e2e-system-preset" }).click();

    // The selected bar should show the preset name
    await expect(page.getByText("e2e-system-preset")).toBeVisible();

    // Open advanced options to check pre-filled values
    await page.getByRole("button", { name: "Advanced" }).click();

    // System preset has cpu=2000, memory=4096, disk=10, ttl=7200.
    await expect(page.getByRole("combobox").filter({ hasText: "2 Cores" }))
      .toBeVisible({ timeout: 5000 });
    await expect(page.getByRole("combobox").filter({ hasText: "4 GB" }))
      .toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel("Disk (GB)")).toHaveValue("10");
    await expect(page.getByLabel("TTL")).toHaveValue("7200s");
  });

  test("custom image input works alongside preset selector", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Open create form
    await page.getByRole("button", { name: /^create$/i }).click();
    await page.waitForSelector("text=Create Environment");

    // Switch to "From Image" tab
    await page.getByText("From Image").click();

    // Type a custom image
    await fillField(page, 'input[placeholder*="Custom image"]', "alpine:latest");
    await page.getByRole("button", { name: "Use" }).click();

    // The selected bar should show the custom image
    await expect(page.getByText("alpine:latest")).toBeVisible();
  });

  test("repository preparation uses a Connect stream and cancels the superseded request", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);
    await page.getByRole("button", { name: /^create$/i }).click();
    await page.waitForSelector("text=Create Environment");
    await page.getByRole("button", { name: "Add another repo" }).click();

    const connectRequests: string[] = [];
    const legacyPrepareRequests: string[] = [];
    let interceptedRequests = 0;
    let firstRouteSettled = false;
    let firstRouteReadyResolve: (() => void) | undefined;
    let releaseFirstRoute: (() => void) | undefined;
    const firstRouteReady = new Promise<void>((resolve) => {
      firstRouteReadyResolve = resolve;
    });
    const firstRouteRelease = new Promise<void>((resolve) => {
      releaseFirstRoute = resolve;
    });
    const firstRequestStarted = new Promise<void>((resolve) => {
      page.on("request", (request) => {
        const url = request.url();
        if (url.includes("/codewire.v1.EnvironmentService/WatchEnvironmentCreate")) {
          connectRequests.push(url);
          if (connectRequests.length === 1) resolve();
        }
        if (url.includes("/api/v1/organizations/") && url.endsWith("/environment-create/prepare")) {
          legacyPrepareRequests.push(url);
        }
      });
    });
    await page.route(/\/codewire\.v1\.EnvironmentService\/WatchEnvironmentCreate$/, async (route) => {
      interceptedRequests += 1;
      if (interceptedRequests === 1) {
        firstRouteReadyResolve?.();
        await firstRouteRelease;
        firstRouteSettled = true;
        await route.fulfill({
          status: 200,
          headers: { "content-type": "application/connect+json" },
          body: connectJsonStream({
            complete: {
              draft: { orgId, repoUrl: cancelledStreamRepoUrl, image: "stale:first" },
              detection: {
                projectType: "stale",
                presetImage: "stale:first",
                setupNotes: "stale first result",
                needsDocker: false,
                hasCompose: false,
              },
            },
          }),
        }).catch(() => undefined);
        return;
      }

      // Keep all typed event variants in the browser proof with deterministic
      // Connect frames, without depending on external repository analysis.
      await route.fulfill({
        status: 200,
        headers: { "content-type": "application/connect+json" },
        body: connectJsonStream(
          {
            progress: {
              phase: "repo_fetch",
              message: "Fetching repository context...",
              total: 1,
              repo: streamRepoUrl,
            },
          },
          { repoFetched: { index: 0, repo: streamRepoUrl, ok: true } },
          {
            complete: {
              draft: {
                orgId,
                repoUrl: streamRepoUrl,
                image: "node:22-alpine",
                cpuMillicores: 2000,
                memoryMb: 4096,
                diskGb: 20,
                ttlSeconds: 7200,
              },
              detection: {
                projectType: "node",
                presetImage: "node:22-alpine",
                setupNotes: "Typed Connect stream fixture",
                needsDocker: false,
                hasCompose: false,
              },
            },
          },
        ),
      });
    });

    await fillField(page, 'input[placeholder="https://github.com/owner/repo"]', cancelledStreamRepoUrl);
    await page.getByRole("button", { name: "Analyze" }).click();
    await firstRequestStarted;
    await firstRouteReady;
    await expect(page.getByText("Preparing...")).toBeVisible();

    // Clearing the in-flight detection aborts its stream before the late
    // response can apply a stale draft to the next run.
    await page.getByRole("button", { name: "Clear all" }).click();
    releaseFirstRoute?.();
    await expect.poll(() => firstRouteSettled).toBe(true);
    await expect(page.getByText("stale first result")).toBeHidden();
    await page.getByRole("button", { name: "Add another repo" }).click();
    const repoInput = page.locator('input[placeholder="https://github.com/owner/repo"]');
    await expect(repoInput).toBeVisible();

    const completedResponse = page.waitForResponse((response) =>
      response.url().includes("/codewire.v1.EnvironmentService/WatchEnvironmentCreate") &&
      response.request().postData()?.includes(streamRepoUrl) === true,
    );
    await fillField(page, 'input[placeholder="https://github.com/owner/repo"]', streamRepoUrl);
    await page.getByRole("button", { name: "Analyze" }).click();
    const response = await completedResponse;
    await expect(page.getByText("Typed Connect stream fixture")).toBeVisible();
    await expect(page.getByText("node:22-alpine", { exact: true })).toBeVisible();

    expect(connectRequests).toHaveLength(2);
    expect(legacyPrepareRequests).toEqual([]);
    expect(response.status()).toBe(200);
    expect(await response.request().headerValue("content-type")).toContain("application/connect+json");
    expect(await response.headerValue("content-type")).toContain("application/connect+json");
  });

  test("wait for environment to reach running", async ({ page }) => {
    test.setTimeout(300_000);
    const [env] = await sql`
      SELECT id FROM environments WHERE org_id = ${orgId} ORDER BY created_at DESC LIMIT 1
    `;
    expect(env).toBeTruthy();

    // Wait for the real worker to provision the environment
    await waitForEnvironmentState(env.id, ["running"], 300_000);
    const [envRow] = await sql`SELECT name FROM environments WHERE id = ${env.id}`;
    runningEnvironment = { envId: env.id, envName: envRow.name as string };

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Wait for the table to show the running environment
    await expect(page.locator("text=running").first()).toBeVisible({ timeout: 15000 });
  });

  test("open terminal drawer for running environment", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    const { envId } = await ensureRunningEnvironment(page);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Click the terminal button in the Access column
    const terminalBtn = page.locator(`a[href="/terminal/${orgId}/${envId}"]`).last();
    await terminalBtn.click();

    // Terminal drawer should appear with xterm rendered
    await expect(page.locator(".xterm")).toBeVisible({ timeout: 10000 });
  });

  test("terminal drawer accepts input and shows command output", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);
    const { envId } = await ensureRunningEnvironment(page);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    const terminalBtn = page.locator(`a[href="/terminal/${orgId}/${envId}"]`).last();
    await terminalBtn.click();

    const terminal = page.locator(".xterm");
    await expect(terminal).toBeVisible({ timeout: 10000 });

    // Focus the xterm surface and issue a command whose output is different
    // from the echoed input.
    await terminal.click();
    await page.keyboard.type("printf '__PW_TERM__%d__\\n' $RANDOM");
    await page.keyboard.press("Enter");

    await expect(page.locator(".xterm-rows")).toContainText(/__PW_TERM__\d+__/);
  });

  test("terminal drawer stays connected while idle and still accepts input", async ({ page }) => {
    test.setTimeout(360_000);

    await login(page, USERS.owner.email, TEST_PASSWORD);
    const { envId } = await ensureRunningEnvironment(page);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    const terminalBtn = page.locator(`a[href="/terminal/${orgId}/${envId}"]`).last();
    await terminalBtn.click();

    const terminal = page.locator(".xterm");
    const closedOverlay = page.getByText("Connection closed");
    await expect(terminal).toBeVisible({ timeout: 10000 });
    await expect(closedOverlay).toBeHidden();

    // Prod reports the session drops after roughly 30s of idleness.
    await page.waitForTimeout(35_000);
    await expect(closedOverlay).toBeHidden();

    await terminal.click();
    await page.keyboard.type("printf '__PW_TERM_IDLE__%d__\\n' $RANDOM");
    await page.keyboard.press("Enter");

    await expect(page.locator(".xterm-rows")).toContainText(/__PW_TERM_IDLE__\d+__/);
    await expect(closedOverlay).toBeHidden();
  });

  test("terminal websocket with cookie auth stays connected while idle", async ({ page }) => {
    test.setTimeout(360_000);

    await login(page, USERS.owner.email, TEST_PASSWORD);
    const { envId } = await ensureRunningEnvironment(page);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    const terminalUrl = terminalWebSocketUrl({
      serverUrl: SERVER_URL,
      pageHostname: new URL(page.url()).hostname,
      orgId,
      envId,
    });

    await page.evaluate(({ terminalUrl }) => {
      const MSG_STDIN = 0x00;
      const MSG_RESIZE = 0x01;
      (window as Window & { __terminalWsResult?: string }).__terminalWsResult = "pending";

      const encodeResize = (cols: number, rows: number) => {
        const buf = new Uint8Array(5);
        buf[0] = MSG_RESIZE;
        buf[1] = (cols >> 8) & 0xff;
        buf[2] = cols & 0xff;
        buf[3] = (rows >> 8) & 0xff;
        buf[4] = rows & 0xff;
        return buf;
      };

      const encodeStdin = (data: string) => {
        const encoded = new TextEncoder().encode(data);
        const buf = new Uint8Array(1 + encoded.length);
        buf[0] = MSG_STDIN;
        buf.set(encoded, 1);
        return buf;
      };

      let settled = false;
      let closeRequested = false;
      let outputObserved = false;
      let output = "";
      let phase = "connecting";
      const ws = new WebSocket(terminalUrl);

      const settle = (msg: string) => {
        if (!settled) {
          settled = true;
          (window as Window & { __terminalWsResult?: string }).__terminalWsResult = msg;
        }
      };

      const timeout = window.setTimeout(() => {
        if (!closeRequested) {
          closeRequested = true;
          try { ws.close(1000, "playwright timeout"); } catch {}
        }
        settle(`timeout:${phase}`);
      }, 90_000);

      ws.binaryType = "arraybuffer";
      ws.onopen = () => {
        phase = "idle";
        ws.send(encodeResize(120, 32));
        window.setTimeout(() => {
          if (closeRequested) return;
          phase = "command";
          ws.send(encodeStdin("printf '__PW_WS_IDLE__%d__\\n' $RANDOM\n"));
        }, 35_000);
      };
      ws.onmessage = (ev) => {
        output += new TextDecoder().decode(new Uint8Array(ev.data));
        if (/__PW_WS_IDLE__\d+__/.test(output) && !closeRequested) {
          outputObserved = true;
          phase = "closing";
          closeRequested = true;
          try { ws.close(1000, "playwright complete"); } catch {
            settle("close-error:closing");
          }
        }
      };
      ws.onerror = () => settle(`error:${phase}`);
      ws.onclose = (ev) => {
        window.clearTimeout(timeout);
        if (!outputObserved) {
          settle(`closed-before-output:${phase}:${ev.code}:${ev.reason || "none"}`);
        } else if (!closeRequested) {
          settle(`closed-without-request:${phase}:${ev.code}:${ev.reason || "none"}`);
        } else {
          settle(`closed:${ev.code}:${ev.reason || "none"}`);
        }
      };
    }, { terminalUrl });

    await expect
      .poll(
        () => page.evaluate(() => (window as Window & { __terminalWsResult?: string }).__terminalWsResult ?? "missing"),
        { timeout: 120_000, intervals: [1000, 2000, 5000] },
      )
      .toMatch(/^closed:1000:/);

    const [lease] = await sql`
      SELECT COUNT(*)::int AS count
      FROM organization_mutation_leases
      WHERE organization_id = ${orgId}
        AND mutation_class = 'environment_runtime_dispatch'
        AND state IN ('active', 'resolution_required')
    `;
    expect(lease.count).toBe(0);
  });

  test("terminal ticket RPC returns a valid ticket", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);

    const ticket = await issueTerminalTicket(page);
    expect(ticket).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  test("terminal ticket close before attachment drains its admission lease", async ({ page }) => {
    await login(page, USERS.owner.email, TEST_PASSWORD);

    const { envId } = await ensureRunningEnvironment(page);
    const ticket = await issueTerminalTicket(page);
    const terminalUrl = new URL(terminalWebSocketUrl({
      serverUrl: SERVER_URL,
      pageHostname: new URL(page.url()).hostname,
      orgId,
      envId,
    }));
    terminalUrl.searchParams.set("ticket", ticket);

    // Open then explicitly close the ticket-authenticated WebSocket through the
    // configured edge before terminal attachment can become an ambient fixture.
    const wsStatus = await page.evaluate(
      async ({ terminalUrl }) => {
        return new Promise<string>((resolve) => {
          const ws = new WebSocket(terminalUrl);
          ws.binaryType = "arraybuffer";
          let settled = false;
          const settle = (result: string) => {
            if (!settled) {
              settled = true;
              resolve(result);
            }
          };
          const timeout = setTimeout(() => {
            try { ws.close(1000, "playwright timeout"); } catch {}
            settle("timeout");
          }, 5000);
          ws.onopen = () => {
            try {
              ws.close(1000, "playwright pre-attach cancellation");
            } catch {
              settle("close-error");
            }
          };
          ws.onerror = () => {
            clearTimeout(timeout);
            settle("error");
          };
          ws.onclose = (ev) => {
            clearTimeout(timeout);
            settle(`closed:${ev.code}:${ev.reason || "none"}`);
          };
        });
      },
      { terminalUrl: terminalUrl.toString() },
    );

    expect(wsStatus).toMatch(/^closed:1000:/);

    const [lease] = await sql`
      SELECT COUNT(*)::int AS count
      FROM organization_mutation_leases
      WHERE organization_id = ${orgId}
        AND mutation_class = 'environment_runtime_dispatch'
        AND state IN ('active', 'resolution_required')
    `;
    expect(lease.count).toBe(0);
  });

  test("register port via ports dialog", async ({ page }) => {
    const connectRequests: string[] = [];
    const restPortRequests: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if (path.includes("/codewire.v1.PortService/")) connectRequests.push(path);
      if (path.startsWith("/api/v1/") && path.includes("/ports")) {
        restPortRequests.push(path);
      }
    });

    const [env] = await sql`
      SELECT id, name FROM environments WHERE org_id = ${orgId} ORDER BY created_at DESC LIMIT 1
    `;

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    await expect(page.locator("text=running").first()).toBeVisible({ timeout: 15000 });

    // Open three-dot menu for the environment row
    const row = page.locator("tr").filter({ hasText: env.name }).first();
    await row.locator("button").last().click();

    // Click "Ports" in the dropdown menu
    await page.getByRole("menuitem", { name: /ports/i }).click();

    // Fill port form in dialog
    await fillField(page, 'input[placeholder="3000"]', "8080");
    await fillField(page, 'input[placeholder="web"]', "web");

    // Submit
    await page.getByRole("button", { name: "Add" }).click();

    // Should see port in dialog table
    await expect(page.getByRole("cell", { name: "8080", exact: true })).toBeVisible({
      timeout: 10000,
    });
    await expect(page.getByRole("cell", { name: "web", exact: true })).toBeVisible();

    const portRow = page.getByRole("row").filter({ hasText: "web" }).last();
    await portRow.getByRole("button").click();
    await expect(page.getByRole("cell", { name: "web", exact: true })).toHaveCount(0);

    for (const method of ["ListPorts", "CreatePort", "DeletePort"]) {
      expect(connectRequests).toContain(`/codewire.v1.PortService/${method}`);
    }
    expect(restPortRequests).toEqual([]);
  });

  test("stop environment via three-dot menu", async ({ page }) => {
    test.setTimeout(120_000);
    const [env] = await sql`
      SELECT id, name FROM environments WHERE org_id = ${orgId} ORDER BY created_at DESC LIMIT 1
    `;

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    await expect(page.locator("text=running").first()).toBeVisible({ timeout: 15000 });

    // Open three-dot menu
    const row = page.locator("tr").filter({ hasText: env.name }).first();
    await row.locator("button").last().click();
    await page.getByRole("menuitem", { name: /stop/i }).waitFor({ state: "visible" });
    await page.getByRole("menuitem", { name: /stop/i }).click();

    // Wait for real worker to stop the environment
    await waitForEnvironmentState(env.id, ["stopped"], 60_000);

    // Wait for stopped state in table
    await expect(page.locator("text=stopped").first()).toBeVisible({ timeout: 15000 });
  });

  test("start environment via three-dot menu", async ({ page }) => {
    test.setTimeout(300_000);
    const [env] = await sql`
      SELECT id, name FROM environments WHERE org_id = ${orgId} ORDER BY created_at DESC LIMIT 1
    `;

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    await expect(page.locator("text=stopped").first()).toBeVisible({ timeout: 15000 });

    // Open three-dot menu
    const row = page.locator("tr").filter({ hasText: env.name }).first();
    await row.locator("button").last().click();
    await page.getByRole("menuitem", { name: /start/i }).waitFor({ state: "visible" });
    await page.getByRole("menuitem", { name: /start/i }).click();

    // Wait for real worker to start the environment
    await waitForEnvironmentState(env.id, ["running"], 300_000);

    // Wait for running state in table
    await expect(page.locator("text=running").first()).toBeVisible({ timeout: 15000 });
  });

  test("destroy environment via three-dot menu", async ({ page }) => {
    test.setTimeout(120_000);
    const [env] = await sql`
      SELECT id, name FROM environments WHERE org_id = ${orgId} ORDER BY created_at DESC LIMIT 1
    `;

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Accept the confirmation dialog
    page.on("dialog", (dialog) => dialog.accept());

    // Open three-dot menu
    const row = page.locator("tr").filter({ hasText: env.name }).first();
    await row.locator("button").last().click();
    await page.getByRole("menuitem", { name: /destroy/i }).waitFor({ state: "visible" });
    await page.getByRole("menuitem", { name: /destroy/i }).click();

    // Wait for real worker to destroy the environment
    await waitForEnvironmentState(env.id, ["destroyed"], 120_000);

    // Should still be on the environments page
    await expect(page).toHaveURL(new RegExp(`/environments`), { timeout: 15000 });
  });

  test("usage Connect RPC returns environment usage data", async ({ page }) => {
    // Create a new environment for usage testing
    const envId = crypto.randomUUID();
    await sql`
      INSERT INTO environments (id, org_id, created_by, type, preset_id, name, state, desired_state,
        cpu_millicores, memory_mb, disk_gb, total_running_seconds, created_at, state_changed_at)
      VALUES (${envId}, ${orgId}, ${userId}, 'sandbox', ${presetId}, 'usage-test-env', 'running', 'started',
        2000, 4096, 10, 3600, NOW(), NOW())
    `;

    // Insert synthetic billing events
    await insertEnvBillingEvents(orgId, envId, 3600, 2000, 4096, 10);

    await login(page, USERS.owner.email, TEST_PASSWORD);

    const body = await page.evaluate(async (organizationId) => {
      const { billingClient } = await import("/src/lib/connect.ts");
      const response = await billingClient.getEnvironmentUsage({ orgId: organizationId });
      return {
        cpuHours: response.currentMonth?.cpuHours,
        perEnvironment: response.perEnvironment.map((entry) => ({
          id: entry.id,
          runningSeconds: entry.runningSeconds,
        })),
      };
    }, orgId);

    // Verify current month has usage.
    expect(body.cpuHours).toBeGreaterThan(0);

    // Verify per-environment usage contains the synthetic environment.
    const entry = body.perEnvironment.find((item) => item.id === envId);
    expect(entry).toBeTruthy();
    expect(entry?.runningSeconds).toBe(3600);
  });

  test("running environment shows cost info in sub-row", async ({ page }) => {
    // Find or create a running env with known running seconds
    const [env] = await sql`
      SELECT id FROM environments WHERE org_id = ${orgId} AND state = 'running'
      ORDER BY created_at DESC LIMIT 1
    `;
    if (env) {
      await sql`
        UPDATE environments SET total_running_seconds = 7200,
          cpu_millicores = 2000, memory_mb = 4096
        WHERE id = ${env.id}
      `;
    }

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);

    // Wait for running state
    await expect(page.locator("text=running").first()).toBeVisible({ timeout: 15000 });

    // Sub-row should show cost (dollar sign) and duration
    const subRow = page.locator("tr.hover\\:bg-transparent").first();
    await expect(subRow.getByText(/^\$\d+\.\d{2}$/)).toBeVisible({ timeout: 5000 });
    await expect(subRow.getByText("2h 0m")).toBeVisible({ timeout: 5000 });
    await expect(subRow.getByText(/^\$\d+\.\d{2}\/h$/)).toBeVisible({ timeout: 5000 });
  });

  test("billing page shows environment usage section", async ({ page }) => {
    // Ensure billing events exist for the org
    const [env] = await sql`
      SELECT id FROM environments WHERE org_id = ${orgId} AND state = 'running'
      ORDER BY created_at DESC LIMIT 1
    `;
    if (env) {
      await insertEnvBillingEvents(orgId, env.id, 3600, 2000, 4096, 10);
    }

    await login(page, USERS.owner.email, TEST_PASSWORD);
    await goto(page, `/dashboard/orgs/${orgSlug}/billing`);

    // Assert "Environment Usage" heading is visible
    await expect(page.locator("text=Environment Usage")).toBeVisible({ timeout: 15000 });

    // Assert "Current Month" card shows a cost value
    await expect(page.locator("text=Current Month")).toBeVisible({ timeout: 10000 });
  });

  test("full lifecycle: create → running → stop → start → destroy", async ({ page }) => {
    test.setTimeout(600_000);

    // Helper: open three-dot menu for an env row and click an item
    const clickMenuAction = async (envName: string, action: RegExp) => {
      const r = page.locator("tr").filter({ hasText: envName }).first();
      await r.locator("button").last().click();
      await page.getByRole("menuitem", { name: action }).waitFor({ state: "visible" });
      await page.getByRole("menuitem", { name: action }).click();
    };

    // Create environment via real API
    await login(page, USERS.owner.email, TEST_PASSWORD);
    const createResp = await page.request.post(
      `/api/v1/organizations/${orgId}/environments`,
      { data: { preset_id: presetId } },
    );
    expect(createResp.ok()).toBeTruthy();
    const { id: envId } = await createResp.json();
    const [envRow] = await sql`SELECT name FROM environments WHERE id = ${envId}`;
    const envName = envRow.name;

    // === Create → running (real worker, real k8s) ===
    await waitForEnvironmentState(envId, ["running"], 300_000);
    await goto(page, `/dashboard/orgs/${orgSlug}/environments`);
    const row = page.locator("tr").filter({ hasText: envName }).first();
    await expect(row.locator("text=running")).toBeVisible({ timeout: 15000 });

    // === Stop via UI ===
    await clickMenuAction(envName, /stop/i);
    await waitForEnvironmentState(envId, ["stopped"], 60_000);
    await expect(page.locator("tr").filter({ hasText: envName }).first()
      .locator("text=stopped")).toBeVisible({ timeout: 15000 });

    // === Start via UI ===
    await clickMenuAction(envName, /start/i);
    await waitForEnvironmentState(envId, ["running"], 300_000);
    await expect(page.locator("tr").filter({ hasText: envName }).first()
      .locator("text=running")).toBeVisible({ timeout: 15000 });

    // === Destroy via UI ===
    page.on("dialog", (dialog) => dialog.accept());
    await clickMenuAction(envName, /destroy/i);
    await waitForEnvironmentState(envId, ["destroyed"], 120_000);

    // Verify final state in DB
    const [final] = await sql`SELECT state FROM environments WHERE id = ${envId}`;
    expect(final.state).toBe("destroyed");
  });
});
