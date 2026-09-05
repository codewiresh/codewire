import { expect, test, type Locator, type Page } from "@playwright/test";
import postgres from "postgres";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getUserId } from "./helpers/db";
import { cleanupEnvironments, waitForEnvironmentState } from "./helpers/environment";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";
import { terminalWebSocketUrl } from "./helpers/terminal-websocket";

const sql = postgres(process.env.DATABASE_URL!);
const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const serverUrl = process.env.SERVER_URL || "http://127.0.0.1:8080";
const fixtureRunIdOverride = process.env.CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID;
if (
  fixtureRunIdOverride !== undefined
  && !/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(fixtureRunIdOverride)
) {
  throw new Error(
    "CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID must be 1-32 lowercase letters, digits, or internal hyphens",
  );
}
const runId = fixtureRunIdOverride ?? `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const slug = `ssr-environments-${runId}`;
const orgName = "SSR Environment Workspace";
const presetName = "ssr-environment-preset";
const environmentName = "ssr-terminal-workspace";
const repositoryUrl = `https://example.test/codewire/${slug}`;
// Immutable workspace image accepted by the Connect-RPC C2 runtime evidence.
// This browser proof must never turn a floating registry tag into a test input.
const workspaceImage = "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467";
// Sealed Kind runs side-load the Forgejo-proven workspace under a disposable
// local alias. Only the test-owned preset may use that alias; browser assertions
// above the product's canonical workspace choice continue to use workspaceImage.
const workspaceRuntimeImage = process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || workspaceImage;

let ownerId = "";
let orgId = "";
let presetId = "";
let environmentId = "";

function watchDisallowedBrowserCalls(page: Page) {
  const calls: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    const terminalEdge = new URL(serverUrl);
    const isTerminalSocket = ["ws:", "wss:"].includes(url.protocol)
      && url.hostname === terminalEdge.hostname
      && url.port === terminalEdge.port
      && /^\/api\/v1\/organizations\/[^/]+\/environments\/[^/]+\/terminal$/.test(url.pathname);
    if (!isTerminalSocket && (
      url.origin !== ssrUrl
      || url.pathname.includes("/codewire.")
      || url.pathname.startsWith("/api/v1/")
    )) {
      calls.push(request.url());
    }
  });
  return calls;
}

async function openRowActions(row: Locator) {
  const trigger = row.locator('summary[aria-label^="Actions for "]');
  await expect(trigger).toBeVisible();
  await trigger.click();
}

async function issueTerminalTicket(page: Page): Promise<string> {
  const response = await page.request.post(
    `${serverUrl}/codewire.console.v1.EnvironmentSetupService/IssueTerminalTicket`,
    { headers: { "content-type": "application/json" }, data: {} },
  );
  expect(response.ok()).toBeTruthy();
  expect(response.headers()["content-type"]).toContain("application/json");
  const { ticket } = await response.json();
  expect(ticket).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  return ticket;
}

async function expectTerminalLeaseDrained() {
  const [lease] = await sql`
    SELECT COUNT(*)::int AS count
    FROM organization_mutation_leases
    WHERE organization_id = ${orgId}
      AND mutation_class = 'environment_runtime_dispatch'
      AND state IN ('active', 'resolution_required')
  `;
  expect(lease.count).toBe(0);
}

async function closeTicketBeforeAttachment(page: Page, ticket: string) {
  const url = new URL(terminalWebSocketUrl({
    serverUrl,
    pageHostname: new URL(page.url()).hostname,
    orgId,
    envId: environmentId,
  }));
  url.searchParams.set("ticket", ticket);
  const result = await page.evaluate(async ({ terminalUrl }) => (
    new Promise<string>((resolve) => {
      const socket = new WebSocket(terminalUrl, ["terminal"]);
      let settled = false;
      const settle = (value: string) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      const timeout = window.setTimeout(() => {
        socket.close(1000, "acceptance timeout");
        settle("timeout");
      }, 10_000);
      socket.addEventListener("open", () => socket.close(1000, "pre-attach cancellation"));
      socket.addEventListener("error", () => {
        window.clearTimeout(timeout);
        settle("error");
      });
      socket.addEventListener("close", (event) => {
        window.clearTimeout(timeout);
        settle(`closed:${event.code}`);
      });
    })
  ), { terminalUrl: url.toString() });
  expect(result).toBe("closed:1000");
}

async function seedPinnedPreset() {
  presetId = crypto.randomUUID();
  await sql`
    INSERT INTO environment_presets
      (id, org_id, name, slug, description, build_status, default_ttl_seconds, project_spec)
    VALUES
      (${presetId}, ${orgId}, ${presetName}, ${presetName},
       'Pinned SSR environment lifecycle preset', 'ready', 3600,
       ${sql.json({
         schema_version: 1,
         image: workspaceRuntimeImage,
         working_directory: "/workspace",
         install_command: "printf 'prepared-by-preset\\n'",
         startup_script: "printf 'started-by-preset\\n'",
         agents: { tools: ["codex"] },
         application_ports: [{ port: 3000, label: "web", access: "creator" }],
         resources: { cpu_millicores: 1000, memory_mib: 2048, disk_gib: 10 },
       })})
  `;
  await sql`
    INSERT INTO sandbox_template_config
      (preset_id, image_ref, sandbox_template_name, persistent_storage)
    VALUES
      (${presetId}, ${workspaceRuntimeImage}, ${`ssr-environment-${runId}`}, false)
  `;
  await sql`
    INSERT INTO repo_configs (id, org_id, repo_url, project_spec, created_by)
    VALUES (
      ${crypto.randomUUID()}, ${orgId}, ${repositoryUrl},
      ${sql.json({
        schema_version: 1,
        preset: presetName,
        working_directory: "/workspace",
      })},
      ${ownerId}
    )
  `;
}

async function openConfiguredImageForm(page: Page) {
  await page.goto(`/${slug}/new/`);
  await page.getByLabel("Workspace image").fill(workspaceRuntimeImage);
  await page.getByLabel("Install Command").fill("printf 'configured-explicitly\\n'");
  await page.getByLabel("Startup Script").fill("printf 'started-explicitly\\n'");
  await page.getByLabel("TTL").fill("3600s");
  await page.locator('input[name="agent"][value="codex"]').check();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Container port").fill("3000");
  await page.getByLabel("Port label").fill("web");
}

test.describe.serial("server-rendered environments", () => {
  test.beforeAll(async () => {
    const seededOwnerId = await getUserId(USERS.master.email);
    if (!seededOwnerId) throw new Error("E2E owner was not seeded");
    ownerId = seededOwnerId;
    orgId = await ensureTestOrg(orgName, slug, ownerId);
    await seedPinnedPreset();
  });

  test.afterAll(async () => {
    await cleanupEnvironments(slug);
    await cleanupTestOrg(slug);
  });

  test("keeps manual repository URL, branch, and mount entry always available", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop repository-entry contract");
    const response = await page.goto(`/${slug}/new/`);
    expect(response?.status()).toBe(200);
    await expect(page.getByLabel("Repository URL", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Branch", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Mount path", { exact: true })).toBeVisible();
    await expect(page.locator("[data-github-repository-picker]")).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Connect GitHub" })).toHaveCount(0);
    await expect(page.locator('a[href*="/api/v1/github/"]')).toHaveCount(0);
  });

  test("renders server-owned create options and resources with no browser service caller", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop create-options and visual contract");
    const disallowedBrowserCalls = watchDisallowedBrowserCalls(page);
    const staleAssetRequests: string[] = [];
    page.on("request", (request) => {
      const pathname = new URL(request.url()).pathname;
      if ([
        "/assets/codewire/environments-v1.js",
        "/assets/codewire/routes/environments-v1.css",
        "/assets/codewire/icons-v1.svg",
      ].includes(pathname)) staleAssetRequests.push(pathname);
    });

    await page.goto(`/${slug}/new/`);
    await expect(page.getByRole("heading", { name: "Sandboxes", exact: true })).toBeVisible();
    await expect(page.locator('script[src="/assets/codewire/environments-v2.js"]')).toHaveCount(1);
    await expect(page.locator('link[href="/assets/codewire/routes/environments-v2.css"]')).toHaveCount(1);
    await expect(page.locator('use[href^="/assets/codewire/icons-v2.svg#"]').first()).toHaveCount(1);
    await expect(
      page.locator(".cw-sidebar-slot").getByRole("link", { name: /View all sandboxes/ }),
    ).toHaveAttribute(
      "href",
      `/${slug}/`,
    );
    await expect(page.locator(`#workspace-image-options option[label="${presetName}"]`)).toHaveAttribute(
      "value",
      workspaceRuntimeImage,
    );
    const drawer = page.locator("#environment-create-card");
    await expect(drawer).toHaveAttribute("role", "dialog");
    await expect(drawer).toHaveAttribute("aria-modal", "true");
    await expect(drawer).toHaveCSS("transform", "none");
    await expect(page.locator("#environment-name")).toBeFocused();
    const ttl = page.getByLabel("TTL");
    await expect(ttl).toHaveValue("infinity");
    await ttl.fill("0");
    await ttl.press("Tab");
    await expect(ttl).toHaveValue("infinity");
    await page.locator("#environment-name").focus();
    await expect(page.locator("#environment-snapshot")).toBeDisabled();
    await expect(page.locator('#environment-snapshot[name]')).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    await expect(page.locator('[action$="/_actions/sandboxes/prepare"]')).toHaveCount(0);
    await expect(page.locator('[data-event-action$="/_events/sandboxes/prepare"]')).toHaveCount(0);
    const drawerGeometry = await drawer.evaluate((element) => {
      const box = element.getBoundingClientRect();
      return { width: box.width, height: box.height, right: box.right, viewportWidth: innerWidth, viewportHeight: innerHeight };
    });
    expect(drawerGeometry.width).toBeCloseTo(540, 3);
    expect(drawerGeometry.height).toBe(drawerGeometry.viewportHeight);
    expect(drawerGeometry.right).toBe(drawerGeometry.viewportWidth);
    expect(disallowedBrowserCalls).toEqual([]);
    expect(staleAssetRequests).toEqual([]);
    await expect(page).toHaveScreenshot("environments-create-desktop.png");
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(new RegExp(`/${slug}/$`));
    await expect(page.locator("[data-drawer]")).toBeHidden();
  });

  test("opens the pre-rendered sheet instantly and updates clean history without navigation", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop history and pre-render contract");
    let documentRequests = 0;
    page.on("request", (request) => {
      if (request.resourceType() === "document") documentRequests += 1;
    });

    await page.goto(`/${slug}/`);
    expect(documentRequests).toBe(1);
    const drawer = page.locator("[data-drawer]");
    await expect(drawer).toBeHidden();
    await expect(drawer.locator("#environment-create-card")).toHaveCount(1);
    await page.locator(".cw-environment-toolbar").getByRole("link", { name: "Create Sandbox" }).click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/`);
    await expect(drawer).toBeVisible();
    await expect(page.locator("#environment-name")).toBeFocused();
    expect(documentRequests).toBe(1);

    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/`);
    await expect(drawer).toBeHidden();
    expect(documentRequests).toBe(1);
  });

  test("keeps image, repositories, mounts, protected secret boundary, agents, and runtime on one compact form", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop environment-create contract");
    await page.setViewportSize({ width: 1066, height: 1103 });

    await page.goto(`/${slug}/new/`);
    const createCard = page.locator("#environment-create-card");
    const dimensions = await createCard.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(dimensions.clientWidth).toBe(539);
    expect(dimensions.scrollWidth - dimensions.clientWidth).toBeLessThanOrEqual(1);
    await expect(page.getByLabel("Workspace image")).toHaveValue(
      workspaceImage,
    );
    await page.getByLabel("Workspace image").fill("registry.example.test/team/workspace:v1");
    await page.getByLabel("Repository URL", { exact: true }).fill(repositoryUrl);
    await page.getByLabel("Mount path", { exact: true }).fill("codewire");
    await page.getByRole("button", { name: "Add another URL" }).click();
    await page.getByLabel("Repository URL").nth(1).fill("https://example.test/codewire/secondary");
    await page.getByLabel("Mount path").nth(1).fill("secondary");
    await expect(page.getByLabel("Repository URL", { exact: true }).first()).toHaveValue(repositoryUrl);
    await expect(page.getByLabel("Mount path", { exact: true }).first()).toHaveValue("codewire");
    await expect(page.getByLabel("Repository URL").nth(1)).toHaveValue(
      "https://example.test/codewire/secondary",
    );
    await expect(page.getByLabel("Mount path").nth(1)).toHaveValue("secondary");
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);

    await page.locator('input[name="agent"][value="codex"]').check();
    await page.getByRole("button", { name: "Add", exact: true }).click();
    await page.getByLabel("Container port").fill("3000");
    await page.getByLabel("Port label").fill("web");
    await page.getByLabel("Install Command").fill("bun install");
    await page.getByLabel("Startup Script").fill("bun run dev");
    await expect(page.locator('input[name="agent"][value="codex"]')).toBeChecked();
    await expect(page.getByLabel("Container port")).toHaveValue("3000");
    await expect(page.getByLabel("Port label")).toHaveValue("web");
    await expect(page.getByRole("heading", { name: "Secrets", exact: true })).toBeVisible();
    await expect(page.getByText(
      "Saved secrets cannot be attached to a Sandbox until protected access is available.",
      { exact: true },
    )).toBeVisible();
    await expect(page.locator([
      'input[name="secret_project"]',
      'input[name="include_org_secrets"]',
      'input[name="include_user_secrets"]',
      'input[name^="agent_secret_"]',
    ].join(","))).toHaveCount(0);
    await expect(page.getByLabel("Install Command")).toHaveValue("bun install");
    await expect(page.getByLabel("Startup Script")).toHaveValue("bun run dev");
    await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("1000");
    await expect(page.getByLabel("Memory", { exact: true })).toHaveValue("2048");
    await expect(page.getByLabel("Disk", { exact: true })).toHaveValue("10");
    await expect(page.getByLabel("TTL")).toHaveValue("infinity");
    await expect(page.getByLabel("Workspace image")).toHaveValue(
      "registry.example.test/team/workspace:v1",
    );
  });

  test("fails closed when repository-only create has no saved configuration", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop repository-resolution contract");
    const name = `unknown-repository-${runId}`;
    const unknownRepository = `https://example.test/codewire/${slug}/unknown`;

    await page.goto(`/${slug}/new/`);
    await page.getByLabel("Name").fill(name);
    await page.getByLabel("Workspace image").fill("");
    await page.getByLabel("Repository URL", { exact: true }).fill(unknownRepository);
    const response = page.waitForResponse((candidate) => (
      candidate.url().endsWith(`/${slug}/_actions/sandboxes/create`)
      && candidate.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    expect((await response).status()).toBe(422);
    await expect(page.getByRole("alert")).toContainText(
      "This repository has no saved Sandbox configuration. Enter a workspace image or use a configured repository.",
    );
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    const [environment] = await sql`
      SELECT COUNT(*)::int AS count FROM environments
      WHERE org_id = ${orgId} AND name = ${name}
    `;
    expect(environment.count).toBe(0);
  });

  test("keeps environment create and inventory usable on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile responsive and visual contract");
    await page.goto(`/${slug}/new/`);
    await expect(page.getByRole("heading", { name: "Create Sandbox" })).toBeVisible();
    await expect(page.getByLabel("TTL")).toHaveValue("infinity");
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    await page.locator(".cw-drawer-body").evaluate((element) => { element.scrollTop = 0; });
    expect(await page.locator("#environment-create-card").evaluate((element) => element.getBoundingClientRect().top)).toBe(0);
    await expect(page).toHaveScreenshot("environments-create-mobile.png");
    await page.getByLabel("Repository URL", { exact: true }).fill(repositoryUrl);
    await page.getByLabel("Branch", { exact: true }).fill("main");
    await page.getByLabel("Mount path", { exact: true }).fill("codewire");
    await expect(page.getByRole("heading", { name: "Runtime", exact: true })).toBeVisible();
    await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue(repositoryUrl);
    await expect(page.getByLabel("Branch", { exact: true })).toHaveValue("main");
    await expect(page.getByLabel("Mount path", { exact: true })).toHaveValue("codewire");
    const mobileCard = page.locator("#environment-create-card");
    const dimensions = await mobileCard.evaluate((element) => ({
      clientWidth: element.clientWidth,
      scrollWidth: element.scrollWidth,
    }));
    expect(dimensions.clientWidth).toBeGreaterThan(0);
    expect(dimensions.scrollWidth - dimensions.clientWidth).toBeLessThanOrEqual(1);
    await expect(page.getByText(
      "Saved secrets cannot be attached to a Sandbox until protected access is available.",
      { exact: true },
    )).toBeVisible();
  });

  test("creates, runs, exposes a port, stops, starts, and destroys through real Kind", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop lifecycle contract");
    test.setTimeout(900_000);
    const disallowedBrowserCalls = watchDisallowedBrowserCalls(page);
    await page.addInitScript(() => {
      const frames: number[][] = [];
      (window as Window & { __terminalFrames?: number[][] }).__terminalFrames = frames;
      const nativeSend = WebSocket.prototype.send;
      WebSocket.prototype.send = function(data: string | ArrayBufferLike | Blob | ArrayBufferView) {
        if (data instanceof ArrayBuffer) frames.push([...new Uint8Array(data)]);
        else if (ArrayBuffer.isView(data)) {
          frames.push([...new Uint8Array(data.buffer, data.byteOffset, data.byteLength)]);
        }
        return (nativeSend as (
          this: WebSocket,
          payload: typeof data,
        ) => void).call(this, data);
      };
    });

    await openConfiguredImageForm(page);
    await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("1000");
    await expect(page.getByLabel("Memory", { exact: true })).toHaveValue("2048");
    await expect(page.getByLabel("Disk", { exact: true })).toHaveValue("10");
    await page.getByLabel("Name").fill(environmentName);
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    await expect(page).toHaveURL(
      `${ssrUrl}/${slug}/?message=environment-created`,
    );
    await expect(page.getByRole("status")).toContainText("Sandbox creation started");
    const sidebarAlignment = await page.evaluate(() => {
      const bounds = (selector: string) => {
        const rect = document.querySelector(selector)?.getBoundingClientRect();
        return rect ? { left: rect.left, right: rect.right } : undefined;
      };
      return {
        organization: bounds(".cw-sidebar-slot .cw-org-switcher > summary"),
        create: bounds(".cw-sidebar-slot .cw-console-create"),
        createIcon: bounds(".cw-sidebar-slot .cw-console-create .cw-icon"),
        heading: bounds(".cw-sidebar-slot .cw-console-rail-heading"),
        headingText: bounds(".cw-sidebar-slot .cw-console-rail-heading h2 > a"),
        row: bounds(".cw-sidebar-slot .cw-rail-row"),
        rowDot: bounds(".cw-sidebar-slot .cw-rail-dot"),
        getStarted: bounds(".cw-sidebar-slot .cw-console-get-started .cw-nav-link"),
        footer: bounds(".cw-sidebar-slot .cw-console-footer .cw-nav-link"),
        footerIcon: bounds(".cw-sidebar-slot .cw-console-footer .cw-nav-link .cw-icon"),
      };
    });
    expect(sidebarAlignment.create).toBeDefined();
    const expectWithinPixel = (actual: number | undefined, expected: number | undefined) => {
      expect(actual).toBeDefined();
      expect(expected).toBeDefined();
      expect(Math.abs((actual ?? 0) - (expected ?? 0))).toBeLessThanOrEqual(1);
    };
    for (const control of [
      sidebarAlignment.organization,
      sidebarAlignment.heading,
      sidebarAlignment.row,
      sidebarAlignment.getStarted,
      sidebarAlignment.footer,
    ]) {
      expectWithinPixel(control?.left, sidebarAlignment.create?.left);
      expectWithinPixel(control?.right, sidebarAlignment.create?.right);
    }
    for (const content of [
      sidebarAlignment.headingText,
      sidebarAlignment.rowDot,
      sidebarAlignment.footerIcon,
    ]) {
      expectWithinPixel(content?.left, sidebarAlignment.createIcon?.left);
    }

    const [created] = await sql`
      SELECT id, cpu_millicores, memory_mb, disk_gb, ttl_seconds,
             project_spec
      FROM environments WHERE org_id = ${orgId} AND name = ${environmentName}
    `;
    expect(created?.id).toBeTruthy();
    environmentId = created.id as string;
    expect(created.cpu_millicores).toBe(1000);
    expect(created.memory_mb).toBe(2048);
    expect(created.disk_gb).toBe(10);
    expect(created.ttl_seconds).toBe(3600);
    expect(created.project_spec).toMatchObject({
      schema_version: 1,
      working_directory: "/workspace",
      install_command: "printf 'configured-explicitly\\n'",
      startup_script: "printf 'started-explicitly\\n'",
      agents: { tools: ["codex"] },
      application_ports: [{ port: 3000, label: "web", access: "creator" }],
      resources: { cpu_millicores: 1000, memory_mib: 2048, disk_gib: 10 },
    });
    expect(created.project_spec).not.toHaveProperty("secrets");
    await waitForEnvironmentState(environmentId, ["running"], 300_000);
    await page.reload();
    let row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("running");
    await expect(row.getByText("1 vCPU · 2 GiB · 10 GiB", { exact: true })).toBeVisible();
    await openRowActions(row);
    await expect(row.locator(".cw-row-menu-meta")).toContainText("usage");

    const terminalLink = row.getByRole("link", { name: "Terminal", exact: true });
    await terminalLink.click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/${environmentId}/`);
    const terminalRoot = page.locator(".cw-terminal-page [data-terminal-root]");
    await expect(terminalRoot.locator(".xterm")).toBeVisible({ timeout: 15_000 });
    await expect(terminalRoot.locator("[data-terminal-status]")).toBeHidden({ timeout: 15_000 });
    const initialResizeCount = await page.evaluate(() => (
      ((window as Window & { __terminalFrames?: number[][] }).__terminalFrames || [])
        .filter((frame) => frame[0] === 0x01 && frame.length === 5).length
    ));
    expect(initialResizeCount).toBeGreaterThan(0);
    await page.setViewportSize({ width: 1180, height: 760 });
    await expect.poll(() => page.evaluate(() => (
      ((window as Window & { __terminalFrames?: number[][] }).__terminalFrames || [])
        .filter((frame) => frame[0] === 0x01 && frame.length === 5).length
    ))).toBeGreaterThan(initialResizeCount);

    // The idle interval is the behavior under test, not a fixture delay: the
    // same attached browser socket must still carry the later command.
    await page.evaluate(() => new Promise((resolve) => window.setTimeout(resolve, 35_000)));
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__SSR_TERM_IDLE__%d__\\n' $RANDOM");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(/__SSR_TERM_IDLE__\d+__/);
    const sentInput = await page.evaluate(() => (
      ((window as Window & { __terminalFrames?: number[][] }).__terminalFrames || [])
        .some((frame) => frame[0] === 0x00 && frame.length > 1)
    ));
    expect(sentInput).toBe(true);
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(page.locator(".cw-sandbox-terminal")).toHaveScreenshot("terminal-drawer-desktop.png", {
      mask: [terminalRoot.locator(".xterm-rows")],
      maskColor: "#080808",
    });
    await expect(page.getByRole("heading", { name: environmentName, exact: true })).toBeVisible();
    await expect(page.locator(".cw-terminal-page .xterm")).toBeVisible({ timeout: 15_000 });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page).toHaveScreenshot("terminal-full-mobile.png", {
      mask: [page.locator(".xterm-rows")],
      maskColor: "#080808",
    });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.getByRole("button", { name: "Disconnect" }).click();
    await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "true");
    await expectTerminalLeaseDrained();

    const noJavaScriptContext = await page.context().browser()!.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: authState,
    });
    const noJavaScriptPage = await noJavaScriptContext.newPage();
    const noJavaScriptRequests: string[] = [];
    noJavaScriptPage.on("request", (request) => noJavaScriptRequests.push(request.url()));
    await noJavaScriptPage.goto(`/${slug}/${environmentId}/`);
    await expect(noJavaScriptPage.getByRole("heading", { name: "Use the CLI terminal" })).toBeVisible();
    expect(await noJavaScriptPage.locator("code").textContent()).toBe(`cw shell ${environmentId}`);
    expect(noJavaScriptRequests.every((url) => new URL(url).origin === ssrUrl)).toBe(true);
    await noJavaScriptContext.close();

    await page.goto(`/${slug}/`);
    const ticket = await issueTerminalTicket(page);
    await closeTicketBeforeAttachment(page, ticket);
    await expectTerminalLeaseDrained();
    expect(disallowedBrowserCalls).toEqual([]);

    await openRowActions(row);
    await row.getByRole("link", { name: "Ports" }).click();
    const portPanel = page.locator(".cw-port-panel");
    await portPanel.getByRole("spinbutton", { name: "Port" }).fill("8080");
    await portPanel.getByLabel("Label", { exact: true }).fill("web");
    await portPanel.getByRole("button", { name: "Add port", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Port created");
    const port = page.locator(".cw-port-row", { hasText: "web" });
    await expect(port).toContainText("8080");
    await port.getByRole("button", { name: "Delete" }).click();
    await expect(page.getByRole("status")).toContainText("Port deleted");
    await expect(page.locator(".cw-port-row", { hasText: "web" })).toHaveCount(0);

    row = page.locator("tr", { hasText: environmentName }).first();
    await openRowActions(row);
    await row.getByRole("button", { name: "Stop" }).click();
    await waitForEnvironmentState(environmentId, ["stopped"], 120_000);
    await page.reload();
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("stopped");

    await openRowActions(row);
    await row.getByRole("button", { name: "Start" }).click();
    await waitForEnvironmentState(environmentId, ["running"], 300_000);
    await page.reload();
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("running");

    await openRowActions(row);
    await row.locator("summary", { hasText: "Destroy" }).click();
    await row.getByRole("button", { name: "Destroy permanently" }).click();
    await waitForEnvironmentState(environmentId, ["destroyed"], 120_000);
    await page.goto(`/${slug}/?state=destroyed`);
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("destroyed");
    expect(disallowedBrowserCalls).toEqual([]);
  });
});
