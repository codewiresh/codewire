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
// Current published immutable Codewire workspace image.
// This browser proof must never turn a floating registry tag into a test input.
const workspaceImage = "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff";
// Sealed Kind runs side-load the Forgejo-proven workspace under a disposable
// local alias. Only the test-owned preset may use that alias; browser assertions
// above the product's canonical workspace choice continue to use workspaceImage.
const workspaceRuntimeImage = process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || workspaceImage;

let ownerId = "";
let orgId = "";
let presetId = "";
let environmentId = "";
let secretProjectId = "";
type TerminalClientFrame = { type: "input"; data: string }
  | { type: "resize"; columns: number; rows: number }
  | { type: "ack"; offset: string };

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
  await expect.poll(async () => {
    const [lease] = await sql`
      SELECT COUNT(*)::int AS count
      FROM organization_mutation_leases
      WHERE organization_id = ${orgId}
        AND mutation_class = 'environment_runtime_dispatch'
        AND state IN ('active', 'resolution_required')
    `;
    return lease.count;
  }, { timeout: 15_000 }).toBe(0);
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
    await expect(page.locator("[data-github-repository-picker]")).toHaveCount(1);
    await expect(page.locator("[data-github-repository-picker]")).not.toBeVisible();
    await expect(page.getByRole("button", { name: "Choose from GitHub" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Custom Git URL" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Connect GitHub", exact: true })).toHaveAttribute("href", `/settings/credentials/?org=${slug}`);
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
    await expect(page.getByRole("heading", { name: "Application secrets", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Provider credentials", exact: true })).toBeVisible();
    await expect(page.getByLabel("Personal secrets", { exact: false })).toBeEnabled();
    await expect(page.getByLabel("Organization secrets", { exact: false })).toBeEnabled();
    await expect(page.getByLabel("Secret project", { exact: true })).toBeEnabled();
    await expect(page.getByLabel("Credential profile", { exact: true })).toBeEnabled();
    await expect(page.locator([
      'input[name^="agent_secret_"]',
      'input[name^="exposure"]',
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
    await expect(page.getByLabel("Name")).toHaveValue(name);
    await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue(unknownRepository);
    await page.evaluate(() => new Promise<void>((resolve) => {
      const onSwap = (event: Event) => {
        if (!(event.target instanceof Element) || event.target.id !== "environment-list") return;
        document.removeEventListener("htmx:afterSwap", onSwap);
        resolve();
      };
      document.addEventListener("htmx:afterSwap", onSwap);
    }));
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    const [environment] = await sql`
      SELECT COUNT(*)::int AS count FROM environments
      WHERE org_id = ${orgId} AND name = ${name}
    `;
    expect(environment.count).toBe(0);
    await page.getByRole("dialog", { name: "Create Sandbox" })
      .getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
    await expect(page.locator("[data-drawer]")).toBeHidden();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/`);
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
    await expect(page.getByLabel("Secret project", { exact: true })).toBeEnabled();
  });

  test("selects a platform secret project and preserves it after a form error", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop source-selection contract");
    // This browser proof exercises source metadata. Actual values are covered by
    // the native and Dev application-secret journey, without putting values in traces.
    await page.goto(`/${slug}/secrets/`);
    await page.getByText("New Project", { exact: true }).click();
    await page.getByLabel("Project name").fill(`source-${runId}`);
    await page.getByRole("button", { name: "Create Project" }).click();
    await expect(page.getByRole("status")).toContainText("Secret project created");
    const [project] = await sql`SELECT id FROM secret_projects WHERE org_id = ${orgId} AND name = ${`source-${runId}`}`;
    expect(project?.id).toBeTruthy();
    secretProjectId = project.id;
    await openConfiguredImageForm(page);
    await page.getByLabel("Secret project", { exact: true }).selectOption(secretProjectId);
    await page.getByLabel("TTL").fill("invalid-ttl");
    const response = page.waitForResponse((candidate) => candidate.url().endsWith(`/${slug}/_actions/sandboxes/create`) && candidate.request().method() === "POST");
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    expect((await response).status()).toBe(422);
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue(secretProjectId);
    await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
    await expect(page.locator('[name="confirm_personal_credentials"]')).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Add or manage personal secrets" })).toHaveAttribute("href", `/${slug}/secrets/user/`);
    await expect(page.getByRole("link", { name: "Manage organization secrets" })).toHaveAttribute("href", `/${slug}/secrets/organization/`);
    await expect(page.getByRole("link", { name: "Manage secret projects" })).toHaveAttribute("href", `/${slug}/secrets/`);
    await expect(page.locator(`a[href="/settings/credentials/?org=${slug}"]`).filter({ hasText: /credentials/ }).last()).toBeVisible();
  });

  test("creates, runs, exposes a port, stops, starts, and destroys through real Kind", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop lifecycle contract");
    test.setTimeout(900_000);
    const disallowedBrowserCalls = watchDisallowedBrowserCalls(page);
    await page.addInitScript(() => {
      const frames: TerminalClientFrame[] = [];
      (window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames = frames;
      const styleViolations: string[] = [];
      (window as Window & { __terminalStyleViolations?: string[] }).__terminalStyleViolations = styleViolations;
      document.addEventListener("securitypolicyviolation", (event) => {
        if (event.violatedDirective.startsWith("style-src")) styleViolations.push(event.violatedDirective);
      });
      const nativeSend = WebSocket.prototype.send;
      WebSocket.prototype.send = function(data: string | ArrayBufferLike | Blob | ArrayBufferView) {
        if (typeof data === "string" && this.protocol === "codewire.durable-terminal.v1") frames.push(JSON.parse(data));
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
    await page.getByLabel("Secret project", { exact: true }).selectOption(secretProjectId);
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
    expect(created.project_spec.secrets).toMatchObject({ project: `platform:id:${secretProjectId}` });
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
    // Runtime Running precedes setup completion; projection and workspace
    // replacement still belong to setup until this authenticated status arrives.
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled({ timeout: 300_000 });
    await expect(page.getByRole("tab")).toHaveCount(0);
    let launchRequests = 0;
    let stopRequests = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/launch")) launchRequests += 1;
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/stop")) stopRequests += 1;
    });
    await page.getByRole("button", { name: "New terminal", exact: true }).click();
    // The bounded private RPC may time out after creating the shell. Inspect
    // inventory once, as the UI advises, without repeating a non-idempotent New.
    await expect.poll(async () => (await page.getByRole("tab").count()) === 1
      || (await page.locator("[data-terminal-message]").innerText()).includes("change could not be confirmed"), { timeout: 90_000 }).toBe(true);
    const recoveredLaunch = await page.getByRole("tab").count() === 0;
    if (recoveredLaunch) {
      await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
      const existing = page.getByLabel("Existing terminal", { exact: true });
      const recovered = existing.locator('option:not([value=""])');
      await expect(recovered).toHaveCount(1);
      await expect(recovered).toContainText(/ · (starting|running)$/);
      await existing.selectOption((await recovered.getAttribute("value"))!);
      await page.getByRole("button", { name: "Open terminal", exact: true }).click();
    }
    await expect(page.getByRole("tab")).toHaveCount(1, { timeout: 15_000 });
    expect(launchRequests).toBe(1);
    expect(stopRequests).toBe(0);
    test.info().annotations.push({ type: "terminal-launch", description: recoveredLaunch ? "Recovered by one read-only refresh after unknown outcome" : "Directly acknowledged" });
    const terminalRoot = page.locator(".cw-terminal-page [data-terminal-tab-panel]:not([hidden]) [data-terminal-root]");
    await expect(terminalRoot.locator(".xterm")).toBeVisible({ timeout: 15_000 });
    const firstSessionId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(firstSessionId).toMatch(/^session-[0-9a-f-]{36}$/);
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled({ timeout: 15_000 });
    expect((await terminalRoot.boundingBox())!.height).toBeGreaterThan(180);
    expect((await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).boundingBox())!.height).toBeLessThan(60);
    await expect.poll(() => page.evaluate(() => (
      ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || [])
        .filter((frame) => frame.type === "resize" && frame.columns > 0 && frame.rows > 0).length
    ))).toBeGreaterThan(0);
    const initialResizeCount = await page.evaluate(() => (
      ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || [])
        .filter((frame) => frame.type === "resize" && frame.columns > 0 && frame.rows > 0).length
    ));
    expect(initialResizeCount).toBeGreaterThan(0);
    await page.setViewportSize({ width: 1180, height: 760 });
    await expect.poll(() => page.evaluate(() => (
      ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || [])
        .filter((frame) => frame.type === "resize" && frame.columns > 0 && frame.rows > 0).length
    ))).toBeGreaterThan(initialResizeCount);

    // The idle interval is the behavior under test, not a fixture delay: the
    // same attached browser socket must still carry the later command.
    await page.evaluate(() => new Promise((resolve) => window.setTimeout(resolve, 35_000)));
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__SSR_TERM_IDLE__%d__\\n' $RANDOM");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(/__SSR_TERM_IDLE__\d+__/);
    const sentInput = await page.evaluate(() => (
      ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || [])
        .some((frame) => frame.type === "input" && frame.data.length > 0)
    ));
    expect(sentInput).toBe(true);
    // Assert actual output under the production response CSP. The chrome-only
    // screenshots below deliberately mask output and cannot protect this.
    await page.keyboard.type("printf '\\033[31m__SSR_ANSI16__\\033[0m \\033[38;5;196m__SSR_ANSI256__\\033[0m \\033[38;2;12;160;240m__SSR_RGB__\\033[0m\\n__SSR_COPY_234__\\n'");
    await page.keyboard.press("Enter");
    const terminalRows = terminalRoot.locator(".xterm-rows");
    await expect(terminalRows.getByText("__SSR_ANSI16__", { exact: true })).toHaveCSS("color", "rgb(204, 0, 0)");
    await expect(terminalRows.getByText("__SSR_ANSI256__", { exact: true })).toHaveCSS("color", "rgb(255, 0, 0)");
    await expect(terminalRows.getByText("__SSR_RGB__", { exact: true })).toHaveCSS("color", "rgb(12, 160, 240)");
    await expect(terminalRows).toHaveCSS("font-family", /IBM Plex Mono/);
    expect(await page.evaluate(() => (window as Window & { __terminalStyleViolations?: string[] }).__terminalStyleViolations)).toEqual([]);
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: ssrUrl });
    const copyBounds = (await terminalRows.getByText("__SSR_COPY_234__", { exact: true }).boundingBox())!;
    await page.mouse.move(copyBounds.x, copyBounds.y + copyBounds.height / 2);
    await page.mouse.down();
    await page.mouse.move(copyBounds.x + copyBounds.width, copyBounds.y + copyBounds.height / 2, { steps: 12 });
    await page.mouse.up();
    await expect(terminalRoot.locator(".xterm-selection div").first()).toBeVisible();
    await page.getByRole("button", { name: "Copy selection", exact: true }).click();
    await expect(page.locator("[data-terminal-copy-status]")).toHaveText("Selection copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("__SSR_COPY_234__");
    const inputBeforeCopy = await page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").length);
    await terminalRoot.locator("textarea").focus();
    await page.keyboard.press("Control+Shift+C");
    expect(await page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").length)).toBe(inputBeforeCopy);
    // Clicking clears selection. Plain Ctrl+C must retain its PTY interrupt.
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.press("Control+C");
    await expect.poll(() => page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").at(-1))).toEqual({ type: "input", data: "\u0003" });

    await page.keyboard.type("cd /tmp; export CW_DURABLE_BROWSER=preserved-session; printf '__DURABLE_PID__%s__\\n' \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRows).toContainText(/__DURABLE_PID__\d+__/);
    const firstPid = /__DURABLE_PID__(\d+)__/.exec(await terminalRows.innerText())![1];
    await page.goto(`/${slug}/`);
    await openRowActions(row);
    await row.getByRole("link", { name: "Terminal", exact: true }).click();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(`__DURABLE_PID__${firstPid}__`);
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__DURABLE_RESUME__%s__%s__%s__\\n' \"$CW_DURABLE_BROWSER\" \"$PWD\" \"$$\"");
    await page.keyboard.press("Enter");
    const resumed = `__DURABLE_RESUME__preserved-session__/tmp__${firstPid}__`;
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);

    await page.getByRole("button", { name: "New terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    const secondSessionId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(secondSessionId).not.toBe(firstSessionId);
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__SECOND_TERMINAL__%s__%s__\\n' \"${CW_DURABLE_BROWSER-unset}\" \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(/__SECOND_TERMINAL__unset__\d+__/);
    expect(/__SECOND_TERMINAL__unset__(\d+)__/.exec(await terminalRoot.locator(".xterm-rows").innerText())![1]).not.toBe(firstPid);
    await page.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.getByRole("dialog", { name: "Close terminal?" }).getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
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

    const detailUrlBeforePorts = page.url();
    const terminalBeforePorts = await terminalRoot.elementHandle();
    const csrfBeforePorts = (await page.context().cookies()).find((cookie) => cookie.name === "codewire_ssr_csrf")?.value;
    await page.getByRole("button", { name: "Ports", exact: true }).click();
    const portPanel = page.getByRole("dialog", { name: `Ports · ${environmentName}`, exact: true });
    await expect(portPanel).toBeVisible();
    const configuredPort = portPanel.locator(".cw-port-row", {
      has: page.getByText("web", { exact: true }),
    });
    await expect(configuredPort).toHaveCount(1);
    await expect(configuredPort).toContainText("3000 · Creator");
    await portPanel.getByRole("spinbutton", { name: "Internal port", exact: true }).fill("8080");
    await portPanel.getByLabel("Preview label", { exact: true }).fill("manual-http");
    await portPanel.getByRole("button", { name: "Add port", exact: true }).click();
    await expect(portPanel.getByRole("status")).toContainText("Port created");
    const port = portPanel.locator(".cw-port-row", {
      has: page.getByText("manual-http", { exact: true }),
    });
    await expect(port).toContainText("8080");
    await port.getByRole("button", { name: "Remove manual-http preview", exact: true }).click();
    await expect(portPanel.getByRole("status")).toContainText("Port deleted");
    await expect(port).toHaveCount(0);
    await expect(configuredPort).toHaveCount(1);
    await expect(configuredPort).toContainText("3000 · Creator");

    await portPanel.getByRole("button", { name: "Close", exact: true }).click();
    await expect(portPanel).not.toBeVisible();
    expect(page.url()).toBe(detailUrlBeforePorts);
    expect(await terminalBeforePorts!.evaluate((element) => element === document.querySelector("[data-terminal-tab-panel]:not([hidden]) [data-terminal-root]"))).toBe(true);
    const csrfAfterPorts = (await page.context().cookies()).find((cookie) => cookie.name === "codewire_ssr_csrf")?.value;
    expect(Boolean(csrfBeforePorts) && csrfBeforePorts === csrfAfterPorts).toBe(true);
    await page.getByRole("button", { name: "Disconnect" }).click();
    await expect(terminalRoot).toHaveAttribute("data-terminal-settled", "true");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
    await page.getByRole("button", { name: "Reconnect", exact: true }).click();
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__DURABLE_RECONNECT__%s__%s__\\n' \"$CW_DURABLE_BROWSER\" \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(`__DURABLE_RECONNECT__preserved-session__${firstPid}__`);
    expect(launchRequests).toBe(2);
    expect(stopRequests).toBe(1);
    await page.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.getByRole("dialog", { name: "Close terminal?" }).getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(0);
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
    await page.goto(`/${slug}/${environmentId}/`);
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    const stopDialog = page.getByRole("dialog", { name: `Stop ${environmentName}?`, exact: true });
    await expect(stopDialog).toBeVisible();
    await expect(stopDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await stopDialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(stopDialog).not.toBeVisible();
    const [notStopped] = await sql`SELECT state FROM environments WHERE id = ${environmentId}`;
    expect(notStopped.state).toBe("running");
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    await stopDialog.getByRole("button", { name: "Stop Sandbox", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/${slug}/${environmentId}/\\?message=`));
    await waitForEnvironmentState(environmentId, ["stopped"], 120_000);
    await page.goto(`/${slug}/`);
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("stopped");

    await openRowActions(row);
    await row.getByText("Secrets and credentials", { exact: true }).click();
    await row.getByRole("link", { name: "Edit secrets and credentials", exact: true }).click();
    const sourceEditor = page.getByRole("dialog", { name: "Edit Sandbox sources", exact: true });
    await expect(sourceEditor).toBeVisible();
    await expect(sourceEditor.getByLabel("Secret project", { exact: true })).toHaveValue(secretProjectId);
    await expect(sourceEditor.locator('[name="expected_secret_project"]')).toHaveValue(secretProjectId);
    await expect(sourceEditor.locator('[name="confirm_personal_secrets"]')).toHaveCount(0);
    await expect(sourceEditor.locator('[name="confirm_personal_credentials"]')).toHaveCount(0);
    await expect(sourceEditor.getByRole("link", { name: "Add or manage personal secrets" })).toHaveAttribute("href", `/${slug}/secrets/user/`);
    await expect(sourceEditor.getByRole("link", { name: "Manage organization secrets" })).toHaveAttribute("href", `/${slug}/secrets/organization/`);
    await expect(sourceEditor.locator(`a[href="/settings/credentials/?org=${slug}"]`)).toBeVisible();
    await sourceEditor.getByLabel("Secret project", { exact: true }).selectOption("");
    await sourceEditor.getByRole("button", { name: "Save sources", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Sandbox sources saved. The Sandbox remains stopped.");
    const [cleared] = await sql`SELECT project_spec, state FROM environments WHERE id = ${environmentId}`;
    expect(cleared.project_spec).not.toHaveProperty("secrets");
    expect(cleared.state).toBe("stopped");

    await page.goto(`/${slug}/${environmentId}/`);
    await page.getByRole("button", { name: "Start", exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/${slug}/${environmentId}/\\?message=`));
    await waitForEnvironmentState(environmentId, ["running"], 300_000);
    await page.reload();
    await expect(page.locator(".cw-sandbox-heading .cw-status")).toContainText(/running/i);
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled({ timeout: 300_000 });
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
    const deleteDialog = page.getByRole("dialog", { name: `Delete ${environmentName}?`, exact: true });
    await expect(deleteDialog).toBeVisible();
    await expect(deleteDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await deleteDialog.getByRole("button", { name: "Delete Sandbox", exact: true }).click();
    await waitForEnvironmentState(environmentId, ["destroyed"], 120_000);
    await page.goto(`/${slug}/?state=destroyed`);
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("destroyed");
    expect(disallowedBrowserCalls).toEqual([]);
  });
});
