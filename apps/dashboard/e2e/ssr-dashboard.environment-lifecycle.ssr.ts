// covers: src/environment_source_forms.rs src/environment_sources.rs src/routes/environments.rs
// covers: src/routes/sandbox_resize.rs src/routes/setup_progress.rs
// covers: src/routes/terminal_readiness.rs src/routes/terminal_sessions.rs
// covers: templates/environment-create-form.html templates/environment-lifetime.html
// covers: templates/environment-list.html templates/environment-ports.html
// covers: templates/environment-resize-fields.html templates/environment-source-fields.html
// covers: templates/environment-sources-edit.html templates/organization-environments-content.html
// covers: templates/organization-environments.html templates/sandbox-rail.html
// covers: templates/terminal.html templates/terminal_resize.html
import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
import { waitForEnvironmentState } from "./helpers/environment";
import {
  environmentJourney,
  keepEnvironmentJourneyEvidence,
  openConfiguredImageForm,
  openRowActions,
  serverUrl,
  setUpEnvironmentJourney,
  ssrUrl,
  tearDownEnvironmentJourney,
  watchDisallowedBrowserCalls,
} from "./helpers/environment-journey";
import { terminalWebSocketUrl } from "./helpers/terminal-websocket";

// The real Sandbox lifecycle through Kind: create, terminal, ports, resize,
// Stop, Start and Delete. It is the longest browser journey, so it has its
// own file and organization and runs on its own worker beside the serial
// Create checks in ssr-dashboard.environments.ssr.ts (#2974).

// As in the Create checks, worker capture is file-scoped and off: the journey
// selects secret sources and types into a live terminal.
test.use({ screenshot: "off", trace: "off", video: "off" });

const journey = environmentJourney({
  slugPrefix: "ssr-lifecycle",
  templatePrefix: "ssr-lifecycle",
  orgName: "SSR Lifecycle Workspace",
});
const { sql, runId, slug } = journey;
const environmentName = "ssr-terminal-workspace";
let environmentId = "";
let secretProjectId = "";
type TerminalClientFrame = { type: "input"; data: string }
  | { type: "resize"; columns: number; rows: number }
  | { type: "ack"; offset: string };

// The Sandbox workspace keeps terminal actions (Rename, Copy selection, the
// existing-session picker, Refresh sessions) and Sandbox actions (Resize,
// Refresh sandbox status, Delete) in two menus.
// Chromium can evict a response body before the test reads it (#2346), so
// these JSON responses are read in a route as they pass through.
async function jsonResponses(page: Page, suffix: string) {
  const seen: { status: number; body: Record<string, unknown> }[] = [];
  let read = 0;
  await page.route((url) => url.pathname.endsWith(suffix), async (route) => {
    const response = await route.fetch();
    const body = await response.text();
    seen.push({ status: response.status(), body: JSON.parse(body) });
    await route.fulfill({ response, body });
  });
  return async () => {
    await expect.poll(() => seen.length).toBeGreaterThan(read);
    return seen[read++];
  };
}

async function workspaceMenu(page: Page, menu: "Terminal actions" | "More actions") {
  const details = page.locator(menu === "Terminal actions" ? "[data-terminal-menu]" : "[data-sandbox-menu]");
  if (!(await details.evaluate((node) => (node as HTMLDetailsElement).open))) await details.locator(":scope > summary").click();
  await expect(details).toHaveJSProperty("open", true);
  return details;
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
      WHERE organization_id = ${journey.orgId}
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
    orgId: journey.orgId,
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

async function sourceDeletionDeadline(): Promise<string> {
  // shutdown_at is a naive UTC source timestamp, with PostgreSQL microsecond
  // precision. Compare the exact BFF nanosecond representation, not a rounded
  // JavaScript Date or a guessed deadline computed from the requested TTL.
  const [source] = await sql`
    SELECT protected,
           to_char(shutdown_at, 'YYYY-MM-DD"T"HH24:MI:SS.US') || '000Z' AS deadline
    FROM environments WHERE id = ${environmentId} AND org_id = ${journey.orgId}
  `;
  expect(source?.protected).toBe(false);
  expect(source?.deadline).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/);
  return source.deadline as string;
}

test.describe.serial("server-rendered environment lifecycle", () => {
  test.beforeAll(async ({}, testInfo) => {
    await setUpEnvironmentJourney(journey, testInfo);
    // Source metadata only: the Create checks prove the secret project UI;
    // this journey needs one selected project to carry through Stop and Start.
    secretProjectId = crypto.randomUUID();
    await sql`
      INSERT INTO secret_projects (id, org_id, name)
      VALUES (${secretProjectId}, ${journey.orgId}, ${`source-${runId}`})
    `;
  });

  test.afterEach(async ({}, testInfo) => {
    await keepEnvironmentJourneyEvidence(journey, testInfo);
  });

  test.afterAll(async () => {
    await tearDownEnvironmentJourney(journey);
  });

  test("creates, runs, exposes a port, stops, starts, and destroys through real Kind", { tag: "@kind-heavy" }, async ({ page, isMobile, workerStorageState }) => {
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

    await openConfiguredImageForm(page, journey);
    // The platform default size (#3554); the journey then picks a smaller
    // CPU and memory so it fits a Kind worker, and keeps the default disk.
    await expect(page.locator("#environment-create-card").getByLabel("CPU", { exact: true })).toHaveValue("2000");
    await expect(page.locator("#environment-create-card").getByLabel("Memory", { exact: true })).toHaveValue("8192");
    await expect(page.locator("#environment-create-card").getByLabel("Disk", { exact: true })).toHaveValue("80");
    await page.locator("#environment-create-card").getByLabel("CPU", { exact: true }).selectOption("1000");
    await page.locator("#environment-create-card").getByLabel("Memory", { exact: true }).selectOption("2048");
    await page.getByLabel("Name").fill(environmentName);
    await page.getByLabel("Secret project", { exact: true }).selectOption(secretProjectId);
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    await expect(page).toHaveURL(
      new RegExp(`^${ssrUrl}/${slug}/[0-9a-f-]{36}/\\?message=environment-created$`),
    );
    // The creation notice stands until the Sandbox runs, well after this
    // Kind Sandbox lands here.
    await expect(page.getByRole("status").filter({ hasText: "Sandbox creation started" })).toBeVisible();
    await expect(page.getByRole("region", { name: "Setup", exact: true })).toBeVisible();
    // The rest of this journey starts from the Sandboxes list.
    await page.goto(`${ssrUrl}/${slug}/`);
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
      FROM environments WHERE org_id = ${journey.orgId} AND name = ${environmentName}
    `;
    expect(created?.id).toBeTruthy();
    environmentId = created.id as string;
    expect(created.cpu_millicores).toBe(1000);
    expect(created.memory_mb).toBe(2048);
    expect(created.disk_gb).toBe(80);
    expect(created.ttl_seconds).toBe(3600);
    expect(created.project_spec).toMatchObject({
      schema_version: 1,
      working_directory: "/workspace",
      install_command: "printf 'configured-explicitly\\n'",
      startup_script: "printf 'started-explicitly\\n'",
      agents: { tools: ["codex"] },
      application_ports: [{ port: 3000, label: "web", access: "creator" }],
      resources: { cpu_millicores: 1000, memory_mib: 2048, disk_gib: 80 },
    });
    expect(created.project_spec.secrets).toMatchObject({ project: `platform:id:${secretProjectId}` });
    await waitForEnvironmentState(environmentId, ["running"], 300_000);
    await page.reload();
    let row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("running");
    await expect(row.getByText("1 vCPU · 2 GiB · 80 GiB", { exact: true })).toBeVisible();
    await openRowActions(row);
    await expect(row.locator(".cw-row-menu-meta")).toContainText("usage");

    let launchRequests = 0;
    let stopRequests = 0;
    let sandboxStopRequests = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/launch")) launchRequests += 1;
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/stop")) stopRequests += 1;
      if (new URL(request.url()).pathname.endsWith("/_actions/sandboxes/stop")) sandboxStopRequests += 1;
    });
    const terminalLink = row.getByRole("link", { name: "Terminal", exact: true });
    await terminalLink.click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/${environmentId}/`);
    // Runtime Running precedes setup completion; projection and workspace
    // replacement still belong to setup until this authenticated status
    // arrives. Then the page opens its one terminal by itself. The bounded
    // private RPC may time out after creating the shell: Retry re-lists once
    // and re-attaches it, without repeating a non-idempotent launch.
    await expect.poll(async () => (await page.getByRole("tab").count()) === 1
      || (await page.locator("[data-terminal-empty]").innerText()).includes("could not be confirmed"), { timeout: 300_000 }).toBe(true);
    const recoveredLaunch = await page.getByRole("tab").count() === 0;
    if (recoveredLaunch) await page.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(1, { timeout: 15_000 });
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
    const initialDeadline = await sourceDeletionDeadline();
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", initialDeadline, { timeout: 30_000 });
    expect(launchRequests).toBe(1);
    expect(stopRequests).toBe(0);
    test.info().annotations.push({ type: "terminal-launch", description: recoveredLaunch ? "Recovered by one Retry re-list after unknown outcome" : "Directly acknowledged" });
    const terminalRoot = page.locator(".cw-terminal-page [data-terminal-tab-panel]:not([hidden]) [data-terminal-root]");
    await expect(terminalRoot.locator(".xterm")).toBeVisible({ timeout: 15_000 });
    const firstSessionId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(firstSessionId).toMatch(/^session-[0-9a-f-]{36}$/);
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled({ timeout: 15_000 });
    expect((await terminalRoot.boundingBox())!.height).toBeGreaterThan(180);
    expect((await page.locator(".cw-workspace-statusbar").boundingBox())!.height).toBeLessThan(60);
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
    await (await workspaceMenu(page, "Terminal actions")).getByRole("button", { name: "Copy selection", exact: true }).click();
    await expect(page.locator("[data-terminal-session-status]:not([hidden]) [data-terminal-copy-status]")).toHaveText("Selection copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("__SSR_COPY_234__");
    const inputBeforeCopy = await page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").length);
    await terminalRoot.locator("textarea").focus();
    await page.keyboard.press("Control+Shift+C");
    expect(await page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").length)).toBe(inputBeforeCopy);
    // Clicking clears selection. Plain Ctrl+C must retain its PTY interrupt.
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.press("Control+C");
    await expect.poll(() => page.evaluate(() => ((window as Window & { __terminalFrames?: TerminalClientFrame[] }).__terminalFrames || []).filter((frame) => frame.type === "input").at(-1))).toEqual({ type: "input", data: "\u0003" });
    // The line discipline discards input queued behind an interrupt, and the
    // shell re-prepares its terminal after SIGINT. Type only once it has drawn
    // a fresh prompt after the ^C, as a person would.
    await expect(terminalRows).toContainText(/\^C[\s\S]*\$\s*$/);

    // Use a deterministic single-row prompt for the durability checks that
    // follow viewport changes.
    await page.keyboard.type("cd /tmp; PS1='$ '; export CW_DURABLE_BROWSER=preserved-session; printf '__DURABLE_PID__%s__\\n' \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRows).toContainText(/__DURABLE_PID__\d+__/);
    const firstPid = /__DURABLE_PID__(\d+)__/.exec(await terminalRows.innerText())![1];
    await (await workspaceMenu(page, "Terminal actions")).getByRole("button", { name: "Rename terminal", exact: true }).click();
    const rename = page.getByRole("dialog", { name: "Rename terminal", exact: true });
    await rename.getByLabel("Terminal name", { exact: true }).fill("Build shell");
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await expect(page.getByRole("tab", { name: "Build shell", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    const filteredListPath = `/${slug}/?${new URLSearchParams({ search: environmentName, state: "running" })}`;
    const filteredDetailPath = `/${slug}/${environmentId}/?${new URLSearchParams({ list_search: environmentName, list_state: "running" })}`;
    await page.goto(filteredListPath);
    await openRowActions(row);
    await row.getByRole("link", { name: "Terminal", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredDetailPath}`);
    await page.getByRole("link", { name: "Back to Sandboxes", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredListPath}`);
    await expect(page.getByLabel("Search Sandboxes", { exact: true })).toHaveValue(environmentName);
    await openRowActions(row);
    const inventoryStopsBeforeCancel = sandboxStopRequests;
    await row.getByRole("button", { name: "Stop", exact: true }).click();
    const inventoryStop = page.getByRole("dialog", { name: `Stop ${environmentName}?`, exact: true });
    await expect(inventoryStop.locator('input[name="environment_id"]')).toHaveValue(environmentId);
    await expect(inventoryStop.locator('input[name="list_search"]')).toHaveValue(environmentName);
    await inventoryStop.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(sandboxStopRequests).toBe(inventoryStopsBeforeCancel);
    await row.getByRole("link", { name: environmentName, exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredDetailPath}`);
    // Continue the existing no-context compatibility and terminal journey too.
    await page.goto(`/${slug}/${environmentId}/`);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(`__DURABLE_PID__${firstPid}__`);
    await expect(page.getByRole("tab", { name: "Build shell", exact: true })).toHaveAttribute("aria-selected", "true");
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
    await (await workspaceMenu(page, "Terminal actions")).getByRole("button", { name: "Rename terminal", exact: true }).click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("Log shell");
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await page.getByRole("tab", { name: "Build shell", exact: true }).click();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
    await page.getByRole("tab", { name: "Build shell", exact: true }).press("ArrowRight");
    await expect(page.getByRole("tab", { name: "Log shell", exact: true })).toBeFocused();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", secondSessionId!);
    await page.getByRole("button", { name: "Close Log shell", exact: true }).click();
    await page.getByRole("dialog", { name: "Close terminal?" }).getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
    await expect(page.getByRole("tab", { name: "Build shell", exact: true })).toHaveAttribute("aria-selected", "true");
    // Restore the ordinary label before the existing chrome goldens. Rename
    // behavior is asserted above; snapshot names stay deterministic.
    await (await workspaceMenu(page, "Terminal actions")).getByRole("button", { name: "Rename terminal", exact: true }).click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("Terminal 1");
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(page.getByRole("heading", { name: environmentName, exact: true })).toBeVisible();
    await expect(page.locator(".cw-terminal-page .xterm")).toBeVisible({ timeout: 15_000 });
    await page.setViewportSize({ width: 390, height: 844 });
    expect((await terminalRoot.boundingBox())!.height).toBeGreaterThanOrEqual(180);
    expect((await page.locator(".cw-workspace-statusbar").boundingBox())!.height).toBeLessThan(100);
    await expect(page.locator("[data-sandbox-lifetime] time")).toBeVisible();
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", await sourceDeletionDeadline());
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveText(/^\d{2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC$/);
    await page.setViewportSize({ width: 1440, height: 900 });
    // The prompt wraps at phone width, so bash's SIGWINCH redraw back to the
    // wide size moves the cursor up a row and clears it. When bash's
    // narrow-width redraw reaches xterm only after it has reflowed back (time
    // at 390 px shorter than a PTY round trip), that row is the line above
    // the prompt. Output printed before this round trip therefore cannot
    // witness Disconnect. Resize and input frames reach the PTY in order, so
    // output printed now follows every redraw.
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__DURABLE_DISCONNECT__%s__%s__%s__\\n' \"$CW_DURABLE_BROWSER\" \"$PWD\" \"$$\"");
    await page.keyboard.press("Enter");
    const beforeDisconnect = `__DURABLE_DISCONNECT__preserved-session__/tmp__${firstPid}__`;
    await expect(terminalRows).toContainText(beforeDisconnect);

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
    await expect(configuredPort).toContainText("3000 · Sandbox creator");
    await portPanel.getByRole("spinbutton", { name: "Internal port", exact: true }).fill("8080");
    await portPanel.getByLabel("Preview label", { exact: true }).fill("manual-http");
    await portPanel.getByRole("button", { name: "Add port", exact: true }).click();
    await expect(portPanel.getByRole("status").filter({ hasText: "Port created" })).toBeVisible();
    const port = portPanel.locator(".cw-port-row", {
      has: page.getByText("manual-http", { exact: true }),
    });
    await expect(port).toContainText("8080");
    const previewUrl = await port.getByRole("link", { name: "Open preview", exact: true }).getAttribute("href");
    expect(previewUrl).toBeTruthy();
    const parsedPreview = new URL(previewUrl!);
    expect(parsedPreview.protocol).toBe("https:");
    expect(parsedPreview.hostname).toContain(`manual-http-${environmentId.slice(0, 5)}-${slug}.`);
    await port.getByRole("button", { name: "Copy URL", exact: true }).click();
    await expect(port.locator("[data-preview-copy-status]")).toHaveText("Preview URL copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(previewUrl);
    await port.getByRole("button", { name: "Remove manual-http preview", exact: true }).click();
    await expect(portPanel.getByRole("status").filter({ hasText: "Port deleted" })).toBeVisible();
    await expect(port).toHaveCount(0);
    await expect(configuredPort).toHaveCount(1);
    await expect(configuredPort).toContainText("3000 · Sandbox creator");

    await portPanel.getByRole("button", { name: "Done", exact: true }).click();
    await expect(portPanel).not.toBeVisible();
    expect(page.url()).toBe(detailUrlBeforePorts);
    expect(await terminalBeforePorts!.evaluate((element) => element === document.querySelector("[data-terminal-tab-panel]:not([hidden]) [data-terminal-root]"))).toBe(true);
    const csrfAfterPorts = (await page.context().cookies()).find((cookie) => cookie.name === "codewire_ssr_csrf")?.value;
    expect(Boolean(csrfBeforePorts) && csrfBeforePorts === csrfAfterPorts).toBe(true);
    // Disconnect detaches the transport only: the settled terminal keeps this
    // shell's rendered output exactly as it was.
    const renderedBeforeDisconnect = await terminalRows.textContent();
    expect(renderedBeforeDisconnect).toContain(beforeDisconnect);
    await page.getByRole("button", { name: "Disconnect" }).click();
    await expect(terminalRoot).toHaveAttribute("data-terminal-settled", "true");
    await expect(terminalRows).toContainText(beforeDisconnect);
    await expect(terminalRows).toHaveText(renderedBeforeDisconnect!);
    await page.getByRole("button", { name: "Reconnect", exact: true }).click();
    await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__DURABLE_RECONNECT__%s__%s__\\n' \"$CW_DURABLE_BROWSER\" \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(`__DURABLE_RECONNECT__preserved-session__${firstPid}__`);
    expect(launchRequests).toBe(2);
    expect(stopRequests).toBe(1);
    // A no-op resource review must use the in-place private route and leave
    // the current terminal root, session and shell alive.
    const originalTerminalRoot = (await terminalRoot.elementHandle())!;
    const nextPlan = await jsonResponses(page, "/_actions/resize/plan");
    const nextApply = await jsonResponses(page, "/_actions/resize/apply");
    await (await workspaceMenu(page, "More actions")).getByRole("button", { name: "Resize", exact: true }).click();
    const resizeDialog = page.getByRole("dialog", { name: `Resize ${environmentName}`, exact: true });
    await resizeDialog.getByRole("button", { name: "Review resize", exact: true }).click();
    const reviewed = await nextPlan();
    expect(reviewed.status).toBe(200);
    const noopPlan = reviewed.body;
    expect(noopPlan.mode).toBe("noop");
    expect(noopPlan.environmentId).toBe(environmentId);
    expect(noopPlan.requestId).toMatch(/^[0-9a-f]{32}$/);
    await expect(resizeDialog.locator("[data-resize-restart-consent]")).not.toBeVisible();
    await expect(resizeDialog.locator("[data-resize-session-consent]")).not.toBeVisible();
    await resizeDialog.getByRole("button", { name: "Apply resize", exact: true }).click();
    const applied = await nextApply();
    expect(applied.status).toBe(200);
    const noopOperation = applied.body;
    expect(noopOperation.requestId).toBe(noopPlan.requestId);
    expect(noopOperation.desiredResources).toEqual(noopPlan.desiredResources);
    await expect(resizeDialog.locator("[data-resize-status]")).toContainText("Resize completed", { timeout: 120_000 });
    await resizeDialog.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/${environmentId}/`);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    expect(await originalTerminalRoot.evaluate((root) => root.isConnected)).toBe(true);
    expect(await terminalRoot.evaluate((root, original) => root === original, originalTerminalRoot)).toBe(true);
    await originalTerminalRoot.dispose();
    await terminalRoot.locator(".xterm").click();
    await page.keyboard.type("printf '__RESIZE_NOOP__%s__\\n' \"$$\"");
    await page.keyboard.press("Enter");
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(`__RESIZE_NOOP__${firstPid}__`);
    expect(launchRequests).toBe(2);
    expect(stopRequests).toBe(1);
    await page.getByRole("button", { name: "Close Terminal 1", exact: true }).click();
    await page.getByRole("dialog", { name: "Close terminal?" }).getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();

    const noJavaScriptContext = await page.context().browser()!.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: workerStorageState,
    });
    const noJavaScriptPage = await noJavaScriptContext.newPage();
    const noJavaScriptRequests: string[] = [];
    noJavaScriptPage.on("request", (request) => noJavaScriptRequests.push(request.url()));
    await noJavaScriptPage.goto(`/${slug}/${environmentId}/`);
    await expect(noJavaScriptPage.getByRole("heading", { name: "Use the CLI terminal" })).toBeVisible();
    expect(await noJavaScriptPage.locator("code").textContent()).toBe(`cw shell ${environmentId}`);
    const managePorts = noJavaScriptPage.getByRole("link", { name: "Manage Ports", exact: true });
    await expect(managePorts).toHaveAttribute("href", `/${slug}/?ports=${environmentId}`);
    await managePorts.click();
    await expect(noJavaScriptPage).toHaveURL(`${ssrUrl}/${slug}/?ports=${environmentId}`);
    await expect(noJavaScriptPage.getByRole("heading", { name: `Ports · ${environmentName}`, exact: true })).toBeVisible();
    await expect(noJavaScriptPage.getByRole("spinbutton", { name: "Internal port", exact: true })).toBeVisible();
    expect(noJavaScriptRequests.every((url) => new URL(url).origin === ssrUrl)).toBe(true);
    await noJavaScriptContext.close();

    await page.goto(`/${slug}/`);
    const ticket = await issueTerminalTicket(page);
    await closeTicketBeforeAttachment(page, ticket);
    await expectTerminalLeaseDrained();
    expect(disallowedBrowserCalls).toEqual([]);
    // Every terminal was closed, so a new visit opens one by itself. That one
    // live terminal stays open across Stop and Start (#2136).
    const launchesBeforeStop = launchRequests;
    await page.goto(filteredDetailPath);
    await expect(page.getByRole("tab")).toHaveCount(1, { timeout: 60_000 });
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
    await expect(page.locator("[data-terminal-connection]")).toHaveText("Connected", { timeout: 60_000 });
    expect(launchRequests).toBe(launchesBeforeStop + 1);
    const lifecycleSessionId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(lifecycleSessionId).toBeTruthy();
    const sandboxStopsBeforeCancel = sandboxStopRequests;
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    const stopDialog = page.getByRole("dialog", { name: `Stop ${environmentName}?`, exact: true });
    await expect(stopDialog).toBeVisible();
    await expect(stopDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await stopDialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(stopDialog).not.toBeVisible();
    expect(sandboxStopRequests).toBe(sandboxStopsBeforeCancel);
    const [notStopped] = await sql`SELECT state FROM environments WHERE id = ${environmentId}`;
    expect(notStopped.state).toBe("running");
    const stopDeadline = await sourceDeletionDeadline();
    await page.getByRole("button", { name: "Stop", exact: true }).click();
    await stopDialog.getByRole("button", { name: "Stop Sandbox", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredDetailPath}&message=environment-stopping`);
    await waitForEnvironmentState(environmentId, ["stopped"], 120_000);
    await expect(page.locator("[data-sandbox-state]")).toContainText("stopped", { timeout: 30_000 });
    expect(await sourceDeletionDeadline()).toBe(stopDeadline);
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", stopDeadline);
    await expect(page.getByRole("button", { name: "Start", exact: true })).toBeEnabled();
    // Stop reloads the page; a stopped Sandbox restores no tabs and says why.
    await expect(page.locator("[data-terminal-empty]")).toHaveText("Start this Sandbox to use its terminals.", { timeout: 30_000 });
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
    // A lifecycle action submitted for the wrong state is rejected by the
    // service and shown on the detail page; the state does not change (#2138).
    await page.locator('form[action$="/_actions/sandboxes/stop"]').evaluate((form: HTMLFormElement) => form.submit());
    await expect(page).toHaveURL(/[?&]error=invalid(?:&|$)/);
    await expect(page.getByRole("alert")).toContainText("The Sandbox request was invalid for its current state.");
    const [stillStopped] = await sql`SELECT state FROM environments WHERE id = ${environmentId}`;
    expect(stillStopped.state).toBe("stopped");
    await page.goto(filteredDetailPath);
    // Stopped compute changes are saved for Start, not a disguised restart.
    await (await workspaceMenu(page, "More actions")).getByRole("button", { name: "Resize", exact: true }).click();
    await resizeDialog.getByLabel("CPU", { exact: true }).selectOption("2000");
    await resizeDialog.getByLabel("Memory", { exact: true }).selectOption("4096");
    await resizeDialog.getByRole("button", { name: "Review resize", exact: true }).click();
    const stoppedPlanResponse = await nextPlan();
    expect(stoppedPlanResponse.status).toBe(200);
    const stoppedPlan = stoppedPlanResponse.body;
    expect(stoppedPlan.mode).toBe("apply-on-start");
    expect(stoppedPlan.restartRequired).toBe(false);
    expect(stoppedPlan.sessionsWillTerminate).toBe(false);
    await resizeDialog.getByRole("button", { name: "Apply resize", exact: true }).click();
    const stoppedResponse = await nextApply();
    expect(stoppedResponse.status).toBe(200);
    expect(stoppedResponse.body.requestId).toBe(stoppedPlan.requestId);
    await expect(resizeDialog.locator("[data-resize-status]")).toContainText("Resize completed", { timeout: 120_000 });
    await resizeDialog.getByRole("button", { name: "Done", exact: true }).click();
    const [deferred] = await sql`SELECT state, cpu_millicores, memory_mb FROM environments WHERE id = ${environmentId}`;
    expect(deferred).toMatchObject({ state: "stopped", cpu_millicores: 2000, memory_mb: 4096 });
    await expect(page.locator("[data-sandbox-resources]")).toHaveCount(2);
    await expect(page.locator("[data-sandbox-resources]")).toHaveText(["2 vCPU · 4 GiB · 80 GiB", "2 vCPU · 4 GiB · 80 GiB"], { timeout: 30_000 });
    await page.goto(`/${slug}/`);
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("stopped");
    await expect(row.locator(".cw-sandbox-lifetime time")).toHaveAttribute("datetime", await sourceDeletionDeadline());

    await openRowActions(row);
    await row.getByText("Secrets and credentials", { exact: true }).click();
    await row.getByRole("link", { name: "Edit secrets and credentials", exact: true }).click();
    const sourceEditor = page.getByRole("dialog", { name: "Edit Sandbox sources", exact: true });
    await expect(sourceEditor).toBeVisible();
    await expect(sourceEditor.getByLabel("Secret project", { exact: true })).toHaveValue(secretProjectId);
    await expect(sourceEditor.locator('[name="expected_secret_project"]')).toHaveValue(secretProjectId);
    await expect(sourceEditor.locator('[name="confirm_personal_secrets"]')).toHaveCount(0);
    await expect(sourceEditor.locator('[name="confirm_personal_credentials"]')).toHaveCount(0);
    await expect(sourceEditor.getByRole("link", { name: "Manage personal secrets" })).toHaveAttribute("href", "/settings/secrets/");
    await expect(sourceEditor.getByRole("link", { name: "Manage organization secrets" })).toHaveAttribute("href", `/${slug}/secrets/organization/`);
    await expect(sourceEditor.locator(`a[href="/settings/credentials/"]`)).toBeVisible();
    await sourceEditor.getByLabel("Secret project", { exact: true }).selectOption("");
    await sourceEditor.getByRole("button", { name: "Save sources", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Sandbox sources saved. The Sandbox remains stopped.");
    const [cleared] = await sql`SELECT project_spec, state FROM environments WHERE id = ${environmentId}`;
    expect(cleared.project_spec).not.toHaveProperty("secrets");
    expect(cleared.state).toBe("stopped");

    await page.goto(filteredDetailPath);
    const beforeStartDeadline = await sourceDeletionDeadline();
    await page.getByRole("button", { name: "Start", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredDetailPath}&message=environment-started`);
    await waitForEnvironmentState(environmentId, ["running"], 300_000);
    await expect(page.locator("[data-sandbox-state]")).toContainText(/running/i, { timeout: 30_000 });
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled({ timeout: 300_000 });
    // Running is observed before the subsequent deadline write. Wait for that
    // source-owned write rather than assuming lifecycle completion implies it.
    await expect.poll(sourceDeletionDeadline, { timeout: 30_000 }).not.toBe(beforeStartDeadline);
    const restartedDeadline = await sourceDeletionDeadline();
    expect(restartedDeadline).not.toBe(beforeStartDeadline);
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", restartedDeadline, { timeout: 30_000 });
    // The same terminal is shown as ended after Start; nothing was launched in its place.
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", lifecycleSessionId!);
    await expect(page.locator("[data-terminal-connection]")).toHaveText(/interrupted|stopped|exited|failed|no longer available/i, { timeout: 60_000 });
    expect(launchRequests).toBe(launchesBeforeStop + 1);
    await page.locator('[data-terminal-tab-item]:has([aria-selected="true"]) [data-terminal-remove-tab]').click();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();
    await (await workspaceMenu(page, "More actions")).getByRole("button", { name: "Delete", exact: true }).click();
    const deleteDialog = page.getByRole("dialog", { name: `Delete ${environmentName}?`, exact: true });
    await expect(deleteDialog).toBeVisible();
    await expect(deleteDialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await deleteDialog.getByRole("button", { name: "Delete Sandbox", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${filteredListPath}&message=environment-destroying&environment=${environmentId}`);
    await waitForEnvironmentState(environmentId, ["destroyed"], 120_000);
    const [destroyed] = await sql`SELECT external_cleanup_completed_at FROM environments WHERE id = ${environmentId}`;
    expect(destroyed.external_cleanup_completed_at).not.toBeNull();
    await page.goto(`/${slug}/?state=destroyed`);
    row = page.locator("tr", { hasText: environmentName }).first();
    await expect(row.locator(".cw-status")).toContainText("deleted");
    expect(disallowedBrowserCalls).toEqual([]);
  });
});
