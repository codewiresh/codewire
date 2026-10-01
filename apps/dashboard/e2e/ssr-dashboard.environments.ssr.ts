import { expect, test } from "./helpers/test";
import type { Locator, Page } from "@playwright/test";
import postgres from "postgres";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { cleanupEnvironments, waitForEnvironmentState } from "./helpers/environment";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { defaultWorkspaceImage } from "./helpers/runtime-images";
import { terminalWebSocketUrl } from "./helpers/terminal-websocket";

// The serial Create setup journey enters write-only personal secret values.
// Worker capture settings must be file-scoped. Explicit layout goldens below
// remain enabled and are taken before those inputs are entered.
test.use({ screenshot: "off", trace: "off", video: "off" });

const sql = postgres(process.env.DATABASE_URL!);
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
// Current published immutable Codewire workspace image in Harbor.
// This browser proof must never turn a floating registry tag into a test input.
const workspaceImage = defaultWorkspaceImage;
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

async function assertExplicitCreateRecovery(page: Page) {
  const dispatches: string[] = [];
  const personalKey = `CREATE_RETURN_${crypto.randomUUID().replaceAll("-", "_")}`;
  let primaryFailure: unknown;
  const watchDispatch = (request: import("@playwright/test").Request) => {
    if (/PrepareEnvironment|\/_actions\/sandboxes\/(?:create|prepare)/.test(request.url())) dispatches.push(request.url());
  };
  page.on("request", watchDispatch);
  try {
    const form = page.locator("[data-environment-form]");
    await expect(form).toHaveAttribute("data-create-draft-actor", ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
    await page.locator("#environment-create-card").getByLabel("CPU", { exact: true }).selectOption("2000");
    await page.getByLabel("Delete after").fill("8h");
    await page.getByLabel("Name", { exact: true }).fill("draft-name-restored");
    await page.getByLabel("Repository URL", { exact: true }).fill("https://draft-canary.invalid/private-repository");
    await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
    const requestedDraft = await form.getAttribute("data-create-draft-id");
    expect(requestedDraft).toMatch(/^[0-9a-f-]{36}$/);
    // Reopening Create brings this tab's newest draft back by itself.
    await page.goto(`/${slug}/new/`);
    await expect(form).toHaveAttribute("data-create-draft-restored", "true");
    await expect(form).toHaveAttribute("data-create-draft-id", requestedDraft!);
    await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
    // A second real Create draft is newer. A return to an unavailable draft
    // opens a fresh form without substituting one, and editing it saves that
    // newer draft. Returning must not offer it in place of the original, or
    // interpret discarded inventory selectors.
    await page.goto(`/${slug}/new/?creation_draft=unavailable`);
    await expect(form).toHaveAttribute("data-create-draft-exact", "true");
    await expect(form).not.toHaveAttribute("data-create-draft-id", requestedDraft!);
    await expect(page.locator("[data-create-draft-status]")).toContainText("The requested draft is unavailable in this tab.");
    await page.locator("#environment-create-card").getByLabel("CPU", { exact: true }).selectOption("4000");
    await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
    for (const suffix of [
      "creation_draft=unavailable",
      `creation_draft=${requestedDraft}&%63reation_draft=${requestedDraft}`,
      `ignored=${"x".repeat(1024)}&%63reation_draft=${requestedDraft}`,
    ]) {
      await page.goto(`/${slug}/new/?${suffix}`);
      await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=unavailable`);
      await expect(form).toHaveAttribute("data-create-draft-exact", "true");
      await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeHidden();
      await expect(page.locator("[data-create-draft-status]")).toContainText("The requested draft is unavailable in this tab.");
      await expect(page.locator('[name="cpu"]')).toHaveValue("1000");
    }
    await page.goto(`/${slug}/new/?destroyed=bogus&sources=first&sources=second&creation_draft=${requestedDraft}`);
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    // The page is served as an exact return of this draft. The automatic
    // restore then swaps in the server's restored card, which carries the
    // draft but not the page's return marker, so read that from the drawer.
    await expect(page.locator("[data-drawer]")).toHaveAttribute("data-create-url", `/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(form).toHaveAttribute("data-create-draft-id", requestedDraft!);
    await expect(form).toHaveAttribute("data-create-draft-actor", ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
    // The exact older draft comes back by itself, never the newer one.
    await expect(form).toHaveAttribute("data-create-draft-restored", "true");
    await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("draft-name-restored");
    // The unchanged drawer controller must keep the explicit query open
    // through ordinary inventory polling, Back, and a reopened view.
    await page.waitForResponse((response) => response.url().includes(`/${slug}/_fragments/sandboxes`) && response.ok());
    await expect(page.locator("[data-drawer]")).toBeVisible();
    await page.goto(`/${slug}/`);
    await page.goBack();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(page.locator("[data-drawer]")).toBeVisible();
    // Restored authored fields stay until Create or an explicit Discard:
    // closing asks first, and Keep editing keeps the drawer and its query.
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("draft-name-restored");
    await page.locator("[data-drawer-panel]").getByRole("link", { name: "Close Create Sandbox" }).click();
    const discardRestored = page.getByRole("dialog", { name: "Discard changes?", exact: true });
    await expect(discardRestored.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
    await discardRestored.getByRole("button", { name: "Keep editing", exact: true }).click();
    await expect(discardRestored).toBeHidden();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(page.locator("[data-drawer]")).toBeVisible();
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("draft-name-restored");
    await page.goto(`/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(page.locator("[data-drawer]")).toBeVisible();
    await page.reload();
    // The exact draft comes back by itself on every return and reload.
    await expect(form).toHaveAttribute("data-create-draft-restored", "true");
    // Exercise the actual native Settings detour, not a direct fabricated
    // return URL: validation, mutation, and explicit Return retain this exact
    // older draft while the new source remains available but unattached.
    // Leaving restored authored fields asks first; saving keeps the handle.
    await page.getByRole("link", { name: "Manage secret projects", exact: true }).click();
    await page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true })
      .getByRole("button", { name: "Save draft and leave", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/secrets/?creation_draft=${requestedDraft}`);
    const returnLink = page.getByRole("link", { name: "Return to Sandbox creation", exact: true });
    await expect(returnLink).toHaveAttribute("href", `/${slug}/new/?creation_draft=${requestedDraft}`);
    await page.getByText("New Project", { exact: true }).click();
    const secretCsrf = await page.locator('input[name="_csrf"]').first().inputValue();
    await page.getByLabel("Project name", { exact: true }).fill(" ");
    const validationResponse = page.waitForResponse((response) => response.request().method() === "POST" && response.url().includes("/secrets/_actions/projects/create"));
    await page.getByRole("button", { name: "Create Project", exact: true }).click();
    expect((await validationResponse).status()).toBe(422);
    await expect(page.getByRole("alert")).toContainText("Name is required");
    await expect(returnLink).toHaveAttribute("href", `/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(page.locator('input[name="_csrf"]').first()).toHaveValue(secretCsrf);
    const detourProjectName = `return-project-${crypto.randomUUID()}`;
    await page.getByLabel("Project name", { exact: true }).fill(detourProjectName);
    await Promise.all([
      page.waitForURL(`${ssrUrl}/${slug}/secrets/?creation_draft=${requestedDraft}&message=project-created`),
      page.getByRole("button", { name: "Create Project", exact: true }).click(),
    ]);
    const [createdProject] = await sql`SELECT id FROM secret_projects WHERE org_id = ${orgId} AND name = ${detourProjectName}`;
    expect(createdProject?.id).toBeTruthy();
    await returnLink.click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(form).toHaveAttribute("data-create-draft-id", requestedDraft!);
    await expect(form).toHaveAttribute("data-create-draft-actor", ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
    // The draft returns by itself; the new project is offered but not attached.
    await expect(form).toHaveAttribute("data-create-draft-restored", "true");
    await expect(page.getByLabel("Secret project", { exact: true }).locator(`option[value="${createdProject.id}"]`)).toHaveText(detourProjectName);
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue("");
    await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("draft-name-restored");
    // The new personal Settings consumer must retain the same exact draft
    // through cancellation, server validation and a real native secret write.
    // Owning tests disable trace/video/failure screenshots around these inputs.
    const personalPath = `/settings/secrets/?creation_draft=${requestedDraft}`;
    await page.getByRole("link", { name: "Manage personal secrets", exact: true }).click();
    await page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true })
      .getByRole("button", { name: "Save draft and leave", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}${personalPath}`);
    const personalReturn = page.getByRole("link", { name: "Return to Create Sandbox", exact: true });
    await expect(personalReturn).toHaveAttribute("href", `/${slug}/new/?creation_draft=${requestedDraft}`);
    const addSecret = page.getByRole("button", { name: "Add secret", exact: true }).first();
    await addSecret.click();
    const secretDialog = page.getByRole("dialog", { name: "Add secret", exact: true });
    await secretDialog.getByLabel("Key", { exact: true }).fill(personalKey);
    await secretDialog.getByLabel("Value", { exact: true }).fill("synthetic-cancelled-creation-value");
    await secretDialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("dialog", { name: "Discard changes?", exact: true })
      .getByRole("button", { name: "Discard changes", exact: true }).click();
    await addSecret.click();
    await expect(secretDialog.getByLabel("Value", { exact: true })).toHaveValue("");
    await secretDialog.getByLabel("Key", { exact: true }).fill("bad-key");
    await secretDialog.getByLabel("Value", { exact: true }).fill("synthetic-rejected-creation-value");
    // Exercise server validation explicitly; normal native field constraints
    // remain separately asserted and unchanged in the product.
    await secretDialog.locator("form").evaluate((node: HTMLFormElement) => { node.noValidate = true; });
    const secretValidation = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/settings/secrets/_actions/set");
    await secretDialog.getByRole("button", { name: "Add secret", exact: true }).click();
    expect((await secretValidation).status()).toBe(422);
    await expect(secretDialog.getByRole("alert")).toContainText("ASCII letters");
    await expect(secretDialog.getByLabel("Value", { exact: true })).toHaveValue("");
    await expect(personalReturn).toHaveAttribute("href", `/${slug}/new/?creation_draft=${requestedDraft}`);
    await secretDialog.getByLabel("Key", { exact: true }).fill(personalKey);
    await secretDialog.getByLabel("Value", { exact: true }).fill("synthetic-saved-creation-value");
    const secretWrite = page.waitForRequest((request) => request.method() === "POST"
      && new URL(request.url()).pathname === "/settings/secrets/_actions/set");
    await secretDialog.getByRole("button", { name: "Add secret", exact: true }).click();
    expect((await secretWrite).headers().origin).toBe(ssrUrl);
    await expect(page).toHaveURL(`${ssrUrl}${personalPath}&message=secret-saved`);
    await expect(page.locator(".cw-personal-secret-row", { hasText: personalKey })).toHaveCount(1);
    const responsePromise = page.waitForResponse((response) => response.url().endsWith(`/${slug}/_fragments/create-draft`));
    await personalReturn.click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    const csrf = await form.locator('[name="_csrf"]').inputValue();
    const response = await responsePromise;
    await expect(form).toHaveAttribute("data-create-draft-id", requestedDraft!);
    expect(response.status()).toBe(200);
    expect(response.headers()["cache-control"]).toBe("private, no-store");
    expect(response.headers()["vary"]).toBe("Cookie");
    expect(response.headers()["set-cookie"]).toBeUndefined();
    await expect(form).toHaveAttribute("data-create-draft-restored", "true");
    await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
    await expect(page.locator('[name="ttl"]')).toHaveValue("8h");
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Secret project", { exact: true }).locator(`option[value="${createdProject.id}"]`)).toHaveText(detourProjectName);
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("draft-name-restored");
    await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("https://draft-canary.invalid/private-repository");
    await expect(form.locator('[name="_csrf"]')).toHaveValue(csrf);
    await expect(page.getByLabel("Name", { exact: true })).toBeFocused();
    await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
    expect(dispatches).toEqual([]);
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    page.off("request", watchDispatch);
    try {
      const [row] = await sql`SELECT COUNT(*)::int AS count FROM tenant_secrets
        WHERE path = ${`/users/${ownerId}`} AND key = ${personalKey}`;
      if (row.count > 0) {
        const response = await page.request.post(`${serverUrl}/codewire.v1.SecretService/DeleteUserSecret`, {
          headers: { Origin: ssrUrl }, data: { key: personalKey }, timeout: 15_000,
        });
        expect(response.status()).toBe(200);
        const [remaining] = await sql`SELECT COUNT(*)::int AS count FROM tenant_secrets
          WHERE path = ${`/users/${ownerId}`} AND key = ${personalKey}`;
        expect(remaining.count).toBe(0);
      }
    } catch (error) {
      if (primaryFailure !== undefined) throw new AggregateError([primaryFailure, error], "Create return and cleanup failed", { cause: primaryFailure });
      throw error;
    }
  }
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

async function sourceDeletionDeadline(): Promise<string> {
  // shutdown_at is a naive UTC source timestamp, with PostgreSQL microsecond
  // precision. Compare the exact BFF nanosecond representation, not a rounded
  // JavaScript Date or a guessed deadline computed from the requested TTL.
  const [source] = await sql`
    SELECT protected,
           to_char(shutdown_at, 'YYYY-MM-DD"T"HH24:MI:SS.US') || '000Z' AS deadline
    FROM environments WHERE id = ${environmentId} AND org_id = ${orgId}
  `;
  expect(source?.protected).toBe(false);
  expect(source?.deadline).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/);
  return source.deadline as string;
}

async function seedPinnedPreset() {
  presetId = crypto.randomUUID();
  await sql`
    INSERT INTO environment_presets
      (id, org_id, name, slug, description, build_status, default_ttl_seconds, auto_image_ref, project_spec)
    VALUES
      (${presetId}, ${orgId}, ${presetName}, ${presetName},
       'Pinned SSR environment lifecycle preset', 'ready', 3600, ${workspaceRuntimeImage},
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
  await page.locator("[data-create-runtime] > summary").click();
  await page.getByLabel("Install Command").fill("printf 'configured-explicitly\\n'");
  await page.getByLabel("Startup Script").fill("printf 'started-explicitly\\n'");
  await page.getByLabel("Delete after").fill("3600s");
  await page.locator('input[name="agent"][value="codex"]').check();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Internal port", { exact: true }).fill("3000");
  await page.getByLabel("Preview label", { exact: true }).fill("web");
}

test.describe.serial("server-rendered environments", () => {
  test.beforeAll(async ({}, testInfo) => {
    ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    orgId = await ensureTestOrg(orgName, slug, ownerId);
    await seedPinnedPreset();
  });

  test.afterAll(async () => {
    if (process.env.CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE === "prepared-kind-terminal") {
      // The isolated renderer has no Kubernetes authority. Only remove SQL
      // fixture data once product Destroy has proved external resource absence.
      // A failed live fixture remains intact for the owning host to diagnose.
      const unsafe = await sql`
        SELECT id FROM environments WHERE org_id = ${orgId}
          AND (state IS DISTINCT FROM 'destroyed' OR external_cleanup_completed_at IS NULL)
      `;
      if (unsafe.length !== 0) throw new Error("Terminal renderer retained an environment without external cleanup proof; host cleanup is required");
      await cleanupTestOrg(slug);
      return;
    }
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
    await expect(page.locator("[data-github-browser]")).toBeVisible();
    // One account-level connection: there is no account selector to choose.
    await expect(page.locator("[data-github-browser]")).toHaveAttribute("data-github-state", "not-configured");
    await expect(page.getByRole("searchbox", { name: "Find a repository" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add custom Git URL" })).toBeVisible();
    const draft = await page.locator("[data-environment-form]").getAttribute("data-create-draft-id");
    await expect(page.getByRole("link", { name: "Connect GitHub", exact: true })).toHaveAttribute("href", `/settings/credentials/?creation_draft=${draft}`);
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
    await expect(page.locator("#environment-name")).toBeFocused();
    const ttl = page.getByLabel("Delete after");
    // No preset is selected, so the field states what empty does.
    await expect(ttl).toHaveValue("");
    await expect(ttl).toHaveAttribute("placeholder", "Not scheduled");
    await ttl.fill("0");
    await ttl.press("Tab");
    await expect(ttl).toHaveValue("");
    await page.locator("#environment-name").focus();
    await expect(page.locator("#environment-snapshot, .cw-snapshot-meter")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    await expect(page.locator('[action$="/_actions/sandboxes/prepare"]')).toHaveCount(0);
    await expect(page.locator('[data-event-action$="/_events/sandboxes/prepare"]')).toHaveCount(0);
    // The drawer slides in (cw-drawer-in); measure where it settles.
    const drawerGeometry = await drawer.evaluate(async (element) => {
      await Promise.all(element.getAnimations().map((animation) => animation.finished));
      const box = element.getBoundingClientRect();
      return { width: box.width, height: box.height, right: box.right, viewportWidth: innerWidth, viewportHeight: innerHeight };
    });
    expect(Math.abs(drawerGeometry.height - drawerGeometry.viewportHeight)).toBeLessThanOrEqual(1);
    expect(Math.abs(drawerGeometry.right - drawerGeometry.viewportWidth)).toBeLessThanOrEqual(1);
    expect(disallowedBrowserCalls).toEqual([]);
    expect(staleAssetRequests).toEqual([]);
    await assertExplicitCreateRecovery(page);
    expect(disallowedBrowserCalls).toEqual([]);
    expect(staleAssetRequests).toEqual([]);
    // Restore brings back authored fields, which stay until Create or an
    // explicit Discard: Escape must ask, not silently close the drawer.
    await page.keyboard.press("Escape");
    const discard = page.getByRole("dialog", { name: "Discard changes?", exact: true });
    await expect(discard.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
    await expect(page.locator("[data-drawer]")).toBeVisible();
    await expect(page.locator("#environment-name")).toHaveValue("draft-name-restored");
    await discard.getByRole("button", { name: "Discard changes", exact: true }).click();
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
    expect(dimensions.clientWidth).toBeGreaterThan(0);
    expect(dimensions.clientWidth).toBeLessThanOrEqual(page.viewportSize()!.width);
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
    await page.getByLabel("Internal port", { exact: true }).fill("3000");
    await page.getByLabel("Preview label", { exact: true }).fill("web");
    await page.locator("[data-create-runtime] > summary").click();
    await page.getByLabel("Install Command").fill("bun install");
    await page.getByLabel("Startup Script").fill("bun run dev");
    await expect(page.locator('input[name="agent"][value="codex"]')).toBeChecked();
    await expect(page.getByLabel("Internal port", { exact: true })).toHaveValue("3000");
    await expect(page.getByLabel("Preview label", { exact: true })).toHaveValue("web");
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
    await expect(page.locator("#environment-create-card").getByLabel("CPU", { exact: true })).toHaveValue("1000");
    await expect(page.locator("#environment-create-card").getByLabel("Memory", { exact: true })).toHaveValue("2048");
    await expect(page.locator("#environment-create-card").getByLabel("Disk", { exact: true })).toHaveValue("10");
    await expect(page.getByLabel("Delete after")).toHaveValue("");
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
    await expect(page.getByLabel("Delete after")).toHaveValue("");
    await expect(page.getByRole("button", { name: "Analyze and generate from repo" })).toHaveCount(0);
    await page.locator(".cw-drawer-body").evaluate((element) => { element.scrollTop = 0; });
    expect(await page.locator("#environment-create-card").evaluate((element) => Math.abs(element.getBoundingClientRect().top))).toBeLessThanOrEqual(1);
    await page.getByLabel("Repository URL", { exact: true }).fill(repositoryUrl);
    await page.getByLabel("Branch", { exact: true }).fill("main");
    await page.getByLabel("Mount path", { exact: true }).fill("codewire");
    await expect(page.locator("[data-create-runtime] > summary")).toHaveText("Runtime commands");
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
    await assertExplicitCreateRecovery(page);
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
    await page.getByLabel("Delete after").fill("invalid-ttl");
    const response = page.waitForResponse((candidate) => candidate.url().endsWith(`/${slug}/_actions/sandboxes/create`) && candidate.request().method() === "POST");
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    expect((await response).status()).toBe(422);
    const ttl = page.getByLabel("Delete after");
    await expect(ttl).toHaveAttribute("aria-invalid", "true");
    await expect(ttl).toHaveAccessibleDescription(/Enter a duration from 60 seconds to 365 days/);
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue(secretProjectId);
    await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
    await expect(page.locator('[name="confirm_personal_credentials"]')).toHaveCount(0);
    const draft = await page.locator("[data-environment-form]").getAttribute("data-create-draft-id");
    await expect(page.getByRole("link", { name: "Manage personal secrets" })).toHaveAttribute("href", `/settings/secrets/?creation_draft=${draft}`);
    await expect(page.getByRole("link", { name: "Manage organization secrets" })).toHaveAttribute("href", `/${slug}/secrets/organization/?creation_draft=${draft}`);
    await expect(page.getByRole("link", { name: "Manage secret projects" })).toHaveAttribute("href", `/${slug}/secrets/?creation_draft=${draft}`);
    await expect(page.locator(`a[href="/settings/credentials/?creation_draft=${draft}"]`).filter({ hasText: /credentials/ }).last()).toBeVisible();
  });

  test("requires explicit recovery when a selected secret project is removed", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop authoritative source-recovery contract");
    // Empty, isolated metadata only; the lifecycle's shared project is untouched.
    const staleProjectId = crypto.randomUUID();
    const name = `stale-source-${runId}`;
    await sql`
      INSERT INTO secret_projects (id, org_id, name)
      VALUES (${staleProjectId}, ${orgId}, ${`removed-source-${runId}`})
    `;
    await openConfiguredImageForm(page);
    await page.getByLabel("Name").fill(name);
    const project = page.getByLabel("Secret project", { exact: true });
    await project.selectOption(staleProjectId);
    await sql`DELETE FROM secret_projects WHERE id = ${staleProjectId} AND org_id = ${orgId}`;
    const rejected = page.waitForResponse((candidate) => (
      candidate.url().endsWith(`/${slug}/_actions/sandboxes/create`)
      && candidate.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    expect((await rejected).status()).toBe(422);
    await expect(project).toBeEnabled();
    await expect(project).toHaveValue(staleProjectId);
    await expect(project).toHaveAttribute("aria-invalid", "true");
    const stale = project.locator(`option[value="${staleProjectId}"]`);
    await expect(stale).toBeEnabled();
    await expect(stale).toHaveText("Current selected project (unavailable)");
    const [notCreated] = await sql`
      SELECT COUNT(*)::int AS count FROM environments WHERE org_id = ${orgId} AND name = ${name}
    `;
    expect(notCreated.count).toBe(0);

    await project.selectOption("");
    // A separate ordinary validation error proves recovery without creating
    // another Sandbox or allowing stale metadata to silently attach resources.
    await page.getByLabel("Delete after").fill("invalid-ttl");
    const recovered = page.waitForResponse((candidate) => (
      candidate.url().endsWith(`/${slug}/_actions/sandboxes/create`)
      && candidate.request().method() === "POST"
    ));
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    expect((await recovered).status()).toBe(422);
    await expect(project).toHaveValue("");
    await expect(project).not.toHaveAttribute("aria-invalid", "true");
    await expect(project.locator(`option[value="${staleProjectId}"]`)).toHaveCount(0);
    await expect(page.getByLabel("Delete after")).toHaveValue("invalid-ttl");
    const [stillNotCreated] = await sql`
      SELECT COUNT(*)::int AS count FROM environments WHERE org_id = ${orgId} AND name = ${name}
    `;
    expect(stillNotCreated.count).toBe(0);
  });

  test("removing all preview rows suppresses inherited preset routes through real Kind", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop backend preview-selection contract");
    test.setTimeout(600_000);
    const name = "ssr-no-preview-workspace";
    await openConfiguredImageForm(page);
    await page.getByLabel("Name").fill(name);
    await page.getByRole("button", { name: "Remove preview port", exact: true }).click();
    await expect(page.locator("[data-app-port-row]")).toHaveCount(0);
    await expect(page.locator('[name="application_previews_explicit"]')).toHaveValue("true");
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/?message=environment-created`);
    const [created] = await sql`
      SELECT id, preset_id, project_spec FROM environments
      WHERE org_id = ${orgId} AND name = ${name}
    `;
    expect(created?.id).toBeTruthy();
    expect(created.preset_id).toBe(presetId);
    expect(created.project_spec.application_ports ?? []).toEqual([]);
    await waitForEnvironmentState(created.id as string, ["running"], 300_000);
    // Running precedes setup's preview registration phase. Assert only after
    // the actual setup owner has finished, not against a transient empty list.
    await expect.poll(async () => {
      const [backend] = await sql`
        SELECT setup_complete FROM sandbox_environment_backend
        WHERE environment_id = ${created.id as string}
      `;
      return backend?.setup_complete === true;
    }, { timeout: 120_000 }).toBe(true);
    const [routes] = await sql`
      SELECT COUNT(*)::int AS count FROM environment_ports
      WHERE environment_id = ${created.id as string}
    `;
    expect(routes.count).toBe(0);
    // Restore the live rail and release resources before the following
    // lifecycle/visual fixture; afterAll remains the failure-path cleanup.
    await page.reload();
    const row = page.locator("tr", { hasText: name }).first();
    await openRowActions(row);
    await row.getByText("Delete", { exact: true }).click();
    await row.getByRole("button", { name: "Delete permanently", exact: true }).click();
    await waitForEnvironmentState(created.id as string, ["destroyed"], 120_000);
    const [destroyed] = await sql`
      SELECT external_cleanup_completed_at FROM environments
      WHERE id = ${created.id as string} AND org_id = ${orgId}
    `;
    expect(destroyed.external_cleanup_completed_at).not.toBeNull();
  });

  test("creates, runs, exposes a port, stops, starts, and destroys through real Kind", async ({ page, isMobile, workerStorageState }) => {
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
    await expect(page.locator("#environment-create-card").getByLabel("CPU", { exact: true })).toHaveValue("1000");
    await expect(page.locator("#environment-create-card").getByLabel("Memory", { exact: true })).toHaveValue("2048");
    await expect(page.locator("#environment-create-card").getByLabel("Disk", { exact: true })).toHaveValue("10");
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
    const initialDeadline = await sourceDeletionDeadline();
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", initialDeadline, { timeout: 30_000 });
    await expect(page.getByRole("tab")).toHaveCount(0);
    let launchRequests = 0;
    let stopRequests = 0;
    let sandboxStopRequests = 0;
    page.on("request", (request) => {
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/launch")) launchRequests += 1;
      if (new URL(request.url()).pathname.endsWith("/_actions/terminal-sessions/stop")) stopRequests += 1;
      if (new URL(request.url()).pathname.endsWith("/_actions/sandboxes/stop")) sandboxStopRequests += 1;
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
    await page.getByRole("button", { name: "Rename terminal", exact: true }).click();
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
    await page.getByRole("button", { name: "Rename terminal", exact: true }).click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("Log shell");
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await page.getByRole("tab", { name: "Build shell", exact: true }).click();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
    await page.getByRole("tab", { name: "Build shell", exact: true }).press("ArrowRight");
    await expect(page.getByRole("tab", { name: "Log shell", exact: true })).toBeFocused();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", secondSessionId!);
    await page.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.getByRole("dialog", { name: "Close terminal?" }).getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstSessionId!);
    await expect(terminalRoot.locator(".xterm-rows")).toContainText(resumed);
    await expect(page.getByRole("tab", { name: "Build shell", exact: true })).toHaveAttribute("aria-selected", "true");
    // Restore the ordinary label before the existing chrome goldens. Rename
    // behavior is asserted above; snapshot names stay deterministic.
    await page.getByRole("button", { name: "Rename terminal", exact: true }).click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("Terminal 1");
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await page.setViewportSize({ width: 1440, height: 900 });
    await expect(page.getByRole("heading", { name: environmentName, exact: true })).toBeVisible();
    await expect(page.locator(".cw-terminal-page .xterm")).toBeVisible({ timeout: 15_000 });
    await page.setViewportSize({ width: 390, height: 844 });
    expect((await terminalRoot.boundingBox())!.height).toBeGreaterThanOrEqual(180);
    expect((await page.locator(".cw-terminal-footer").boundingBox())!.height).toBeLessThan(100);
    await expect(page.locator("[data-sandbox-lifetime] time")).toBeVisible();
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveAttribute("datetime", await sourceDeletionDeadline());
    await expect(page.locator("[data-sandbox-lifetime] time")).toHaveText(/^\d{2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2} UTC$/);
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
    // A no-op resource review must use the in-place private route and leave
    // the current terminal root, session and shell alive.
    const originalTerminalRoot = (await terminalRoot.elementHandle())!;
    await page.getByRole("button", { name: "Resize", exact: true }).click();
    const resizeDialog = page.getByRole("dialog", { name: `Resize ${environmentName}`, exact: true });
    const noopReview = page.waitForResponse((response) => response.url().endsWith("/_actions/resize/plan"));
    await resizeDialog.getByRole("button", { name: "Review resize", exact: true }).click();
    const reviewed = await noopReview;
    expect(reviewed.status()).toBe(200);
    const noopPlan = await reviewed.json();
    expect(noopPlan.mode).toBe("noop");
    expect(noopPlan.environmentId).toBe(environmentId);
    expect(noopPlan.requestId).toMatch(/^[0-9a-f]{32}$/);
    await expect(resizeDialog.locator("[data-resize-restart-consent]")).not.toBeVisible();
    await expect(resizeDialog.locator("[data-resize-session-consent]")).not.toBeVisible();
    const noopAck = page.waitForResponse((response) => response.url().endsWith("/_actions/resize/apply"));
    await resizeDialog.getByRole("button", { name: "Apply resize", exact: true }).click();
    const applied = await noopAck;
    expect(applied.status()).toBe(200);
    const noopOperation = await applied.json();
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
    await page.getByRole("button", { name: "Close terminal", exact: true }).click();
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
    await page.goto(filteredDetailPath);
    await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();
    // One live terminal stays open across Stop and Start (#2136).
    const launchesBeforeStop = launchRequests;
    await page.getByRole("button", { name: "New terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.locator("[data-terminal-connection]")).toHaveText("Connected", { timeout: 60_000 });
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
    await page.getByRole("button", { name: "Resize", exact: true }).click();
    await resizeDialog.getByLabel("CPU", { exact: true }).selectOption("2000");
    await resizeDialog.getByLabel("Memory", { exact: true }).selectOption("4096");
    const stoppedReview = page.waitForResponse((response) => response.url().endsWith("/_actions/resize/plan"));
    await resizeDialog.getByRole("button", { name: "Review resize", exact: true }).click();
    const stoppedPlanResponse = await stoppedReview;
    expect(stoppedPlanResponse.status()).toBe(200);
    const stoppedPlan = await stoppedPlanResponse.json();
    expect(stoppedPlan.mode).toBe("apply-on-start");
    expect(stoppedPlan.restartRequired).toBe(false);
    expect(stoppedPlan.sessionsWillTerminate).toBe(false);
    const stoppedAck = page.waitForResponse((response) => response.url().endsWith("/_actions/resize/apply"));
    await resizeDialog.getByRole("button", { name: "Apply resize", exact: true }).click();
    const stoppedResponse = await stoppedAck;
    expect(stoppedResponse.status()).toBe(200);
    expect((await stoppedResponse.json()).requestId).toBe(stoppedPlan.requestId);
    await expect(resizeDialog.locator("[data-resize-status]")).toContainText("Resize completed", { timeout: 120_000 });
    await resizeDialog.getByRole("button", { name: "Done", exact: true }).click();
    const [deferred] = await sql`SELECT state, cpu_millicores, memory_mb FROM environments WHERE id = ${environmentId}`;
    expect(deferred).toMatchObject({ state: "stopped", cpu_millicores: 2000, memory_mb: 4096 });
    await expect(page.locator("[data-sandbox-resources]")).toHaveCount(2);
    await expect(page.locator("[data-sandbox-resources]")).toHaveText(["2 vCPU · 4 GiB · 10 GiB", "2 vCPU · 4 GiB · 10 GiB"], { timeout: 30_000 });
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
    await page.getByRole("button", { name: "Remove tab", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(0);
    await expectTerminalLeaseDrained();
    await page.getByRole("button", { name: "Delete", exact: true }).click();
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
