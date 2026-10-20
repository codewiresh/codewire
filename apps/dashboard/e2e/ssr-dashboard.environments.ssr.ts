// covers: src/credentials_connect.rs src/environment_source_forms.rs src/environment_sources.rs
// covers: src/routes/environment_drafts.rs src/routes/environments.rs
// covers: src/routes/personal_secrets.rs src/routes/secrets_presets.rs
// covers: src/secrets_presets_connect.rs templates/environment-create-form.html
// covers: templates/environment-lifetime.html templates/environment-list.html
// covers: templates/environment-resize-fields.html templates/environment-source-fields.html
// covers: templates/organization-environments-content.html
// covers: templates/organization-environments.html templates/organization-secrets-content.html
// covers: templates/organization-secrets.html templates/settings-secrets.html
import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
import { waitForEnvironmentState } from "./helpers/environment";
import {
  environmentJourney,
  keepEnvironmentJourneyEvidence,
  openConfiguredImageForm as openJourneyImageForm,
  openRowActions,
  presetName,
  serverUrl,
  setUpEnvironmentJourney,
  ssrUrl,
  tearDownEnvironmentJourney,
  watchDisallowedBrowserCalls,
  workspaceImage,
  workspaceRuntimeImage,
} from "./helpers/environment-journey";

// The serial Create setup journey enters write-only personal secret values.
// Worker capture settings must be file-scoped. Explicit layout goldens below
// remain enabled and are taken before those inputs are entered.
test.use({ screenshot: "off", trace: "off", video: "off" });

// The real Sandbox lifecycle runs in ssr-dashboard.environment-lifecycle.ssr.ts
// on its own organization, so a second worker runs it beside these checks.
const journey = environmentJourney({
  slugPrefix: "ssr-environments",
  templatePrefix: "ssr-environment",
  orgName: "SSR Environment Workspace",
});
const { sql, runId, slug, repositoryUrl } = journey;
let secretProjectId = "";

const openConfiguredImageForm = (page: Page) => openJourneyImageForm(page, journey);

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
    await expect(form).toHaveAttribute("data-create-draft-actor", journey.ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", journey.orgId);
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
    await expect(form).toHaveAttribute("data-create-draft-actor", journey.ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", journey.orgId);
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
    const discardRestored = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
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
    const [createdProject] = await sql`SELECT id FROM secret_projects WHERE org_id = ${journey.orgId} AND name = ${detourProjectName}`;
    expect(createdProject?.id).toBeTruthy();
    await returnLink.click();
    await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${requestedDraft}`);
    await expect(form).toHaveAttribute("data-create-draft-id", requestedDraft!);
    await expect(form).toHaveAttribute("data-create-draft-actor", journey.ownerId);
    await expect(form).toHaveAttribute("data-create-draft-organization", journey.orgId);
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
        WHERE path = ${`/users/${journey.ownerId}`} AND key = ${personalKey}`;
      if (row.count > 0) {
        const response = await page.request.post(`${serverUrl}/codewire.v1.SecretService/DeleteUserSecret`, {
          headers: { Origin: ssrUrl }, data: { key: personalKey }, timeout: 15_000,
        });
        expect(response.status()).toBe(200);
        const [remaining] = await sql`SELECT COUNT(*)::int AS count FROM tenant_secrets
          WHERE path = ${`/users/${journey.ownerId}`} AND key = ${personalKey}`;
        expect(remaining.count).toBe(0);
      }
    } catch (error) {
      if (primaryFailure !== undefined) throw new AggregateError([primaryFailure, error], "Create return and cleanup failed", { cause: primaryFailure });
      throw error;
    }
  }
}

test.describe.serial("server-rendered environments", () => {
  test.beforeAll(async ({}, testInfo) => {
    await setUpEnvironmentJourney(journey, testInfo);
  });

  test.afterEach(async ({}, testInfo) => {
    await keepEnvironmentJourneyEvidence(journey, testInfo);
  });

  test.afterAll(async () => {
    await tearDownEnvironmentJourney(journey);
  });

  test("keeps manual repository URL, branch, and mount entry always available", { tag: "@smoke" }, async ({ page, isMobile }) => {
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

  test("renders server-owned create options and resources with no browser service caller", { tag: "@smoke" }, async ({ page, isMobile }) => {
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
    const discard = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
    await expect(discard.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
    await expect(page.locator("[data-drawer]")).toBeVisible();
    await expect(page.locator("#environment-name")).toHaveValue("draft-name-restored");
    await discard.getByRole("button", { name: "Discard draft", exact: true }).click();
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
      WHERE org_id = ${journey.orgId} AND name = ${name}
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
    const [project] = await sql`SELECT id FROM secret_projects WHERE org_id = ${journey.orgId} AND name = ${`source-${runId}`}`;
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
    // Empty, isolated metadata only; the selected source project is untouched.
    const staleProjectId = crypto.randomUUID();
    const name = `stale-source-${runId}`;
    await sql`
      INSERT INTO secret_projects (id, org_id, name)
      VALUES (${staleProjectId}, ${journey.orgId}, ${`removed-source-${runId}`})
    `;
    await openConfiguredImageForm(page);
    await page.getByLabel("Name").fill(name);
    const project = page.getByLabel("Secret project", { exact: true });
    await project.selectOption(staleProjectId);
    await sql`DELETE FROM secret_projects WHERE id = ${staleProjectId} AND org_id = ${journey.orgId}`;
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
      SELECT COUNT(*)::int AS count FROM environments WHERE org_id = ${journey.orgId} AND name = ${name}
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
      SELECT COUNT(*)::int AS count FROM environments WHERE org_id = ${journey.orgId} AND name = ${name}
    `;
    expect(stillNotCreated.count).toBe(0);
  });

  test("removing all preview rows suppresses inherited preset routes through real Kind", { tag: "@kind-heavy" }, async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop backend preview-selection contract");
    test.setTimeout(600_000);
    const name = "ssr-no-preview-workspace";
    await openConfiguredImageForm(page);
    await page.getByLabel("Name").fill(name);
    await page.getByRole("button", { name: "Remove preview port", exact: true }).click();
    await expect(page.locator("[data-app-port-row]")).toHaveCount(0);
    await expect(page.locator('[name="application_previews_explicit"]')).toHaveValue("true");
    await page.getByRole("button", { name: "Create Sandbox" }).click();
    // Create lands on the new Sandbox's page, where its setup stages stream.
    await expect(page).toHaveURL(new RegExp(`^${ssrUrl}/${slug}/[0-9a-f-]{36}/\\?message=environment-created$`));
    const [created] = await sql`
      SELECT id, preset_id, project_spec FROM environments
      WHERE org_id = ${journey.orgId} AND name = ${name}
    `;
    expect(created?.id).toBeTruthy();
    expect(created.preset_id).toBe(journey.presetId);
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
    // Restore the live rail and release resources; afterAll remains the
    // failure-path cleanup.
    await page.goto(`${ssrUrl}/${slug}/`);
    const row = page.locator("tr", { hasText: name }).first();
    await openRowActions(row);
    await row.getByText("Delete", { exact: true }).click();
    await row.getByRole("button", { name: "Delete permanently", exact: true }).click();
    await waitForEnvironmentState(created.id as string, ["destroyed"], 120_000);
    const [destroyed] = await sql`
      SELECT external_cleanup_completed_at FROM environments
      WHERE id = ${created.id as string} AND org_id = ${journey.orgId}
    `;
    expect(destroyed.external_cleanup_completed_at).not.toBeNull();
  });
});
