import { expect, test, type Page } from "@playwright/test";

// Presentation and interaction proof on the editable fixture using production
// scripts. No mocked provider or backend success: account discovery and checkout
// have separate service/runtime tests.
test.use({ storageState: { cookies: [], origins: [] } });

const fixturePath = "/reference/fixtures/create-sandbox.html";
const exampleRows = /<section aria-label="GitHub repository results" data-github-results-page>[\s\S]*?<\/section>/;
// The markup github-repositories.html renders for public, available repositories.
const repositoryPage = (names: string[], next = "") => `<section aria-label="GitHub repository results" data-github-results-page><ul class="cw-github-repository-list">${names.map((name) => `<li><button class="cw-row-button" type="button" data-select-github-repository data-repository-url="https://github.com/${name}.git" data-repository-branch="main" data-repository-name="${name}" data-repository-private="false"><span class="cw-github-repository-copy"><span class="cw-sr-only" data-github-repository-verb>Add</span> <strong>${name}</strong> <span class="cw-github-repository-badges"><span class="cw-badge">Public</span></span></span><span class="cw-github-repository-action" aria-hidden="true" data-github-repository-action>+ Add</span></button></li>`).join("")}</ul>${next ? `<button class="cw-button cw-button--outline" type="button" data-github-next data-page-token="${next}">Next page</button>` : ""}</section>`;
const repositoryError = (message: string) => `<section aria-label="GitHub repository results" data-github-results-page><p class="cw-field-error" role="alert">${message}</p></section>`;

test.beforeEach(async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
});

test("inline GitHub browser adds a repository without changing the runtime profile or draft", async ({ page }) => {
  const drawer = page.locator("[data-drawer-panel]");
  const browser = page.locator("[data-github-browser]");
  await page.getByRole("textbox", { name: "Name", exact: true }).fill("keep-my-sandbox-draft");
  await expect(browser).toBeVisible();
  // The account's one GitHub connection is shown, never chosen.
  await expect(browser).toHaveAttribute("data-github-state", "connected");
  await expect(browser.getByRole("combobox", { name: "GitHub account" })).toHaveCount(0);
  await expect(browser.getByText("Connected as @synthetic-user")).toBeVisible();
  await expect(browser.getByRole("link", { name: "Manage GitHub connection" })).toHaveAttribute("href", /settings-credentials\.html/);
  const addDocs = browser.getByRole("button", { name: "Add codewiresh/docs Public", exact: true });
  await expect(addDocs).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await addDocs.click();
  const added = page.locator("[data-repository-row]").last();
  await expect(added.getByRole("textbox", { name: "Repository URL" })).toHaveValue("https://github.com/codewiresh/docs.git");
  await expect(added.getByRole("textbox", { name: "Branch" })).toBeFocused();
  await expect(browser.getByRole("button", { name: "Remove codewiresh/docs Public", exact: true })).toContainText("− Remove");
  await expect(page.getByRole("combobox", { name: "Credential profile", exact: true })).toHaveValue("");
  await expect(drawer).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("keep-my-sandbox-draft");
});

test("custom Git URLs remain editable with unique, labelled repository rows", async ({ page }) => {
  await page.getByRole("button", { name: "Add custom Git URL", exact: true }).click();
  const rows = page.locator("[data-repository-row]");
  await expect(rows).toHaveCount(2);
  const added = rows.nth(1);
  await added.getByRole("textbox", { name: "Repository URL", exact: true }).fill("https://git.example.test/team/project.git");
  await added.getByRole("textbox", { name: "Branch", exact: true }).fill("development");
  await added.getByRole("textbox", { name: "Mount path", exact: true }).fill("project");
  await expect(added.getByRole("textbox", { name: "Repository URL", exact: true })).toHaveAttribute("name", "repo_url_1");
  await added.getByRole("button", { name: "Remove repository" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first().getByRole("textbox", { name: "Repository URL", exact: true })).toHaveValue("https://github.com/codewiresh/codewire");
  await rows.first().getByRole("button", { name: "Remove repository" }).click();
  await expect(rows).toHaveCount(0);
});

test("repository search checks later pages before reporting no matches", async ({ page }) => {
  const browser = page.locator("[data-github-browser]");
  const visited: string[] = [];
  const fields = new Set<string>();
  await page.route("**/fixture/_fragments/github-repositories", async (route) => {
    const body = new URLSearchParams(route.request().postData() || "");
    body.forEach((_value, key) => fields.add(key));
    const token = body.get("page_token") || "";
    visited.push(token);
    const name = token ? "synthetic-user/later-repository" : "synthetic-user/earlier-repository";
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: repositoryPage([name], token ? "" : "second-page") });
  });
  await browser.getByRole("searchbox", { name: "Find a repository" }).fill("later-repository");
  await expect(browser.getByRole("status")).toContainText("1 matching repositories found across 2 pages");
  expect(visited).toEqual(["", "second-page"]);
  // Discovery is owner-scoped: no credential or profile selector is sent.
  expect([...fields].sort()).toEqual(["_csrf", "page_token"]);
  await expect(browser.locator("[data-select-github-repository]")).toHaveCount(1);
  await browser.getByRole("button", { name: "Add synthetic-user/later-repository Public", exact: true }).click();
  await expect(page.locator("[data-repository-row]").last().getByRole("textbox", { name: "Repository URL" }))
    .toHaveValue("https://github.com/synthetic-user/later-repository.git");
});

test("an empty GitHub connection explains what to change and offers the custom URL path", async ({ page }) => {
  await page.route("**/_fragments/github-repositories", (route) => route.fulfill({
    contentType: "text/html; charset=utf-8",
    body: '<section data-github-results-page><ul></ul><p role="status">No repositories are available on this page for your GitHub account.</p></section>',
  }));
  // Remove the fixture's example rows so the picker loads through its endpoint.
  await page.route("**/reference/fixtures/create-sandbox.html", async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace(/<section aria-label="GitHub repository results" data-github-results-page>[\s\S]*?<\/section>/, "");
    await route.fulfill({ response, body });
  });
  await page.reload();
  const browser = page.locator("[data-github-browser]");
  await expect(browser.locator("[data-github-status]")).toHaveText(
    "No repositories are available through this GitHub connection. Change the repositories the Codewire GitHub App can access, or use Add custom Git URL.",
  );
  await expect(page.getByText("Use an HTTPS Git URL without a username or token in it.", { exact: true })).toBeVisible();
});

// Serves the fixture the way the Sandboxes list renders it: Create is a closed
// drawer, either already holding its choices or loading them in the
// background. Repositories come only from the endpoint.
async function serveClosedCreateDrawer(page: Page, choices: "rendered" | "background") {
  let hydrated = "";
  await page.route((url) => url.pathname === fixturePath, async (route) => {
    const response = await route.fetch();
    hydrated = (await response.text()).replace(exampleRows, "");
    await route.fulfill({
      response,
      body: choices === "rendered" ? hydrated : hydrated
        .replace('data-create-options-loading="false"', 'data-create-options-loading="true"')
        .replace('data-github-state="connected"', 'data-github-state="not-configured"'),
    });
  });
  await page.route("**/fixture/_fragments/create-options", (route) => {
    const start = hydrated.indexOf('<section id="environment-create-card"');
    const end = hydrated.indexOf("<template data-repository-template>", start);
    return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: hydrated.slice(start, end) });
  });
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN!;
  // Any URL other than the drawer's own renders it closed, as the list does.
  await page.goto(`${origin}${fixturePath}?inventory`);
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-options-loading", "false");
}

for (const choices of ["rendered", "background"] as const) {
  test(`repositories load when the Create drawer opens after the page settled (choices ${choices})`, async ({ page }) => {
    const requests: string[] = [];
    await page.route("**/fixture/_fragments/github-repositories", (route) => {
      requests.push(new URLSearchParams(route.request().postData() || "").get("page_token") || "");
      return route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: repositoryPage(["synthetic-user/opened-later"]) });
    });
    await serveClosedCreateDrawer(page, choices);
    // Whatever the closed drawer did in the background has settled.
    await page.waitForLoadState("networkidle");
    await page.getByRole("link", { name: "Create Sandbox", exact: true }).click();
    const browser = page.locator("[data-github-browser]");
    await expect(browser).toBeVisible();
    await expect(browser.getByRole("button", { name: "Add synthetic-user/opened-later Public", exact: true })).toBeVisible();
    await expect(browser.locator("[data-github-status]")).toHaveText("1 repositories loaded. Choose one to add.");
    await expect(browser.locator("[data-github-results]")).not.toHaveAttribute("aria-busy", "true");
    // A closed drawer asks GitHub for nothing; opening it asks once.
    expect(requests).toEqual([""]);
  });
}

test("closing Create during a repository load restarts it when Create opens again", async ({ page }) => {
  let held = true;
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  let requests = 0;
  await page.route("**/fixture/_fragments/github-repositories", async (route) => {
    requests += 1;
    if (held) await released;
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: repositoryPage(["synthetic-user/reopened"]) });
  });
  await page.route((url) => url.pathname === fixturePath, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, body: (await response.text()).replace(exampleRows, "") });
  });
  // Create opens at its own URL and starts loading at once.
  const first = page.waitForRequest("**/fixture/_fragments/github-repositories");
  await page.reload();
  await first;
  const browser = page.locator("[data-github-browser]");
  await expect(browser.locator("[data-github-results]")).toHaveAttribute("aria-busy", "true");
  await page.keyboard.press("Escape");
  await expect(page.locator("[data-drawer]")).toBeHidden();
  held = false;
  release();
  await page.getByRole("link", { name: "Create Sandbox", exact: true }).click();
  await expect(browser.getByRole("button", { name: "Add synthetic-user/reopened Public", exact: true })).toBeVisible();
  await expect(browser.locator("[data-github-results]")).not.toHaveAttribute("aria-busy", "true");
  expect(requests).toBe(2);
});

// Opens Create at its own URL with repositories served only by `respond`.
async function openWithRepositories(page: Page, respond: (attempt: number) => { status: number; body: string } | Promise<{ status: number; body: string }>) {
  let attempts = 0;
  await page.route("**/fixture/_fragments/github-repositories", async (route) => {
    attempts += 1;
    const { status, body } = await respond(attempts);
    await route.fulfill({ status, contentType: "text/html; charset=utf-8", body });
  });
  await page.route((url) => url.pathname === fixturePath, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, body: (await response.text()).replace(exampleRows, "") });
  });
  await page.reload();
  return () => attempts;
}

test("a transient repository failure retries by itself", async ({ page }) => {
  const attempts = await openWithRepositories(page, (attempt) => attempt === 1
    ? { status: 503, body: repositoryError("Repository access unavailable. Try again later or enter a custom Git URL.") }
    : { status: 200, body: repositoryPage(["synthetic-user/recovered"]) });
  const browser = page.locator("[data-github-browser]");
  await expect(browser.locator("[data-github-status]")).toHaveText("Repositories did not load. Retrying (1 of 2)…");
  await expect(browser.locator("[data-github-placeholder]")).toBeVisible();
  await expect(browser.getByRole("button", { name: "Add synthetic-user/recovered Public", exact: true })).toBeVisible();
  await expect(browser.locator("[data-github-placeholder]")).toBeHidden();
  await expect(browser.getByRole("button", { name: "Retry", exact: true })).toBeHidden();
  expect(attempts()).toBe(2);
});

test("repositories that keep failing offer Retry, which loads them again", async ({ page }) => {
  let failing = true;
  const attempts = await openWithRepositories(page, () => failing
    ? { status: 502, body: repositoryError("The repository service returned an invalid response. Try again later.") }
    : { status: 200, body: repositoryPage(["synthetic-user/after-retry"]) });
  const browser = page.locator("[data-github-browser]");
  const retry = browser.getByRole("button", { name: "Retry", exact: true });
  await expect(browser.locator("[data-github-status]")).toHaveText("Repositories did not load. Retrying (2 of 2)…");
  await expect(retry).toBeVisible({ timeout: 10_000 });
  await expect(browser.locator("[data-github-status]")).toHaveText("The repository service returned an invalid response. Try again later.");
  await expect(browser.locator("[data-github-results]")).not.toHaveAttribute("aria-busy", "true");
  await expect(browser.locator("[data-github-spinner]")).toBeHidden();
  expect(attempts()).toBe(3);
  failing = false;
  await retry.click();
  await expect(browser.getByRole("button", { name: "Add synthetic-user/after-retry Public", exact: true })).toBeVisible();
  await expect(retry).toBeHidden();
  expect(attempts()).toBe(4);
});

test("a definite repository failure is shown at once without retrying", async ({ page }) => {
  const attempts = await openWithRepositories(page, () => ({ status: 422, body: repositoryError("Reconnect required. Reconnect GitHub in Settings to browse repositories.") }));
  const browser = page.locator("[data-github-browser]");
  await expect(browser.locator("[data-github-status]")).toHaveText("Reconnect required. Reconnect GitHub in Settings to browse repositories.");
  await expect(browser.getByRole("button", { name: "Retry", exact: true })).toBeVisible();
  // Longer than the first automatic retry would wait.
  await page.waitForTimeout(1_500);
  expect(attempts()).toBe(1);
});

test("a slow repository load shows its progress and keeps saying so", async ({ page }) => {
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  await openWithRepositories(page, async () => {
    await released;
    return { status: 200, body: repositoryPage(["synthetic-user/slow"]) };
  });
  const browser = page.locator("[data-github-browser]");
  await expect(browser.locator("[data-github-status]")).toHaveText("Loading GitHub repositories…");
  await expect(browser.locator("[data-github-results]")).toHaveAttribute("aria-busy", "true");
  await expect(browser.locator("[data-github-spinner]")).toBeVisible();
  await expect(browser.locator("[data-github-placeholder] li")).toHaveCount(4);
  await expect(browser.locator("[data-github-placeholder]")).toBeVisible();
  await expect(browser.locator("[data-github-status]")).toHaveText("Still loading repositories from GitHub…", { timeout: 8_000 });
  release();
  await expect(browser.getByRole("button", { name: "Add synthetic-user/slow Public", exact: true })).toBeVisible();
  await expect(browser.locator("[data-github-spinner]")).toBeHidden();
  await expect(browser.locator("[data-github-placeholder]")).toBeHidden();
});

test("repository rows show the full name and visibility pills", async ({ page }) => {
  const browser = page.locator("[data-github-browser]");
  const pills = (name: string) => browser.locator(`[data-repository-name="${name}"] .cw-badge`);
  await expect(pills("codewiresh/codewire")).toHaveText(["Private"]);
  await expect(pills("codewiresh/docs")).toHaveText(["Public"]);
  await expect(pills("codewiresh/website-2019")).toHaveText(["Public", "Archived"]);
  await expect(pills("codewiresh/billing-export")).toHaveText(["Private", "Unavailable"]);
  await expect(browser.getByRole("button", { name: "Add codewiresh/billing-export Private Unavailable", exact: true })).toBeDisabled();
  // Rounded pills on the name's line; the action stays at the row's end.
  const docs = browser.locator('[data-repository-name="codewiresh/docs"]');
  expect(await pills("codewiresh/docs").evaluate((pill) => getComputedStyle(pill).borderTopLeftRadius)).toBe("999px");
  const [name, pill, action] = await Promise.all([docs.locator("strong"), pills("codewiresh/docs"), docs.locator("[data-github-repository-action]")].map((item) => item.boundingBox()));
  expect(Math.abs((name!.y + name!.height / 2) - (pill!.y + pill!.height / 2))).toBeLessThanOrEqual(2);
  const row = (await docs.boundingBox())!;
  expect(row.x + row.width - (action!.x + action!.width)).toBeLessThanOrEqual(16);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("each row's Add or Remove follows the repositories selected below", async ({ page }) => {
  const browser = page.locator("[data-github-browser]");
  const rows = page.locator("[data-repository-row]");
  const docs = browser.locator('[data-repository-name="codewiresh/docs"]');
  const codewire = browser.locator('[data-repository-name="codewiresh/codewire"]');
  // The fixture already selects codewiresh/codewire, written without .git.
  await expect(codewire).toHaveAccessibleName("Remove codewiresh/codewire Private");
  await expect(codewire.locator("[data-github-repository-action]")).toHaveText("− Remove");
  await expect(docs).toHaveAccessibleName("Add codewiresh/docs Public");
  await expect(docs.locator("[data-github-repository-action]")).toHaveText("+ Add");
  await docs.click();
  await expect(rows).toHaveCount(2);
  await expect(docs).toHaveAccessibleName("Remove codewiresh/docs Public");
  // Removing it with the X below turns the row back to Add.
  await rows.nth(1).getByRole("button", { name: "Remove repository" }).click();
  await expect(rows).toHaveCount(1);
  await expect(docs).toHaveAccessibleName("Add codewiresh/docs Public");
  // Remove in the browser deletes the matching row below and keeps focus.
  await codewire.click();
  await expect(rows).toHaveCount(0);
  await expect(codewire).toHaveAccessibleName("Add codewiresh/codewire Private");
  await expect(codewire).toBeFocused();
  await expect(browser.locator("[data-github-status]")).toHaveText("codewiresh/codewire removed.");
  // Typing the same repository as a custom URL counts as selecting it.
  await page.getByRole("button", { name: "Add custom Git URL", exact: true }).click();
  const url = rows.first().getByRole("textbox", { name: "Repository URL", exact: true });
  await url.fill("https://github.com/CodewireSH/docs/");
  await expect(docs).toHaveAccessibleName("Remove codewiresh/docs Public");
  await url.fill("https://github.com/codewiresh/docs-site");
  await expect(docs).toHaveAccessibleName("Add codewiresh/docs Public");
  // Search results are rendered with the label the rows below call for.
  await url.fill("https://github.com/synthetic-user/later-repository.git");
  await page.route("**/fixture/_fragments/github-repositories", (route) => route.fulfill({
    status: 200, contentType: "text/html; charset=utf-8", body: repositoryPage(["synthetic-user/later-repository", "synthetic-user/other-repository"]),
  }));
  await browser.getByRole("searchbox", { name: "Find a repository" }).fill("repository");
  await expect(browser.getByRole("button", { name: "Remove synthetic-user/later-repository Public", exact: true })).toBeVisible();
  await expect(browser.getByRole("button", { name: "Add synthetic-user/other-repository Public", exact: true })).toBeVisible();
});

test("at the repository limit, rows not yet added are disabled with the reason", async ({ page }) => {
  await page.route((url) => url.pathname === fixturePath, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, body: (await response.text()).replace('data-repository-limit="108"', 'data-repository-limit="1"') });
  });
  await page.reload();
  const browser = page.locator("[data-github-browser]");
  const limit = browser.locator("[data-github-repository-limit]");
  await expect(limit).toBeVisible();
  await expect(browser.getByRole("button", { name: "Add codewiresh/docs Public", exact: true })).toBeDisabled();
  await expect(browser.getByRole("button", { name: "Remove codewiresh/codewire Private", exact: true })).toBeEnabled();
  await browser.getByRole("button", { name: "Remove codewiresh/codewire Private", exact: true }).click();
  await expect(limit).toBeHidden();
  await expect(browser.getByRole("button", { name: "Add codewiresh/docs Public", exact: true })).toBeEnabled();
});

// Vertical centre of each element, for alignment checks.
async function centres(...locators: ReturnType<Page["locator"]>[]) {
  return Promise.all(locators.map(async (locator) => {
    const box = (await locator.boundingBox())!;
    return box.y + box.height / 2;
  }));
}

// A row's trailing action sits on its controls' line, not on the label stack.
// On a wide drawer every control shares that line; on a phone the first
// control keeps the action beside it and the other fields wrap below.
async function expectActionOnControlLine(page: Page, action: ReturnType<Page["locator"]>, controls: ReturnType<Page["locator"]>[]) {
  const [actionCentre, ...controlCentres] = await centres(action, ...controls);
  const wide = page.viewportSize()!.width >= 1024;
  for (const centre of wide ? controlCentres : controlCentres.slice(0, 1)) expect(Math.abs(actionCentre - centre)).toBeLessThanOrEqual(1);
  if (!wide) {
    const first = (await controls[0].boundingBox())!;
    expect((await action.boundingBox())!.x).toBeGreaterThanOrEqual(first.x + first.width);
    for (const control of controls.slice(1)) expect((await control.boundingBox())!.y).toBeGreaterThan(first.y + first.height);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

test("a selected repository's remove button sits on its input line", async ({ page }) => {
  const row = page.locator("[data-repository-row]").first();
  await expectActionOnControlLine(page, row.getByRole("button", { name: "Remove repository" }), [
    row.getByRole("textbox", { name: "Repository URL", exact: true }),
    row.getByRole("textbox", { name: "Branch", exact: true }),
    row.locator(".cw-workspace-mount"),
  ]);
});

// The row the server renders for a preview port it rejected.
const rejectedPortRow = '<li class="cw-field-row cw-app-port-row" data-app-port-row><div class="cw-field"><label class="cw-label" for="app-port-0">Internal port</label><input class="cw-input cw-mono" id="app-port-0" name="app_port_0" type="number" min="1" max="65535" value="0" placeholder="3000" required aria-invalid="true" aria-describedby="app-port-error-0"><p class="cw-field-error" id="app-port-error-0" role="alert">Use a port from 1 to 65535.</p></div><div class="cw-field"><label class="cw-label" for="app-label-0">Preview label</label><input class="cw-input cw-mono" id="app-label-0" name="app_label_0" value="web" placeholder="web" required></div><div class="cw-field"><label class="cw-label" for="app-access-0">Who can open the preview?</label><select class="cw-select" id="app-access-0" name="app_access_0"><option value="creator" selected>Sandbox creator</option></select></div><button class="cw-icon-button" type="button" data-remove-app-port aria-label="Remove preview port"><svg class="cw-icon" aria-hidden="true"><use href="../../assets/icons.svg#icon-close"/></svg></button></li>';

for (const state of ["added", "rejected"] as const) {
  test(`a preview port's remove button sits on its input line (${state})`, async ({ page }) => {
    if (state === "added") await page.getByRole("button", { name: "Add", exact: true }).click();
    else {
      await page.route((url) => url.pathname === fixturePath, async (route) => {
        const response = await route.fetch();
        const body = (await response.text()).replace('<li class="cw-empty-inline" data-empty-app-ports>No preview ports configured</li>', rejectedPortRow);
        await route.fulfill({ response, body });
      });
      await page.reload();
      await expect(page.getByRole("alert").filter({ hasText: "Use a port from 1 to 65535." })).toBeVisible();
    }
    const row = page.locator("[data-app-port-row]").first();
    await expectActionOnControlLine(page, row.getByRole("button", { name: "Remove preview port" }), [
      row.locator('[name^="app_port_"]'), row.locator('[name^="app_label_"]'), row.locator('[name^="app_access_"]'),
    ]);
  });
}

test("Add port sits on the input line of the ports form, even beside an error", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN!;
  await page.route("**/reference/fixtures/terminal-ports.html", async (route) => {
    const response = await route.fetch();
    const body = (await response.text()).replace('maxlength="22" required>', 'maxlength="22" required aria-invalid="true" aria-describedby="managed-label-error"><p class="cw-field-error" id="managed-label-error" role="alert">Use lowercase letters, digits and hyphens.</p>');
    await route.fulfill({ response, body });
  });
  await page.goto(`${origin}/reference/fixtures/terminal.html`);
  await page.getByRole("button", { name: "Ports", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Ports · Example Sandbox", exact: true }).locator(".cw-port-form");
  await expect(form.getByRole("alert")).toBeVisible();
  const add = form.getByRole("button", { name: "Add port", exact: true });
  const controls = [form.getByLabel("Internal port"), form.getByLabel("Preview label"), form.getByLabel("Who can open the preview?")];
  const [addCentre, ...controlCentres] = await centres(add, ...controls);
  if (page.viewportSize()!.width >= 1024) {
    for (const centre of controlCentres) expect(Math.abs(addCentre - centre)).toBeLessThanOrEqual(1);
  } else {
    // On a phone the form is one column and Add port comes after every field.
    expect((await add.boundingBox())!.y).toBeGreaterThan(Math.max(...controlCentres));
  }
  expect(await form.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
});

test("a cached-page return restarts the repository load the page left", async ({ page }) => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let second!: () => void;
  const secondRequest = new Promise<void>((resolve) => { second = resolve; });
  const attempts = await openWithRepositories(page, async (attempt) => {
    if (attempt === 1) await held;
    else second();
    return { status: 200, body: repositoryPage([attempt === 1 ? "synthetic-user/stale" : "synthetic-user/current"]) };
  });
  try {
    const browser = page.locator("[data-github-browser]");
    await expect(browser.locator("[data-github-results]")).toHaveAttribute("aria-busy", "true");
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
      window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    });
    await secondRequest;
    await expect(browser.getByRole("button", { name: "Add synthetic-user/current Public", exact: true })).toBeVisible();
    release();
    await expect(browser.locator("[data-select-github-repository]")).toHaveCount(1);
    expect(attempts()).toBe(2);
  } finally {
    release();
  }
});
