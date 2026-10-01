import { expect, test } from "@playwright/test";

// Presentation and interaction proof on the editable fixture using production
// scripts. No mocked provider or backend success: account discovery and checkout
// have separate service/runtime tests.
test.use({ storageState: { cookies: [], origins: [] } });

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
  const addDocs = browser.getByRole("button", { name: /codewiresh\/docs.*Add/ });
  await expect(addDocs).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await addDocs.click();
  const added = page.locator("[data-repository-row]").last();
  await expect(added.getByRole("textbox", { name: "Repository URL" })).toHaveValue("https://github.com/codewiresh/docs.git");
  await expect(added.getByRole("textbox", { name: "Branch" })).toBeFocused();
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
    const next = token ? "" : '<button type="button" data-github-next data-page-token="second-page">Next page</button>';
    const name = token ? "synthetic-user/later-repository" : "synthetic-user/earlier-repository";
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: `<section data-github-results-page><ul class="cw-github-repository-list"><li><button type="button" data-select-github-repository data-repository-url="https://github.com/${name}.git" data-repository-branch="main" data-repository-name="${name}"><strong>${name}</strong><small>Public</small></button></li></ul>${next}</section>` });
  });
  await browser.getByRole("searchbox", { name: "Find a repository" }).fill("later-repository");
  await expect(browser.getByRole("status")).toContainText("1 matching repositories found across 2 pages");
  expect(visited).toEqual(["", "second-page"]);
  // Discovery is owner-scoped: no credential or profile selector is sent.
  expect([...fields].sort()).toEqual(["_csrf", "page_token"]);
  await expect(browser.locator("[data-select-github-repository]")).toHaveCount(1);
  await browser.getByRole("button", { name: /synthetic-user\/later-repository/ }).click();
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
