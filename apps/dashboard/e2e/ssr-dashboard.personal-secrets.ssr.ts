import { expect, test, type Locator, type Page } from "./helpers/fixture-test";

// Production dialog controller against editable synthetic fixtures only.
// Authenticated ownership, BFF keyset paging and 422 rendering belong to BFF tests.
test.use({ storageState: { cookies: [], origins: [] } });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });
const action = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const discard = async (page: Page) => action(dialog(page, "Discard changes?"), "Discard changes").click();
const fixture = (name = "settings-secrets") => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/${name}.html`;
const fits = async (page: Page, owner?: Locator) => {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  if (owner) expect(await owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
};
const footer = async (owner: Locator, primary: string) => {
  await expect(owner.locator("[data-dialog-close]")).toHaveCount(1);
  await expect(owner.locator(".cw-dialog-header button")).toHaveCount(0);
  await expect(owner.locator(".cw-dialog-actions").getByRole("button", { name: "Cancel", exact: true })).toBeVisible();
  await expect(owner.locator('button[type="submit"]')).toHaveCount(1);
  const submit = owner.locator(".cw-dialog-actions").getByRole("button", { name: primary, exact: true });
  await expect(submit).toBeVisible();
  expect(await submit.evaluate((node: HTMLButtonElement) => node.form?.closest("dialog") === node.closest("dialog"))).toBe(true);
};

test.beforeEach(async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
  await page.goto(fixture());
});

test("Settings uses one subtitle-free heading and personal destinations independent of organization navigation", async ({ page }) => {
  for (const [path, active] of [["settings-account", "Account"], ["settings-credentials", "Credentials"], ["settings-secrets", "Secrets"]]) {
    await page.goto(fixture(path));
    const aside = page.locator(".cw-context-nav");
    await expect(aside.locator("header")).toHaveText("Settings");
    await expect(aside.getByRole("list", { name: "Personal", exact: true }).getByRole("link")).toHaveText(["Account", "Credentials", "Secrets", "API keys"]);
    await expect(aside.locator('[aria-current="page"]')).toHaveText(active);
    await expect(aside.getByRole("list", { name: "Personal", exact: true }).getByRole("link", { name: "API keys", exact: true })).toHaveAttribute("href", "settings-api-keys.html");
    await expect(aside.getByRole("heading", { name: /Organization/ })).toHaveCount(0);
    await fits(page);
  }
  await page.screenshot({ path: test.info().outputPath("personal-secrets-list.png") });
  await page.goto(fixture("application-secrets"));
  const org = page.getByRole("navigation", { name: "Organization navigation", exact: true });
  await expect(page.locator(".cw-context-nav > header")).toHaveText("Settings");
  await expect(org.getByRole("list", { name: "Personal", exact: true }).getByRole("link", { name: "Secrets", exact: true })).toHaveAttribute("href", "settings-secrets.html");
  const organization = org.getByRole("list", { name: "Organization · Example organization", exact: true });
  await expect(organization.getByRole("link", { name: "API keys", exact: true })).toHaveAttribute("href", "/example-org/api-keys/");
  await expect(organization.locator('[aria-current="page"]')).toHaveText("Secrets");
  await expect(org.getByRole("list", { name: "Admin", exact: true }).getByRole("link")).not.toHaveCount(0);
  if ((page.viewportSize()?.width || 0) < 640) {
    expect(await org.evaluate((node) => node.getBoundingClientRect().height)).toBeLessThan(80);
    for (const label of await org.getByRole("heading", { level: 3 }).all()) {
      expect(await label.evaluate((node) => node.getBoundingClientRect().height)).toBeLessThanOrEqual(28);
    }
  }
  await fits(page);
  await page.screenshot({ path: test.info().outputPath("scoped-settings-navigation.png") });
});

test("Add secret keeps drafts only in the active DOM and never submits on dismissal", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  const add = action(page, "Add secret");
  await add.click();
  const owner = dialog(page, "Add secret");
  await footer(owner, "Add secret");
  await expect(owner.getByLabel("Key", { exact: true })).toBeFocused();
  await expect(owner.getByLabel("Value", { exact: true })).toHaveAttribute("maxlength", "65536");
  await owner.getByLabel("Key", { exact: true }).fill("INVALID-KEY");
  await owner.getByLabel("Value", { exact: true }).fill("synthetic-write-only-value");
  await action(owner, "Add secret").click();
  expect(await owner.locator("form").evaluate((form: HTMLFormElement) => form.checkValidity())).toBe(false);
  await owner.getByLabel("Key", { exact: true }).fill("VALID_KEY");
  await owner.locator('[name="_csrf"]').evaluate((node: HTMLInputElement) => { node.value = "fresh-hidden-csrf"; });
  await page.screenshot({ path: test.info().outputPath("add-secret-dialog.png") });
  await fits(page, owner);
  await action(owner, "Cancel").click();
  await expect(action(dialog(page, "Discard changes?"), "Keep editing")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(owner.getByLabel("Value", { exact: true })).toHaveValue("synthetic-write-only-value");
  await expect(owner.getByLabel("Key", { exact: true })).toHaveValue("VALID_KEY");
  await action(owner, "Cancel").click();
  await discard(page);
  await expect(add).toBeFocused();
  await add.click();
  await expect(owner.getByLabel("Key", { exact: true })).toHaveValue("");
  await expect(owner.getByLabel("Value", { exact: true })).toHaveValue("");
  await expect(owner.locator('[name="_csrf"]')).toHaveValue("fresh-hidden-csrf");
  await expect(owner.locator('[name="account_id"]')).toHaveValue("fixture-personal-account");
  await expect(owner.locator('[name="mode"]')).toHaveValue("add");
  await action(owner, "Cancel").click();
  expect(posts).toBe(0);
});

test("replacement and rename footers target only the original key and preserve page context", async ({ page }) => {
  const posts: { path: string; cursor: string | null; fields: Record<string, string> }[] = [];
  await page.route("**/settings/secrets/_actions/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    posts.push({ path: url.pathname, cursor: url.searchParams.get("cursor"), fields: Object.fromEntries(new URLSearchParams(request.postData() || "")) });
    await route.fulfill({ status: 204 });
  });
  const row = page.locator(".cw-personal-secret-row").filter({ has: page.getByRole("heading", { name: "DATABASE_URL", exact: true }) });
  const replace = action(row, "Replace value");
  await replace.click();
  const owner = dialog(page, "Replace DATABASE_URL");
  await footer(owner, "Save value");
  await expect(owner.getByLabel("Replacement value", { exact: true })).toBeFocused();
  await expect(owner.locator('[name="key"]')).toHaveAttribute("type", "hidden");
  await expect(owner.locator('[name="key"]')).toHaveValue("DATABASE_URL");
  await owner.getByLabel("Replacement value", { exact: true }).fill("synthetic-replacement");
  await action(owner, "Save value").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual({ path: "/settings/secrets/_actions/set", cursor: "AAA_PREVIOUS", fields: {
    _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "DATABASE_URL", mode: "replace", value: "synthetic-replacement",
  } });
  // The intercepted 204 is not a product success acknowledgement.
  await action(owner, "Cancel").click();
  await discard(page);
  await expect(replace).toBeFocused();
  await action(row, "Rename").click();
  const rename = dialog(page, "Rename DATABASE_URL");
  await footer(rename, "Save name");
  await expect(rename.getByLabel("New key", { exact: true })).toHaveValue("DATABASE_URL");
  await rename.getByLabel("New key", { exact: true }).fill("RENAMED_DATABASE_URL");
  await action(rename, "Save name").click();
  await expect.poll(() => posts.length).toBe(2);
  expect(posts[1]).toEqual({ path: "/settings/secrets/_actions/rename", cursor: "AAA_PREVIOUS", fields: {
    _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "DATABASE_URL", new_key: "RENAMED_DATABASE_URL",
  } });
  await fits(page, rename);
});

test("Delete requires its own confirmation, Cancel is default and no value is sent", async ({ page }) => {
  const posts: Record<string, string>[] = [];
  await page.route("**/settings/secrets/_actions/delete**", async (route) => {
    posts.push(Object.fromEntries(new URLSearchParams(route.request().postData() || "")));
    await route.fulfill({ status: 204 });
  });
  const row = page.locator(".cw-personal-secret-row").filter({ has: page.getByRole("heading", { name: "APP_TOKEN", exact: true }) });
  const remove = action(row, "Delete");
  await remove.click();
  const owner = dialog(page, "Delete APP_TOKEN?");
  await footer(owner, "Delete secret");
  await expect(action(owner, "Cancel")).toBeFocused();
  await expect(owner).toContainText("does not revoke access at an external service");
  await page.keyboard.press("Escape");
  await expect(remove).toBeFocused();
  expect(posts).toEqual([]);
  await remove.click();
  await page.screenshot({ path: test.info().outputPath("delete-secret-dialog.png") });
  await fits(page, owner);
  await action(owner, "Delete secret").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual({ _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "APP_TOKEN" });
});

test("empty and unavailable states remain distinct and pagination never implies a total", async ({ page }) => {
  const pages = page.getByRole("navigation", { name: "Secret pages", exact: true });
  await expect(pages.getByRole("link", { name: "First page" })).toHaveAttribute("href", "settings-secrets.html?creation_draft=00000000-0000-4000-8000-000000000003");
  await expect(pages.getByRole("link", { name: "Next page" })).toHaveAttribute("href", "settings-secrets.html?cursor=DATABASE_URL&creation_draft=00000000-0000-4000-8000-000000000003");
  await page.goto(fixture("settings-secrets-empty"));
  await expect(page.getByText("No personal secrets yet. Add a secret when a workload needs one.", { exact: true })).toBeVisible();
  await expect(action(page, "Add secret")).toBeVisible();
  await expect(page.locator(".cw-personal-secret-row")).toHaveCount(0);
  const mobile = (page.viewportSize()?.width || 0) < 640;
  if (mobile) await action(page, "Toggle sidebar").click();
  const sidebar = page.locator(mobile ? ".cw-mobile-drawer" : ".cw-sidebar-slot");
  await expect(sidebar.getByText("Choose an organization above to view its Sandboxes.", { exact: true })).toBeVisible();
  await expect(sidebar.getByText("Create an organization to start a Sandbox.", { exact: true })).toHaveCount(0);
  await sidebar.locator("summary").click();
  await expect(sidebar.getByRole("link", { name: "Example organization" })).toHaveAttribute("href", "sandboxes.html");
  if (mobile) await action(sidebar, "Collapse navigation").click();
  await fits(page);
  await page.screenshot({ path: test.info().outputPath("personal-secrets-no-selected-org.png") });
  await page.goto(fixture("settings-secrets-unavailable"));
  await expect(page.getByRole("status").filter({ hasText: "Organization navigation" })).toContainText("Personal settings still work");
  await expect(page.getByRole("status").filter({ hasText: "Personal secrets are temporarily unavailable" })).toBeVisible();
  await expect(page.getByText(/No personal secrets yet/)).toHaveCount(0);
  await expect(action(page, "Add secret")).toHaveCount(0);
  await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Reload secrets" })).toHaveAttribute("href", "settings-secrets.html");
  if ((page.viewportSize()?.width || 0) < 640) {
    expect(await page.locator(".cw-context-nav").evaluate((node) => node.getBoundingClientRect().height)).toBeLessThan(200);
  }
  await fits(page);
  await page.screenshot({ path: test.info().outputPath("personal-secrets-unavailable.png") });
});

test.describe("Personal Secrets without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("native forms submit exact fields and Delete exposes its warning before confirmation", async ({ page }) => {
    const posts: { path: string; cursor: string | null; fields: Record<string, string> }[] = [];
    await page.route("**/settings/secrets/_actions/**", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      posts.push({ path: url.pathname, cursor: url.searchParams.get("cursor"), fields: Object.fromEntries(new URLSearchParams(request.postData() || "")) });
      // A native browser submit, intercepted only to avoid a real mutation.
      // This 204 is not a product acknowledgement or managed-backend proof.
      await route.fulfill({ status: 204 });
    });
    for (const launcher of await page.locator("[data-dialog-open]").all()) await expect(launcher).toBeHidden();
    const add = page.getByRole("form", { name: "Add secret", exact: true });
    await expect(add).toBeVisible();
    await expect(page.locator("#fallback-add-secret")).toContainText("Saving an existing key replaces its value");
    await expect(add.getByLabel("Value", { exact: true })).toHaveValue("");
    await add.getByLabel("Key", { exact: true }).fill("NEW_SYNTHETIC_KEY");
    await add.getByLabel("Value", { exact: true }).fill("synthetic-no-js-value");
    await action(add, "Add secret").click();
    await expect.poll(() => posts.length).toBe(1);
    expect(posts[0]).toEqual({ path: "/settings/secrets/_actions/set", cursor: "AAA_PREVIOUS", fields: {
      _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "NEW_SYNTHETIC_KEY", mode: "add", value: "synthetic-no-js-value",
    } });

    await page.goto(fixture());
    const replaceDetails = page.locator("#fallback-secret-1-value");
    await replaceDetails.locator("summary").click();
    const replace = page.getByRole("form", { name: "Replace DATABASE_URL", exact: true });
    await expect(replace.getByLabel("Replacement value", { exact: true })).toHaveValue("");
    await replace.getByLabel("Replacement value", { exact: true }).fill("synthetic-no-js-replacement");
    await action(replace, "Save value").click();
    await expect.poll(() => posts.length).toBe(2);
    expect(posts[1]).toEqual({ path: "/settings/secrets/_actions/set", cursor: "AAA_PREVIOUS", fields: {
      _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "DATABASE_URL", mode: "replace", value: "synthetic-no-js-replacement",
    } });

    await page.goto(fixture());
    const renameDetails = page.locator("#fallback-secret-1-rename");
    await renameDetails.locator("summary").click();
    const rename = page.getByRole("form", { name: "Rename DATABASE_URL", exact: true });
    await expect(rename.getByLabel("New key", { exact: true })).toHaveValue("DATABASE_URL");
    await rename.getByLabel("New key", { exact: true }).fill("RENAMED_DATABASE_URL");
    await action(rename, "Save name").click();
    await expect.poll(() => posts.length).toBe(3);
    expect(posts[2]).toEqual({ path: "/settings/secrets/_actions/rename", cursor: "AAA_PREVIOUS", fields: {
      _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "DATABASE_URL", new_key: "RENAMED_DATABASE_URL",
    } });

    await page.goto(fixture());
    const removeDetails = page.locator("#fallback-secret-2-delete");
    await expect(action(removeDetails, "Delete secret")).toBeHidden();
    await removeDetails.locator("summary").click();
    await expect(removeDetails.locator("p")).toBeVisible();
    await expect(removeDetails).toContainText("does not revoke access at an external service");
    await expect(removeDetails).toContainText("APP_TOKEN");
    await removeDetails.locator("summary").click();
    await expect(action(removeDetails, "Delete secret")).toBeHidden();
    expect(posts).toHaveLength(3);
    await removeDetails.locator("summary").click();
    await fits(page, removeDetails);
    await page.screenshot({ path: test.info().outputPath("personal-secrets-no-js-delete.png") });
    await action(removeDetails, "Delete secret").click();
    await expect.poll(() => posts.length).toBe(4);
    expect(posts[3]).toEqual({ path: "/settings/secrets/_actions/delete", cursor: "AAA_PREVIOUS", fields: {
      _csrf: "design-fixture-only", account_id: "fixture-personal-account", key: "APP_TOKEN",
    } });

    await page.goto(fixture("settings-secrets-empty"));
    await expect(page.getByRole("form", { name: "Add secret", exact: true })).toBeVisible();
    await expect(page.locator('[id^="fallback-secret-"]')).toHaveCount(0);
    await page.goto(fixture("settings-secrets-unavailable"));
    await expect(page.getByRole("status").filter({ hasText: "Personal secrets are temporarily unavailable" })).toBeVisible();
    await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Reload secrets" })).toBeVisible();
    await fits(page);
  });
});
