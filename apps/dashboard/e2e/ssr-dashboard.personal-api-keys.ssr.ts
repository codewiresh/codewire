import { expect, test, type Locator, type Page } from "./helpers/fixture-test";

// Editable synthetic fixtures exercise the production controllers. Actor,
// membership, bounded aggregation and service acknowledgements belong to BFF tests.
test.use({ storageState: { cookies: [], origins: [] } });
const fixture = (suffix = "") => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/settings-api-keys${suffix}.html`;
const action = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const row = (page: Page, name: string) => page.getByRole("row").filter({ has: page.locator("th strong").getByText(name, { exact: true }) });
const rowMenu = async (owner: Locator) => {
  const menu = owner.locator("details.cw-menu");
  await menu.locator(":scope > summary").click();
  await expect(menu).toHaveAttribute("open", "");
  return menu;
};
const menuItems = (menu: Locator) => menu.locator(".cw-menu-panel").getByRole("button");
// Open a row menu, check its visible actions, then close it so it cannot cover the next row.
const expectMenu = async (owner: Locator, actions: string[]) => {
  const menu = await rowMenu(owner);
  await expect(menuItems(menu)).toHaveText(actions);
  await menu.locator(":scope > summary").click();
  await expect(menu).not.toHaveAttribute("open", "");
};
const fits = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
const syntheticKey = "cw_fixture_synthetic_one_time_key_not_a_real_credential";
const authority = { _csrf: "design-fixture-only", account_id: "fixture-current-user" };
type Post = { path: string; org: string | null; cursor: string | null; fields: Record<string, string> };
async function capturePosts(page: Page) {
  const posts: Post[] = [];
  await page.route("**/settings/api-keys/_actions/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    posts.push({ path: url.pathname, org: url.searchParams.get("org"), cursor: url.searchParams.get("cursor"), fields: Object.fromEntries(new URLSearchParams(request.postData() || "")) });
    // Native browser submission, intercepted to avoid a real mutation. This
    // response does not simulate a service success or one-time key creation.
    await route.fulfill({ status: 204 });
  });
  return posts;
}
// Personal pages carry no organization in the URL; each form names its own.
const submitted = (action: string, fields: Record<string, string>): Post => ({ path: `/settings/api-keys/_actions/${action}`, org: null, cursor: "fixture-page", fields: { ...authority, ...fields } });

test.beforeEach(async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run the owned design preview and set CODEWIRE_DESIGN_ORIGIN");
  await page.goto(fixture());
});

test("one inventory lists every key with its organization, status and permitted actions", { tag: "@mobile" }, async ({ page }) => {
  const personal = page.getByRole("list", { name: "Personal", exact: true });
  await expect(personal.getByRole("link")).toHaveText(["Account", "Credentials", "Secrets", "API keys"]);
  await expect(personal.locator('[aria-current="page"]')).toHaveText("API keys");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("API keys");
  await expect(page.locator(".cw-page-title-row .cw-badge")).toHaveText("3 keys");
  // Organization names appear once; no "name · slug" pairs and no scope labels.
  await expect(page.locator("main")).not.toContainText(" · alpha-team");
  await expect(page.locator("main")).not.toContainText("Scope");
  const desktop = (page.viewportSize()?.width || 0) >= 1024;
  // Phones keep the name, organization, status and actions; dates are secondary.
  await expect(page.getByRole("columnheader")).toHaveText(desktop
    ? ["Name", "Organization", "Status", "Last used", "Expires", "Actions"]
    : ["Name", "Organization", "Status", "Actions"]);
  const ci = row(page, "CI pipeline");
  await expect(ci.getByRole("cell").first()).toHaveText("Alpha team");
  await expect(ci.getByRole("link", { name: "Alpha team", exact: true })).toHaveAttribute("href", "/alpha-team/api-keys/");
  await expect(ci).toContainText("cw_y-ci…");
  await expect(ci).toContainText("Active");
  if (desktop) expect(await ci.evaluate((node) => node.getBoundingClientRect().height)).toBeLessThan(80);
  await expectMenu(ci, ["Disable", "Delete"]);
  await expectMenu(row(page, "Old deploy"), ["Delete"]);
  await expectMenu(row(page, "Beta helper"), ["Enable"]);
  await expect(page.getByText("Only organization owners and admins can delete keys.", { exact: true })).toBeVisible();
  // An unavailable organization says so instead of looking empty.
  await expect(page.getByRole("status").filter({ hasText: "Gamma group" })).toContainText("does not mean you have no keys there");
  await expect(row(page, "Delta")).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Organization pages" }).getByRole("link", { name: "Next page" })).toHaveAttribute("href", "settings-api-keys.html?cursor=fixture-next");
  await fits(page);
  await page.screenshot({ path: test.info().outputPath("personal-api-keys.png"), fullPage: true });
  if ((page.viewportSize()?.width || 0) < 640) {
    for (const section of ["security", "sessions"]) {
      await page.goto(`${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/settings-account.html#${section}`);
      const target = page.locator(`#${section}`);
      expect(await target.evaluate((node) => node.getBoundingClientRect().top)).toBeGreaterThanOrEqual(60);
    }
  }
});

test("the filter toolbar searches, filters by status and organization, and keeps the page", async ({ page }) => {
  const toolbar = page.getByRole("search", { name: "Filter API keys", exact: true });
  await expect(toolbar.getByLabel("Organization", { exact: true }).locator("option")).toHaveText(["All organizations", "Alpha team", "Beta lab", "Gamma group", "Delta space"]);
  await expect(toolbar.locator('input[name="cursor"]')).toHaveValue("fixture-page");
  await toolbar.getByLabel("Search API keys", { exact: true }).fill("beta");
  await toolbar.getByLabel("Status", { exact: true }).selectOption("disabled");
  await toolbar.getByLabel("Organization", { exact: true }).selectOption("fixture-org-beta");
  const navigation = page.waitForRequest((request) => request.method() === "GET" && request.url().includes("search=beta"));
  await page.route("**/settings/api-keys/?**", (route) => route.fulfill({ status: 204 }));
  await toolbar.getByRole("button", { name: "Filter", exact: true }).click();
  const url = new URL((await navigation).url());
  expect(Object.fromEntries(url.searchParams)).toEqual({ cursor: "fixture-page", search: "beta", status: "disabled", organization: "fixture-org-beta" });
});

test("Create requires an explicit organization, one footer and preserves dirty drafts", { tag: "@mobile" }, async ({ page }) => {
  const posts = await capturePosts(page);
  const trigger = action(page, "Create key");
  await trigger.click();
  const owner = page.getByRole("dialog", { name: "Create API key", exact: true });
  await expect(owner.locator(".cw-dialog-header button")).toHaveCount(0);
  await expect(owner.locator("[data-dialog-close]")).toHaveCount(1);
  await expect(owner.getByLabel("Organization", { exact: true })).toHaveValue("");
  await owner.getByLabel("Name", { exact: true }).fill("Native test key");
  await action(owner, "Create key").click();
  expect(posts).toHaveLength(0);
  await owner.getByLabel("Organization", { exact: true }).selectOption("fixture-org-beta");
  await owner.getByLabel("Expiration", { exact: true }).selectOption("30");
  await action(owner, "Cancel").click();
  const confirm = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(action(confirm, "Keep editing")).toBeFocused();
  await action(confirm, "Keep editing").click();
  await expect(owner.getByLabel("Name", { exact: true })).toHaveValue("Native test key");
  const submit = action(owner, "Create key");
  expect(await submit.evaluate((node: HTMLButtonElement) => node.form?.id)).toBe("create-personal-api-key-form");
  await page.screenshot({ path: test.info().outputPath("create-personal-api-key.png") });
  await submit.click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual(submitted("create", { org_id: "fixture-org-beta", name: "Native test key", expiration: "30" }));
  await fits(page);
});

test("menu actions and the Delete confirmation submit exact key and organization bindings", async ({ page }) => {
  const posts = await capturePosts(page);
  await menuItems(await rowMenu(row(page, "Beta helper"))).getByText("Enable", { exact: true }).click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual(submitted("toggle", { org_id: "fixture-org-beta", key_id: "fixture-key-beta", disabled: "false" }));
  await page.goto(fixture());
  const trigger = menuItems(await rowMenu(row(page, "CI pipeline"))).getByText("Delete", { exact: true });
  await trigger.click();
  const owner = page.getByRole("dialog", { name: "Delete CI pipeline?", exact: true });
  await expect(action(owner, "Cancel")).toBeFocused();
  await expect(owner).toContainText("Alpha team");
  await expect(owner).toContainText("Future requests using it will fail");
  await page.keyboard.press("Escape");
  await expect(owner).toBeHidden();
  expect(posts).toHaveLength(1);
  await trigger.click();
  await action(owner, "Delete key").click();
  await expect.poll(() => posts.length).toBe(2);
  expect(posts[1]).toEqual(submitted("delete", { org_id: "fixture-org-alpha", key_id: "fixture-key-ci" }));
});

test("unavailable organization inventory is not confused with no memberships", { tag: "@mobile" }, async ({ page }) => {
  await page.goto(fixture("-unavailable"));
  await expect(page.getByRole("status")).toContainText("does not mean you have no keys");
  await expect(action(page, "Create key")).toBeDisabled();
  await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "New organization", exact: true })).toHaveCount(0);
  await page.goto(fixture("-empty"));
  await expect(page.getByText("Join or create an organization before creating an API key.")).toBeVisible();
  await expect(page.getByRole("link", { name: "New organization", exact: true })).toHaveAttribute("href", "/organizations/new/");
  await expect(action(page, "Create key")).toBeDisabled();
  await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
  await fits(page);
});

test("one-time reveal replaces inventory, supports copy and clears only its raw value on pagehide", { tag: "@mobile" }, async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(fixture("-one-time"));
  await expect(page.locator("body")).toHaveAttribute("hx-history", "false");
  const value = page.locator("[data-one-time-api-key]");
  await expect(value).toHaveCount(1);
  await expect(value).toHaveText(syntheticKey);
  await expect(page.locator("table, form:not([data-sign-out]), dialog")).toHaveCount(0);
  await expect(action(page, "Create key")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Done", exact: true })).toHaveAttribute("href", "settings-api-keys.html");
  const copy = page.locator("[data-copy-api-key]");
  await copy.click();
  await expect(copy).toHaveText("Copied");
  await page.evaluate(() => {
    const publicValue = document.createElement("code");
    publicValue.id = "synthetic-public-value";
    publicValue.textContent = "public-invitation-example";
    document.body.append(publicValue);
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
  });
  await expect(value).toHaveText("Key hidden. Return to API keys to view its metadata.");
  await expect(copy).toBeDisabled();
  await expect(page.locator("#synthetic-public-value")).toHaveText("public-invitation-example");
  await expect(page.locator("body")).not.toContainText(syntheticKey);
  await fits(page);
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("native Create, menus and Delete remain usable without dialog launchers", { tag: "@mobile" }, async ({ page }) => {
    const posts = await capturePosts(page);
    for (const launcher of await page.locator("[data-dialog-open]").all()) await expect(launcher).toBeHidden();
    const form = page.getByRole("form", { name: "Create API key", exact: true });
    await form.getByLabel("Organization", { exact: true }).selectOption("fixture-org-alpha");
    await form.getByLabel("Name", { exact: true }).fill("No JS key");
    await form.getByLabel("Expiration", { exact: true }).selectOption("60");
    await action(form, "Create key").click();
    await expect.poll(() => posts.length).toBe(1);
    expect(posts[0]).toEqual(submitted("create", { org_id: "fixture-org-alpha", name: "No JS key", expiration: "60" }));
    const menu = await rowMenu(row(page, "CI pipeline"));
    await expect(menuItems(menu).filter({ visible: true })).toHaveText(["Disable", "Delete permanently"]);
    await action(menu, "Delete permanently").click();
    await expect.poll(() => posts.length).toBe(2);
    expect(posts[1]).toEqual(submitted("delete", { org_id: "fixture-org-alpha", key_id: "fixture-key-ci" }));
    await fits(page);
  });

  test("one-time key has one selectable value and a native Done destination", async ({ page }) => {
    await page.goto(fixture("-one-time"));
    const value = page.locator("[data-one-time-api-key]");
    await expect(value).toHaveCount(1);
    await expect(value).toHaveText(syntheticKey);
    await expect(page.locator("[data-copy-api-key]")).toBeHidden();
    await value.click();
    expect(await page.evaluate(() => window.getSelection()?.toString())).toBe(syntheticKey);
    await expect(page.locator("form:not([data-sign-out]), dialog")).toHaveCount(0);
    await page.getByRole("link", { name: "Done", exact: true }).click();
    await expect(page.getByRole("table", { name: "Your API keys", exact: true })).toBeVisible();
    await expect(page.locator("[data-one-time-api-key]")).toHaveCount(0);
  });
});
