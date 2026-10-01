import { expect, test, type Locator, type Page } from "@playwright/test";

// Editable synthetic fixtures exercise the production controllers. Actor,
// membership, bounded aggregation and service acknowledgements belong to BFF tests.
test.use({ storageState: { cookies: [], origins: [] } });
const fixture = (suffix = "") => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/settings-api-keys${suffix}.html`;
const action = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const row = (page: Page, name: string) => page.locator(".cw-personal-api-key-row").filter({ has: page.getByRole("heading", { name, exact: true }) });
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

test("personal keys retain organization groups, permission distinctions and readable mobile anchors", async ({ page }) => {
  const personal = page.getByRole("list", { name: "Personal", exact: true });
  await expect(personal.getByRole("link")).toHaveText(["Account", "Credentials", "Secrets", "API Keys"]);
  await expect(personal.locator('[aria-current="page"]')).toHaveText("API Keys");
  await expect(page.getByText("Scope labels are metadata, not enforced permission limits.", { exact: false })).toBeVisible();
  await expect(page.getByRole("region", { name: "Alpha team", exact: true })).toContainText("Organization · alpha-team");
  await expect(action(row(page, "CI pipeline"), "Disable")).toBeVisible();
  await expect(action(row(page, "CI pipeline"), "Delete")).toBeVisible();
  const ci = row(page, "CI pipeline");
  const details = ci.getByText("Key details", { exact: true }).locator("..");
  await expect(details).toHaveJSProperty("open", false);
  await expect(ci.getByText("Prefix cw_y-ci… · Last used Never", { exact: true })).toBeVisible();
  await expect(details.getByText("Created", { exact: true })).toBeHidden();
  expect(await ci.evaluate((node) => node.getBoundingClientRect().height)).toBeLessThan(240);
  await details.locator("summary").click();
  for (const label of ["Created", "Expires", "Scope labels"]) await expect(details.getByText(label, { exact: true })).toBeVisible();
  await expect(action(ci, "Disable")).toBeVisible();
  await expect(action(ci, "Delete")).toBeVisible();
  await details.locator("summary").click();
  await expect(details).toHaveJSProperty("open", false);
  await expect(action(row(page, "Old deploy"), "Enable")).toHaveCount(0);
  await expect(action(row(page, "Old deploy"), "Disable")).toHaveCount(0);
  await expect(action(row(page, "Beta helper"), "Enable")).toBeVisible();
  await expect(action(row(page, "Beta helper"), "Delete")).toHaveCount(0);
  const missing = page.getByRole("region", { name: "Gamma group", exact: true });
  await expect(missing.getByRole("status")).toContainText("does not mean you have no keys here");
  await expect(missing.locator("form")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Delta space", exact: true })).toContainText("You have no API keys in this organization.");
  await expect(page.getByRole("navigation", { name: "Organization pages" }).getByRole("link", { name: "Next page" })).toHaveAttribute("href", "settings-api-keys.html?cursor=fixture-next");
  await fits(page);
  await page.screenshot({ path: test.info().outputPath("personal-api-keys.png"), fullPage: true });
  if ((page.viewportSize()?.width || 0) < 1024) {
    for (const section of ["security", "sessions"]) {
      await page.goto(`${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/settings-account.html#${section}`);
      const target = page.locator(`#${section}`);
      expect(await target.evaluate((node) => node.getBoundingClientRect().top)).toBeGreaterThanOrEqual(60);
    }
  }
});

test("Create requires an explicit organization, one footer and preserves dirty drafts", async ({ page }) => {
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

test("toggle and separate Delete confirmation submit exact key and organization bindings", async ({ page }) => {
  const posts = await capturePosts(page);
  await action(row(page, "Beta helper"), "Enable").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual(submitted("toggle", { org_id: "fixture-org-beta", key_id: "fixture-key-beta", disabled: "false" }));
  const trigger = action(row(page, "CI pipeline"), "Delete");
  await trigger.click();
  const owner = page.getByRole("dialog", { name: "Delete CI pipeline?", exact: true });
  await expect(action(owner, "Cancel")).toBeFocused();
  await expect(owner).toContainText("Alpha team");
  await expect(owner).toContainText("Future requests using it will fail");
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  expect(posts).toHaveLength(1);
  await trigger.click();
  await action(owner, "Delete key").click();
  await expect.poll(() => posts.length).toBe(2);
  expect(posts[1]).toEqual(submitted("delete", { org_id: "fixture-org-alpha", key_id: "fixture-key-ci" }));
});

test("unavailable organization inventory is not confused with no memberships", async ({ page }) => {
  await page.goto(fixture("-unavailable"));
  await expect(page.getByRole("status")).toContainText("does not mean you have no API keys");
  await expect(action(page, "Create key")).toBeDisabled();
  await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "New organization", exact: true })).toHaveCount(0);
  await page.goto(fixture("-empty"));
  await expect(page.getByText("Join or create an organization before creating an API key.", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "New organization", exact: true })).toHaveAttribute("href", "/organizations/new/");
  await expect(action(page, "Create key")).toBeDisabled();
  await expect(page.locator("form:not([data-sign-out])")).toHaveCount(0);
  await fits(page);
});

test("one-time reveal replaces inventory, supports copy and clears only its raw value on pagehide", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(fixture("-one-time"));
  await expect(page.locator("body")).toHaveAttribute("hx-history", "false");
  const value = page.locator("[data-one-time-api-key]");
  await expect(value).toHaveCount(1);
  await expect(value).toHaveText(syntheticKey);
  await expect(page.locator(".cw-personal-api-key-groups, form:not([data-sign-out]), dialog")).toHaveCount(0);
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
  await expect(value).toHaveText("Key hidden. Return to API Keys to view its metadata.");
  await expect(copy).toBeDisabled();
  await expect(page.locator("#synthetic-public-value")).toHaveText("public-invitation-example");
  await expect(page.locator("body")).not.toContainText(syntheticKey);
  await fits(page);
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("native Create and Delete disclosure remain usable without dialog launchers", async ({ page }) => {
    const posts = await capturePosts(page);
    for (const launcher of await page.locator("[data-dialog-open]").all()) await expect(launcher).toBeHidden();
    const ci = row(page, "CI pipeline");
    const details = ci.getByText("Key details", { exact: true }).locator("..");
    await expect(details).toHaveJSProperty("open", false);
    await expect(action(ci, "Disable")).toBeVisible();
    await details.locator("summary").click();
    for (const label of ["Created", "Expires", "Scope labels"]) await expect(details.getByText(label, { exact: true })).toBeVisible();
    await details.locator("summary").click();
    const form = page.getByRole("form", { name: "Create API key", exact: true });
    await form.getByLabel("Organization", { exact: true }).selectOption("fixture-org-alpha");
    await form.getByLabel("Name", { exact: true }).fill("No JS key");
    await form.getByLabel("Expiration", { exact: true }).selectOption("60");
    await action(form, "Create key").click();
    await expect.poll(() => posts.length).toBe(1);
    expect(posts[0]).toEqual(submitted("create", { org_id: "fixture-org-alpha", name: "No JS key", expiration: "60" }));
    const confirm = page.locator("#fallback-api-key-1-1-delete");
    await expect(action(confirm, "Delete key")).toBeHidden();
    await confirm.locator("summary").click();
    await expect(confirm.locator("p")).toBeVisible();
    await expect(confirm).toContainText("Alpha team");
    await expect(confirm).toContainText("Future requests using it will fail");
    await confirm.locator("summary").click();
    expect(posts).toHaveLength(1);
    await confirm.locator("summary").click();
    await action(confirm, "Delete key").click();
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
    await expect(page.getByRole("heading", { name: "Your organization keys", exact: true })).toBeVisible();
    await expect(page.locator("[data-one-time-api-key]")).toHaveCount(0);
  });
});
