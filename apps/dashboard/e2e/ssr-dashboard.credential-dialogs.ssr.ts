import { expect, test, type Locator, type Page } from "@playwright/test";

// Editable fixture + production scripts. Provider authorization/publication and
// authenticated error rendering remain separate managed browser proof.
test.use({ storageState: { cookies: [], origins: [] } });

test.beforeEach(async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/settings-credentials.html`);
});

test("explicit Create return carries only its draft handle while credential inputs stay private", async ({ page }) => {
  const returnLink = page.getByRole("link", { name: "Return to Create Sandbox", exact: true });
  await expect(returnLink).toHaveAttribute("href", "/fixture-org/new/?creation_draft=00000000-0000-4000-8000-000000000003");
  await choose(page, "OpenAI API key");
  const dialog = page.getByRole("dialog", { name: "Add OpenAI API key", exact: true });
  const privateCanary = "synthetic-draft-return-write-only-canary";
  await dialog.getByLabel("API key", { exact: true }).fill(privateCanary);
  await expect(returnLink).toHaveAttribute("href", "/fixture-org/new/?creation_draft=00000000-0000-4000-8000-000000000003");
  expect(await page.locator("a[href]").evaluateAll((links) => links.map((link) => link.getAttribute("href")).join("\n"))).not.toContain(privateCanary);
});

const dialog = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });
const action = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const prompt = (page: Page) => dialog(page, "Discard changes?");
const choose = async (page: Page, name: string) => {
  await action(page, "Add credential").click();
  await action(dialog(page, "Add credential"), name).click();
};
const discard = async (page: Page) => action(prompt(page), "Discard changes").click();
// Each credential and profile row opens its actions from a trailing ⋯ menu.
const rowMenu = async (row: Locator) => {
  const menu = row.locator("details.cw-menu");
  await menu.locator(":scope > summary").click();
  await expect(menu).toHaveAttribute("open", "");
  return menu;
};
const menuItems = (menu: Locator) => menu.locator(".cw-menu-panel").getByRole("button");
const fits = async (page: Page, owner: Locator) => {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
};
const footer = async (owner: Locator, primary?: string, dismissal = "Cancel") => {
  await expect(owner.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
  await expect(owner.locator("[data-dialog-close]")).toHaveCount(1);
  await expect(owner.locator(".cw-dialog-actions").getByRole("button", { name: dismissal, exact: true })).toBeVisible();
  await expect(owner.locator('button[type="submit"]:not([data-dialog-open], [data-dialog-close])')).toHaveCount(primary ? 1 : 0);
  if (primary) {
    const submit = owner.locator(".cw-dialog-actions").getByRole("button", { name: primary, exact: true });
    await expect(submit).toBeVisible();
    expect(await submit.evaluate((node: HTMLButtonElement) => node.form?.closest("dialog") === node.closest("dialog"))).toBe(true);
  }
};

test("five full-row choices open focused provider editors with Back and one footer", async ({ page }) => {
  const errors: string[] = [];
  const posts: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => { if (request.method() === "POST") posts.push(request.url()); });
  const add = action(page, "Add credential");
  await add.click();
  const chooser = dialog(page, "Add credential");
  await expect(chooser.locator(".cw-credential-types > li")).toHaveCount(5);
  await footer(chooser);
  await fits(page, chooser);
  await page.screenshot({ path: test.info().outputPath("credential-chooser.png") });
  for (const [name, title, primary, provider] of [
    // The fixture account already has its one GitHub connection, so the
    // connect dialog routes to Reconnect and offers no second authorization.
    ["GitHub", "Connect GitHub", "", ""],
    ["Codex", "Connect Codex", "Connect Codex", "codex"],
    ["OpenAI API key", "Add OpenAI API key", "Add API key", "openai"],
    ["Anthropic API key", "Add Anthropic API key", "Add API key", "anthropic"],
  ]) {
    const row = action(chooser, name);
    await expect(row.locator("svg")).toHaveCount(2);
    // The description itself is inside the action, not detached underneath it.
    await row.locator("span > span").click();
    const editor = dialog(page, title);
    await expect(page.locator("dialog[open]")).toHaveCount(1);
    await footer(editor, primary || undefined, name === "GitHub" ? "Done" : "Cancel");
    // Back opens the chooser through its own form; it never submits the editor's values.
    expect(await action(editor, "Back").evaluate((button: HTMLButtonElement) => button.form?.matches(".cw-dialog-launcher")
      && [...button.form.elements].every((field) => field === button || ["creation_draft", "dialog"].includes((field as HTMLInputElement).name)))).toBe(true);
    if (provider) await expect(editor.locator('[name="provider"]')).toHaveValue(provider);
    if (name === "GitHub") {
      await expect(editor.locator('input[name="name"]')).toHaveCount(0);
      await expect(action(editor, "Done")).toBeFocused();
      await expect(action(editor, "Continue to GitHub")).toHaveCount(0);
      // The one account-level connection is stated plainly; the actions are
      // reconnecting it or disconnecting it to use a different account.
      await expect(editor).toContainText("Your GitHub account verified-user is already connected.");
      await expect(editor).toContainText("Active");
      await expect(action(editor, "Reconnect")).toBeVisible();
      await expect(action(editor, "Disconnect")).toBeVisible();
      await expect(editor.getByRole("heading", { level: 3 })).toHaveCount(0);
      await page.screenshot({ path: test.info().outputPath("github-saved-connections.png") });
    }
    if (name.includes("API key")) {
      await expect(editor.getByRole("combobox")).toHaveCount(0);
      await expect(editor.getByLabel("Credential name", { exact: true })).toBeFocused();
      await expect(editor.getByLabel("Hard expiry (UTC)", { exact: true })).not.toBeVisible();
    }
    await fits(page, editor);
    await action(editor, "Back").click();
    await expect(chooser).toBeVisible();
    await expect(row).toBeFocused();
    await expect(page.locator("dialog[open]")).toHaveCount(1);
  }
  await action(chooser, "Cancel").click();
  await expect(add).toBeFocused();
  expect(posts).toEqual([]);
  expect(errors).toEqual([]);
});

test("saved GitHub connection opens its exact reconnect dialog without submitting", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  await choose(page, "GitHub");
  const connect = dialog(page, "Connect GitHub");
  await action(connect, "Reconnect").click();
  const reconnect = dialog(page, "Reconnect verified-user");
  await expect(reconnect).toBeVisible();
  await expect(connect).not.toBeVisible();
  await expect(page.locator("dialog[open]")).toHaveCount(1);
  await expect(reconnect.locator('[name="credential_id"]')).toHaveValue("fixture-github");
  expect(posts).toBe(0);
});

test("SSH chooses Generate or Import and Back clears private values only after discard", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  await choose(page, "SSH key");
  const method = dialog(page, "Add SSH key");
  await expect(method.getByRole("textbox")).toHaveCount(0);
  await footer(method);
  await action(method, "Generate").click();
  const generate = dialog(page, "Generate SSH key");
  await footer(generate, "Generate SSH key");
  await expect(generate.locator('[name="private_key"]')).toHaveCount(0);
  await action(generate, "Back").click();
  await action(method, "Import").click();
  const imported = dialog(page, "Import SSH key");
  await footer(imported, "Import SSH key");
  await expect(page.locator("dialog[open]")).toHaveCount(1);
  await imported.getByLabel("OpenSSH private key", { exact: true }).fill("synthetic-write-only-private-key");
  await imported.getByLabel("Passphrase (optional)", { exact: true }).fill("synthetic-passphrase");
  await page.screenshot({ path: test.info().outputPath("ssh-import-dialog.png") });
  await fits(page, imported);
  await action(imported, "Back").click();
  await action(prompt(page), "Keep editing").click();
  await expect(imported.getByLabel("OpenSSH private key", { exact: true })).toHaveValue("synthetic-write-only-private-key");
  await action(imported, "Back").click();
  await discard(page);
  await expect(method).toBeVisible();
  await action(method, "Import").click();
  await expect(imported.locator('[name="private_key"]')).toHaveValue("");
  await expect(imported.locator('[name="passphrase"]')).toHaveValue("");
  await action(imported, "Cancel").click();
  await expect(action(page, "Add credential")).toBeFocused();
  expect(posts).toBe(0);
});

test("rows keep status and expiry visible and open focused editors straight from their menu", async ({ page }) => {
  // Anchored on the menu's name, which stays put when the label text is replaced below.
  const row = page.locator(".cw-credential-row").filter({ has: page.locator('summary[aria-label="Actions for Work API"]') });
  await expect(row.locator(".cw-credential-identity")).toContainText("Expires 2026-12-31 12:00 UTC");
  await expect(row.locator(".cw-credential-status")).toHaveText("Active");
  await expect(row).not.toContainText("Generation");
  // No intermediary manage step: the row menu holds the actions themselves.
  await expect(row.getByRole("button", { name: /^Manage /u })).toHaveCount(0);
  const trigger = row.locator("details.cw-menu > summary");
  await expect(trigger).toHaveAccessibleName("Actions for Work API");
  const menu = await rowMenu(row);
  await expect(menuItems(menu)).toHaveText(["Rename", "Rotate API key", "Revoke"]);
  await action(menu, "Rotate API key").click();
  const rotate = dialog(page, "Rotate Work API");
  await footer(rotate, "Rotate API key");
  await expect(action(rotate, "Back")).toHaveCount(0);
  await expect(rotate.locator('[name="credential_id"]')).toHaveValue("fixture-openai");
  await expect(rotate.locator('[name="expected_revocation_generation"]')).toHaveValue("3");
  await expect(rotate.getByLabel("Replacement API key", { exact: true })).toBeFocused();
  await action(rotate, "Cancel").click();
  await expect(action(menu, "Rotate API key")).toBeFocused();
  await action(menu, "Rename").click();
  const rename = dialog(page, "Rename Work API");
  await footer(rename, "Save name");
  await expect(rename.getByLabel("New name")).toHaveValue("Work API");
  await expect(rename.locator('[name="expected_name"]')).toHaveValue("Work API");
  await action(rename, "Cancel").click();
  await expect(action(menu, "Rename")).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(menu).not.toHaveAttribute("open", "");
  await expect(trigger).toBeFocused();
  await page.screenshot({ path: test.info().outputPath("credentials-list.png") });
  // Credential labels may be 256 characters with no whitespace. The row and
  // its dialog titles must stay bounded at the mobile viewport too.
  await row.locator(".cw-credential-identity strong").evaluate((node) => { node.textContent = "a".repeat(256); });
  await fits(page, row);
  await rowMenu(row);
  await action(row, "Rename").click();
  await rename.getByRole("heading").evaluate((node) => { node.textContent = `Rename ${"a".repeat(256)}`; });
  await fits(page, page.locator("#credential-fixture-openai-rename"));
});

test("a credential whose refresh failed says Reconnect needed and reconnects from its row", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  const row = page.locator(".cw-credential-row").filter({ has: page.locator('summary[aria-label="Actions for Work Codex"]') });
  await expect(row.locator(".cw-credential-status")).toHaveText("Reconnect needed");
  await expect(row.locator(".cw-credential-status")).toHaveAttribute("data-tone", "warning");
  // The action is on the row itself, not only inside the ⋯ menu.
  const reconnect = row.locator(":scope > form > .cw-credential-reconnect");
  await expect(reconnect).toBeVisible();
  await expect(reconnect).toHaveAccessibleName("Reconnect Work Codex");
  // Active rows keep their actions in the menu alone.
  await expect(page.locator(".cw-credential-reconnect")).toHaveCount(1);
  await fits(page, row);
  await page.screenshot({ path: test.info().outputPath("credential-reconnect-needed.png") });
  await reconnect.click();
  const editor = dialog(page, "Reconnect Work Codex");
  await expect(editor).toBeVisible();
  await expect(page.locator("dialog[open]")).toHaveCount(1);
  await expect(editor.locator('[name="credential_id"]')).toHaveValue("fixture-codex");
  await action(editor, "Cancel").click();
  await expect(editor).not.toBeVisible();
  await expect(reconnect).toBeFocused();
  expect(posts).toBe(0);
});

test("profile rows open exact-revision editors from their menu with native validation", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  const create = action(page, "Create profile");
  const row = page.locator(".cw-profile-row");
  await expect(row.locator(":scope > header")).toContainText("Codex: Work Codex Reconnect needed, GitHub: @verified-user, SSH: Work SSH");
  await expect(row.locator(":scope > header")).not.toContainText("Revision");
  // Only identities that are not active carry a status in the summary.
  await expect(row.locator(":scope > header .cw-credential-status")).toHaveText(["Reconnect needed", "Revoked"]);
  await create.click();
  const editor = dialog(page, "Create profile");
  await footer(editor, "Create profile");
  // Codex, OpenAI, Anthropic and SSH; GitHub is always the account connection.
  await expect(editor.getByRole("combobox")).toHaveCount(4);
  await expect(editor.getByRole("combobox", { name: "GitHub", exact: true })).toHaveCount(0);
  await expect(editor.getByLabel("Profile name", { exact: true })).toBeFocused();
  await editor.getByLabel("Profile name", { exact: true }).fill("Not a valid name");
  await action(editor, "Create profile").click();
  await expect(editor).toBeVisible();
  expect(await editor.locator("form:not(.cw-dialog-launcher)").evaluate((form: HTMLFormElement) => form.checkValidity())).toBe(false);
  await fits(page, editor);
  await page.screenshot({ path: test.info().outputPath("create-profile-dialog.png") });
  await action(editor, "Cancel").click();
  await discard(page);
  await expect(create).toBeFocused();
  const menu = await rowMenu(row);
  await expect(menuItems(menu)).toHaveText(["Rename", "Edit identities", "Delete"]);
  await action(menu, "Edit identities").click();
  const edit = dialog(page, "Edit work");
  await footer(edit, "Save profile");
  await expect(edit.getByText("Revision 7. Saving creates a new revision; existing Sandboxes keep their bound revision.", { exact: true })).not.toBeVisible();
  await expect(edit.locator('[name="expected_revision"]')).toHaveValue("7");
  await expect(edit.getByRole("combobox", { name: "GitHub", exact: true })).toHaveCount(0);
  const codex = edit.getByRole("combobox", { name: "Codex", exact: true });
  await expect(codex).toHaveValue("fixture-codex");
  // Reverted values are clean; untouched/default selects do not warn.
  await codex.selectOption("");
  await codex.selectOption("fixture-codex");
  await action(edit, "Cancel").click();
  await expect(prompt(page)).not.toBeVisible();
  await expect(action(menu, "Edit identities")).toBeFocused();
  await action(menu, "Edit identities").click();
  await edit.locator('[name="expected_revision"]').evaluate((node: HTMLInputElement) => { node.value = "8"; });
  await codex.selectOption("");
  await action(edit, "Cancel").click();
  await discard(page);
  await action(menu, "Edit identities").click();
  await expect(codex).toHaveValue("fixture-codex");
  await expect(edit.locator('[name="expected_revision"]')).toHaveValue("8");
  expect(posts).toBe(0);
});

test("profile Rename edits one name at the observed revision and posts only the label", async ({ page }) => {
  const posts: { path: string; fields: Record<string, string> }[] = [];
  await page.route("**/settings/credentials/_actions/**", async (route) => {
    const request = route.request();
    posts.push({ path: new URL(request.url()).pathname, fields: Object.fromEntries(new URLSearchParams(request.postData() || "")) });
    await route.fulfill({ status: 204 });
  });
  const menu = await rowMenu(page.locator(".cw-profile-row"));
  await action(menu, "Rename").click();
  const rename = dialog(page, "Rename work");
  await footer(rename, "Save name");
  await expect(page.locator("dialog[open]")).toHaveCount(1);
  const field = rename.getByLabel("New name", { exact: true });
  await expect(field).toBeFocused();
  await expect(field).toHaveValue("work");
  await expect(rename.getByRole("textbox")).toHaveCount(1);
  await expect(rename.getByRole("combobox")).toHaveCount(0);
  await expect(rename.locator('[name="profile_id"]')).toHaveValue("fixture-profile");
  await expect(rename.locator('[name="expected_revision"]')).toHaveValue("7");
  await expect(rename.locator('[name="expected_name"]')).toHaveValue("work");
  // Create profile's native name rules apply before anything is sent.
  await field.fill("Not a valid name");
  await action(rename, "Save name").click();
  await expect(rename).toBeVisible();
  expect(await rename.locator("form:not(.cw-dialog-launcher)").evaluate((form: HTMLFormElement) => form.checkValidity())).toBe(false);
  expect(posts).toEqual([]);
  // An edited name asks before Cancel discards it, then returns to the menu.
  await action(rename, "Cancel").click();
  await discard(page);
  await expect(action(menu, "Rename")).toBeFocused();
  await action(menu, "Rename").click();
  await expect(field).toHaveValue("work");
  await field.fill("personal");
  await fits(page, rename);
  await page.screenshot({ path: test.info().outputPath("profile-rename-dialog.png") });
  await action(rename, "Save name").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual({ path: "/settings/credentials/_actions/profiles/rename", fields: {
    _csrf: "design-fixture-only", profile_id: "fixture-profile", expected_revision: "7", expected_name: "work", name: "personal",
  } });
});

test("Keep editing, Escape and backdrop retain private DOM and fresh hidden authority", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  await choose(page, "OpenAI API key");
  const api = dialog(page, "Add OpenAI API key");
  const key = api.getByLabel("API key", { exact: true });
  await key.fill("synthetic-kept-private-value");
  await api.locator('[name="_csrf"]').evaluate((node: HTMLInputElement) => { node.value = "fresh-csrf-fence"; });
  await page.keyboard.press("Escape");
  await expect(action(prompt(page), "Keep editing")).toBeFocused();
  await page.screenshot({ path: test.info().outputPath("discard-changes-dialog.png") });
  await page.keyboard.press("Escape");
  await expect(key).toBeFocused();
  await expect(key).toHaveValue("synthetic-kept-private-value");
  await action(api, "Cancel").click();
  await action(prompt(page), "Keep editing").click();
  await expect(action(api, "Cancel")).toBeFocused();
  await page.mouse.click(2, 2);
  await expect(prompt(page)).toBeVisible();
  await page.mouse.click(2, 2);
  await expect(prompt(page)).not.toBeVisible();
  await expect(key).toHaveValue("synthetic-kept-private-value");
  await action(api, "Cancel").click();
  await discard(page);
  await expect(page.locator("#openai-api-key-value")).toHaveValue("");
  await expect(page.locator('#add-openai-api-key [name="_csrf"]')).toHaveValue("fresh-csrf-fence");
  expect(posts).toBe(0);
});

test("inner form replacement fences pending dismissal and preserves new validation", async ({ page }) => {
  await choose(page, "Anthropic API key");
  const api = dialog(page, "Add Anthropic API key");
  await api.getByLabel("API key", { exact: true }).fill("synthetic-old-draft");
  await action(api, "Cancel").click();
  await expect(prompt(page)).toBeVisible();
  // Emulate a late owner-form HTMX replacement from test code only.
  await api.locator("form:not(.cw-dialog-launcher)").evaluate((form) => {
    const replacement = form.cloneNode(true) as HTMLFormElement;
    (replacement.elements.namedItem("value") as HTMLInputElement).value = "";
    const error = document.createElement("p");
    error.setAttribute("role", "alert");
    error.textContent = "The credential changed. Review the current form.";
    replacement.prepend(error);
    form.replaceWith(replacement);
  });
  await expect(prompt(page)).not.toBeVisible();
  await expect(api).toBeVisible();
  await expect(api.getByRole("alert")).toHaveText("The credential changed. Review the current form.");
  await expect(api.getByLabel("API key", { exact: true })).toHaveValue("");
  await action(api, "Cancel").click();
  await expect(api).not.toBeVisible();
});

test("reconnect consent and destructive confirms preserve exact authority and never submit on navigation", async ({ page }) => {
  const posts: { path: string; fields: Record<string, string> }[] = [];
  await page.route("**/settings/credentials/_actions/**", async (route) => {
    const request = route.request();
    posts.push({ path: new URL(request.url()).pathname, fields: Object.fromEntries(new URLSearchParams(request.postData() || "")) });
    await route.fulfill({ status: 204 });
  });
  const github = await rowMenu(page.locator(".cw-credential-row").filter({ hasText: "verified-user" }));
  await expect(menuItems(github)).toHaveText(["Reconnect", "Disconnect GitHub"]);
  await action(github, "Reconnect").click();
  const reconnect = dialog(page, "Reconnect verified-user");
  await footer(reconnect, "Continue to GitHub");
  const consent = reconnect.getByRole("checkbox");
  await consent.check();
  await action(reconnect, "Cancel").click();
  await action(prompt(page), "Keep editing").click();
  await expect(consent).toBeChecked();
  await action(reconnect, "Cancel").click();
  await discard(page);
  await action(github, "Reconnect").click();
  await expect(consent).not.toBeChecked();
  await expect(reconnect.locator('[name="expected_revocation_generation"]')).toHaveValue("1");
  await action(reconnect, "Cancel").click();
  // GitHub has no revoke step: one confirmed Disconnect removes the connection.
  await expect(action(github, "Revoke")).toHaveCount(0);
  await action(github, "Disconnect GitHub").click();
  const removal = dialog(page, "Disconnect GitHub?");
  await footer(removal, "Disconnect GitHub");
  await expect(action(removal, "Cancel")).toBeFocused();
  await expect(removal).toContainText("Profiles show GitHub as missing until you connect again");
  await page.screenshot({ path: test.info().outputPath("github-delete-confirmation.png") });
  await fits(page, removal);
  expect(posts).toEqual([]);
  await action(removal, "Disconnect GitHub").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual({ path: "/settings/credentials/_actions/credentials/delete", fields: {
    _csrf: "design-fixture-only", credential_id: "fixture-github", expected_revocation_generation: "1",
  } });
  await action(removal, "Cancel").click();
  // A revoked credential offers Delete in place of Revoke.
  const revoked = await rowMenu(page.locator(".cw-credential-row").filter({ hasText: "Old Anthropic" }));
  await expect(menuItems(revoked)).toHaveText(["Rename", "Rotate API key", "Delete"]);
  await action(revoked, "Delete").click();
  const deleted = dialog(page, "Delete Old Anthropic?");
  await footer(deleted, "Delete credential");
  await expect(deleted).toContainText("no profile references");
  await action(deleted, "Cancel").click();
  expect(posts).toHaveLength(1);
});

test("leaving a retained document clears private values without changing hidden bindings", async ({ page }) => {
  await choose(page, "OpenAI API key");
  const api = dialog(page, "Add OpenAI API key");
  await api.getByLabel("API key", { exact: true }).fill("synthetic-navigation-private-value");
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
  await expect(api.getByLabel("API key", { exact: true })).toHaveValue("");
  await expect(api.locator('[name="_csrf"]')).toHaveValue("design-fixture-only");
  await expect(api.locator('[name="provider"]')).toHaveValue("openai");
});

test("explicit leaving-page Discard fences a dialog request that began after the prompt opened", async ({ page }) => {
  await choose(page, "OpenAI API key");
  const api = dialog(page, "Add OpenAI API key");
  await api.getByLabel("API key", { exact: true }).fill("private-discard-canary");
  // Controller-unit proof, using the actual HTMX lifecycle/version fence.
  // A background request may start while the native prompt is open. No real
  // mutation is aborted, retried or fabricated by this static fixture.
  const obsoleteResponsePrevented = page.evaluate(() => new Promise<boolean>((resolve) => {
    const owner = document.querySelector("#add-openai-api-key")!;
    const target = owner.querySelector("form")!;
    const xhr = {};
    document.dispatchEvent(new CustomEvent("codewire:guard-navigation", {
      cancelable: true,
      detail: { owner, perform: () => {
        const response = new CustomEvent("htmx:beforeOnLoad", { cancelable: true, detail: { xhr } });
        resolve(!document.dispatchEvent(response));
      } },
    }));
    document.dispatchEvent(new CustomEvent("htmx:beforeRequest", { detail: { target, xhr } }));
  }));
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Discard changes", exact: true }).click();
  expect(await obsoleteResponsePrevented).toBe(true);
  await expect(api.getByLabel("API key", { exact: true })).toHaveValue("");
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("each dialog opens and cancels through a native GET form that keeps the Create draft", async ({ page }) => {
    const opened = page.waitForRequest((request) => request.url().includes("dialog=add-credential"));
    await page.route("**/settings-credentials.html?**", (route) => route.fulfill({ status: 204 }));
    await action(page, "Add credential").click();
    const url = new URL((await opened).url());
    // The fragment brings the dialog into view on the reloaded page.
    await expect(page.locator("form.cw-dialog-launcher").filter({ has: page.locator('input[name="dialog"][value="add-credential"]') }).first())
      .toHaveAttribute("action", "settings-credentials.html#add-credential");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      creation_draft: "00000000-0000-4000-8000-000000000003", dialog: "add-credential",
    });
    for (const form of await page.locator("form.cw-dialog-launcher").all()) {
      await expect(form).toHaveAttribute("method", "get");
      await expect(form.locator('input[name="creation_draft"]')).toHaveValue("00000000-0000-4000-8000-000000000003");
    }
    await expect(page.locator('button[type="button"][data-dialog-open], button[type="button"][data-dialog-close]')).toHaveCount(0);
  });
});
