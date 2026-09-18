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
const fits = async (page: Page, owner: Locator) => {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(await owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
};
const footer = async (owner: Locator, primary?: string, dismissal = "Cancel") => {
  await expect(owner.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
  await expect(owner.locator("[data-dialog-close]")).toHaveCount(1);
  await expect(owner.locator(".cw-dialog-actions").getByRole("button", { name: dismissal, exact: true })).toBeVisible();
  await expect(owner.locator('button[type="submit"]')).toHaveCount(primary ? 1 : 0);
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
    ["GitHub", "Connect GitHub", "Continue to GitHub", ""],
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
    await footer(editor, primary);
    await expect(action(editor, "Back")).toHaveAttribute("type", "button");
    if (provider) await expect(editor.locator('[name="provider"]')).toHaveValue(provider);
    if (name === "GitHub") {
      await expect(editor.locator('input[name="name"]')).toHaveCount(0);
      await expect(action(editor, primary)).toBeFocused();
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

test("management keeps status and expiry visible, mechanics secondary and edits focused", async ({ page }) => {
  const row = page.locator(".cw-credential-row").filter({ has: action(page, "Manage Work API") });
  await expect(row.locator(":scope > .cw-settings-muted")).toHaveText("Expires 2026-12-31 12:00 UTC");
  await expect(row.locator(":scope > .cw-credential-identity")).not.toContainText("Generation");
  await action(row, "Manage Work API").click();
  const manage = dialog(page, "Manage Work API");
  await footer(manage, undefined, "Done");
  await expect(manage.locator(".cw-credential-status")).toHaveText("Active");
  const mechanics = manage.getByText("Generation 3. Actions apply only to this exact credential generation.", { exact: true });
  await expect(mechanics).not.toBeVisible();
  await manage.getByText("Details", { exact: true }).click();
  await expect(mechanics).toBeVisible();
  await action(manage, "Rotate API key").click();
  const rotate = dialog(page, "Rotate Work API");
  await footer(rotate, "Rotate API key");
  await expect(rotate.locator('[name="credential_id"]')).toHaveValue("fixture-openai");
  await expect(rotate.locator('[name="expected_revocation_generation"]')).toHaveValue("3");
  await expect(rotate.getByLabel("Replacement API key", { exact: true })).toBeFocused();
  await action(rotate, "Back").click();
  await action(manage, "Rename").click();
  const rename = dialog(page, "Rename Work API");
  await footer(rename, "Save name");
  await expect(rename.getByLabel("New name")).toHaveValue("Work API");
  await expect(rename.locator('[name="expected_name"]')).toHaveValue("Work API");
  await action(rename, "Cancel").click();
  await expect(action(row, "Manage Work API")).toBeFocused();
  await page.screenshot({ path: test.info().outputPath("credentials-list.png") });
  await action(row, "Manage Work API").click();
  // Credential labels may be 256 characters with no whitespace. Native dialog
  // titles and read-only text must remain bounded at the mobile viewport too.
  await manage.getByRole("heading").evaluate((node) => { node.textContent = `Manage ${"a".repeat(256)}`; });
  await fits(page, page.locator("#credential-fixture-openai"));
});

test("profiles have read-only summary and exact-revision focused editors with native validation", async ({ page }) => {
  let posts = 0;
  page.on("request", (request) => { if (request.method() === "POST") posts += 1; });
  const create = action(page, "Create profile");
  const row = page.locator(".cw-profile-row");
  await expect(row.locator(":scope > header")).toContainText("Codex: Work Codex, GitHub: verified-user, SSH: Work SSH");
  await expect(row.locator(":scope > header")).not.toContainText("Revision");
  await expect(row.locator(":scope > header .cw-credential-status")).toHaveText("Revoked");
  await create.click();
  const editor = dialog(page, "Create profile");
  await footer(editor, "Create profile");
  await expect(editor.getByRole("combobox")).toHaveCount(5);
  await expect(editor.getByLabel("Profile name", { exact: true })).toBeFocused();
  await editor.getByLabel("Profile name", { exact: true }).fill("Not a valid name");
  await action(editor, "Create profile").click();
  await expect(editor).toBeVisible();
  expect(await editor.locator("form").evaluate((form: HTMLFormElement) => form.checkValidity())).toBe(false);
  await fits(page, editor);
  await page.screenshot({ path: test.info().outputPath("create-profile-dialog.png") });
  await action(editor, "Cancel").click();
  await discard(page);
  await expect(create).toBeFocused();
  await action(row, "Manage profile").click();
  const summary = dialog(page, "work");
  await footer(summary, undefined, "Done");
  await action(summary, "Edit profile").click();
  const edit = dialog(page, "Edit work");
  await footer(edit, "Save profile");
  await expect(edit.getByText("Revision 7. Saving creates a new revision; existing Sandboxes keep their bound revision.", { exact: true })).not.toBeVisible();
  await expect(edit.locator('[name="expected_revision"]')).toHaveValue("7");
  const github = edit.getByRole("combobox", { name: "GitHub", exact: true });
  await expect(github).toHaveValue("fixture-github");
  // Reverted values are clean; untouched/default selects do not warn.
  await github.selectOption("");
  await github.selectOption("fixture-github");
  await action(edit, "Back").click();
  await expect(prompt(page)).not.toBeVisible();
  await action(summary, "Edit profile").click();
  await edit.locator('[name="expected_revision"]').evaluate((node: HTMLInputElement) => { node.value = "8"; });
  await github.selectOption("");
  await action(edit, "Cancel").click();
  await discard(page);
  await action(row, "Manage profile").click();
  await action(summary, "Edit profile").click();
  await expect(github).toHaveValue("fixture-github");
  await expect(edit.locator('[name="expected_revision"]')).toHaveValue("8");
  expect(posts).toBe(0);
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
  await api.locator("form").evaluate((form) => {
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
  await action(page, "Manage verified-user").click();
  const manage = dialog(page, "Manage verified-user");
  await action(manage, "Reconnect").click();
  const reconnect = dialog(page, "Reconnect verified-user");
  await footer(reconnect, "Continue to GitHub");
  const consent = reconnect.getByRole("checkbox");
  await consent.check();
  await action(reconnect, "Back").click();
  await action(prompt(page), "Keep editing").click();
  await expect(consent).toBeChecked();
  await action(reconnect, "Back").click();
  await discard(page);
  await action(manage, "Reconnect").click();
  await expect(consent).not.toBeChecked();
  await expect(reconnect.locator('[name="expected_revocation_generation"]')).toHaveValue("1");
  await action(reconnect, "Back").click();
  await action(manage, "Revoke credential").click();
  const revoke = dialog(page, "Revoke verified-user?");
  await footer(revoke, "Revoke credential");
  await expect(action(revoke, "Cancel")).toBeFocused();
  await expect(revoke).toContainText("Existing Sandbox bindings are not reassigned");
  await page.screenshot({ path: test.info().outputPath("revoke-confirmation.png") });
  await fits(page, revoke);
  expect(posts).toEqual([]);
  await action(revoke, "Revoke credential").click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toEqual({ path: "/settings/credentials/_actions/credentials/revoke", fields: {
    _csrf: "design-fixture-only", credential_id: "fixture-github", expected_revocation_generation: "1",
  } });
  await action(revoke, "Cancel").click();
  await action(page, "Manage Old Anthropic").click();
  await action(dialog(page, "Manage Old Anthropic"), "Delete credential").click();
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
