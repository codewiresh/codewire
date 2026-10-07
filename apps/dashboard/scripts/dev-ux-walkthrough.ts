// Runs ONLY inside the existing protected Dev auth helper. No traces, page
// dumps, screenshots, stored browser sessions, or provider authorizations.
import { expect, request, type Locator, type Page } from "@playwright/test";
import { DevUxError, type OwnedUxSandbox } from "./dev-ux-ownership";

const ORIGIN = "https://codewire-dev.sh";
// Re-attaching a surviving terminal after navigation, reload, reconnect, or
// closing another tab takes a few seconds on Dev; the 5s expect default is
// shorter than that real round trip.
const TERMINAL_ATTACH_MS = 30_000;
const button = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });
// The Sandbox workspace keeps terminal actions and Sandbox actions in two
// menus; open one, as a person does, before using what it holds.
async function workspaceMenu(page: Page, menu: "Terminal actions" | "More actions"): Promise<Locator> {
  const details = page.locator(menu === "Terminal actions" ? "[data-terminal-menu]" : "[data-sandbox-menu]");
  if (!(await details.evaluate((node) => (node as HTMLDetailsElement).open))) await details.locator(":scope > summary").click();
  await expect(details).toHaveJSProperty("open", true);
  return details;
}

function passed(name: string, started: number): void {
  console.error(`[dev-ux] ${name}:passed duration_ms=${Date.now() - started}`);
}

// `started` defaults to the call; pass an earlier instant to time from an
// event that precedes the step, such as the server accepting Create.
async function stage(name: string, operation: () => Promise<void>, started = Date.now()): Promise<void> {
  // A step may raise a narrower fixed label; anything else maps to the step.
  try { await operation(); } catch (error) {
    throw error instanceof DevUxError && error.stage.startsWith(`${name}-`) ? error : new DevUxError(name);
  }
  passed(name, started);
}

async function visit(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN}${path}`, { waitUntil: "domcontentloaded" });
  const actual = new URL(page.url());
  if (actual.origin !== ORIGIN || actual.pathname !== path.split("?")[0]) throw new DevUxError("ux-route");
}

// Layout settles after resizes, dialog transitions, and terminal refits; poll
// until it fits instead of sampling one mid-transition frame.
async function fits(page: Page, owner?: Locator): Promise<void> {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), { timeout: 5_000 }).toBe(true);
  if (owner) await expect.poll(() => owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1), { timeout: 5_000 }).toBe(true);
}

// Read-only page checks below never open a create or destructive action. Rows
// and names are the Dev account's own data: each check holds for whatever rows
// exist and never assumes a count or a name.

// No unset value renders in place of a name, and every status is in words.
async function noUnsetValues(page: Page): Promise<void> {
  const main = page.locator("main");
  await expect(main).not.toContainText("null · null");
  await expect(main.getByText(/^(?:null|undefined)$/)).toHaveCount(0);
  await expect(main.locator(".cw-status").filter({ hasNotText: /\S/ })).toHaveCount(0);
}

// One Settings shell headed exactly "Settings", whose only current link is
// this page within its own group.
async function settingsShell(page: Page, group: "personal" | "organization", current: string): Promise<void> {
  const shell = page.locator(".cw-context-nav");
  await expect(shell.locator(".cw-context-nav-heading")).toHaveText("Settings");
  await expect(shell.getByRole("heading", { name: "Settings", exact: true, level: 2 })).toBeVisible();
  await expect(shell.locator('a[aria-current="page"]')).toHaveCount(1);
  await expect(shell.locator(`ul[aria-labelledby="settings-${group}-title"] a[aria-current="page"]`)).toHaveAttribute("href", current);
}

// A page title as written, never uppercased.
async function pageTitle(header: Locator, title: string): Promise<void> {
  const heading = header.getByRole("heading", { level: 1 });
  await expect(heading).toHaveText(title);
  await expect(heading).toHaveCSS("text-transform", "none");
}

// GitHub reconnects or disconnects; other credentials rename, optionally
// reconnect or rotate, then revoke while active or delete once revoked.
const CREDENTIAL_MENU = /^(?:Reconnect,Disconnect GitHub|Rename(?:,Reconnect)?(?:,Rotate API key)?,(?:Revoke|Delete))$/;
const menuItems = (rows: Locator) => rows.evaluateAll((nodes) => nodes.map((row) => Array.from(
  row.querySelectorAll(":scope > details.cw-menu .cw-menu-item"), (item) => item.textContent?.trim()).join(",")));

// Credential rows show an icon, a name, a status in words and one actions menu
// holding only that row's actions: no Manage step, generation or revision.
// Profile rows show the account's GitHub connection, or that it is missing.
async function credentialRows(page: Page): Promise<void> {
  const credentials = page.locator(".cw-credential-row");
  const profiles = page.locator(".cw-profile-row");
  const count = await credentials.count();
  if (!count) await expect(page.getByText("No credentials yet. Add a provider account, API key or SSH identity to get started.", { exact: true })).toBeVisible();
  await expect(page.locator(".cw-credential-row > .cw-credential-identity > svg.cw-icon")).toHaveCount(count);
  await expect(page.locator(".cw-credential-row > .cw-credential-identity strong").filter({ hasText: /\S/ })).toHaveCount(count);
  await expect(page.locator(".cw-credential-row > .cw-credential-status").filter({ hasText: /\S/ })).toHaveCount(count);
  await expect(page.locator('.cw-credential-row > details.cw-menu > summary[aria-label^="Actions for "]')).toHaveCount(count);
  await expect(credentials.filter({ hasText: /Generation|Revision/ })).toHaveCount(0);
  const credentialMenus = await menuItems(credentials);
  for (const menu of credentialMenus) expect(menu).toMatch(CREDENTIAL_MENU);
  if (!await profiles.count()) await expect(page.getByText("No profiles yet. Create a profile from your credentials, then select it for a Sandbox.", { exact: true })).toBeVisible();
  await expect(page.locator(".cw-profile-row > header").filter({ hasText: /Generation|Revision/ })).toHaveCount(0);
  for (const menu of await menuItems(profiles)) expect(menu).toBe("Rename,Edit identities,Delete");
  const github = credentialMenus.some((menu) => menu.endsWith("Disconnect GitHub")) ? /GitHub: @\S/ : /GitHub: missing/;
  for (const summary of await profiles.locator(":scope > header").allTextContents()) expect(summary).toMatch(github);
  await expect(page.locator(":is(.cw-credential-row, .cw-profile-row)").getByRole("button", { name: /^Manage\b/ })).toHaveCount(0);
  // The keyboard opens the first row menu; Escape closes it and returns focus.
  // Nothing in the menu is chosen.
  const menu = page.locator(":is(.cw-credential-row, .cw-profile-row) > details.cw-menu").first();
  if (await menu.count()) {
    const trigger = menu.locator(":scope > summary");
    await trigger.focus();
    await page.keyboard.press("Enter");
    await expect(menu).toHaveAttribute("open", "");
    await expect(menu.locator(".cw-menu-item").first()).toBeVisible();
    await fits(page);
    await page.keyboard.press("Escape");
    await expect(menu).not.toHaveAttribute("open", "");
    await expect(trigger).toBeFocused();
  }
}

// Settings lists the account's own keys across its organizations, each linked
// to that organization's inventory, and Create asks which organization a key
// belongs to. Create is never opened here.
async function personalApiKeys(page: Page): Promise<void> {
  const header = page.locator(".cw-settings-content > .cw-page-header");
  await pageTitle(header, "API keys");
  await expect(header.locator(".cw-page-title-row .cw-badge")).toHaveText(/^\d+ keys?$/);
  await expect(header.locator(".cw-page-description")).toHaveText("Codewire API keys you created, for the CLI and SDK. Each key belongs to one organization.");
  await expect(button(header, "Create key")).toBeEnabled();
  const organization = page.locator("#create-personal-api-key-org");
  await expect(organization).toHaveAttribute("required", "");
  await expect(organization.locator("option").first()).toHaveAttribute("value", "");
  await expect(organization.locator("option").filter({ hasText: /^(?:null|undefined)$|null · null/ })).toHaveCount(0);
  await expect(page.getByRole("search", { name: "Filter API keys", exact: true })).toBeVisible();
  await apiKeyTable(page, ["Name", "Organization", "Status", "Last used", "Expires"], "You have no API keys yet. Create one to use the Codewire CLI or SDK.");
  const owners = await page.locator(".cw-table tbody tr").evaluateAll((rows) => rows.map((row) => row.querySelector(":scope > td:nth-child(2) > a")?.getAttribute("href") ?? ""));
  for (const owner of owners) expect(owner).toMatch(/^\/[a-z0-9]+(?:-[a-z0-9]+)*\/api-keys\/$/);
}

// The organization's own inventory stays separate and scoped to it.
async function organizationApiKeys(page: Page, slug: string): Promise<void> {
  await visit(page, `/${slug}/api-keys/`);
  const header = page.locator("#organization-content > .cw-page-header");
  await pageTitle(header, "API keys");
  await expect(header.locator(".cw-page-title-row .cw-badge")).toHaveText(/^\d+ keys?$/);
  await expect(header.locator(".cw-page-description")).toHaveText(/^Codewire API keys for \S.*, for the CLI and SDK\.$/);
  await settingsShell(page, "organization", `/${slug}/api-keys/`);
  await expect(page.locator("#settings-organization-title")).toHaveText(/^Organization · \S/);
  await apiKeyTable(page, ["Name", "Created by", "Status", "Last used", "Created"], "No API keys yet. Create one for programmatic access.");
  await noUnsetValues(page);
  await fits(page);
}

// A table with declared column headers when keys exist, else the empty state.
async function apiKeyTable(page: Page, columns: string[], empty: string): Promise<void> {
  if (await page.locator(".cw-table").count()) {
    await expect(page.locator('.cw-table thead th[scope="col"]')).toHaveText([...columns, "Actions"]);
  } else {
    await expect(page.getByText(empty, { exact: true })).toBeVisible();
  }
}

// View only: never fill or submit this form.
async function createOrganization(page: Page): Promise<void> {
  await visit(page, "/organizations/new/");
  const title = page.getByRole("heading", { name: "Create Organization", exact: true, level: 1 });
  await expect(title).toBeVisible();
  await expect(title).toHaveCSS("text-transform", "none");
  expect(parseFloat(await title.evaluate((node) => getComputedStyle(node).fontSize))).toBeGreaterThanOrEqual(24);
  await expect(page.locator(".cw-form-icon")).toHaveCount(0);
  await expect(page.getByText("Organizations group your Sandboxes and team members together")).toHaveCount(0);
  const panel = (await page.locator(".cw-form-page").boundingBox())!;
  const name = (await page.getByLabel("Organization name", { exact: true }).boundingBox())!;
  expect(panel.width).toBeLessThanOrEqual(512);
  expect(name.width).toBeLessThan(panel.width);
  await fits(page);
}

async function credentials(page: Page, slug: string, width: number): Promise<void> {
  const add = button(page, "Add credential");
  const chooser = dialog(page, "Add credential");
  await stage(`credentials-page-${width}`, async () => {
    await visit(page, `/settings/credentials/?org=${slug}`);
    await expect(page.getByRole("heading", { name: "Credentials", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Profiles", exact: true, level: 2 })).toBeVisible();
    await expect(page.locator(".cw-settings-content > .cw-page-header .cw-page-description"))
      .toHaveText("Add and manage provider credentials for things like GitHub, SSH keys, Claude, and Codex.");
    await settingsShell(page, "personal", "/settings/credentials/");
    await credentialRows(page);
    // Git commit identity is attribution, apart from authentication and profiles.
    const identity = page.locator("#git-identity");
    await expect(identity.getByRole("heading", { name: "Git commit identity", exact: true, level: 2 })).toBeVisible();
    await expect(identity.locator(".cw-card-description"))
      .toHaveText("Author name and email for Sandbox commits. This is commit attribution, not a GitHub login, provider credential or profile member.");
    await expect(identity.getByText("Clear either field to use its independent account fallback. Connecting GitHub does not overwrite your Codewire email.")).toBeVisible();
    for (const field of ["Commit author name", "Commit author email"]) await expect(identity.getByLabel(field, { exact: true })).toBeVisible();
    await noUnsetValues(page);
  });
  await stage(`credentials-chooser-${width}`, async () => {
    await add.click();
    await expect(chooser.locator(".cw-credential-types > li")).toHaveCount(6);
    await expect(chooser.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
    await fits(page, chooser);
  });
  for (const [key, choice, title] of [
    ["github", "GitHub", "Connect GitHub"], ["codex", "Codex", "Connect Codex"],
    ["openai", "OpenAI API key", "Add OpenAI API key"], ["anthropic", "Anthropic API key", "Add Anthropic API key"],
    ["claude", "Claude subscription token", "Add Claude subscription token"], ["ssh", "SSH key", "Add SSH key"],
  ]) {
    await stage(`credentials-${key}-${width}`, async () => {
      await button(chooser, choice).click();
      const editor = dialog(page, title);
      await expect(editor).toBeVisible();
      await expect(page.locator("dialog[open]")).toHaveCount(1);
      await expect(editor.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
      await expect(editor.locator("[data-dialog-close]")).toHaveCount(1);
      if (choice === "GitHub") {
        await expect(editor.locator('input[name="name"]')).toHaveCount(0);
        // One account-level connection: connected accounts see it and can
        // reconnect; others continue to GitHub.
        if (await editor.getByText(/is already connected/).count()) {
          await expect(button(editor, "Reconnect")).toBeVisible();
          await expect(button(editor, "Disconnect")).toBeVisible();
        } else {
          await expect(button(editor, "Continue to GitHub")).toBeVisible();
        }
      }
      await fits(page, editor);
      await button(editor, "Back").click();
      await expect(button(chooser, choice)).toBeFocused();
    });
  }
  await stage(`credentials-profile-${width}`, async () => {
    await button(chooser, "Cancel").click();
    await expect(add).toBeFocused();
    await button(page, "Create profile").click();
    const profile = dialog(page, "Create profile");
    await expect(profile.getByLabel("Profile name", { exact: true })).toBeFocused();
    for (const provider of ["Codex", "OpenAI API", "Anthropic", "SSH"]) {
      await expect(profile.getByLabel(provider, { exact: true })).toBeVisible();
    }
    // GitHub is one account-level connection included in every profile, not a
    // per-profile choice.
    await expect(profile.getByLabel("GitHub", { exact: true })).toHaveCount(0);
    await fits(page, profile);
    await button(profile, "Cancel").click();
  });
}

async function settings(page: Page, slug: string, width: number): Promise<void> {
  for (const [scope, query] of [["organization", `?org=${slug}`], ["personal", ""]] as const) {
    await stage(`settings-account-${scope}-${width}`, async () => {
      await visit(page, `/settings/${query}`);
      for (const title of ["Account details", "Security", "Active sessions"]) {
        await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
      }
      // A plain "Account" title and one short description, with no eyebrow.
      const header = page.locator(".cw-settings-content > .cw-page-header");
      await pageTitle(header, "Account");
      await expect(header.locator("p")).toHaveText(["Your account details, security and browser sessions."]);
      await expect(header.getByText(/personal/i)).toHaveCount(0);
      await settingsShell(page, "personal", "/settings/");
      // Session controls are available, and this browser leads its page.
      const sessions = page.locator("#sessions");
      await expect(sessions.getByText("Session controls are unavailable")).toHaveCount(0);
      await expect(sessions.locator(".cw-account-sessions")).toHaveCount(1);
      const rows = sessions.locator(".cw-account-session");
      if (await rows.getByRole("heading", { name: "This browser", exact: true }).count()) {
        await expect(rows.first().locator(":scope > header > h3")).toHaveText("This browser");
        await expect(rows.first().locator(":scope > header > p")).toHaveText(/^Signed in .+ · Expires .+$/);
      }
      await noUnsetValues(page);
      await fits(page);
      if (scope === "personal") {
        // Old Security and Sessions links land on their Account sections.
        if (width === 1440) {
          for (const section of ["security", "sessions"]) {
            await page.goto(`${ORIGIN}/settings/${section}/`, { waitUntil: "domcontentloaded" });
            await expect(page).toHaveURL(`${ORIGIN}/settings/#${section}`);
            await expect(page.getByRole("heading", { name: "Account", exact: true, level: 1 })).toBeVisible();
          }
        }
        // No stage owns Create Organization; it is an account page.
        await createOrganization(page);
      }
    });
    for (const [path, title] of [["secrets", "Secrets"], ["api-keys", "API keys"]]) {
      await stage(`settings-${path}-${scope}-${width}`, async () => {
        await visit(page, `/settings/${path}/${query}`);
        await expect(page.getByRole("heading", { name: title, exact: true, level: 1 })).toBeVisible();
        await settingsShell(page, "personal", `/settings/${path}/`);
        if (path === "api-keys") await personalApiKeys(page);
        await noUnsetValues(page);
        await fits(page);
        if (path === "api-keys" && scope === "organization") await organizationApiKeys(page, slug);
      });
    }
  }
}

// Each step is its own fixed stage so a Dev failure names the failing step.
async function createForm(page: Page, slug: string, userId: string, orgId: string, width: number): Promise<void> {
  const form = page.locator("[data-environment-form]");
  const github = page.locator("[data-github-browser]");
  await stage(`create-editable-${width}`, async () => {
    await visit(page, `/${slug}/new/`);
    await expect(form).toHaveAttribute("data-create-draft-actor", userId);
    await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
  });
  await stage(`create-options-${width}`, async () => {
    await expect(form).toHaveAttribute("data-create-options-loading", "false", { timeout: 30_000 });
    await expect(form.locator('[name="confirm_personal_credentials"], [name="confirm_personal_secrets"]')).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Manage personal secrets", exact: true })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Manage provider credentials" }).getByRole("link")).toBeVisible();
  });
  await stage(`create-github-${width}`, async () => {
    await expect(github.getByRole("heading", { name: "From GitHub", exact: true })).toBeVisible();
    await expect(github.getByText("GitHub account", { exact: true })).toBeVisible();
    await expect(github.locator("[data-github-connection-status]")).toBeVisible();
    await expect(github.getByRole("searchbox", { name: "Find a repository" })).toBeVisible();
    await expect(github.locator("[data-github-setup-link]")).toHaveText(/^(Connect GitHub|Reconnect GitHub|Manage GitHub connection)$/);
  });
  await stage(`create-preview-${width}`, async () => {
    await expect(page.getByLabel("Repository URL", { exact: true })).toBeVisible();
    await expect(page.locator(".cw-preview-pattern")).toContainText("https://{label}-{sandbox-id-prefix}-");
    await expect(dialog(page, "Choose a GitHub repository")).toHaveCount(0);
  });
  await stage(`create-fit-${width}`, async () => {
    await fits(page, github);
    await fits(page, page.locator("#environment-create-card"));
    // CPU, Memory, Disk and Delete after share one row on desktop and two on a
    // phone, each with its own help beside its label.
    const resources = page.locator(".cw-create-resources");
    const tops = await resources.locator(":scope > .cw-field").evaluateAll((fields) =>
      fields.map((field) => Math.round(field.getBoundingClientRect().top)));
    expect(tops).toHaveLength(4);
    if (width === 1440) expect(new Set(tops).size).toBe(1);
    else expect([tops[0] === tops[1], tops[2] === tops[3], tops[2] > tops[0]]).toEqual([true, true, true]);
    for (const [name, help, text] of [
      ["About CPU", "cpu", "1000 millicores equals 1 vCPU."], ["About memory", "memory", "1024 MiB equals 1 GiB."],
      ["About disk", "disk", "Workspace disk size is measured in GiB."],
      ["About automatic deletion", "ttl", "Stop and activity do not cancel the deadline; setup and Start reschedule it."],
    ]) {
      await expect(button(resources, name)).toBeVisible();
      await expect(page.locator(`#environment-${help}-help`)).toContainText(text);
    }
    await expect(page.locator("#environment-ttl-help")).toContainText("Schedules automatic deletion of the Sandbox and workspace files; this is not an idle timeout.");
    // The keyboard reaches the CPU help from Name; Escape closes only the help.
    const cpuHelp = page.locator("#environment-cpu-help");
    await page.getByLabel("Name", { exact: true }).focus();
    await page.keyboard.press("Tab");
    await expect(button(resources, "About CPU")).toBeFocused();
    await expect(cpuHelp).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(cpuHelp).toBeHidden();
    await expect(form).toBeVisible();
    // Section headings read exactly like the field labels around them.
    const textStyle = (owner: Locator) => owner.evaluate((node) => {
      const style = getComputedStyle(node);
      return `${style.color} ${style.fontSize} ${style.fontWeight}`;
    });
    const label = await textStyle(page.locator('label[for="environment-name"]'));
    for (const heading of ["#create-resources-title", "#create-repositories-title"]) expect(await textStyle(page.locator(heading))).toBe(label);
  });
  // Read-only setup detours: do not create credentials or application secrets.
  for (const destination of ["secrets", "credentials"]) {
    await stage(`create-detour-${destination}-${width}`, async () => {
      await page.locator("#environment-create-card").getByLabel("CPU", { exact: true }).selectOption("2000");
      await page.getByLabel("Delete after", { exact: true }).fill("8h");
      await page.getByLabel("Name", { exact: true }).fill(`dev-ux-draft-${destination}`);
      await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
      const draft = await form.getAttribute("data-create-draft-id");
      expect(draft).toMatch(/^[0-9a-f-]{36}$/);
      const setup = destination === "secrets"
        ? page.getByRole("link", { name: "Manage personal secrets", exact: true })
        : page.getByRole("navigation", { name: "Manage provider credentials" }).getByRole("link");
      await setup.click();
      // A dirty form asks before leaving; the saved draft is kept.
      // Personal Settings carry no organization; the draft handle alone returns.
      const destinationUrl = `${ORIGIN}/settings/${destination}/?creation_draft=${draft}`;
      const leave = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
      await Promise.race([page.waitForURL(destinationUrl), leave.waitFor()]);
      if (await leave.isVisible()) await button(leave, "Save draft and leave").click();
      await expect(page).toHaveURL(destinationUrl);
      const back = page.getByRole("link", { name: "Return to Create Sandbox", exact: true });
      await expect(back).toHaveAttribute("href", `/${slug}/new/?creation_draft=${draft}`);
      await back.click();
      await expect(form).toHaveAttribute("data-create-draft-id", draft!);
      await expect(form).toHaveAttribute("data-create-draft-actor", userId);
      await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
      // The exact draft comes back by itself after the detour.
      await expect(form).toHaveAttribute("data-create-draft-restored", "true");
      await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
      await expect(page.locator('[name="ttl"]')).toHaveValue("8h");
      await expect(page.getByLabel("Name", { exact: true })).toHaveValue(`dev-ux-draft-${destination}`);
      await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("");
      await fits(page, page.locator("#environment-create-card"));
    });
  }
}

export async function runDevUxWalkthrough(page: Page, options: {
  slug: string; userId: string; orgId: string; owned: OwnedUxSandbox; deadline: number;
}): Promise<void> {
  const { slug, userId, orgId, owned, deadline } = options;
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(30_000);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await credentials(page, slug, width);
    await settings(page, slug, width);
    if (width === 1440) {
      await stage("settings-to-create-1440", async () => {
        // Personal pages visited directly carry no organization context, so
        // start from organization-scoped Settings, where Create is offered.
        await visit(page, `/settings/?org=${slug}`);
        await page.getByRole("link", { name: "Create Sandbox", exact: true }).first().click();
        const form = page.locator("[data-environment-form]");
        await expect(form).toHaveAttribute("data-create-draft-actor", userId);
        await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
      });
    }
    await createForm(page, slug, userId, orgId, width);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  let previewPattern = "";
  await stage("create-sandbox", async () => {
    await owned.admit(deadline);
    previewPattern = (await page.locator(".cw-preview-pattern").innerText()).trim();
    await page.getByLabel("Name", { exact: true }).fill(owned.name);
    await page.locator("#environment-create-card").getByLabel("CPU", { exact: true }).selectOption("1000");
    await page.locator("#environment-create-card").getByLabel("Memory", { exact: true }).selectOption("2048");
    await page.locator("#environment-create-card").getByLabel("Disk", { exact: true }).selectOption("10");
    // Create names the exact units the detail page and Resize show.
    for (const [field, unit] of [["CPU", "1 vCPU"], ["Memory", "2 GiB"], ["Disk", "10 GiB"]]) {
      await expect(page.locator("#environment-create-card").getByLabel(field, { exact: true }).locator("option:checked")).toHaveText(unit);
    }
    await page.getByLabel("Delete after", { exact: true }).fill("1h");
    // Use the product's configured default image. Never inherit a saved source
    // selection or attach the dedicated account's existing secrets/providers.
    await page.locator("[data-reset-workspace-image]").click();
    expect(await page.getByLabel("Workspace image", { exact: true }).inputValue()).not.toBe("");
    await expect(page.getByLabel("Credential profile", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
    await expect(page.getByLabel("Organization secrets", { exact: false })).not.toBeChecked();
    await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("");
    for (const agent of await page.locator('input[name="agent"]').all()) await agent.uncheck();
  });
  // Time the backend start apart from the UI checks. New terminal is enabled
  // only after setup completes and the runtime is ready.
  let submitted = 0;
  let accepted = 0;
  await stage("create-submit", async () => {
    owned.beforeCreate();
    submitted = Date.now();
    await button(page, "Create Sandbox").click();
    // Create lands on the new Sandbox's page, which has several live statuses.
    await expect(page.getByRole("status").filter({ hasText: "Sandbox creation started" })).toBeVisible();
    accepted = Date.now();
  });
  const id = await owned.createdId(deadline);
  const detailPath = `/${slug}/${id}/`;
  const terminal = page.locator("[data-terminal-tab-panel]:not([hidden]) [data-terminal-root]");
  const rows = terminal.locator(".xterm-rows");
  const send = async (command: string) => {
    await terminal.locator("textarea").focus();
    await page.keyboard.type(command);
    await page.keyboard.press("Enter");
  };
  let firstId: string | null = null;
  let pid = "";
  let job = "";
  // Backend start runs while the ownership lookup above resolves the ID, so
  // time it from acceptance rather than from this step's own start.
  await stage("create-to-terminal-enabled", async () => {
    await visit(page, detailPath);
    await expect(button(page, "New terminal")).toBeEnabled({ timeout: 240_000 });
  }, accepted);
  await stage("terminal-attach", async () => {
    await button(page, "New terminal").click();
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: 60_000 });
    firstId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(firstId).toBeTruthy();
  });
  passed("create-to-terminal", submitted);
  await stage("terminal-colors-copy", async () => {
    await send("export CW_UX_SESSION=preserved; printf '\\033[31m__UX_RED__\\033[0m\\n__UX_COPY__\\n__UX_PID__%s__\\n' \"$$\"");
    await expect(rows).toContainText(/__UX_PID__\d+__/);
    pid = /__UX_PID__(\d+)__/.exec(await rows.innerText())![1];
    await expect(rows.getByText("__UX_RED__", { exact: true })).toHaveCSS("color", "rgb(204, 0, 0)");
    await expect(rows).toHaveCSS("font-family", /IBM Plex Mono/);
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: ORIGIN });
    const bounds = (await rows.getByText("__UX_COPY__", { exact: true }).boundingBox())!;
    await page.mouse.move(bounds.x, bounds.y + bounds.height / 2);
    await page.mouse.down();
    await page.mouse.move(bounds.x + bounds.width, bounds.y + bounds.height / 2, { steps: 12 });
    await page.mouse.up();
    await button(await workspaceMenu(page, "Terminal actions"), "Copy selection").click();
    await expect(page.locator("[data-terminal-session-status]:not([hidden]) [data-terminal-copy-status]")).toHaveText("Selection copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("__UX_COPY__");
  });
  const rename = dialog(page, "Rename terminal");
  const close = dialog(page, "Close terminal?");
  let secondId: string | null = null;
  await stage("terminal-tabs-job", async () => {
    // The job must outlive every terminal stage below, including slow
    // attaches; the disposable Sandbox is destroyed at the end of the run.
    await send("cd /tmp; sleep 3600 & CW_UX_JOB=$!; printf '__UX_JOB__%s__\\n' \"$CW_UX_JOB\"");
    await expect(rows).toContainText(/__UX_JOB__\d+__/);
    job = /__UX_JOB__(\d+)__/.exec(await rows.innerText())![1];
  });
  await stage("terminal-tabs-rename", async () => {
    await button(await workspaceMenu(page, "Terminal actions"), "Rename terminal").click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("UX shell");
    await button(rename, "Save name").click();
  });
  await stage("terminal-tabs-navigation", async () => {
    await visit(page, `/settings/?org=${slug}`);
    await visit(page, detailPath);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstId!);
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
  });
  await stage("terminal-tabs-second", async () => {
    await button(page, "New terminal").click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    secondId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(secondId).toBeTruthy();
    expect(secondId).not.toBe(firstId);
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
    await send("printf '__UX_SECOND__%s__%s__\\n' \"${CW_UX_SESSION-unset}\" \"$$\"");
    await expect(rows).toContainText(/__UX_SECOND__unset__\d+__/);
    expect(/__UX_SECOND__unset__(\d+)__/.exec(await rows.innerText())![1]).not.toBe(pid);
  });
  await stage("terminal-tabs-reload", async () => {
    await button(await workspaceMenu(page, "Terminal actions"), "Rename terminal").click();
    await rename.getByLabel("Terminal name", { exact: true }).fill("UX logs");
    await button(rename, "Save name").click();
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.getByRole("tab")).toHaveText(["UX shell", "UX logs"]);
    await expect(page.getByRole("tab", { name: "UX logs", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", secondId!);
  });
  await stage("terminal-tabs-reconnect", async () => {
    await page.getByRole("tab", { name: "UX shell", exact: true }).click();
    await button(page, "Disconnect").click();
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
    await button(page, "Reconnect").click();
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
    await send("test \"$(jobs -pr)\" = \"$CW_UX_JOB\" && kill -0 \"$CW_UX_JOB\" && printf '__UX_RESUMED__%s__%s__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\" \"$PWD\" \"$CW_UX_JOB\"");
    await expect(rows).toContainText(`__UX_RESUMED__preserved__${pid}__/tmp__${job}__`);
  });
  await stage("terminal-tabs-switch", async () => {
    await page.getByRole("tab", { name: "UX shell", exact: true }).press("ArrowRight");
    await expect(page.getByRole("tab", { name: "UX logs", exact: true })).toBeFocused();
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", secondId!);
  });
  await stage("terminal-tabs-close", async () => {
    // Each tab carries its own close button, named for the tab.
    await button(page, "Close UX logs").click();
    await button(close, "Cancel").click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    await button(page, "Close UX logs").click();
    await button(close, "Close terminal").click();
  });
  await stage("terminal-tabs-survivor-tab", async () => {
    await expect(page.getByRole("tab")).toHaveCount(1);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstId!);
  });
  await stage("terminal-tabs-survivor-connected", async () => {
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
  });
  // Closing the confirmation dialog must leave keyboard input with the
  // surviving terminal before anything is typed into it.
  await stage("terminal-tabs-survivor-focus", async () => {
    await terminal.locator("textarea").focus();
    await expect(terminal.locator("textarea")).toBeFocused();
  });
  await stage("terminal-tabs-survivor-shell", async () => {
    // Always print, so a changed shell reports a mismatch instead of silence.
    await send("printf '__UX_SURVIVOR__%s__%s__%s__%s__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\" \"$PWD\" \"$CW_UX_JOB\" \"$(jobs -pr)\" \"$(kill -0 \"$CW_UX_JOB\" 2>/dev/null && echo alive || echo gone)\"");
    try {
      await expect(rows).toContainText(`__UX_SURVIVOR__preserved__${pid}__/tmp__${job}__${job}__alive__`);
    } catch {
      // Value-blind classification from fixed tokens only: lost input or
      // redraw, a command that ran without output, different values, or a
      // terminal that detached.
      const text = await rows.innerText().catch(() => "");
      const detached = !(await button(page, "Disconnect").isEnabled().catch(() => false));
      const kind = detached ? "detached"
        : /__UX_SURVIVOR__(?!%s)/.test(text) ? "mismatch"
        : text.includes("jobs -pr") ? "no-output"
        : "no-echo";
      throw new DevUxError(`terminal-tabs-survivor-shell-${kind}`);
    }
  });
  await stage("terminal-tabs-mobile-fit", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await fits(page);
    await expect.poll(async () => (await terminal.boundingBox())?.height ?? 0, { timeout: 5_000 }).toBeGreaterThanOrEqual(180);
    await page.setViewportSize({ width: 1440, height: 900 });
  });
  // Same bounded synthetic server as commodity smoke; never serve files or
  // attach provider credentials. Destroying this owned Sandbox cleans it up.
  const canary = "codewire-dev-ux-preview";
  const before = page.url();
  const ports = dialog(page, `Ports · ${owned.name}`);
  const port = ports.locator(".cw-port-row", { has: page.getByText("ux-preview", { exact: true }) });
  let preview = "";
  await stage("ports-preview-server", async () => {
    await send(`node -e 'require("http").createServer((q,s)=>{s.writeHead(200,{"content-type":"text/plain","cache-control":"no-store"});s.end("${canary}")}).listen(8080,"0.0.0.0")' >/dev/null 2>&1 &`);
    await send(`for i in 1 2 3 4 5; do test "$(curl -fsS --max-time 2 http://127.0.0.1:8080)" = "${canary}" && { printf '__UX_PREVIEW_%s__\\n' ready; break; }; sleep 1; done`);
    await expect(rows).toContainText("__UX_PREVIEW_ready__");
  });
  await stage("ports-preview-add", async () => {
    await button(page, "Ports").click();
    await expect(ports).toBeVisible();
    await expect(ports.getByLabel("Internal port", { exact: true })).toBeVisible();
    await ports.getByLabel("Internal port", { exact: true }).fill("8080");
    await ports.getByLabel("Preview label", { exact: true }).fill("ux-preview");
    await expect(ports.getByLabel("Who can open the preview?", { exact: true })).toHaveValue("creator");
    await button(ports, "Add port").click();
    await expect(port).toContainText("8080 · Sandbox creator");
  });
  await stage("ports-preview-url", async () => {
    const open = port.getByRole("link", { name: "Open preview", exact: true });
    preview = (await open.getAttribute("href")) ?? "";
    const expected = new URL(previewPattern.replace("{label}", "ux-preview").replace("{sandbox-id-prefix}", id.slice(0, 5)));
    expect(expected.protocol).toBe("https:");
    expect(expected.hostname.startsWith(`ux-preview-${id.slice(0, 5)}-${slug}.`)).toBe(true);
    expect(new URL(preview).href).toBe(expected.href);
    await button(port, "Copy URL").click();
    await expect(port.locator("[data-preview-copy-status]")).toHaveText("Preview URL copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(preview);
  });
  // Isolated request context has no browser cookies. Do not follow login
  // redirects, inject auth across domains, or change the preview to public.
  const anonymous = await request.newContext();
  let previewPage: Page | undefined;
  try {
    await stage("ports-preview-denied", async () => {
      const denied = await anonymous.get(preview, { maxRedirects: 0, timeout: 15_000 });
      expect([302, 303, 401, 403]).toContain(denied.status());
      expect(await denied.text()).not.toContain(canary);
    });
    // #2142: a signed-in creator opens the private preview directly, with no
    // confirmation; its scoped cookie works only while this session is live.
    // Each step is its own stage so a Dev failure names where it stopped.
    await stage("ports-preview-open", async () => {
      const opened = page.waitForEvent("popup");
      await port.getByRole("link", { name: "Open preview", exact: true }).click();
      previewPage = await opened;
    });
    await stage("ports-preview-handoff", async () => {
      await expect(previewPage!).toHaveURL(new URL(preview).href, { timeout: 30_000 });
    });
    await stage("ports-preview-content", async () => {
      await expect(previewPage!.locator("body")).toHaveText(canary);
    });
    await stage("ports-preview-reload", async () => {
      await previewPage!.reload({ waitUntil: "domcontentloaded" });
      await expect(previewPage!).toHaveURL(new URL(preview).href);
      await expect(previewPage!.locator("body")).toHaveText(canary);
    });
    await stage("ports-preview-removed", async () => {
      await button(port, "Remove ux-preview preview").click();
      await expect(port).toHaveCount(0);
      const removed = await anonymous.get(preview, { maxRedirects: 0, timeout: 15_000 });
      expect(removed.status()).toBe(404);
      expect(await removed.text()).not.toContain(canary);
    });
    // Removing the port revokes the open browser preview as well.
    await stage("ports-preview-revoked", async () => {
      const revoked = await previewPage!.reload({ waitUntil: "domcontentloaded" });
      expect(revoked?.status()).toBe(404);
      await expect(previewPage!.locator("body")).not.toContainText(canary);
    });
  } finally {
    await previewPage?.close();
    await anonymous.dispose();
  }
  await stage("ports-close", async () => {
    await button(ports, "Done").click();
    expect(page.url()).toBe(before);
    // The dialog must leave the live terminal intact. Check its latest
    // output: earlier lines may have scrolled out of the visible rows.
    await expect(rows).toContainText("__UX_PREVIEW_ready__");
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
  });
  await stage("resize-dismissal", async () => {
    // The detail page shows the exact resources and the scheduled deletion
    // that Delete after = 1h requested.
    await expect(page.locator("[data-sandbox-resources]")).toHaveText(["1 vCPU · 2 GiB · 10 GiB", "1 vCPU · 2 GiB · 10 GiB"]);
    const deadline = Date.parse((await page.locator("[data-sandbox-lifetime] time").getAttribute("datetime")) ?? "");
    expect(deadline).toBeGreaterThan(Date.now());
    expect(deadline).toBeLessThanOrEqual(Date.now() + 65 * 60_000);
    const sandboxMenu = await workspaceMenu(page, "More actions");
    await button(sandboxMenu, "Resize").click();
    const resize = dialog(page, `Resize ${owned.name}`);
    await expect(resize).toBeVisible();
    // Resize offers Create's choices with the current resources selected.
    await expect(resize).toContainText("Some changes require a restart.");
    await expect(resize.getByLabel("CPU", { exact: true }).locator("option:checked")).toHaveText("1 vCPU");
    await expect(resize.getByLabel("Memory", { exact: true }).locator("option:checked")).toHaveText("2 GiB");
    await expect(resize.getByLabel("Disk (GiB)", { exact: true })).toHaveValue("10");
    await page.mouse.click(2, 2);
    await expect(resize).not.toBeVisible();
    await expect(button(sandboxMenu, "Resize")).toBeFocused();
  });
  await stage("lifecycle-live-state", async () => {
    await button(page, "Stop").click();
    const stop = dialog(page, `Stop ${owned.name}?`);
    await expect(button(stop, "Cancel")).toBeFocused();
    // Each confirmation says what happens to processes, files and the deadline.
    for (const effect of ["Running processes and terminal sessions will end.", "Workspace files are kept",
      "Stopping does not cancel automatic deletion."]) await expect(stop).toContainText(effect);
    await button(stop, "Cancel").click();
    await expect(page.locator("[data-sandbox-state]")).toHaveText("running");
    await button(page, "Stop").click();
    await button(stop, "Stop Sandbox").click();
    await expect(page).toHaveURL(`${ORIGIN}${detailPath}?message=environment-stopping`);
    await expect(page.locator("[data-sandbox-state]")).toHaveText("stopped", { timeout: 120_000 });
    await button(page, "Start").click();
    await expect(page).toHaveURL(`${ORIGIN}${detailPath}?message=environment-started`);
    await expect(page.locator("[data-sandbox-state]")).toHaveText("running", { timeout: 240_000 });
    await expect(button(page, "New terminal")).toBeEnabled({ timeout: 60_000 });
    await button(await workspaceMenu(page, "More actions"), "Delete").click();
    const deletion = dialog(page, `Delete ${owned.name}?`);
    await expect(button(deletion, "Cancel")).toBeFocused();
    await expect(deletion).toContainText("This permanently deletes the Sandbox and its workspace files.");
    await button(deletion, "Cancel").click();
    await button(await workspaceMenu(page, "More actions"), "Delete").click();
    await button(deletion, "Delete Sandbox").click();
    await expect(page).toHaveURL(`${ORIGIN}/${slug}/?message=environment-destroying&environment=${id}`);
    // Independent CLI finally cleanup proves terminal destruction, even when
    // the browser loses an acknowledgment. Do not equate this redirect to it.
  });
}
