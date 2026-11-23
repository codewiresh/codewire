// Runs ONLY inside the existing protected Dev auth helper. No traces, page
// dumps, screenshots, stored browser sessions, or provider authorizations.
import { expect, request, type Locator, type Page, type WebSocketRoute } from "@playwright/test";
import { DevUxError, failureClassOf, holds, setupRowsSeen, type Expectation, type OwnedUxApiKey, type OwnedUxSandbox } from "./dev-ux-ownership";

const ORIGIN = "https://codewire-dev.sh";
// Re-attaching a surviving terminal after navigation, reload, reconnect, or
// closing another tab takes a few seconds on Dev; the 5s expect default is
// shorter than that real round trip.
const TERMINAL_ATTACH_MS = 30_000;
const button = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });
// The selected terminal's connection status. An attached terminal reads
// Connected and offers no control; Reconnect shows only while it is detached.
const terminalConnection = (page: Page) => page.locator("[data-terminal-session-status]:not([hidden]) [data-terminal-connection]");
const attachedTerminal = (page: Page, timeout: number) => expect(terminalConnection(page)).toHaveText("Connected", { timeout });
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
  // A step may raise a narrower fixed label; anything else maps to the step,
  // keeping only the value-blind class of what failed.
  try { await operation(); } catch (error) {
    throw error instanceof DevUxError && error.stage.startsWith(`${name}-`) ? error
      : new DevUxError(name, failureClassOf(error));
  }
  passed(name, started);
}

// The start list (#3772; `sandbox-start-list` in docs/journeys/cloud-sandbox.md).
// Its first row is the start itself and project setup adds only its named
// steps, so any other row belongs to another run. The list keeps its rows
// once the page hides it, so reading them after the Sandbox runs gives every
// row that start showed.
const START_ROW = "Starting the Sandbox";
const SETUP_ROWS = new Set(["Checking sidecar readiness", "Configuring environment", "Cloning repositories",
  "Running install command", "Running startup script", "Checking agent tools", "Registering ports"]);
const startListRows = (page: Page) =>
  page.locator("[data-setup-progress] [data-setup-stages] > .cw-setup-stage > .cw-setup-row > .cw-setup-stage-label");

// The page an action has just sent to a starting Sandbox: the list is up with
// its start row, and no alert above it repeats what the list says.
const startListShown = (page: Page, alert: string): Expectation[] => [
  ["list-visible", () => expect(page.getByRole("region", { name: "Starting your Sandbox", exact: true })).toBeVisible()],
  ["first-row", () => expect(startListRows(page).first()).toHaveText(START_ROW)],
  ["no-alert", () => expect(page.getByText(alert, { exact: true })).toHaveCount(0)],
];

// The start-list checks could not run against Dev before they merged, so one
// that fails is reported by `holds` and does not fail the walk yet (#3772).

// Why a shell command's marker did not appear, from fixed tokens only: the
// selected terminal was paused by the Sandbox readiness check or account
// check, or detached, at that moment; or the command's own echo is on screen
// with no output, with different values, or not at all. Each read is
// immediate, so a terminal that reconnects later is not mistaken for one
// that stayed attached.
async function shellFailure(page: Page, rows: Locator, echo: string, marker: RegExp): Promise<string> {
  const status = page.locator("[data-terminal-session-status]:not([hidden])");
  const read = async (locator: Locator) => (await locator.textContent({ timeout: 1_000 }).catch(() => "")) ?? "";
  const connection = (await read(status.locator("[data-terminal-connection]"))).trim();
  const text = await rows.innerText({ timeout: 1_000 }).catch(() => "");
  if (/^(Sandbox status is unavailable|Checking )/.test(connection)) return "paused";
  if (connection !== "Connected") return "detached";
  if (marker.test(text)) return "mismatch";
  return text.includes(echo) ? "no-output" : "no-echo";
}

async function visit(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN}${path}`, { waitUntil: "domcontentloaded" });
  const actual = new URL(page.url());
  if (actual.origin !== ORIGIN || actual.pathname !== path.split("?")[0]) throw new DevUxError("ux-route", "navigation");
}

// Layout settles after resizes, dialog transitions, and terminal refits; poll
// until it fits instead of sampling one mid-transition frame.
async function fits(page: Page, owner?: Locator): Promise<void> {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), { timeout: 5_000 }).toBe(true);
  if (owner) await expect.poll(() => owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1), { timeout: 5_000 }).toBe(true);
}

// Read-only page checks below never open a create or destructive action, but
// for the walk's own API key, which it makes and deletes itself. Rows and
// names are the Dev account's own data: each check holds for whatever rows
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
async function personalApiKeys(page: Page, key: OwnedUxApiKey): Promise<void> {
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
  await apiKeyDeleteWording(page, "api-key-delete-wording-personal", key);
  const owners = await page.locator(".cw-table tbody tr").evaluateAll((rows) => rows.map((row) => row.querySelector(":scope > td:nth-child(2) > a")?.getAttribute("href") ?? ""));
  for (const owner of owners) expect(owner).toMatch(/^\/[a-z0-9]+(?:-[a-z0-9]+)*\/api-keys\/$/);
}

// The organization's own inventory stays separate and scoped to it.
async function organizationApiKeys(page: Page, slug: string, key: OwnedUxApiKey): Promise<void> {
  await visit(page, `/${slug}/api-keys/`);
  const header = page.locator("#organization-content > .cw-page-header");
  await pageTitle(header, "API keys");
  await expect(header.locator(".cw-page-title-row .cw-badge")).toHaveText(/^\d+ keys?$/);
  await expect(header.locator(".cw-page-description")).toHaveText(/^Codewire API keys for \S.*, for the CLI and SDK\.$/);
  await settingsShell(page, "organization", `/${slug}/api-keys/`);
  await expect(page.locator("#settings-organization-title")).toHaveText(/^Organization · \S/);
  await apiKeyTable(page, ["Name", "Created by", "Status", "Last used", "Created"], "No API keys yet. Create one for programmatic access.");
  await apiKeyDeleteWording(page, "api-key-delete-wording-organization", key);
  await noUnsetValues(page);
  await fits(page);
}

// The console sidebar links Updates just above Documentation, and that link
// opens the public page (#5324, docs/journeys/updates.md U1 step 2). A miss
// prints not-held and does not fail the walk.
async function updatesLink(page: Page): Promise<void> {
  const started = Date.now();
  const links = page.locator("nav.cw-console-sidebar a.cw-nav-link");
  if (await holds("updates-link", [
    ["sidebar-link", async () => {
      await visit(page, "/dashboard/");
      await expect(links.filter({ hasText: "Updates" })).toHaveAttribute("href", "/updates");
    }],
    ["above-docs", async () => {
      const hrefs = await links.evaluateAll((nodes) => nodes.map((node) => node.getAttribute("href")));
      expect(hrefs.indexOf("/updates")).toBeGreaterThanOrEqual(0);
      expect(hrefs.indexOf("/docs") - hrefs.indexOf("/updates")).toBe(1);
    }],
    ["opens-page", async () => {
      expect((await page.request.get(`${ORIGIN}/updates`)).status()).toBe(200);
    }],
  ])) passed("updates-link", started);
}

// An organization's Network policies page is in its settings navigation and
// lists the built-in open and locked policies (#5114, docs/journeys/
// network-and-egress.md policy-dashboard). View only: nothing is created.
async function networkPolicies(page: Page, slug: string): Promise<void> {
  const started = Date.now();
  if (await holds("network-policies", [
    ["page-title", async () => {
      await visit(page, `/${slug}/network-policies/`);
      await expect(page.locator("main h1.cw-page-title")).toHaveText("Network policies");
    }],
    ["nav-link", async () => {
      await expect(page.locator(`a.cw-nav-link[href="/${slug}/network-policies/"]`)).toHaveAttribute("aria-current", "page");
    }],
    ["built-ins", async () => {
      await expect(page.locator(".cw-network-policy-list .cw-network-policy-copy > strong")).toHaveText(["open", "locked"]);
    }],
  ])) passed("network-policies", started);
}

// Each key a member may delete has a Delete dialog that says what deleting does
// in one sentence (#3586). The walk reads it in its own key's dialog, so there
// is always one to read, and deletes only that key. A miss prints not-held and
// does not fail the walk yet: it could not run on Dev first.
const API_KEY_DELETED = "All connections using this key are dropped when it is deleted.";
const API_KEY_CREATE = "/settings/api-keys/_actions/create";
// A key's Delete dialog, found by its title, open or not.
const keyDialog = (page: Page, name: string) =>
  page.locator('dialog[id^="api-key-"][id$="-delete"]').filter({ hasText: `Delete ${name}?` });

// Delete, opened from the key's row menu as a person does.
async function openKeyDelete(page: Page, name: string): Promise<Locator> {
  const menu = page.locator("details.cw-menu").filter({ has: page.locator(`summary[aria-label="Actions for ${name}"]`) });
  await menu.locator(":scope > summary").click();
  await menu.locator('button[data-dialog-open$="-delete"]').click();
  const open = keyDialog(page, name);
  await expect(open).toBeVisible();
  return open;
}

// The walk's own key (#3586; `key-revoke` in docs/journeys/api-keys.md), made
// once so every delivery reads the Delete dialog of a key that exists. Only
// its name is read back, never the secret shown once. A key not made is
// reported here, and the checks that need it then report too.
async function createScratchKey(page: Page, key: OwnedUxApiKey, orgId: string, deadline: number): Promise<void> {
  const started = Date.now();
  if (await holds("api-key-scratch-create", [["created", async () => {
    await key.admit(deadline);
    await visit(page, "/settings/api-keys/");
    await button(page.locator(".cw-settings-content > .cw-page-header"), "Create key").click();
    const create = dialog(page, "Create API key");
    await create.locator("#create-personal-api-key-org").selectOption(orgId);
    await create.locator("#create-personal-api-key-name").fill(key.name);
    await create.locator("#create-personal-api-key-expiration").selectOption("30");
    const answered = page.waitForResponse((response) => response.request().method() === "POST"
      && new URL(response.url()).pathname === API_KEY_CREATE).then(() => true, () => false);
    key.beforeCreate();
    await button(create, "Create key").click();
    if (!(await answered)) throw new DevUxError("api-key-scratch-create", "timeout");
    key.createAnswered();
    const reveal = page.locator("[data-api-key-reveal]");
    await expect(reveal.locator("dd").first()).toHaveText(key.name);
    await reveal.getByRole("link", { name: "Done", exact: true }).click();
    await key.bind(await keyDialog(page, key.name).locator('input[name="key_id"]').inputValue(), deadline);
  }]])) passed("api-key-scratch-create", started);
}

// The sentence in the key's Delete dialog, then Cancel, which keeps the key.
async function apiKeyDeleteWording(page: Page, name: string, key: OwnedUxApiKey): Promise<void> {
  const started = Date.now();
  if (await holds(name, [["delete-wording", async () => {
    if (!key.bound) throw new DevUxError(name);
    const open = await openKeyDelete(page, key.name);
    await expect(open.locator(".cw-dialog-body")).toContainText(API_KEY_DELETED);
    await fits(page);
    await button(open, "Cancel").click();
    await expect(open).toBeHidden();
  }]])) passed(name, started);
}

// Delete confirmed from the dialog: the row leaves the page, and the
// organization's list no longer names the key.
async function deleteScratchKey(page: Page, key: OwnedUxApiKey, deadline: number): Promise<void> {
  const started = Date.now();
  if (await holds("api-key-scratch-delete", [
    ["deleted", async () => {
      if (!key.bound) throw new DevUxError("api-key-scratch-delete");
      await visit(page, "/settings/api-keys/");
      await button(await openKeyDelete(page, key.name), "Delete key").click();
      await expect(page.locator(`summary[aria-label="Actions for ${key.name}"]`)).toHaveCount(0);
    }],
    ["gone", async () => expect(await key.absent(deadline)).toBe(true)],
  ])) passed("api-key-scratch-delete", started);
}

// A table with declared column headers when keys exist, else the empty state.
async function apiKeyTable(page: Page, columns: string[], empty: string): Promise<void> {
  if (await page.locator(".cw-table").count()) {
    await expect(page.locator('.cw-table thead th[scope="col"]')).toHaveText([...columns, "Actions"]);
  } else {
    await expect(page.getByText(empty, { exact: true })).toBeVisible();
  }
}

// The account home, "Welcome to Codewire" (owner, 2026-11-10): the cards load
// after the page, one per organization, each with its figures in words or a
// note that they are unavailable. The checklist is the account's own state, so
// only its shape is checked when it shows.
async function accountHome(page: Page, slug: string): Promise<void> {
  await visit(page, "/dashboard/");
  await pageTitle(page.locator("main .cw-page-header"), "Welcome to Codewire");
  await expect(page.locator(".cw-console-breadcrumb")).toHaveText("home");
  const overview = page.locator("[data-account-overview]");
  await expect(overview).toHaveAttribute("aria-busy", "false");
  const card = overview.locator(".cw-org-overview > li > article.cw-card").filter({
    has: page.locator(`#${slug}-name`),
  });
  await expect(card).toHaveCount(1);
  await expect(card.getByRole("link", { name: "Sandboxes", exact: true })).toHaveAttribute("href", `/${slug}/`);
  // One organization's card spans the list; several share a grid on a wide
  // screen and stack on a phone (#4464).
  const list = overview.locator(".cw-org-overview");
  const items = list.locator(":scope > li");
  const listWidth = (await list.boundingBox())!.width;
  const widths = await items.evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect().width));
  // The columns the list lays out at this width: 1 up to 48rem (768 px), 2 above.
  const columns = await list.evaluate((node) => getComputedStyle(node).gridTemplateColumns.trim().split(/\s+/).length);
  expect(columns).toBe(page.viewportSize()!.width > 768 ? 2 : 1);
  for (const width of widths) {
    if (widths.length === 1 || columns === 1) expect(Math.abs(width - listWidth)).toBeLessThanOrEqual(1);
    else expect(width).toBeLessThan(listWidth - 1);
  }
  if (await card.locator("dl.cw-stat-grid").count()) {
    await expect(card.locator("dl.cw-stat-grid dt")).toHaveText(["Balance", "This month", "Running"]);
    // Two decimals, "< €0.01" under a cent, and ∞ (named Unlimited) for an Unlimited organization (#4464).
    const amount = /^(?:-?€\d+\.\d{2}|< €0\.01|> -€0\.01)$/;
    const balance = card.locator("dl.cw-stat-grid dd").nth(0);
    if (await balance.getAttribute("title") === "Unlimited") await expect(balance).toHaveText("∞Unlimited");
    else await expect(balance).toHaveText(amount);
    await expect(card.locator("dl.cw-stat-grid dd").nth(1)).toHaveText(amount);
    await expect(card.locator("dl.cw-stat-grid dd").nth(2)).toHaveText(/^\d+$/);
  } else {
    await expect(card.getByText("Its balance and usage are unavailable right now.", { exact: true })).toBeVisible();
  }
  const checklist = overview.getByRole("region", { name: "Get started" });
  if (await checklist.count()) {
    await expect(checklist.locator(".cw-card-description")).toHaveText(
      /^[0-2] of 3 done\. Each step ticks itself off, and this goes away when all three are\.$/,
    );
    await expect(checklist.locator(".cw-checklist > li strong")).toHaveText([
      "Install the CLI", "Add a card", "Create your first cloud sandbox",
    ]);
  }
  await noUnsetValues(page);
  await fits(page);
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
    await expect(chooser.locator(".cw-credential-types > li")).toHaveCount(7);
    await expect(chooser.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
    await fits(page, chooser);
  });
  for (const [key, choice, title] of [
    ["github", "GitHub", "Connect GitHub"], ["codex", "Codex", "Connect Codex"],
    ["claude-sign-in", "Connect Claude", "Connect Claude"],
    ["claude", "Claude (token)", "Connect Claude (token)"],
    ["openai", "OpenAI API key", "Add OpenAI API key"], ["anthropic", "Anthropic API key", "Add Anthropic API key"],
    ["ssh", "SSH key", "Add SSH key"],
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

async function settings(page: Page, slug: string, width: number, key: OwnedUxApiKey): Promise<void> {
  for (const [scope, query] of [["organization", `?org=${slug}`], ["personal", ""]] as const) {
    await stage(`settings-account-${scope}-${width}`, async () => {
      await visit(page, `/settings/${query}`);
      for (const title of ["Account details", "Security", "Sign-in methods", "Active sessions"]) {
        await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
      }
      // A plain "Account" title and one short description, with no eyebrow.
      const header = page.locator(".cw-settings-content > .cw-page-header");
      await pageTitle(header, "Account");
      await expect(header.locator("p")).toHaveText(["Your account details, organizations, security, sign-in methods and browser sessions."]);
      // The password row leads Sign-in methods; providers follow when configured.
      // Its heading carries the method's state beside the name (#4275).
      const methods = page.locator("#sign-in-methods");
      await expect(methods.locator(".cw-security-row").first().locator("h3")).toHaveText(/^Password (Set|Not set)$/);
      await expect(methods.getByText("Connected providers are unavailable")).toHaveCount(0);
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
        if (path === "api-keys") await personalApiKeys(page, key);
        await noUnsetValues(page);
        await fits(page);
        if (path === "api-keys" && scope === "organization") await organizationApiKeys(page, slug, key);
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
  // Typing as the drawer opens stays in the field it started in (#4378). The
  // drawer's focus waits for the first frame, which can come late on a busy
  // page; a tab of its own holds the frames until typing is under way, so its
  // frames and its tab-scoped draft never reach the rest of the walk.
  await stage(`create-typing-${width}`, async () => {
    const typing = await page.context().newPage();
    try {
      await typing.setViewportSize({ width, height: 900 });
      await typing.addInitScript(() => {
        const frame = window.requestAnimationFrame.bind(window);
        const held: FrameRequestCallback[] = [];
        window.requestAnimationFrame = (callback) => { held.push(callback); return 0; };
        Object.assign(window, {
          releaseFrames: () => new Promise<void>((resolve) => {
            window.requestAnimationFrame = frame;
            held.splice(0).forEach((callback) => frame(callback));
            frame(() => frame(() => resolve()));
          }),
        });
      });
      await visit(typing, `/${slug}/new/`);
      const name = typing.getByLabel("Name", { exact: true });
      const repository = typing.getByLabel("Repository URL", { exact: true });
      const named = await name.inputValue();
      await repository.click();
      await repository.press("ControlOrMeta+a");
      await repository.pressSequentially("https://example.test/");
      await typing.evaluate(() => (window as unknown as { releaseFrames: () => Promise<void> }).releaseFrames());
      await repository.pressSequentially("owner/repo");
      await expect(repository).toHaveValue("https://example.test/owner/repo");
      await expect(repository).toBeFocused();
      await expect(name).toHaveValue(named);
    } finally {
      await typing.close();
    }
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

// What each theme paints. The terminal keeps its own dark surface and text in
// both, so the surface holding its text is what shows the output stays readable.
const THEMES = {
  light: { background: "rgb(255, 255, 255)", text: "rgb(0, 0, 0)" },
  dark: { background: "rgb(10, 10, 10)", text: "rgb(219, 209, 173)" },
} as const;

// The account menu's switch on the live workspace: each choice repaints the
// page at once, stays on the next page at both widths, and leaves the shell
// attached. A Sandbox page has no console header, so its switch is in the
// account menu at the foot of the sidebar.
// Colours only; this helper takes no screenshots.
async function themes(page: Page, terminal: Locator, rows: Locator, options: {
  slug: string; detailPath: string; sessionId: string; pid: string; send: (command: string) => Promise<void>;
}): Promise<void> {
  const { slug, detailPath, sessionId, pid, send } = options;
  const menu = page.locator(".cw-sidebar-slot .cw-account-menu");
  const toggle = menu.locator("[data-theme-switch]");
  // Opens the account menu, checks the choice shown, switches once and closes it.
  const switchTheme = async (from: string, to: string) => {
    await menu.locator(":scope > summary").click();
    await expect(toggle).toHaveAttribute("data-theme-current", from);
    await toggle.click();
    await expect(toggle).toHaveAttribute("data-theme-current", to);
    await menu.locator(":scope > summary").click();
    await expect(menu).toHaveJSProperty("open", false);
  };
  const painted = async (theme: keyof typeof THEMES) => {
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await expect(page.locator("body")).toHaveCSS("background-color", THEMES[theme].background);
    await expect(page.locator("body")).toHaveCSS("color", THEMES[theme].text);
  };
  const terminalPainted = async (theme: keyof typeof THEMES) => {
    await painted(theme);
    await expect(terminal.locator(".xterm-scrollable-element")).toHaveCSS("background-color", "rgb(10, 10, 10)");
    await expect(rows).toHaveCSS("color", "rgb(228, 228, 231)");
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", sessionId);
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
  };
  let shown = "system";
  for (const theme of ["light", "dark"] as const) {
    await stage(`theme-${theme}`, async () => {
      await switchTheme(shown, theme);
      shown = theme;
      await terminalPainted(theme);
    });
    await stage(`theme-${theme}-pages`, async () => {
      for (const width of [390, 1440]) {
        await page.setViewportSize({ width, height: 900 });
        await visit(page, `/settings/?org=${slug}`);
        await painted(theme);
        await fits(page);
        await visit(page, detailPath);
        await terminalPainted(theme);
        await fits(page);
      }
    });
  }
  await stage("theme-system", async () => {
    await switchTheme(shown, "system");
    await expect(page.locator("html")).not.toHaveAttribute("data-theme", /./);
    await send("printf '__UX_THEME__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\"");
    await expect(rows).toContainText(`__UX_THEME__preserved__${pid}__`);
  });
}

// A failed setup and its Retry (#5065; `sandbox-setup-retry` in
// docs/journeys/cloud-sandbox.md). Two more Sandboxes fail setup: one at its
// install command until a file exists, one at its clone. Dev's own origin has
// no repository at the clone's address, so the banner names that host
// without any credential (#5053). The two start in a tab of their own once
// the walk's Sandbox has a terminal, so their setup runs while the walk goes
// on, and are checked after it.
const SETUP_FIXED = "/tmp/dev-ux-setup-fixed";
const MISSING_REPOSITORY = `${ORIGIN}/_dev-ux/no-repository.git`;
const notice = (page: Page) => page.locator("[data-sandbox-notice]");
const noticeText = (page: Page) => notice(page).locator("[data-sandbox-notice-text]");
const setupRows = (page: Page) => page.locator("[data-setup-progress] [data-setup-stages] > .cw-setup-stage");

async function typeLine(page: Page, command: string): Promise<void> {
  const input = page.locator("[data-terminal-tab-panel]:not([hidden]) [data-terminal-root] textarea");
  await input.focus();
  // Keystrokes reach the shell only from the focused terminal. After a menu
  // or dialog, type only once focus has actually arrived there.
  await expect(input).toBeFocused();
  await page.keyboard.type(command);
  await page.keyboard.press("Enter");
}

async function createFailingSetup(page: Page, slug: string, owned: OwnedUxSandbox, deadline: number,
  setup: { install: string } | { repository: string }): Promise<string> {
  await owned.admit(deadline);
  await visit(page, `/${slug}/new/`);
  const card = page.locator("#environment-create-card");
  await page.getByLabel("Name", { exact: true }).fill(owned.name);
  await card.getByLabel("CPU", { exact: true }).selectOption("1000");
  await card.getByLabel("Memory", { exact: true }).selectOption("2048");
  await card.getByLabel("Disk", { exact: true }).selectOption("10");
  await page.getByLabel("Delete after", { exact: true }).fill("1h");
  await page.locator("[data-reset-workspace-image]").click();
  await expect(page.getByLabel("Credential profile", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
  await expect(page.getByLabel("Organization secrets", { exact: false })).not.toBeChecked();
  for (const agent of await page.locator('input[name="agent"]').all()) await agent.uncheck();
  if ("install" in setup) {
    await page.locator("[data-create-runtime] > summary").click();
    await page.getByLabel("Install command", { exact: true }).fill(setup.install);
  } else {
    await page.getByLabel("Repository URL", { exact: true }).fill(setup.repository);
    await page.getByLabel("Mount path", { exact: true }).fill("missing");
  }
  owned.beforeCreate();
  await button(page, "Create Sandbox").click();
  await expect(page).toHaveURL(/\/[0-9a-f-]{36}\/\?message=environment-created$/);
  return `/${slug}/${await owned.createdId(deadline)}/`;
}

// The banner says where setup stopped, over a terminal that opened anyway.
const failedOpen = (page: Page, path: string, step: string): Expectation[] => [
  ["failed-banner", async () => {
    await visit(page, path);
    await expect(noticeText(page)).toHaveText(new RegExp(`^Setup failed at ${step}: `), { timeout: 120_000 });
  }],
  ["danger-tone", () => expect(notice(page)).toHaveAttribute("data-tone", "danger")],
  ["terminal-open", () => attachedTerminal(page, 60_000)],
];

// The Desktop panel (docs/journeys/desktop.md, `desktop-dashboard`): Start,
// typing, Paste and Copy through the viewer, a fifth viewer refused, and Stop.
// The page's own terminal opens a terminal on the desktop and reads back what
// reached it. These checks could not run against Dev before they merged, so
// one that fails is reported by `holds` and does not fail the walk (#3223).
// They share one budget, so a slow Dev adds at most about that much.
const DESKTOP_BUDGET_MS = 150_000;
const DESKTOP_START_MS = 90_000;
const DESKTOP_CONNECT_MS = 30_000;
async function desktop(page: Page, detailPath: string, rows: Locator, send: (command: string) => Promise<void>): Promise<void> {
  const panelOf = (owner: Page) => owner.locator("[data-desktop-panel]");
  const show = (owner: Page, view: "Terminal" | "Desktop") =>
    owner.getByRole("group", { name: "Sandbox view" }).getByRole("button", { name: view, exact: true }).click();
  const reaches = (owner: Page, state: string, timeout = DESKTOP_CONNECT_MS) =>
    expect(panelOf(owner)).toHaveAttribute("data-desktop-state", state, { timeout });
  const panel = panelOf(page);
  const canvas = panel.locator("canvas");
  // Keys reach the desktop only while the viewer's canvas has focus.
  const keys = async (text: string) => {
    await canvas.focus();
    await page.keyboard.type(text, { delay: 30 });
  };
  const ends = Date.now() + DESKTOP_BUDGET_MS;
  const inTime: Expectation = ["in-time", async () => {
    if (Date.now() > ends) throw new DevUxError("desktop", "timeout");
  }];
  const viewers: Page[] = [];
  // The walk routes terminal sockets, so Playwright gives this page its own
  // WebSocket class for every socket, the desktop stream's too. noVNC accepts
  // a socket only when its members are its own or its class's
  // (core/websock.js), and this class keeps them on a base class, so they are
  // copied down to WebSocket's own prototype before the viewer opens one, as
  // the panel's fixture spec does. It only moves those members, so it undoes
  // what the route's class swap did to noVNC's check and nothing more; a real
  // browser's WebSocket already has them. The other viewer pages route nothing.
  const ownSocketMembers = () => page.evaluate(() => {
    const own = WebSocket.prototype;
    for (const name of ["send", "close", "binaryType", "onerror", "onmessage", "onopen"]) {
      if (Object.hasOwn(own, name)) continue;
      for (let base = Object.getPrototypeOf(own); base; base = Object.getPrototypeOf(base)) {
        const member = Object.getOwnPropertyDescriptor(base, name);
        if (member) { Object.defineProperty(own, name, member); break; }
      }
    }
  });
  const viewer = async () => {
    const other = await page.context().newPage();
    viewers.push(other);
    await other.setViewportSize({ width: 1440, height: 900 });
    await visit(other, detailPath);
    await show(other, "Desktop");
    return other;
  };
  try {
    let started = Date.now();
    if (!(await holds("desktop-start", [
      inTime,
      ["started", async () => {
        await ownSocketMembers();
        await show(page, "Desktop");
        await reaches(page, "stopped");
        await button(panel, "Start desktop").click();
      }],
      ["connected", () => reaches(page, "connected", DESKTOP_START_MS)],
      ["fills", async () => expect((await canvas.boundingBox())?.width ?? 0).toBeGreaterThan(200)],
    ]))) return;
    passed("desktop-start", started);
    started = Date.now();
    if (await holds("desktop-input", [
      inTime,
      // Printed in two parts, so the command's own echo is not the marker.
      ["terminal-opened", async () => {
        await show(page, "Terminal");
        await send("DISPLAY=:1 setsid xfce4-terminal --disable-server >/dev/null 2>&1 </dev/null & " +
          "DISPLAY=:1 timeout 20 xdotool search --sync --class xfce4-terminal windowactivate --sync && " +
          "printf '__UX_DESKTOP_%s__\\n' RAISED");
        await expect(rows).toContainText("__UX_DESKTOP_RAISED__", { timeout: DESKTOP_CONNECT_MS });
      }],
      ["reconnected", async () => {
        await show(page, "Desktop");
        await reaches(page, "connected");
      }],
      ["typed", async () => {
        await keys("echo __UX_DESKTOP_TYPED__ > /tmp/ux-desktop-typed");
        await page.keyboard.press("Enter");
      }],
      ["paste-note", async () => {
        await page.evaluate(() => navigator.clipboard.writeText("__UX_DESKTOP_PASTED__"));
        await button(panel, "Paste to desktop").click();
        await expect(panel.locator("[data-desktop-note]")).toHaveText("Pasted to the desktop.");
      }],
      ["pasted", async () => {
        await keys("echo ");
        await page.keyboard.press("Control+Shift+V");
        await keys(" > /tmp/ux-desktop-pasted");
        await page.keyboard.press("Enter");
      }],
      ["copy-enabled", async () => {
        await keys("clear; printf '__UX_DESKTOP_%s__\\n' COPIED");
        await page.keyboard.press("Enter");
        await page.keyboard.press("Control+Shift+A");
        await page.keyboard.press("Control+Shift+C");
        await expect(button(panel, "Copy from desktop")).toBeEnabled({ timeout: 10_000 });
      }],
      // The desktop's clipboard reaches the page a moment after it changes.
      ["copied", () => expect.poll(async () => {
        await button(panel, "Copy from desktop").click();
        return page.evaluate(() => navigator.clipboard.readText());
      }, { timeout: 10_000 }).toContain("__UX_DESKTOP_COPIED__")],
    ])) passed("desktop-input", started);
    started = Date.now();
    if (await holds("desktop-viewers", [
      inTime,
      ["second", async () => reaches(await viewer(), "connected")],
      ["third", async () => reaches(await viewer(), "connected")],
      ["fourth", async () => reaches(await viewer(), "connected")],
      ["fifth-refused", async () => reaches(await viewer(), "lost")],
      ["limit-named", () => expect(viewers[3].locator("[data-desktop-status]"))
        .toHaveText(/^4 viewers already watch this desktop/)],
    ])) passed("desktop-viewers", started);
    for (const other of viewers.splice(0)) await other.close();
    started = Date.now();
    if (await holds("desktop-stop", [
      inTime,
      ["stopped", async () => {
        await button(panel, "Stop desktop").click();
        await reaches(page, "stopped", 60_000);
      }],
    ])) passed("desktop-stop", started);
    started = Date.now();
    if (await holds("desktop-reached", [
      inTime,
      ["typed", async () => {
        await show(page, "Terminal");
        await send("cat /tmp/ux-desktop-typed /tmp/ux-desktop-pasted");
        await expect(rows).toContainText("__UX_DESKTOP_TYPED__");
      }],
      ["pasted", () => expect(rows).toContainText("__UX_DESKTOP_PASTED__")],
    ])) passed("desktop-reached", started);
  } finally {
    for (const other of viewers) await other.close().catch(() => {});
    // The stages after these use the terminal.
    await show(page, "Terminal").catch(() => {});
  }
}

export async function runDevUxWalkthrough(page: Page, options: {
  slug: string; userId: string; orgId: string; owned: OwnedUxSandbox; deadline: number;
  own: () => OwnedUxSandbox; key: OwnedUxApiKey;
}): Promise<void> {
  const { slug, userId, orgId, owned, deadline, own, key } = options;
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(30_000);
  // Terminal sockets pass through unchanged. The reconnect journey drops the
  // selected one, as a lost connection does: the page offers no Disconnect.
  // Closing a routed socket's server side never reaches the page, so the drop
  // closes the page's side (as an abnormal close) and then the server's.
  const terminalSockets: Array<{ sessionId: string | null; page: WebSocketRoute; server: WebSocketRoute }> = [];
  await page.routeWebSocket("**/terminal?**", (socket) => {
    terminalSockets.push({
      sessionId: new URL(socket.url()).searchParams.get("session_id"),
      page: socket,
      server: socket.connectToServer(),
    });
  });
  const socketsOf = (id: string | null) => terminalSockets.filter((socket) => socket.sessionId === id);
  await page.setViewportSize({ width: 1440, height: 900 });
  await createScratchKey(page, key, orgId, deadline);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await stage(`account-home-${width}`, () => accountHome(page, slug));
    await credentials(page, slug, width);
    await settings(page, slug, width, key);
    if (width === 1440) {
      await updatesLink(page);
      await networkPolicies(page, slug);
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
  await deleteScratchKey(page, key, deadline);
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
  // Time the backend start apart from the UI checks. The page opens its own
  // terminal once setup completes and the runtime is ready; New terminal is
  // enabled after that launch.
  let submitted = 0;
  let accepted = 0;
  await stage("create-submit", async () => {
    owned.beforeCreate();
    submitted = Date.now();
    await button(page, "Create Sandbox").click();
    // Create lands on the new Sandbox's page; the landing URL is the
    // acceptance.
    await expect(page).toHaveURL(/\/[0-9a-f-]{36}\/\?message=environment-created$/);
    accepted = Date.now();
  });
  // This shape has no warm pool on Dev, so its start outlasts the landing
  // page's first paint and the list is there to check.
  const landed = Date.now();
  if (await holds("create-start-list", startListShown(page, "Sandbox creation started."))) passed("create-start-list", landed);
  const id = await owned.createdId(deadline);
  const detailPath = `/${slug}/${id}/`;
  const terminal = page.locator("[data-terminal-tab-panel]:not([hidden]) [data-terminal-root]");
  const rows = terminal.locator(".xterm-rows");
  const send = (command: string) => typeLine(page, command);
  let firstId: string | null = null;
  let pid = "";
  let job = "";
  // Backend start runs while the ownership lookup above resolves the ID, so
  // time it from acceptance rather than from this step's own start.
  await stage("create-to-terminal-enabled", async () => {
    await visit(page, detailPath);
    await expect(page.getByRole("tab")).toHaveCount(1, { timeout: 240_000 });
    await expect(button(page, "New terminal")).toBeEnabled({ timeout: 60_000 });
  }, accepted);
  // The page above joined the start part-way: it may hold the start row, the
  // setup steps still to come, or no list at all if the Sandbox already ran.
  const ran = Date.now();
  let listed: string[] = [];
  if (await holds("create-start-list-rows", [
    ["rows-read", async () => { listed = await startListRows(page).allTextContents(); }],
    ["no-repeat", async () => expect(new Set(listed).size).toBe(listed.length)],
    ["known-rows", async () => expect(listed.filter((row, index) => !(index === 0 && row === START_ROW) && !SETUP_ROWS.has(row))).toEqual([])],
  ])) passed("create-start-list-rows", ran);
  await stage("terminal-attach", async () => {
    await attachedTerminal(page, 60_000);
    firstId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(firstId).toBeTruthy();
  });
  passed("create-to-terminal", submitted);
  const failing = await page.context().newPage();
  const installing = own();
  const cloning = own();
  let installPath = "";
  let clonePath = "";
  // These checks could not run against Dev before they merged, so one that
  // fails is reported by `holds` and does not fail the walk yet (#5065).
  await failing.setViewportSize({ width: 1440, height: 900 });
  const retryCreated = Date.now();
  if (await holds("setup-retry-create", [
    ["install-created", async () => {
      installPath = await createFailingSetup(failing, slug, installing, deadline, { install: `test -f ${SETUP_FIXED}` });
    }],
    ["clone-created", async () => {
      clonePath = await createFailingSetup(failing, slug, cloning, deadline, { repository: MISSING_REPOSITORY });
    }],
  ])) passed("setup-retry-create", retryCreated);
  await stage("terminal-colors-copy", async () => {
    await send("export CW_UX_SESSION=preserved; printf '\\033[31m__UX_RED__\\033[0m\\n__UX_COPY__\\n__UX_PID__%s__\\n' \"$$\"");
    await expect(rows).toContainText(/__UX_PID__\d+__/);
    pid = /__UX_PID__(\d+)__/.exec(await rows.innerText())![1];
    await expect(rows.getByText("__UX_RED__", { exact: true })).toHaveCSS("color", "rgb(204, 0, 0)");
    await expect(rows).toHaveCSS("font-family", /Geist Mono/);
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
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
  });
  await stage("terminal-tabs-second", async () => {
    await button(page, "New terminal").click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    secondId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(secondId).toBeTruthy();
    expect(secondId).not.toBe(firstId);
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
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
  // Each step of the reconnect journey reports itself, so a Dev failure
  // names the step rather than the whole journey.
  await stage("terminal-tabs-reconnect-select", async () => {
    await page.getByRole("tab", { name: "UX shell", exact: true }).click();
  });
  // A restored tab may still be attaching after the reload. The replay
  // follows the socket's opening; a drop before it leaves nothing on screen
  // for the next step to find retained.
  await stage("terminal-tabs-reconnect-attached", async () => {
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
  });
  // The connection drops and the tab re-attaches by itself to the same shell.
  await stage("terminal-tabs-reconnect-drop", async () => {
    const selected = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    const before = socketsOf(selected);
    expect(before.length, "the selected terminal's socket").toBeGreaterThan(0);
    const dropped = before.at(-1)!;
    await dropped.page.close({ code: 1011, reason: "walkthrough connection drop" });
    await dropped.server.close({ code: 1000, reason: "walkthrough connection drop" });
    await expect.poll(() => socketsOf(selected).length, { timeout: TERMINAL_ATTACH_MS }).toBeGreaterThan(before.length);
  });
  await stage("terminal-tabs-reconnect-retained", async () => {
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
  });
  await stage("terminal-tabs-reconnect-attach", async () => {
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
  });
  await stage("terminal-tabs-reconnect-shell", async () => {
    // Always print, so a changed shell reports a mismatch instead of silence.
    await send("printf '__UX_RESUMED__%s__%s__%s__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\" \"$PWD\" \"$CW_UX_JOB\" \"$(test \"$(jobs -pr)\" = \"$CW_UX_JOB\" && kill -0 \"$CW_UX_JOB\" 2>/dev/null && echo alive || echo gone)\"");
    try {
      await expect(rows).toContainText(`__UX_RESUMED__preserved__${pid}__/tmp__${job}__alive__`);
    } catch {
      throw new DevUxError(`terminal-tabs-reconnect-shell-${await shellFailure(page, rows, "__UX_RESUMED__%s", /__UX_RESUMED__(?!%s)/)}`);
    }
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
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
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
      throw new DevUxError(`terminal-tabs-survivor-shell-${await shellFailure(page, rows, "__UX_SURVIVOR__%s", /__UX_SURVIVOR__(?!%s)/)}`);
    }
  });
  await stage("terminal-tabs-mobile-fit", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await fits(page);
    await expect.poll(async () => (await terminal.boundingBox())?.height ?? 0, { timeout: 5_000 }).toBeGreaterThanOrEqual(180);
    await page.setViewportSize({ width: 1440, height: 900 });
  });
  await themes(page, terminal, rows, { slug, detailPath, sessionId: firstId!, pid, send });
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
    await attachedTerminal(page, TERMINAL_ATTACH_MS);
  });
  // More actions lists Open in VS Code first, its icon saying it opens
  // outside the page, with Resize and Delete; Refresh sandbox status is gone,
  // since the page's status updates by itself (owner, 2026-11-13, #4542).
  await stage("sandbox-menu", async () => {
    const sandboxMenu = await workspaceMenu(page, "More actions");
    const items = sandboxMenu.locator(":scope > .cw-menu-panel > .cw-menu-item:visible");
    const open = sandboxMenu.getByRole("link", { name: "Open in VS Code", exact: true });
    await expect(items.first()).toHaveText("Open in VS Code");
    await expect(open).toHaveAttribute("href", /^vscode:\/\//);
    await expect(open.locator('svg[aria-hidden="true"] use')).toHaveAttribute("href", /#icon-external$/);
    await expect(button(sandboxMenu, "Resize")).toBeVisible();
    await expect(button(sandboxMenu, "Delete")).toBeVisible();
    await expect(page.getByRole("button", { name: /Refresh sandbox status/ })).toHaveCount(0);
    await page.keyboard.press("Escape");
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
  await desktop(page, detailPath, rows, send);
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
    // This Sandbox's setup finished on its first run, so a restart shows the
    // start row alone, from the first paint until it runs.
    const restarted = Date.now();
    const shownAlone = await holds("lifecycle-live-state-start-list", [
      ...startListShown(page, "Sandbox start requested."),
      ["one-row", () => expect(startListRows(page)).toHaveText([START_ROW])],
    ]);
    await expect(page.locator("[data-sandbox-state]")).toHaveText("running", { timeout: 240_000 });
    await expect(button(page, "New terminal")).toBeEnabled({ timeout: 60_000 });
    if (shownAlone && await holds("lifecycle-live-state-start-list", [
      ["one-row-kept", async () => expect(await startListRows(page).allTextContents()).toEqual([START_ROW])],
    ])) passed("lifecycle-live-state-start-list", restarted);
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
  // Each check runs only on what the one before it showed: a Retry needs
  // the failed Sandbox, and the list needs the Retry.
  let started = Date.now();
  const install = !!installPath
    && await holds("setup-retry-banner", failedOpen(failing, installPath, "Running install command"));
  if (install) passed("setup-retry-banner", started);
  started = Date.now();
  const resumed = install && await holds("setup-retry-resume", [
    ["fixed", async () => {
      await typeLine(failing, `touch ${SETUP_FIXED} && printf '__UX_%s__\\n' FIXED`);
      await expect(failing.locator("[data-terminal-tab-panel]:not([hidden]) .xterm-rows")).toContainText("__UX_FIXED__");
    }],
    ["retried", async () => {
      // A Retry returns to this same page, so wait for the page it returns to.
      await Promise.all([
        failing.waitForEvent("framenavigated", (frame) => frame === failing.mainFrame()),
        button(notice(failing), "Retry setup").click(),
      ]);
      await failing.waitForLoadState("domcontentloaded");
    }],
    // The banner says "Setting up" while the Retry runs, and goes once setup
    // completes; a Sandbox ready with nothing to say shows no notice.
    ["ready", async () => {
      await expect(notice(failing)).toBeHidden({ timeout: 120_000 });
      await expect(failing.locator("[data-sandbox-state]")).toHaveText("running");
      await expect(button(failing, "New terminal")).toBeEnabled({ timeout: 60_000 });
    }],
  ]);
  if (resumed) passed("setup-retry-resume", started);
  // The list keeps its rows once the Sandbox is ready. A Retry fast enough to
  // finish before the page follows it shows no list.
  started = Date.now();
  let labels: string[] = [];
  if (resumed && await holds("setup-retry-resume-list", [
    ["retry-heading", () => expect(failing.locator("[data-setup-progress] h2")).toHaveText("Retrying setup")],
    ["install-ran", async () => {
      labels = await setupRows(failing).locator(":scope > .cw-setup-row > .cw-setup-stage-label").allTextContents();
      expect(labels.indexOf("Running install command")).toBeGreaterThan(0);
      await expect(setupRows(failing).nth(labels.indexOf("Running install command")))
        .toHaveAttribute("data-state", "completed");
    }],
    // The steps before install were done on the failed run and are not run again.
    ["earlier-done", async () => {
      for (const row of (await setupRows(failing).all()).slice(0, labels.indexOf("Running install command"))) {
        await expect(row).toHaveAttribute("data-instant", "");
      }
    }],
  ])) passed("setup-retry-resume-list", started);
  else if (resumed) {
    // What the list held, by fixed step names and states only.
    const rows = await setupRows(failing).evaluateAll((items) => items.map((item) => ({
      label: item.querySelector(":scope > .cw-setup-row > .cw-setup-stage-label")?.textContent ?? "",
      state: item.getAttribute("data-state") ?? "",
      instant: item.hasAttribute("data-instant"),
    })));
    console.error(`[dev-ux] setup-retry-resume-list:rows ${setupRowsSeen(rows)}`);
  }
  started = Date.now();
  const reclone = dialog(failing, "Retry cloning?");
  if (clonePath && await holds("setup-retry-reclone", [
    ...failedOpen(failing, clonePath, "Cloning repositories"),
    // The reason is ours and names the project's host (#5053).
    ["host-named", () => expect(noticeText(failing)).toContainText(`: ${new URL(ORIGIN).host} `)],
    ["asked", async () => {
      await button(notice(failing), "Retry setup").click();
      // The server refuses to clone again unasked and returns with its question.
      await expect(failing).toHaveURL(`${ORIGIN}${clonePath}?confirm=reclone`);
      await expect(reclone).toBeVisible();
    }],
    ["cancelled", async () => {
      await button(reclone, "Cancel").click();
      await expect(reclone).toBeHidden();
      await expect(noticeText(failing)).toHaveText(/^Setup failed at Cloning repositories: /);
    }],
  ])) passed("setup-retry-reclone", started);
  // Deleting both here starts their destruction together; the harness's own
  // cleanup then confirms each by its ID, whatever happened above.
  const remove = (path: string, name: string) => async () => {
    await visit(failing, path);
    await button(await workspaceMenu(failing, "More actions"), "Delete").click();
    await button(dialog(failing, `Delete ${name}?`), "Delete Sandbox").click();
    await expect(failing).toHaveURL(`${ORIGIN}/${slug}/?message=environment-destroying&environment=${path.split("/")[2]}`);
  };
  started = Date.now();
  const deletions: Expectation[] = [];
  if (clonePath) deletions.push(["clone-deleted", remove(clonePath, cloning.name)]);
  if (installPath) deletions.push(["install-deleted", remove(installPath, installing.name)]);
  if (deletions.length && await holds("setup-retry-delete", deletions)) passed("setup-retry-delete", started);
  await failing.close();
}
