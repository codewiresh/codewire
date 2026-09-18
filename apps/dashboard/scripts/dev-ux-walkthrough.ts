// Runs ONLY inside the existing protected Dev auth helper. No traces, page
// dumps, screenshots, stored browser sessions, or provider authorizations.
import { expect, type Locator, type Page } from "@playwright/test";
import { DevUxError, type OwnedUxSandbox } from "./dev-ux-ownership";

const ORIGIN = "https://codewire-dev.sh";
const button = (owner: Page | Locator, name: string) => owner.getByRole("button", { name, exact: true });
const dialog = (page: Page, name: string) => page.getByRole("dialog", { name, exact: true });

async function stage(name: string, operation: () => Promise<void>): Promise<void> {
  try { await operation(); } catch { throw new DevUxError(name); }
  console.error(`[dev-ux] ${name}:passed`);
}

async function visit(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN}${path}`, { waitUntil: "domcontentloaded" });
  const actual = new URL(page.url());
  if (actual.origin !== ORIGIN || actual.pathname !== path.split("?")[0]) throw new DevUxError("ux-route");
}

async function fits(page: Page, owner?: Locator): Promise<void> {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  if (owner) expect(await owner.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
}

async function credentials(page: Page, slug: string): Promise<void> {
  await visit(page, `/settings/credentials/?org=${slug}`);
  for (const title of ["Credentials", "Profiles"]) {
    await expect(page.getByRole("heading", { name: title, exact: true, level: 2 })).toBeVisible();
  }
  const add = button(page, "Add credential");
  await add.click();
  const chooser = dialog(page, "Add credential");
  await expect(chooser.locator(".cw-credential-types > li")).toHaveCount(5);
  await expect(chooser.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
  await fits(page, chooser);
  for (const [choice, title] of [
    ["GitHub", "Connect GitHub"], ["Codex", "Connect Codex"],
    ["OpenAI API key", "Add OpenAI API key"], ["Anthropic API key", "Add Anthropic API key"],
    ["SSH key", "Add SSH key"],
  ]) {
    await button(chooser, choice).click();
    const editor = dialog(page, title);
    await expect(editor).toBeVisible();
    await expect(page.locator("dialog[open]")).toHaveCount(1);
    await expect(editor.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
    await expect(editor.locator("[data-dialog-close]")).toHaveCount(1);
    if (choice === "GitHub") {
      await expect(editor.locator('input[name="name"]')).toHaveCount(0);
      await expect(button(editor, "Continue to GitHub")).toBeVisible();
    }
    await fits(page, editor);
    await button(editor, "Back").click();
    await expect(button(chooser, choice)).toBeFocused();
  }
  await button(chooser, "Cancel").click();
  await expect(add).toBeFocused();
  await button(page, "Create profile").click();
  const profile = dialog(page, "Create profile");
  await expect(profile.getByLabel("Profile name", { exact: true })).toBeFocused();
  for (const provider of ["Codex", "OpenAI API", "GitHub", "Anthropic", "SSH"]) {
    await expect(profile.getByLabel(provider, { exact: true })).toBeVisible();
  }
  await fits(page, profile);
  await button(profile, "Cancel").click();
}

async function settings(page: Page, slug: string): Promise<void> {
  await visit(page, `/settings/?org=${slug}`);
  for (const title of ["Account details", "Security", "Active sessions"]) {
    await expect(page.getByRole("heading", { name: title, exact: true })).toBeVisible();
  }
  await fits(page);
  for (const [path, title] of [["secrets", "Secrets"], ["api-keys", "API Keys"]]) {
    await visit(page, `/settings/${path}/?org=${slug}`);
    await expect(page.getByRole("heading", { name: title, exact: true, level: 1 })).toBeVisible();
    await fits(page);
  }
}

async function createForm(page: Page, slug: string, userId: string, orgId: string): Promise<void> {
  await visit(page, `/${slug}/new/`);
  const form = page.locator("[data-environment-form]");
  await expect(form).toHaveAttribute("data-create-draft-actor", userId);
  await expect(form).toHaveAttribute("data-create-draft-organization", orgId);
  await expect(form.locator('[name="confirm_personal_credentials"], [name="confirm_personal_secrets"]')).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Add or manage personal secrets", exact: true })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Manage provider credentials" }).getByRole("link")).toBeVisible();
  await expect(page.getByRole("link", { name: "Connect GitHub", exact: true })).toBeVisible();
  await expect(page.getByLabel("Repository URL", { exact: true })).toBeVisible();
  await expect(page.locator(".cw-preview-pattern")).toContainText("https://{label}-{sandbox-id-prefix}-");
  await button(page, "Choose from GitHub").click();
  const picker = dialog(page, "Choose a GitHub repository");
  await expect(picker).toBeVisible();
  await expect(picker.getByRole("link", { name: "Connect GitHub or create a profile in Settings" })).toBeVisible();
  await button(picker, "Close GitHub repositories").click();
  await fits(page, page.locator("#environment-create-card"));
}

export async function runDevUxWalkthrough(page: Page, options: {
  slug: string; userId: string; orgId: string; owned: OwnedUxSandbox; deadline: number;
}): Promise<void> {
  const { slug, userId, orgId, owned, deadline } = options;
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(30_000);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await stage(`credentials-${width}`, () => credentials(page, slug));
    await stage(`settings-${width}`, () => settings(page, slug));
    await stage(`create-form-${width}`, () => createForm(page, slug, userId, orgId));
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await stage("create-sandbox", async () => {
    await owned.admit(deadline);
    await page.getByLabel("Name", { exact: true }).fill(owned.name);
    await page.locator("[data-create-resources] > summary").click();
    await page.getByLabel("CPU", { exact: true }).selectOption("1000");
    await page.getByLabel("Memory", { exact: true }).selectOption("2048");
    await page.getByLabel("Disk", { exact: true }).selectOption("10");
    await page.getByLabel("Delete after (TTL)", { exact: true }).fill("1h");
    // Use the product's configured default image. Never inherit a saved source
    // selection or attach the dedicated account's existing secrets/providers.
    expect(await page.getByLabel("Workspace image", { exact: true }).inputValue()).not.toBe("");
    await expect(page.getByLabel("Credential profile", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Secret project", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Personal secrets", { exact: false })).not.toBeChecked();
    await expect(page.getByLabel("Organization secrets", { exact: false })).not.toBeChecked();
    await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("");
    for (const agent of await page.locator('input[name="agent"]').all()) await agent.uncheck();
    owned.beforeCreate();
    await button(page, "Create Sandbox").click();
    await expect(page.getByRole("status")).toContainText("Sandbox creation started");
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
  await stage("terminal-colors-copy", async () => {
    await visit(page, detailPath);
    await expect(button(page, "New terminal")).toBeEnabled({ timeout: 240_000 });
    await button(page, "New terminal").click();
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: 60_000 });
    firstId = await page.getByRole("tabpanel").getAttribute("data-terminal-session-id");
    expect(firstId).toBeTruthy();
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
    await button(page, "Copy selection").click();
    await expect(page.locator("[data-terminal-copy-status]")).toHaveText("Selection copied.");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("__UX_COPY__");
  });
  await stage("terminal-tabs-navigation-reconnect", async () => {
    await button(page, "Rename terminal").click();
    const rename = dialog(page, "Rename terminal");
    await rename.getByLabel("Terminal name", { exact: true }).fill("UX shell");
    await button(rename, "Save name").click();
    await visit(page, `/settings/?org=${slug}`);
    await visit(page, detailPath);
    await expect(page.getByRole("tabpanel")).toHaveAttribute("data-terminal-session-id", firstId!);
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
    await expect(button(page, "Disconnect")).toBeEnabled();
    await button(page, "New terminal").click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    await expect(button(page, "Disconnect")).toBeEnabled();
    await send("printf '__UX_SECOND__%s__%s__\\n' \"${CW_UX_SESSION-unset}\" \"$$\"");
    await expect(rows).toContainText(/__UX_SECOND__unset__\d+__/);
    expect(/__UX_SECOND__unset__(\d+)__/.exec(await rows.innerText())![1]).not.toBe(pid);
    await page.getByRole("tab", { name: "UX shell", exact: true }).click();
    await button(page, "Disconnect").click();
    await expect(rows).toContainText(`__UX_PID__${pid}__`);
    await button(page, "Reconnect").click();
    await expect(button(page, "Disconnect")).toBeEnabled();
    await send("printf '__UX_RESUMED__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\"");
    await expect(rows).toContainText(`__UX_RESUMED__preserved__${pid}__`);
    await page.setViewportSize({ width: 390, height: 844 });
    await fits(page);
    expect((await terminal.boundingBox())!.height).toBeGreaterThanOrEqual(180);
    await page.setViewportSize({ width: 1440, height: 900 });
  });
  await stage("ports-resize-dismissal", async () => {
    const before = page.url();
    await button(page, "Ports").click();
    const ports = dialog(page, `Ports · ${owned.name}`);
    await expect(ports).toBeVisible();
    await expect(ports.getByLabel("Internal port", { exact: true })).toBeVisible();
    await button(ports, "Close").click();
    expect(page.url()).toBe(before);
    await expect(rows).toContainText(`__UX_RESUMED__preserved__${pid}__`);
    await button(page, "Resize").click();
    const resize = dialog(page, `Resize ${owned.name}`);
    await expect(resize).toBeVisible();
    await page.mouse.click(2, 2);
    await expect(resize).not.toBeVisible();
    await expect(button(page, "Resize")).toBeFocused();
  });
  await stage("lifecycle-live-state", async () => {
    await button(page, "Stop").click();
    const stop = dialog(page, `Stop ${owned.name}?`);
    await expect(button(stop, "Cancel")).toBeFocused();
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
    await button(page, "Delete").click();
    const deletion = dialog(page, `Delete ${owned.name}?`);
    await expect(button(deletion, "Cancel")).toBeFocused();
    await button(deletion, "Cancel").click();
    await button(page, "Delete").click();
    await button(deletion, "Delete Sandbox").click();
    await expect(page).toHaveURL(`${ORIGIN}/${slug}/?message=environment-destroying`);
    // Independent CLI finally cleanup proves terminal destruction, even when
    // the browser loses an acknowledgment. Do not equate this redirect to it.
  });
}
