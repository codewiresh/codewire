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

async function stage(name: string, operation: () => Promise<void>): Promise<void> {
  const started = Date.now();
  try { await operation(); } catch { throw new DevUxError(name); }
  console.error(`[dev-ux] ${name}:passed duration_ms=${Date.now() - started}`);
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

async function credentials(page: Page, slug: string, width: number): Promise<void> {
  const add = button(page, "Add credential");
  const chooser = dialog(page, "Add credential");
  await stage(`credentials-page-${width}`, async () => {
    await visit(page, `/settings/credentials/?org=${slug}`);
    await expect(page.getByRole("heading", { name: "Credentials", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Profiles", exact: true, level: 2 })).toBeVisible();
  });
  await stage(`credentials-chooser-${width}`, async () => {
    await add.click();
    await expect(chooser.locator(".cw-credential-types > li")).toHaveCount(5);
    await expect(chooser.locator(".cw-dialog-header [data-dialog-close]")).toHaveCount(0);
    await fits(page, chooser);
  });
  for (const [key, choice, title] of [
    ["github", "GitHub", "Connect GitHub"], ["codex", "Codex", "Connect Codex"],
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
        const connection = editor.getByRole("region", { name: "Your GitHub connection", exact: true });
        if (await connection.count()) {
          await expect(connection.getByRole("button", { name: /^Reconnect / })).toBeVisible();
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
      await fits(page);
    });
    for (const [path, title] of [["secrets", "Secrets"], ["api-keys", "API Keys"]]) {
      await stage(`settings-${path}-${scope}-${width}`, async () => {
        await visit(page, `/settings/${path}/${query}`);
        await expect(page.getByRole("heading", { name: title, exact: true, level: 1 })).toBeVisible();
        await fits(page);
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
  });
  // Read-only setup detours: do not create credentials or application secrets.
  for (const destination of ["secrets", "credentials"]) {
    await stage(`create-detour-${destination}-${width}`, async () => {
      if (await page.locator("[data-create-resources]").getAttribute("open") === null) {
        await page.locator("[data-create-resources] > summary").click();
      }
      await page.getByLabel("CPU", { exact: true }).selectOption("2000");
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
      const destinationUrl = `${ORIGIN}/settings/${destination}/?org=${slug}&creation_draft=${draft}`;
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
      await expect(page.locator('[name="cpu"]')).toHaveValue("1000");
      await button(page, "Restore saved draft").click();
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
    if (await page.locator("[data-create-resources]").getAttribute("open") === null) {
      await page.locator("[data-create-resources] > summary").click();
    }
    await page.getByLabel("CPU", { exact: true }).selectOption("1000");
    await page.getByLabel("Memory", { exact: true }).selectOption("2048");
    await page.getByLabel("Disk", { exact: true }).selectOption("10");
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
  let job = "";
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
  const rename = dialog(page, "Rename terminal");
  const close = dialog(page, "Close terminal?");
  let secondId: string | null = null;
  await stage("terminal-tabs-job", async () => {
    await send("cd /tmp; sleep 300 & CW_UX_JOB=$!; printf '__UX_JOB__%s__\\n' \"$CW_UX_JOB\"");
    await expect(rows).toContainText(/__UX_JOB__\d+__/);
    job = /__UX_JOB__(\d+)__/.exec(await rows.innerText())![1];
  });
  await stage("terminal-tabs-rename", async () => {
    await button(page, "Rename terminal").click();
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
    await button(page, "Rename terminal").click();
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
    await button(page, "Close terminal").click();
    await button(close, "Cancel").click();
    await expect(page.getByRole("tab")).toHaveCount(2);
    await button(page, "Close terminal").click();
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
    await send("test \"$(jobs -pr)\" = \"$CW_UX_JOB\" && kill -0 \"$CW_UX_JOB\" && printf '__UX_SURVIVOR__%s__%s__%s__%s__\\n' \"$CW_UX_SESSION\" \"$$\" \"$PWD\" \"$CW_UX_JOB\"");
    await expect(rows).toContainText(`__UX_SURVIVOR__preserved__${pid}__/tmp__${job}__`);
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
    await expect(port).toContainText("8080 · Creator");
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
  try {
    await stage("ports-preview-denied", async () => {
      const denied = await anonymous.get(preview, { maxRedirects: 0, timeout: 15_000 });
      expect([302, 303, 401, 403]).toContain(denied.status());
      expect(await denied.text()).not.toContain(canary);
    });
    // #2142: normal private-preview Open has no browser-auth handoff yet.
    // Do not inject a full account cookie or claim authenticated Open proof.
    await stage("ports-preview-removed", async () => {
      await button(port, "Remove ux-preview preview").click();
      await expect(port).toHaveCount(0);
      const removed = await anonymous.get(preview, { maxRedirects: 0, timeout: 15_000 });
      expect(removed.status()).toBe(404);
      expect(await removed.text()).not.toContain(canary);
    });
  } finally { await anonymous.dispose(); }
  await stage("ports-close", async () => {
    await button(ports, "Close").click();
    expect(page.url()).toBe(before);
    // The dialog must leave the live terminal intact. Check its latest
    // output: earlier lines may have scrolled out of the visible rows.
    await expect(rows).toContainText("__UX_PREVIEW_ready__");
    await expect(button(page, "Disconnect")).toBeEnabled({ timeout: TERMINAL_ATTACH_MS });
  });
  await stage("resize-dismissal", async () => {
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
