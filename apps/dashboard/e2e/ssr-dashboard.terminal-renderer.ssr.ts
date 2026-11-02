import { expect, test } from "./helpers/fixture-test";

// Focused rendered-fixture proof using the existing Playwright runner and
// checked-in `make design-system` topology. The real sandbox lifecycle test
// separately covers transport; this preview never pretends to be a backend.
test.use({ storageState: { cookies: [], origins: [] } });

test("ports load in place and late dismissed responses cannot redirect or replace current content", { tag: "@mobile" }, async ({ page }) => {
  const designOrigin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!designOrigin, "Run make design-system for the focused fixture check");
  await page.goto(`${designOrigin}/reference/fixtures/terminal.html`);
  const originalUrl = page.url();
  const terminal = await page.locator("[data-terminal-root]").elementHandle();
  const ports = page.getByRole("button", { name: "Ports", exact: true });
  const dialog = page.getByRole("dialog", { name: "Ports · Example Sandbox", exact: true });
  await ports.click();
  await expect(dialog.getByText("Internal port 3000 · Sandbox creator", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("link", { name: "Open preview" })).toHaveAttribute("href", "https://web-5d1db-example.preview.example.test");
  expect(await dialog.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("ports-dialog.png") });
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  let releaseStale: (() => void) | undefined;
  let requests = 0;
  await page.route("**/reference/fixtures/terminal-ports.html", async (route) => {
    requests += 1;
    if (requests === 1) {
      await new Promise<void>((resolve) => { releaseStale = resolve; });
      await route.fulfill({ status: 200, headers: { "HX-Redirect": "/stale-dialog-must-not-navigate", "X-Stale-Fixture": "true" }, body: "<p>Stale response</p>" });
    } else await route.continue();
  });
  await ports.click();
  await expect.poll(() => Boolean(releaseStale)).toBe(true);
  await expect(page.locator("#sandbox-ports-content")).toHaveJSProperty("inert", true);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await ports.click();
  const staleResponse = page.waitForResponse((response) => response.headers()["x-stale-fixture"] === "true");
  releaseStale!();
  await staleResponse;
  // HTMX serializes requests from the same dialog element. The queued fresh
  // request runs after the obsolete response has been suppressed.
  await expect.poll(() => requests).toBe(2);
  await expect(page.locator("#sandbox-ports-content")).toHaveJSProperty("inert", false);
  await expect(dialog.getByText("Internal port 3000 · Sandbox creator", { exact: true })).toBeVisible();
  await expect(page.getByText("Stale response", { exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await page.unroute("**/reference/fixtures/terminal-ports.html");
  await page.route("**/reference/fixtures/terminal-ports.html", (route) => route.fulfill({ status: 503, body: "Synthetic unavailable" }));
  await ports.click();
  await expect(dialog.getByRole("alert")).toContainText("The ports could not be refreshed");
  await expect(page.locator("#sandbox-ports-content")).toHaveJSProperty("inert", true);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(ports).toBeFocused();
  expect(page.url()).toBe(originalUrl);
  expect(await terminal!.evaluate((element) => element === document.querySelector("[data-terminal-root]"))).toBe(true);
});

test("sandbox dialogs and resize dismiss without navigation or terminal replacement", { tag: "@mobile" }, async ({ page }) => {
  const designOrigin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!designOrigin, "Run make design-system for the focused fixture check");
  await page.goto(`${designOrigin}/reference/fixtures/terminal.html`);
  await expect(page.locator(".xterm")).toBeVisible();
  const terminal = await page.locator("[data-terminal-root]").elementHandle();
  const originalUrl = page.url();
  for (const name of ["Stop", "Delete"]) {
    const trigger = page.getByRole("button", { name, exact: true });
    const dialog = page.getByRole("dialog", { name: `${name} Example Sandbox?`, exact: true });
    await trigger.click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await expect(trigger).toBeFocused();
    await trigger.click();
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    await expect(trigger).toBeFocused();
    await trigger.click();
    const bounds = (await dialog.locator("p").boundingBox())!;
    await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
    await page.mouse.down();
    await page.mouse.move(5, 5);
    await page.mouse.up();
    await expect(dialog).toBeVisible();
    await page.mouse.click(5, 5);
    await expect(dialog).not.toBeVisible();
    await expect(trigger).toBeFocused();
  }
  const resize = page.locator(".cw-action-menu");
  const summary = resize.locator("summary");
  await summary.click();
  await resize.getByLabel("CPU", { exact: true }).selectOption("4000");
  await expect(resize).toHaveJSProperty("open", true);
  await page.getByRole("heading", { name: "Sandbox terminal", exact: true }).click();
  await expect(resize).toHaveJSProperty("open", false);
  await summary.click();
  await expect(resize.getByLabel("CPU", { exact: true })).toHaveValue("4000");
  await page.keyboard.press("Escape");
  await expect(resize).toHaveJSProperty("open", false);
  await expect(summary).toBeFocused();
  expect(page.url()).toBe(originalUrl);
  expect(await terminal!.evaluate((element) => element === document.querySelector("[data-terminal-root]"))).toBe(true);
});

test("legacy Escape does not consume a key without a drawer or interfere with native overlay dismissal", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for the focused fixture check");
  await page.goto(`${origin}/reference/fixtures/terminal.html`);
  await expect(page.locator(".xterm")).toBeVisible();
  const renderer = (await page.locator(".xterm").elementHandle())!;
  await page.addScriptTag({ url: `${origin}/terminal.js` });
  expect(await page.evaluate(() => {
    const event = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    document.dispatchEvent(event);
    return event.defaultPrevented;
  })).toBe(false);
  expect(await page.evaluate(async () => {
    const drawer = document.createElement("aside");
    drawer.dataset.terminalDrawer = "";
    document.body.append(drawer);
    const event = new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true });
    event.preventDefault();
    document.dispatchEvent(event);
    await Promise.resolve();
    await Promise.resolve();
    return drawer.hidden;
  })).toBe(false);
  const stop = page.getByRole("button", { name: "Stop", exact: true });
  await stop.click();
  const dialog = page.getByRole("dialog", { name: "Stop Example Sandbox?", exact: true });
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(stop).toBeFocused();
  await expect(page.locator("[data-terminal-drawer]")).toHaveJSProperty("hidden", false);
  expect(await renderer.evaluate((element) => element === document.querySelector(".xterm"))).toBe(true);
});

test("terminal presentation preserves colors, metrics, selection and strict CSP", { tag: "@mobile" }, async ({ page, context }) => {
  const designOrigin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!designOrigin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for the focused fixture check");
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: designOrigin! });
  await page.addInitScript(() => {
    const violations: string[] = [];
    (window as Window & { terminalStyleViolations?: string[] }).terminalStyleViolations = violations;
    document.addEventListener("securitypolicyviolation", (event) => violations.push(event.violatedDirective));
  });
  await page.goto(`${designOrigin}/reference/fixtures/terminal.html`);
  const rows = page.locator(".xterm-rows");
  // The renderer's first frame is start-up, not what this test checks; on a
  // loaded host it took longer than an assertion's 5 s (the full fixture gate
  // under a 20 % CPU quota), so it gets the start-up deadline.
  await expect(rows.getByText("codewire-terminal-copy-234", { exact: true })).toBeVisible({ timeout: 15_000 });
  // The pinned xterm 6.0.0 default ANSI palette uses Tango red (#cc0000).
  await expect(rows.getByText("ANSI red", { exact: true })).toHaveCSS("color", "rgb(204, 0, 0)");
  await expect(rows.getByText("256 red", { exact: true })).toHaveCSS("color", "rgb(255, 0, 0)");
  await expect(rows.getByText("RGB blue", { exact: true })).toHaveCSS("color", "rgb(12, 160, 240)");
  await expect(rows.getByText("256 background", { exact: true })).toHaveCSS("background-color", "rgb(255, 0, 0)");
  await expect(rows.getByText("RGB background", { exact: true })).toHaveCSS("background-color", "rgb(12, 160, 240)");
  await expect(rows).toHaveCSS("font-family", /Geist Mono/);
  expect(await page.evaluate(() => document.fonts.check('13px "Geist Mono"'))).toBe(true);
  expect(await page.locator("[data-terminal-root] style").evaluateAll((styles) => styles.every((style) => (style as HTMLElement).nonce === "codewire-terminal-design-preview"))).toBe(true);
  expect(await page.evaluate(() => (window as Window & { terminalStyleViolations?: string[] }).terminalStyleViolations)).toEqual([]);

  const canary = rows.getByText("codewire-terminal-copy-234", { exact: true });
  // boundingBox does not wait: it reads null while the renderer is still
  // laying out or replacing the row (the full fixture gate, mobile, under
  // load). Measure once the row is rendered.
  let measured: Awaited<ReturnType<typeof canary.boundingBox>> = null;
  await expect.poll(async () => (measured = await canary.boundingBox())).not.toBeNull();
  const bounds = measured!;
  await page.mouse.move(bounds.x, bounds.y + bounds.height / 2);
  await page.mouse.down();
  await page.mouse.move(bounds.x + bounds.width, bounds.y + bounds.height / 2, { steps: 12 });
  await page.mouse.up();
  await expect(page.locator(".xterm-selection div").first()).toBeVisible();
  const copy = page.getByRole("button", { name: "Copy selection", exact: true });
  await expect(copy).toBeEnabled();
  await copy.click();
  await expect(page.getByRole("status")).toHaveText("Selection copied.");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("codewire-terminal-copy-234");
  await page.evaluate(() => navigator.clipboard.writeText("synthetic clipboard before shortcut"));
  await page.locator(".xterm textarea").focus();
  await page.keyboard.press("Control+Shift+C");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("codewire-terminal-copy-234");
  // Browser denial is an explicit failure, not a false "copied" indication.
  await page.evaluate(() => {
    Object.defineProperty(navigator.clipboard, "writeText", {
      configurable: true,
      value: () => Promise.reject(new DOMException("Synthetic denial", "NotAllowedError")),
    });
  });
  await copy.click();
  await expect(page.getByRole("status")).toContainText("Clipboard access was denied");

  // Resize real character geometry, including the bundled font, not a masked
  // screenshot of the text. All output remains visible and selectable.
  await page.setViewportSize({ width: 1000, height: 700 });
  await expect(rows.getByText("RGB blue", { exact: true })).toHaveCSS("color", "rgb(12, 160, 240)");

  const blockedColor = await page.evaluate(() => {
    const node = document.createElement("p");
    node.textContent = "Untrusted style canary";
    node.id = "untrusted-style-canary";
    node.setAttribute("style", "color: rgb(1, 2, 3)");
    const style = document.createElement("style");
    style.textContent = "#untrusted-style-canary { color: rgb(4, 5, 6) }";
    document.body.append(node, style);
    return getComputedStyle(node).color;
  });
  expect(blockedColor).not.toBe("rgb(1, 2, 3)");
  expect(blockedColor).not.toBe("rgb(4, 5, 6)");
  await expect.poll(() => page.evaluate(() => (window as Window & { terminalStyleViolations?: string[] }).terminalStyleViolations)).toEqual(expect.arrayContaining(["style-src-attr", "style-src-elem"]));
});
