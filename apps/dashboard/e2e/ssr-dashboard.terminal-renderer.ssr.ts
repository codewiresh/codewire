import { expect, test } from "@playwright/test";

// Focused rendered-fixture proof using the existing Playwright runner and
// checked-in `make design-system` topology. The real sandbox lifecycle test
// separately covers transport; this preview never pretends to be a backend.
test.use({ storageState: { cookies: [], origins: [] } });

test("terminal presentation preserves colors, metrics, selection and strict CSP", async ({ page, context }) => {
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
  // The pinned xterm 6.0.0 default ANSI palette uses Tango red (#cc0000).
  await expect(rows.getByText("ANSI red", { exact: true })).toHaveCSS("color", "rgb(204, 0, 0)");
  await expect(rows.getByText("256 red", { exact: true })).toHaveCSS("color", "rgb(255, 0, 0)");
  await expect(rows.getByText("RGB blue", { exact: true })).toHaveCSS("color", "rgb(12, 160, 240)");
  await expect(rows.getByText("256 background", { exact: true })).toHaveCSS("background-color", "rgb(255, 0, 0)");
  await expect(rows.getByText("RGB background", { exact: true })).toHaveCSS("background-color", "rgb(12, 160, 240)");
  await expect(rows).toHaveCSS("font-family", /IBM Plex Mono/);
  expect(await page.evaluate(() => document.fonts.check('13px "IBM Plex Mono"'))).toBe(true);
  expect(await page.locator("[data-terminal-root] style").evaluateAll((styles) => styles.every((style) => (style as HTMLElement).nonce === "codewire-terminal-design-preview"))).toBe(true);
  await expect(page.locator("[data-terminal-root] style")).toHaveCount(3);
  expect(await page.evaluate(() => (window as Window & { terminalStyleViolations?: string[] }).terminalStyleViolations)).toEqual([]);

  const canary = rows.getByText("codewire-terminal-copy-234", { exact: true });
  const bounds = (await canary.boundingBox())!;
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
