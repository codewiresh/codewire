import { expect, test } from "@playwright/test";

// The Create sheet slides in; with motion a help trigger can move out from under
// the pointer, hover-hide its popover, and let Escape close the sheet instead.
// Reduced motion removes that race; a rarer one under heavy load remains.
test.use({ storageState: { cookies: [], origins: [] }, contextOptions: { reducedMotion: "reduce" } });

test("Create resource help stays readable without editing or closing the form", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);

  const rows = await page.locator(".cw-create-resources > .cw-field").evaluateAll((fields) =>
    fields.map((field) => Math.round(field.getBoundingClientRect().top)));
  expect(rows).toHaveLength(4);
  if ((page.viewportSize()?.width || 0) > 672) {
    expect(new Set(rows).size).toBe(1);
  } else {
    expect(rows[0]).toBe(rows[1]);
    expect(rows[2]).toBe(rows[3]);
    expect(rows[2]).toBeGreaterThan(rows[0]);
  }

  const cpu = page.getByRole("button", { name: "About CPU" });
  const help = page.locator("#fixture-cpu-help");
  if ((page.viewportSize()?.width || 0) > 672) await cpu.hover();
  else await cpu.tap();
  await expect(help).toBeVisible();
  await expect(help).not.toBeEmpty();
  const bounds = await help.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(page.viewportSize()!.height);
  await page.screenshot({ path: test.info().outputPath("create-resource-help.png") });

  await page.keyboard.press("Escape");
  await expect(help).not.toBeVisible();
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await expect(page.locator("[data-create-draft-status]")).toHaveText("");
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("codewire.create-selections.v1:")).length)).toBe(0);

  // Keyboard users reach the first resource help from the field before it.
  await page.getByRole("textbox", { name: "Name", exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(cpu).toBeFocused();
  await expect(help).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(help).not.toBeVisible();
  await expect(page.locator("[data-drawer]")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const fixture of ["create-sandbox.html", "edit-sandbox-sources.html"]) {
  test(`${fixture} keeps source detail behind accessible help`, async ({ page }) => {
    const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
    test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
    await page.goto(`${origin}/reference/fixtures/${fixture}`);

    const secretHelp = page.getByRole("button", { name: "About application secrets" });
    const triggerStyle = await secretHelp.evaluate((button) => {
      const style = getComputedStyle(button);
      return { width: button.getBoundingClientRect().width, border: style.borderTopWidth };
    });
    expect(triggerStyle.width).toBeGreaterThanOrEqual(24);
    expect(parseFloat(triggerStyle.border)).toBeGreaterThan(0);
    await secretHelp.click();
    await expect(page.locator("[id$='-secrets-help']")).toBeVisible();
    await expect(page.locator("[id$='-secrets-help']")).toContainText("Sandbox processes and root can read them");
    await page.keyboard.press("Escape");
    await expect(page.locator("[id$='-secrets-help']")).not.toBeVisible();

    await page.getByRole("button", { name: "About provider credentials" }).click();
    await expect(page.locator("[id$='-credentials-help']")).toContainText("Private keys and tokens stay outside the Sandbox");
    await expect(page.getByRole("link", { name: "Manage personal secrets" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Manage organization secrets" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Manage secret projects" })).toBeVisible();
    await page.keyboard.press("Escape");
    await page.locator(".cw-create-panel").filter({ has: page.getByRole("heading", { name: "Application secrets", exact: true }) }).screenshot({ path: test.info().outputPath(`${fixture}-secret-panel.png`) });
  });
}

test("source help without a trigger id stays open while its container scrolls", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);

  const trigger = page.getByRole("button", { name: "About application secrets" });
  await expect(trigger).not.toHaveAttribute("id");
  await trigger.click();
  const help = page.locator("#environment-create-secrets-help");
  await expect(help).toBeVisible();
  // Focusing or scrolling to a trigger scrolls the drawer; the open help must
  // follow its trigger rather than close.
  await page.locator(".cw-drawer-body").evaluate((body) => body.dispatchEvent(new Event("scroll")));
  await expect(help).toBeVisible();
  await expect(help).not.toHaveAttribute("data-field-help-trigger");
});

test("workspace image choices open as a listbox, filter, and pick by keyboard or pointer", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const image = page.getByRole("combobox", { name: "Workspace image", exact: true });
  const choices = page.getByRole("listbox", { name: "Suggested images", exact: true });
  // The native datalist popup is replaced; the datalist stays the source of choices.
  await expect(image).not.toHaveAttribute("list");
  await expect(image).toHaveAttribute("aria-expanded", "false");
  await image.click();
  await expect(choices).toBeVisible();
  await expect(choices.getByRole("option")).toHaveCount(3);
  await expect(choices.getByRole("option").first()).toContainText("Codewire workspace");
  await expect(choices.getByRole("option").first()).toContainText("Official");
  await page.screenshot({ path: test.info().outputPath("image-combobox.png") });

  // Clearing or typing an exact choice leaves nothing to suggest.
  await image.fill("");
  await expect(choices).toBeHidden();
  await image.fill("ghcr.io/example/node-22:1.4.0");
  await expect(choices).toBeHidden();
  await image.fill("python");
  await expect(choices.getByRole("option")).toHaveText([/Python 3\.13/]);
  await image.press("ArrowDown");
  await expect(image).toHaveAttribute("aria-activedescendant", "fixture-image-choices-0");
  await expect(choices.getByRole("option").first()).toHaveAttribute("aria-selected", "true");
  await image.press("Enter");
  await expect(image).toHaveValue("docker.io/library/python:3.13-slim");
  await expect(choices).toBeHidden();
  await expect(image).toBeFocused();

  // Escape closes only the list; the Create sheet stays open.
  await image.press("ArrowDown");
  await expect(choices).toBeVisible();
  await image.press("Escape");
  await expect(choices).toBeHidden();
  await expect(page.getByRole("heading", { name: "Create Sandbox", exact: true })).toBeVisible();

  await image.click();
  await choices.getByRole("option").filter({ hasText: "Node 22" }).click();
  await expect(image).toHaveValue("ghcr.io/example/node-22:1.4.0");
  await expect(image).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("workspace image keeps the native datalist", async ({ page }) => {
    const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
    test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
    await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
    await expect(page.locator("#fixture-image")).toHaveAttribute("list", "workspace-image-options");
    await expect(page.locator("#workspace-image-options option")).toHaveCount(3);
  });
});
