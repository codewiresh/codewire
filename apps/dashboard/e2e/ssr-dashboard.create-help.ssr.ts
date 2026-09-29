import { expect, test } from "@playwright/test";

// The Create sheet slides in; with motion a help trigger can move out from under
// the pointer, hover-hide its popover, and let Escape close the sheet instead.
test.use({ storageState: { cookies: [], origins: [] }, reducedMotion: "reduce" });

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
  await expect(help).toContainText("1000 millicores equals 1 vCPU");
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
    await page.locator(".cw-secret-panel").screenshot({ path: test.info().outputPath(`${fixture}-secret-panel.png`) });
  });
}
