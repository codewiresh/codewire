import { expect, test } from "@playwright/test";

test.use({ storageState: { cookies: [], origins: [] } });

test("preview choices show an unassigned URL pattern and native labeled rows", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const ports = page.locator('section[aria-labelledby="ports-title"]');
  await expect(ports.locator(".cw-preview-pattern")).toHaveText("https://{label}-{sandbox-id-prefix}-example.preview.example.test");
  await expect(ports.locator("a")).toHaveCount(0);
  await expect(ports.locator("ul[data-app-port-rows] + p[data-create-preview-hint]"))
    .toContainText("HTTP on each internal port opens at a preview URL like");
  await expect(ports.locator("[data-create-preview-hint]")).toContainText("with the access selected above");
  await ports.getByRole("button", { name: "About preview access" }).click();
  await expect(ports.locator("#create-ports-help")).toContainText("not an assigned URL");
  await expect(ports.locator("#create-ports-help")).toContainText("does not block every other form of network access");
  await page.keyboard.press("Escape");
  await expect(ports.locator("#create-ports-help")).not.toBeVisible();
  await ports.getByRole("button", { name: "Add", exact: true }).click();
  const row = ports.locator("li[data-app-port-row]");
  await row.getByLabel("Internal port", { exact: true }).fill("3000");
  await row.getByLabel("Preview label", { exact: true }).fill("9web");
  await row.getByLabel("Who can open the preview?", { exact: true }).selectOption("creator");
  expect(await row.getByLabel("Preview label", { exact: true }).evaluate((node) => node instanceof HTMLInputElement && node.checkValidity())).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await row.getByRole("button", { name: "Remove preview port", exact: true }).click();
  await expect(ports.locator("li[data-app-port-row]")).toHaveCount(0);
});

test("assigned preview URL copies exactly and clipboard denial has a manual fallback", async ({ page, context }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin });
  await page.goto(`${origin}/reference/fixtures/terminal.html`);
  await page.getByRole("button", { name: "Ports", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Ports · Example Sandbox", exact: true });
  const url = "https://web-5d1db-example.preview.example.test";
  await expect(dialog.getByRole("link", { name: "Open preview", exact: true })).toHaveAttribute("href", url);
  await dialog.getByRole("button", { name: "Copy URL", exact: true }).click();
  await expect(dialog.locator("[data-preview-copy-status]")).toHaveText("Preview URL copied.");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async () => { throw new Error("Synthetic clipboard denial"); } } });
  });
  await page.reload();
  await page.getByRole("button", { name: "Ports", exact: true }).click();
  await dialog.getByRole("button", { name: "Copy URL", exact: true }).click();
  await expect(dialog.locator("[data-preview-copy-status]")).toHaveText("Could not copy. Select and copy the preview URL above.");
  await expect(dialog.getByRole("link", { name: url, exact: true })).toHaveAttribute("href", url);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
});
