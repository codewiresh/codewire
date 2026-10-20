import { expect, test } from "./helpers/fixture-test";

test.use({ storageState: { cookies: [], origins: [] } });

test("Create Organization keeps a readable title and bounded form at desktop and mobile widths", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-organization.html`);

  const title = page.getByRole("heading", { name: "Create Organization", exact: true });
  const form = page.locator("#organization-form");
  await expect(title).toBeVisible();
  await expect(page.getByLabel("Organization name", { exact: true })).toBeVisible();
  await expect(page.locator(".cw-form-icon")).toHaveCount(0);
  await expect(page.getByText("Organizations group your Sandboxes and team members together")).toHaveCount(0);

  const layout = await page.evaluate(() => {
    const panel = document.querySelector(".cw-form-page") as HTMLElement;
    const heading = document.querySelector(".cw-form-page .cw-page-title") as HTMLElement;
    const input = document.querySelector("#organization-name") as HTMLElement;
    return {
      viewport: innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      panelWidth: panel.getBoundingClientRect().width,
      inputWidth: input.getBoundingClientRect().width,
      textTransform: getComputedStyle(heading).textTransform,
      fontSize: parseFloat(getComputedStyle(heading).fontSize),
    };
  });
  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewport);
  expect(layout.panelWidth).toBeLessThanOrEqual(512);
  expect(layout.inputWidth).toBeLessThan(layout.panelWidth);
  expect(layout.textTransform).toBe("none");
  expect(layout.fontSize).toBeGreaterThanOrEqual(24);
  await expect(form.getByRole("button", { name: "Create Organization" })).toBeVisible();
});
