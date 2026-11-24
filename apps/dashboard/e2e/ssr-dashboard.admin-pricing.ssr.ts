import { expect, test, type Page } from "./helpers/fixture-test";

// The admin Pricing page (#5782; docs/dev/BILLING.md "Prices", journey
// billing-admin-prices) in its edit, review and unavailable states: what an
// administrator reads and types, and a page that fits a phone without
// horizontal scroll.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

async function open(page: Page, fixture: string) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/${fixture}.html`);
  await expect(page.getByRole("heading", { level: 1, name: "Pricing" })).toBeVisible();
  await expect(page.getByText("A change applies from the next metering draw and never re-prices past usage.")).toBeVisible();
}

async function expectNoSidewaysScroll(page: Page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
}

test("each charged card edits its four rates in euros; Unlimited has no form", { tag: "@mobile" }, async ({ page }) => {
  await open(page, "admin-pricing");
  const headings = page.getByRole("heading", { level: 2 });
  await expect(headings).toHaveText(["Regular", "Discounted", "Unlimited"]);

  const regular = page.getByRole("region", { name: "Regular" });
  await expect(regular.getByText("Updated Nov 23, 2026, 00:00 UTC")).toBeVisible();
  for (const [label, value] of [
    ["vCPU, per hour", "0.0438"],
    ["Memory, per GiB-hour", "0.0141"],
    ["Disk, per GiB-hour", "0.000087"],
    ["Storage while suspended or hibernated, per GiB-hour", "0"],
  ] as const) {
    const input = regular.getByLabel(label);
    await expect(input).toHaveValue(value);
    await expect(input).toHaveAttribute("type", "text");
    await expect(input).toHaveAttribute("inputmode", "decimal");
    // The € sits inside the control, on its line.
    const group = (await input.locator("xpath=..").boundingBox())!;
    const box = (await input.boundingBox())!;
    expect(box.x).toBeGreaterThan(group.x);
    expect(box.x + box.width).toBeLessThanOrEqual(group.x + group.width + 1);
  }
  await expect(regular.locator(".cw-input-group > span")).toHaveText(["€", "€", "€", "€"]);
  await expect(regular.getByRole("button", { name: "Review" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Discounted" }).getByLabel("Disk, per GiB-hour")).toHaveValue("0.0000435");

  const unlimited = page.getByRole("region", { name: "Unlimited" });
  await expect(unlimited.locator("form")).toHaveCount(0);
  await expect(unlimited.locator("dd")).toHaveText(["€0", "€0", "€0", "€0"]);
  await expect(unlimited.getByText("Unlimited is never charged.")).toBeVisible();
  await expectNoSidewaysScroll(page);
});

test("the review lists the changed rates and asks to confirm a large increase", { tag: "@mobile" }, async ({ page }) => {
  await open(page, "admin-pricing-review");
  const review = page.getByRole("region", { name: "Review Regular's prices" });
  const table = review.getByRole("table");
  await expect(table.getByRole("columnheader")).toHaveText(["Rate", "Now", "New"]);
  await expect(table.getByRole("rowheader")).toHaveText([
    "vCPU, per hour",
    "Memory, per GiB-hour",
    "Storage while suspended or hibernated, per GiB-hour",
  ]);
  const cpu = table.getByRole("row", { name: /vCPU, per hour/ });
  await expect(cpu.getByRole("cell")).toHaveText(["€0.0438", "€0.1More than double"]);
  await expect(cpu.locator('.cw-badge[data-tone="warning"]')).toHaveText("More than double");
  await expect(table.getByRole("row", { name: /Memory/ }).locator(".cw-badge")).toHaveCount(0);

  const confirm = review.getByRole("checkbox", { name: "I confirm these increases." });
  await expect(confirm).not.toBeChecked();
  await expect(confirm).toHaveJSProperty("required", true);
  await expect(review.getByRole("button", { name: "Save prices" })).toBeVisible();
  await expect(review.getByRole("link", { name: "Back" })).toBeVisible();
  // The table may scroll inside its frame on a phone; the page never does.
  await expectNoSidewaysScroll(page);
});

test("a failed read shows the error and nothing to edit", { tag: "@mobile" }, async ({ page }) => {
  await open(page, "admin-pricing-unavailable");
  await expect(page.getByRole("alert")).toHaveText("Prices can't be loaded right now.");
  await expect(page.locator("form")).toHaveCount(0);
  await expect(page.getByRole("heading", { level: 2 })).toHaveCount(0);
  await expectNoSidewaysScroll(page);
});
