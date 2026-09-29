import { expect, test, type Page } from "@playwright/test";

// The expiry calendar is ours; the native datetime-local input stays the
// submitted UTC value and the no-script fallback.
test.use({ storageState: { cookies: [], origins: [] } });

const fixture = () => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/settings-credentials.html`;
const pad = (value: number) => String(value).padStart(2, "0");
const utcDay = (offset: number) => {
  const now = new Date();
  const day = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offset));
  return `${day.getUTCFullYear()}-${pad(day.getUTCMonth() + 1)}-${pad(day.getUTCDate())}`;
};
const openExpiry = async (page: Page) => {
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await page.getByRole("dialog", { name: "Add credential", exact: true }).getByRole("button", { name: "OpenAI API key", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add OpenAI API key", exact: true });
  await dialog.getByText("Optional expiry", { exact: true }).click();
  return dialog;
};

test.beforeEach(async () => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
});

test("the expiry calendar selects UTC dates by keyboard and pointer and writes the native value", async ({ page }) => {
  await page.goto(fixture());
  const dialog = await openExpiry(page);
  const input = dialog.getByLabel("Hard expiry (UTC)", { exact: true });
  const toggle = dialog.getByRole("button", { name: "Choose date and time", exact: true });
  await toggle.click();
  const picker = page.getByRole("dialog", { name: "Choose Hard expiry (UTC)", exact: true });
  await expect(picker).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(picker.locator("[aria-current='date']")).toBeFocused();

  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(input).toHaveValue(`${utcDay(8)}T00:00`);
  await picker.getByLabel("Time (UTC)", { exact: true }).fill("13:30");
  await picker.getByLabel("Time (UTC)", { exact: true }).press("Tab");
  await expect(input).toHaveValue(`${utcDay(8)}T13:30`);

  await expect(picker.locator("td[aria-selected='true'] button")).toHaveCount(1);

  await page.keyboard.press("Escape");
  await expect(picker).toBeHidden();
  await expect(toggle).toBeFocused();
  await expect(dialog).toBeVisible();

  await toggle.click();
  await picker.getByRole("button", { name: "Clear", exact: true }).click();
  await expect(input).toHaveValue("");
  await picker.getByRole("button", { name: "Done", exact: true }).click();
  await expect(picker).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(0);
});

test("past days cannot be chosen and months page without leaving the dialog", async ({ page }) => {
  await page.goto(fixture());
  const dialog = await openExpiry(page);
  await dialog.getByRole("button", { name: "Choose date and time", exact: true }).click();
  const picker = page.getByRole("dialog", { name: "Choose Hard expiry (UTC)", exact: true });
  await expect(picker.getByRole("button", { name: "Previous month", exact: true })).toBeDisabled();
  await picker.getByRole("button", { name: "Next month", exact: true }).click();
  await expect(picker.locator("tbody button:disabled")).toHaveCount(0);
  await picker.locator("tbody button").first().click();
  await expect(dialog.getByLabel("Hard expiry (UTC)", { exact: true })).toHaveValue(/T00:00$/);
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });
  test("the native date and time input remains the whole control", async ({ page }) => {
    await page.goto(fixture());
    const input = page.locator("#openai-api-key-expiry");
    await expect(input).toHaveAttribute("type", "datetime-local");
    await expect(page.getByRole("button", { name: "Choose date and time" })).toHaveCount(0);
  });
});
