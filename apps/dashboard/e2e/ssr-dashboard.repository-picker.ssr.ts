import { expect, test } from "@playwright/test";

// Presentation and interaction proof on the editable fixture using production
// scripts. No mocked provider or backend success: account discovery and checkout
// have separate service/runtime tests.
test.use({ storageState: { cookies: [], origins: [] } });

test.beforeEach(async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
});

test("GitHub dialog preserves the Sandbox draft and supports keyboard, cancel and backdrop dismissal", async ({ page }) => {
  const drawer = page.locator("[data-drawer-panel]");
  const dialog = page.getByRole("dialog", { name: "Choose a GitHub repository", exact: true });
  const opener = page.getByRole("button", { name: "Choose from GitHub", exact: true });
  await page.getByRole("textbox", { name: "Name", exact: true }).fill("keep-my-sandbox-draft");
  await opener.click();
  await expect(dialog).toBeVisible();
  expect(await dialog.evaluate((element) => element.matches(":modal"))).toBe(true);
  await expect(dialog.getByRole("combobox", { name: "GitHub credential profile" })).toBeFocused();
  await expect(dialog.getByRole("status")).toContainText("Choose a profile with a GitHub connection");
  await expect(dialog.getByRole("link", { name: "Connect GitHub or create a profile in Settings" })).toHaveAttribute("href", "settings-credentials.html");
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(drawer).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("keep-my-sandbox-draft");
  await expect(opener).toBeFocused();

  await opener.click();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  await opener.click();
  // The native dialog fills the top layer; a viewport corner is its backdrop.
  await page.mouse.click(2, 2);
  await expect(dialog).not.toBeVisible();
  await expect(drawer).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("keep-my-sandbox-draft");
});

test("custom Git URLs remain editable with unique, labelled repository rows", async ({ page }) => {
  await page.getByRole("button", { name: "Custom Git URL", exact: true }).click();
  const rows = page.locator("[data-repository-row]");
  await expect(rows).toHaveCount(2);
  const added = rows.nth(1);
  await added.getByRole("textbox", { name: "Repository URL", exact: true }).fill("https://git.example.test/team/project.git");
  await added.getByRole("textbox", { name: "Branch", exact: true }).fill("development");
  await added.getByRole("textbox", { name: "Mount path", exact: true }).fill("project");
  await expect(added.getByRole("textbox", { name: "Repository URL", exact: true })).toHaveAttribute("name", "repo_url_1");
  await added.getByRole("button", { name: "Remove repository" }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first().getByRole("textbox", { name: "Repository URL", exact: true })).toHaveValue("https://github.com/codewiresh/codewire");
});
