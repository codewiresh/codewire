import { expect, test } from "@playwright/test";

// Editable fixture + production scripts. Provider authorization/publication is
// proved separately by the managed owner-isolated credential browser journey.
test.use({ storageState: { cookies: [], origins: [] } });

test.beforeEach(async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/settings-credentials.html`);
});

test("credential types switch native dialogs and cancellation restores focus without retaining private inputs", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const add = page.getByRole("button", { name: "Add credential", exact: true });
  await expect(page.locator("dialog[open]")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Profiles", exact: true })).toBeVisible();
  await page.screenshot({ path: test.info().outputPath("credentials-list.png") });
  await add.click();
  const chooser = page.getByRole("dialog", { name: "Add credential", exact: true });
  await expect(chooser).toBeVisible();
  await chooser.getByRole("button", { name: "GitHub", exact: true }).click();
  const github = page.getByRole("dialog", { name: "Connect GitHub", exact: true });
  await expect(chooser).not.toBeVisible();
  await expect(github).toBeVisible();
  await expect(page.locator("dialog[open]")).toHaveCount(1);
  await expect(github.locator('input[name="name"]')).toHaveCount(0);
  await expect(github.getByRole("button", { name: "Connect GitHub", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(github).not.toBeVisible();
  await expect(add).toBeFocused();

  await add.click();
  await chooser.getByRole("button", { name: "API key", exact: true }).click();
  const api = page.getByRole("dialog", { name: "Add API key", exact: true });
  await api.getByLabel("API key", { exact: true }).fill("synthetic-cancelled-key");
  await api.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(add).toBeFocused();
  await add.click();
  await chooser.getByRole("button", { name: "API key", exact: true }).click();
  await expect(api.getByLabel("API key", { exact: true })).toHaveValue("");
  await page.mouse.click(2, 2);
  await expect(api).not.toBeVisible();
  await expect(add).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(errors).toEqual([]);
});

test("profiles show their identity combination with create and exact-revision edit forms in dialogs", async ({ page }) => {
  const create = page.getByRole("button", { name: "Create profile", exact: true });
  const row = page.locator(".cw-profile-row");
  await expect(row).toContainText("Codex: Work Codex, GitHub: verified-user, SSH: Work SSH");
  await expect(row).toContainText("Revision 7");
  await create.click();
  const dialog = page.getByRole("dialog", { name: "Create profile", exact: true });
  await expect(dialog.getByRole("textbox", { name: "Profile name" })).toBeFocused();
  await expect(dialog.getByRole("combobox")).toHaveCount(5);
  await page.screenshot({ path: test.info().outputPath("create-profile-dialog.png") });
  await dialog.getByRole("textbox", { name: "Profile name" }).fill("work-github");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(create).toBeFocused();
  await row.getByRole("button", { name: "Edit profile", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "Edit work", exact: true });
  await expect(edit.locator('[name="expected_revision"]')).toHaveValue("7");
  await expect(edit.getByRole("combobox", { name: "GitHub", exact: true })).toHaveValue("fixture-github");
  await edit.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(row.getByRole("button", { name: "Edit profile", exact: true })).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
