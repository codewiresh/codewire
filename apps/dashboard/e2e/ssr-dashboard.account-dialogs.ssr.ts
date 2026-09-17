import { expect, test } from "@playwright/test";

// Editable Account fixture with production dialog behavior. Synthetic POSTs
// are intercepted externally; no instrumentation enters the product assets.
test.use({ storageState: { cookies: [], origins: [] } });

test("Account sections share a page and exact-session confirmation cancels safely", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const requests: string[] = [];
  await page.route("**/settings/_actions/sessions/revoke", async (route) => {
    requests.push(route.request().postData() || "");
    await route.fulfill({ status: 200, contentType: "text/plain", body: "Synthetic session signed out" });
  });
  await page.goto(`${origin}/reference/fixtures/settings-account.html`);
  for (const name of ["Account details", "Security", "Active sessions"]) {
    await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("link", { name: "Credentials", exact: true })).toHaveAttribute("href", "settings-credentials.html");
  const button = page.getByRole("button", { name: "Sign out session", exact: true });
  await button.click();
  const dialog = page.getByRole("dialog", { name: "Sign out session?", exact: true });
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await expect(dialog).toContainText("session-other");
  await expect(dialog.locator('[name="account_id"]')).toHaveValue("fixture-account");
  await expect(dialog.locator('[name="session_id"]')).toHaveValue("session-other");
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(button).toBeFocused();
  expect(requests).toEqual([]);
  await button.click();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(button).toBeFocused();
  expect(requests).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("account-sections.png"), fullPage: true });
  await button.click();
  await dialog.getByRole("button", { name: "Sign out session", exact: true }).click();
  await expect(page.getByText("Synthetic session signed out", { exact: true })).toBeVisible();
  expect(requests).toHaveLength(1);
  const form = new URLSearchParams(requests[0]);
  expect(Object.fromEntries(form)).toEqual({ _csrf: "design-fixture-only", account_id: "fixture-account", session_id: "session-other" });
});
