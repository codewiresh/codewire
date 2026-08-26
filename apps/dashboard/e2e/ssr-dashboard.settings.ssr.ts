import { expect, test, type Page } from "@playwright/test";

const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const credentialName = `SSR Credential ${runId}`;
const credentialHost = `git-${runId}.example.test`;
const credentialValue = `e2e-settings-value-${crypto.randomUUID()}`;

test.use({ screenshot: "off", trace: "off" });

function watchBrowserServiceCalls(page: Page) {
  const calls: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes("/codewire.console.v1.") || path.startsWith("/api/v1/")) {
      calls.push(path);
    }
  });
  return calls;
}

test.describe.serial("server-rendered settings mutations", () => {
  test("creates and deletes a credential without exposing its value", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop settings mutation contract");
    const browserServiceCalls = watchBrowserServiceCalls(page);

    await page.goto("/settings/");
    await page.getByText("Add credential", { exact: true }).click();
    const form = page.locator('form[action="/settings/_actions/credentials/create"]');
    await form.getByLabel("Name", { exact: true }).fill(credentialName);
    await form.getByLabel("Host", { exact: true }).fill(credentialHost);
    await form.getByLabel("Username (optional)").fill("e2e-user");
    await form.getByLabel("Token or password").fill(credentialValue);
    await form.getByRole("button", { name: "Save credential" }).click();

    await expect(page).toHaveURL(/\/settings\/\?message=credential-created$/);
    await expect(page.getByRole("status")).toContainText("Git credential saved");
    expect(await page.content()).not.toContain(credentialValue);
    const row = page.locator(".cw-credential-row", { hasText: credentialName });
    await expect(row).toContainText(credentialHost);
    await row.getByRole("button", { name: "Delete" }).click();
    await expect(page).toHaveURL(/\/settings\/\?message=credential-deleted$/);
    await expect(page.getByRole("status")).toContainText("Git credential deleted");
    await expect(page.locator(".cw-credential-row", { hasText: credentialName })).toHaveCount(0);
    expect(browserServiceCalls).toEqual([]);
  });

  test("updates and restores Git identity through the Rust form", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop settings mutation contract");
    const browserServiceCalls = watchBrowserServiceCalls(page);

    await page.goto("/settings/");
    const form = page.locator('form[action="/settings/_actions/git-identity"]');
    const name = form.getByLabel("Name", { exact: true });
    const email = form.getByLabel("Email", { exact: true });
    const originalName = await name.inputValue();
    const originalEmail = await email.inputValue();
    await name.fill("SSR Git Identity");
    await email.fill(`ssr-git-${runId}@example.test`);
    await page.getByRole("button", { name: "Save identity" }).click();
    await expect(page.getByRole("status")).toContainText("Git identity saved");
    await expect(page.getByLabel("Name", { exact: true }).last()).toHaveValue("SSR Git Identity");

    await page.locator('form[action="/settings/_actions/git-identity"]').getByLabel("Name", { exact: true }).fill(originalName);
    await page.locator('form[action="/settings/_actions/git-identity"]').getByLabel("Email", { exact: true }).fill(originalEmail);
    await page.getByRole("button", { name: "Save identity" }).click();
    await expect(page.getByRole("status")).toContainText("Git identity saved");
    expect(browserServiceCalls).toEqual([]);
  });

  test("creates or rotates the account SSH key through the Rust form", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop settings mutation contract");
    const browserServiceCalls = watchBrowserServiceCalls(page);

    await page.goto("/settings/");
    const create = page.getByRole("button", { name: "Create SSH key" });
    if (await create.isVisible()) {
      await create.click();
      await expect(page.getByRole("status")).toContainText("SSH key created");
    } else {
      const before = await page.locator(".cw-public-key").textContent();
      await page.getByRole("button", { name: "Regenerate key" }).click();
      await expect(page.getByRole("status")).toContainText("SSH key regenerated");
      await expect(page.locator(".cw-public-key")).not.toHaveText(before || "");
    }
    await expect(page.locator(".cw-public-key")).toContainText("ssh-");
    expect(browserServiceCalls).toEqual([]);
  });
});
