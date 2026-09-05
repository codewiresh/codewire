import { expect, test, type Page } from "@playwright/test";

const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;

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
});
