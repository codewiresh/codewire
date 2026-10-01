import { expect, test } from "./helpers/test";
import type { Page } from "@playwright/test";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

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
  test("updates and restores Git identity through the Rust form", async ({ page, isMobile }, testInfo) => {
    test.skip(!!isMobile, "desktop settings mutation contract");
    const browserServiceCalls = watchBrowserServiceCalls(page);

    const ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    const org = { slug: `e2e-settings-identity-${runId}` };
    try {
      await ensureTestOrg("SSR Settings Identity", org.slug, ownerId);
      const context = `?org=${encodeURIComponent(org.slug)}`;
      await page.goto(`/settings/credentials/${context}`);
      const form = page.locator('form[action^="/settings/credentials/_actions/git-identity"]');
      const name = form.getByLabel("Commit author name", { exact: true });
      const email = form.getByLabel("Commit author email", { exact: true });
      const originalName = await name.inputValue();
      const originalEmail = await email.inputValue();
      try {
        await name.fill("SSR Git Identity");
        await email.fill(`ssr-git-${runId}@example.test`);
        await page.getByRole("button", { name: "Save commit identity" }).click();
        await expect(page.getByRole("status")).toContainText("Git commit identity saved");
        await expect(page).toHaveURL("/settings/credentials/?message=identity-saved#git-identity");
        await expect(page.getByLabel("Commit author name", { exact: true }).last()).toHaveValue("SSR Git Identity");
      } finally {
        // Restore even when a post-save assertion fails; exercise the retained
        // legacy POST contract without a redirect that would discard its body.
        await page.goto(`/settings/credentials/${context}`);
        const identity = page.locator('form[action^="/settings/credentials/_actions/git-identity"]');
        const csrf = await identity.locator('[name="_csrf"]').inputValue();
        const response = await page.context().request.post(`/settings/_actions/git-identity${context}`, {
          form: { _csrf: csrf, git_name: originalName, git_email: originalEmail },
          headers: { Origin: new URL(page.url()).origin }, maxRedirects: 0,
        });
        expect(response.status()).toBe(303);
        expect(response.headers().location).not.toContain("org=");
        expect(response.headers().location).toContain("message=identity-saved#git-identity");
        await page.goto(response.headers().location);
        await expect(page.getByLabel("Commit author name", { exact: true }).last()).toHaveValue(originalName);
        await expect(page.getByLabel("Commit author email", { exact: true }).last()).toHaveValue(originalEmail);
      }
      expect(browserServiceCalls).toEqual([]);
    } finally {
      await cleanupTestOrg(org.slug);
    }
  });
});
