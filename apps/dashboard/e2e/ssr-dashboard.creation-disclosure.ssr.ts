import { expect, test } from "@playwright/test";

// Native form/disclosure proof only; not real auth or managed-Sandbox proof.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

test("creation keeps sources visible and closed advanced fields remain native form values", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native creation fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const resources = page.locator("[data-create-resources]");
  const runtime = page.locator("[data-create-runtime]");
  await expect(resources).not.toHaveAttribute("open", "");
  await expect(runtime).not.toHaveAttribute("open", "");
  await expect(page.getByLabel("CPU", { exact: true })).toBeHidden();
  await expect(page.getByLabel("Install Command", { exact: true })).toBeHidden();
  await expect(page.getByRole("heading", { name: "Repositories", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Application secrets", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provider credentials", exact: true })).toBeVisible();
  await expect(page.locator(".cw-snapshot-stub, .cw-snapshot-meter")).toHaveCount(0);
  await resources.locator("summary").click();
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Memory", { exact: true }).selectOption("4096");
  await page.getByLabel("Disk", { exact: true }).selectOption("20");
  await expect(page.getByLabel("CPU", { exact: true }).locator("option:checked")).toHaveText("2 vCPU");
  await expect(page.getByLabel("Memory", { exact: true }).locator("option:checked")).toHaveText("4 GiB");
  await expect(page.getByLabel("TTL")).toHaveAccessibleDescription(/automatic deletion.*not an idle timeout/);
  await resources.locator("summary").click();
  await runtime.locator("summary").click();
  await page.getByLabel("Install Command", { exact: true }).fill("bun install");
  await page.getByLabel("Startup Script", { exact: true }).fill("bun run dev");
  await runtime.locator("summary").click();
  const fields = await page.locator("[data-environment-form]").evaluate((form: HTMLFormElement) => {
    const data = new FormData(form);
    return Object.fromEntries(["cpu", "memory", "disk", "ttl", "install_command", "startup_script"].map((name) => [name, data.get(name)]));
  });
  expect(fields).toEqual({ cpu: "2000", memory: "4096", disk: "20", ttl: "infinity", install_command: "bun install", startup_script: "bun run dev" });
});
