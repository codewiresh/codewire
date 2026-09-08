import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "@playwright/test";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

test.describe("managed provider credential browser journey", () => {
  test.skip(
    process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1",
    "requires the managed non-promotable Kind credential fixture",
  );
  test.use({ storageState: authState });

  test("connects GitHub through the session BFF, then revokes and deletes it", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop credential lifecycle contract");
    const name = `e2e-github-${randomUUID()}`;

    const settings = await page.goto("/settings/credentials/");
    expect(settings?.status()).toBe(200);
    const connectCard = page.locator("section", {
      has: page.getByRole("heading", { name: "Connect provider account", exact: true }),
    });
    const form = connectCard.locator("form");
    await form.getByLabel("Provider").selectOption("github");
    await form.getByLabel("Credential name").fill(name);

    const enrollmentResponse = page.waitForResponse((response) => (
      response.url().includes("/settings/credentials/_actions/credentials/oauth/enroll")
      && response.request().method() === "POST"
    ));
    await form.getByRole("button", { name: "Start connection", exact: true }).click();
    const response = await enrollmentResponse;
    expect(response.status()).toBe(200);
    expect(response.headers()["cache-control"]).toBe("no-store, no-cache, must-revalidate");
    expect(response.headers()["x-accel-buffering"]).toBe("no");
    const responseBody = await response.text();
    const challenge = responseBody.indexOf("ABCD-EFGH");
    const committed = responseBody.indexOf("Credential connected.");
    expect(challenge).toBeGreaterThan(-1);
    expect(committed).toBeGreaterThan(challenge);

    await expect(page.getByRole("heading", { name: "Authorize GitHub", exact: true })).toBeVisible();
    await expect(page.getByText("ABCD-EFGH", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open GitHub authorization", exact: true }))
      .toHaveAttribute("href", "https://github.com/login/device");
    await expect(page.getByRole("status")).toHaveText("Credential connected.");
    let rendered = await page.locator("body").textContent();
    expect(rendered?.includes("gho_")).toBe(false);
    expect(rendered?.includes("oauth_token")).toBe(false);

    await page.getByRole("link", { name: "Return to credentials", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/`);
    let row = page.locator(".cw-credential-row", { hasText: name });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("GitHub · OAuth");
    await expect(row).toContainText("synthetic-user");
    await expect(row).toContainText("Active");
    await expect(row).toContainText("Generation 1");
    rendered = await page.locator("body").textContent();
    expect(rendered?.includes("gho_")).toBe(false);
    expect(rendered?.includes("oauth_token")).toBe(false);

    await row.getByText("Revoke", { exact: true }).click();
    await row.getByRole("button", { name: `Revoke ${name}`, exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-revoked`);
    await expect(page.getByRole("status")).toHaveText("Credential revoked.");
    row = page.locator(".cw-credential-row", { hasText: name });
    await expect(row).toContainText("Revoked");
    await expect(row).toContainText("Generation 2");

    await row.getByText("Delete", { exact: true }).click();
    await row.getByRole("button", { name: `Delete ${name}`, exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-deleted`);
    await expect(page.getByRole("status")).toHaveText("Credential deleted.");
    await expect(page.locator(".cw-credential-row", { hasText: name })).toHaveCount(0);
  });
});
