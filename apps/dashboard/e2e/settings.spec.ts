import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

const ACCOUNT_SERVICE_PATH = "/codewire.console.v1.AccountService/";
const GITHUB_SERVICE_PATH = "/codewire.console.v1.GitHubService/";
const credentialName = `E2E Connect Credential ${Date.now()}`;
const credentialHost = `e2e-connect-${Date.now()}.example.test`;

function captureConsoleTraffic(page: Page) {
  const connectRequests: string[] = [];
  const restRequests: string[] = [];

  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes(ACCOUNT_SERVICE_PATH) || path.includes(GITHUB_SERVICE_PATH)) {
      connectRequests.push(path);
    }
    if (
      path.startsWith("/api/v1/github/") ||
      path === "/api/v1/user/ssh-key" ||
      path.startsWith("/api/v1/user/ssh-key/") ||
      path === "/api/v1/user/git-identity" ||
      path === "/api/v1/git-credentials" ||
      path.startsWith("/api/v1/git-credentials/")
    ) {
      restRequests.push(path);
    }
  });

  return { connectRequests, restRequests };
}

test.describe.serial("Console account settings", () => {
  test("loads every settings panel through Connect", async ({ page }) => {
    const { connectRequests, restRequests } = captureConsoleTraffic(page);

    await page.goto("/dashboard/settings", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");

    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible({
      timeout: 10000,
    });
    await expect(page.getByText("Git Authentication")).toBeVisible();
    await expect(page.getByText("Git Identity")).toBeVisible();
    await expect(page.getByText("SSH Key")).toBeVisible();
    await expect(page.locator("code").first()).toContainText("ssh-", {
      timeout: 10000,
    });

    for (const method of [
      "GetGitHubStatus",
      "ListGitCredentials",
      "GetGitIdentity",
      "EnsureSshKey",
    ]) {
      const service = method === "GetGitHubStatus" ? GITHUB_SERVICE_PATH : ACCOUNT_SERVICE_PATH;
      expect(connectRequests).toContain(`${service}${method}`);
    }
    expect(restRequests).toEqual([]);
  });

  test("creates and deletes a git credential through Connect", async ({ page }) => {
    const { connectRequests, restRequests } = captureConsoleTraffic(page);

    await page.goto("/dashboard/settings", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");
    await page.getByRole("button", { name: /add credential/i }).click();
    await page.locator("#cred-name").fill(credentialName);
    await page.locator("#cred-host").fill(credentialHost);
    await page.getByLabel("Username (optional)").fill("e2e-user");
    await page.getByLabel("Token / Password").fill("e2e-connect-token");

    const createResponse = page.waitForResponse((response) =>
      response.url().includes(`${ACCOUNT_SERVICE_PATH}CreateGitCredential`) && response.ok(),
    );
    await page.locator("#cred-password").locator("xpath=../..").getByRole("button", { name: "Save" }).click();
    await createResponse;
    await expect(page.getByText(credentialName, { exact: true })).toBeVisible();

    const credentialRow = page.getByText(credentialName, { exact: true }).locator("xpath=../..");
    const deleteResponse = page.waitForResponse((response) =>
      response.url().includes(`${ACCOUNT_SERVICE_PATH}DeleteGitCredential`) && response.ok(),
    );
    await credentialRow.getByRole("button").click();
    await deleteResponse;
    await expect(page.getByText(credentialName, { exact: true })).toBeHidden();

    for (const method of ["ListGitCredentials", "CreateGitCredential", "DeleteGitCredential"]) {
      expect(connectRequests).toContain(`${ACCOUNT_SERVICE_PATH}${method}`);
    }
    expect(restRequests).toEqual([]);
  });

  test("renders a typed Connect credential error", async ({ page }) => {
    const { connectRequests, restRequests } = captureConsoleTraffic(page);

    await page.goto("/dashboard/settings", { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");
    await page.getByRole("button", { name: /add credential/i }).click();
    await page.locator("#cred-name").fill("GitHub credential");
    await page.locator("#cred-host").fill("github.com");
    await page.getByLabel("Token / Password").fill("not-stored");

    const errorResponse = page.waitForResponse((response) =>
      response.url().includes(`${ACCOUNT_SERVICE_PATH}CreateGitCredential`) && response.status() === 400,
    );
    await page.locator("#cred-password").locator("xpath=../..").getByRole("button", { name: "Save" }).click();
    await errorResponse;

    await expect(page.getByText(/use GitHub OAuth for github\.com/i)).toBeVisible();
    expect(connectRequests).toContain(`${ACCOUNT_SERVICE_PATH}CreateGitCredential`);
    expect(restRequests).toEqual([]);
  });
});
