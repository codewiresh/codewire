import { test, expect } from "./fixtures";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const ORG_SLUG = `e2e-api-keys-${Date.now()}`;
const KEY_NAME = "E2E Connect API Key";
const API_KEY_SERVICE_PATH = "/codewire.v1.ApiKeyService/";

test("manages API keys through Connect", async ({ page }) => {
  const userId = await getUserId(USERS.master.email);
  if (!userId) throw new Error("E2E master user was not seeded");

  await ensureTestOrg("E2E API Keys", ORG_SLUG, userId);
  const connectRequests: string[] = [];
  const restApiKeyRequests: string[] = [];

  page.on("request", (request) => {
    const url = request.url();
    if (url.includes(API_KEY_SERVICE_PATH)) connectRequests.push(url);
    if (url.includes("/api/v1/organizations/") && url.includes("/api-keys")) {
      restApiKeyRequests.push(url);
    }
  });

  try {
    await page.goto(`/dashboard/orgs/${ORG_SLUG}/api-keys`, { waitUntil: "domcontentloaded" });
    await expect(page.getByText("No API keys yet. Create one for programmatic access.")).toBeVisible();

    await page.getByRole("button", { name: "Create Key" }).click();
    const createDialog = page.getByRole("dialog").filter({ hasText: "Create API Key" });
    await createDialog.getByLabel("Name").fill(KEY_NAME);

    const createResponse = page.waitForResponse(
      (response) => response.url().includes("/codewire.v1.ApiKeyService/CreateApiKey") && response.ok(),
    );
    await createDialog.getByRole("button", { name: "Create", exact: true }).click();
    await createResponse;

    const revealDialog = page.getByRole("dialog").filter({ hasText: "API Key Created" });
    await expect(revealDialog.getByText(/^cw_/)).toBeVisible();
    await revealDialog.getByRole("button", { name: "Done" }).click();

    const keyRow = page.getByRole("row").filter({ hasText: KEY_NAME });
    await expect(keyRow).toBeVisible();

    const updateResponse = page.waitForResponse(
      (response) => response.url().includes("/codewire.v1.ApiKeyService/UpdateApiKey") && response.ok(),
    );
    await keyRow.getByRole("button", { name: "Disable API key" }).click();
    await updateResponse;
    await expect(keyRow.getByText("Disabled")).toBeVisible();

    await keyRow.getByRole("button", { name: "Delete API key" }).click();
    const deleteDialog = page.getByRole("dialog").filter({ hasText: "Delete API Key" });
    const deleteResponse = page.waitForResponse(
      (response) => response.url().includes("/codewire.v1.ApiKeyService/DeleteApiKey") && response.ok(),
    );
    await deleteDialog.getByRole("button", { name: "Delete", exact: true }).click();
    await deleteResponse;
    await expect(page.getByRole("row").filter({ hasText: KEY_NAME })).toHaveCount(0);

    for (const method of ["ListApiKeys", "CreateApiKey", "UpdateApiKey", "DeleteApiKey"]) {
      expect(connectRequests.some((url) => url.includes(`${API_KEY_SERVICE_PATH}${method}`))).toBe(true);
    }
    expect(restApiKeyRequests).toEqual([]);
  } finally {
    await cleanupTestOrg(ORG_SLUG);
  }
});
