import { test, expect } from "./fixtures";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const ORG_SLUG = `e2e-connect-smoke-${Date.now()}`;

test("same-origin Connect client sends the session cookie through Vite", async ({ page }) => {
  const userId = await getUserId(USERS.master.email);
  if (!userId) throw new Error("E2E master user was not seeded");

  const orgId = await ensureTestOrg("E2E Connect Smoke", ORG_SLUG, userId);

  try {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const result = await page.evaluate(async (id) => {
      const { apiKeyClient } = await import("/src/lib/connect.ts");
      const response = await apiKeyClient.listApiKeys({ orgId: id });
      return {
        apiKeyCount: response.apiKeys.length,
        nextPageToken: response.nextPageToken,
      };
    }, orgId);

    expect(result).toEqual({ apiKeyCount: 0, nextPageToken: "" });
  } finally {
    await cleanupTestOrg(ORG_SLUG);
  }
});

test("dev-mode terminal ticket uses the generated Connect client", async ({ page }) => {
  const ticketRequestContentTypes: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/codewire.console.v1.EnvironmentSetupService/IssueTerminalTicket")) {
      ticketRequestContentTypes.push(request.headers()["content-type"] ?? "");
    }
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const ticket = await page.evaluate(async () => {
    const { environmentSetupClient } = await import("/src/lib/connect.ts");
    const response = await environmentSetupClient.issueTerminalTicket({});
    return response.ticket;
  });

  expect(ticket).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  expect(ticketRequestContentTypes).toEqual(["application/json"]);
});
