import postgres from "postgres";
import type { Page } from "@playwright/test";
import { create, toBinary } from "@bufbuild/protobuf";
import { BadRequestSchema } from "@codewire/proto-ts";
import { test, expect } from "./fixtures";
import { getUserId } from "./helpers/db";
import { ensureTestOrg, cleanupTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const sql = postgres(process.env.DATABASE_URL!);
const timestamp = Date.now();
const TEST_ORG_SLUG = `e2e-secrets-${timestamp}`;
const TEST_ORG_NAME = `E2E Secrets ${timestamp}`;
const PROJECT_NAME = `Secret Project ${timestamp}`;
const PROJECT_SECRET_KEY = `E2E_PROJECT_SECRET_${timestamp}`;
const RENAMED_PROJECT_SECRET_KEY = `E2E_PROJECT_SECRET_RENAMED_${timestamp}`;
const ORG_SECRET_KEY = `E2E_ORG_SECRET_${timestamp}`;
const RENAMED_ORG_SECRET_KEY = `E2E_ORG_SECRET_RENAMED_${timestamp}`;
const USER_SECRET_KEY = `E2E_USER_SECRET_${timestamp}`;
const RENAMED_USER_SECRET_KEY = `E2E_USER_SECRET_RENAMED_${timestamp}`;
const SECRET_SERVICE_PATH = "/codewire.v1.SecretService/";

const badRequestError = (field: string, description: string) => ({
  code: "invalid_argument",
  message: "validation failed",
  details: [
    {
      type: "google.rpc.BadRequest",
      value: Buffer.from(
        toBinary(
          BadRequestSchema,
          create(BadRequestSchema, {
            fieldViolations: [{ field, description }],
          }),
        ),
      ).toString("base64"),
    },
  ],
});

let testOrgId = "";
let masterUserId = "";

async function gotoSecrets(page: Page) {
  await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/secrets`, {
    waitUntil: "commit",
  });
  await page.waitForLoadState("domcontentloaded");
}

async function gotoSecretBucket(
  page: Page,
  bucket: "organization" | "user",
) {
  await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/secrets/${bucket}`, {
    waitUntil: "commit",
  });
  await page.waitForLoadState("domcontentloaded");
}

function captureSecretTraffic(page: Page) {
  const connectRequests: string[] = [];
  const restRequests: string[] = [];

  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.includes(SECRET_SERVICE_PATH)) connectRequests.push(path);
    if (
      path === "/api/v1/secrets" ||
      path.startsWith("/api/v1/secrets/") ||
      path === "/api/v1/user/secrets" ||
      path.startsWith("/api/v1/user/secrets/") ||
      (path.startsWith("/api/v1/organizations/") && path.includes("/secret-projects"))
    ) {
      restRequests.push(path);
    }
  });

  return { connectRequests, restRequests };
}

test.describe.serial("Secrets Page", () => {
  test.beforeAll(async () => {
    const userId = await getUserId(USERS.master.email);
    if (userId) {
      masterUserId = userId;
      testOrgId = await ensureTestOrg(TEST_ORG_NAME, TEST_ORG_SLUG, userId);
    }
  });

  test.afterAll(async () => {
    if (testOrgId) {
      await sql`
        DELETE FROM local_secrets
        WHERE path = ${`/org-secrets/${testOrgId}`}
           OR path LIKE ${`/projects/${testOrgId}/%`}
      `;
    }
    if (masterUserId) {
      await sql`
        DELETE FROM local_secrets
        WHERE path = ${`/users/${masterUserId}`}
          AND key LIKE 'E2E_%'
      `;
    }
    await cleanupTestOrg(TEST_ORG_SLUG);
  });

  test("should display secrets landing buckets and project form", async ({
    page,
  }) => {
    const { connectRequests, restRequests } = captureSecretTraffic(page);
    await gotoSecrets(page);

    await expect(page.getByRole("heading", { name: TEST_ORG_NAME }))
      .toBeVisible({ timeout: 10000 });
    await expect(page.getByRole("link", { name: /^Organization$/ }))
      .toBeVisible();
    await expect(
      page.getByRole("link", {
        name: /User Your personal credentials, injected into all environments/,
      }),
    ).toBeVisible();
    await expect(page.getByPlaceholder("New project name")).toBeVisible();
    await expect(page.getByRole("button", { name: /create/i })).toBeDisabled();
    await expect(page.getByText("No secret projects yet. Create one above."))
      .toBeVisible();
    expect(connectRequests).toContain(`${SECRET_SERVICE_PATH}ListSecretProjects`);
    expect(restRequests).toEqual([]);
  });

  test("should create, manage, and delete a secret project", async ({ page }) => {
    const { connectRequests, restRequests } = captureSecretTraffic(page);
    await gotoSecrets(page);

    await page.getByPlaceholder("New project name").fill(PROJECT_NAME);
    await page.getByRole("button", { name: /^create$/i }).click();
    const projectLink = page.getByRole("link", { name: new RegExp(PROJECT_NAME) });
    await expect(projectLink)
      .toBeVisible({ timeout: 10000 });

    await projectLink.click();
    await expect(page.getByRole("heading", { name: PROJECT_NAME })).toBeVisible();
    await page.getByPlaceholder("KEY_NAME").fill(PROJECT_SECRET_KEY);
    await page.getByPlaceholder("value").fill("project-secret-value");
    await page.getByRole("button", { name: /add/i }).click();
    await expect(page.getByText(PROJECT_SECRET_KEY)).toBeVisible({ timeout: 10000 });

    await page.getByRole("button", { name: `Rename secret ${PROJECT_SECRET_KEY}` }).click();
    await page.getByPlaceholder("NEW_KEY_NAME").fill(RENAMED_PROJECT_SECRET_KEY);
    await page.getByRole("button", { name: "Rename", exact: true }).click();
    await expect(page.getByText(RENAMED_PROJECT_SECRET_KEY)).toBeVisible({ timeout: 10000 });

    await page.getByRole("button", { name: `Delete secret ${RENAMED_PROJECT_SECRET_KEY}` }).click();
    await expect(page.getByText(RENAMED_PROJECT_SECRET_KEY)).not.toBeVisible({
      timeout: 10000,
    });

    await page.getByRole("link", { name: /back to secrets/i }).click();

    const projectRow = page
      .locator("div")
      .filter({ hasText: PROJECT_NAME })
      .filter({ has: page.getByRole("button") })
      .last();
    await projectRow.getByRole("button").click();
    await expect(page.getByRole("link", { name: new RegExp(PROJECT_NAME) }))
      .not.toBeVisible({ timeout: 10000 });
    for (const method of [
      "CreateSecretProject",
      "ListProjectSecrets",
      "SetProjectSecret",
      "RenameProjectSecret",
      "DeleteProjectSecret",
      "DeleteSecretProject",
    ]) {
      expect(connectRequests).toContain(`${SECRET_SERVICE_PATH}${method}`);
    }
    expect(restRequests).toEqual([]);
  });

  test("should add, update, and delete an organization secret", async ({
    page,
  }) => {
    const { connectRequests, restRequests } = captureSecretTraffic(page);
    await gotoSecretBucket(page, "organization");

    await expect(page.getByRole("heading", { name: "Organization Secrets" }))
      .toBeVisible({ timeout: 10000 });
    await expect(page.getByText("No secrets configured. Add one above."))
      .toBeVisible();
    await expect(page.getByRole("button", { name: /add/i })).toBeDisabled();

    await page.getByPlaceholder("KEY_NAME").fill(ORG_SECRET_KEY);
    await page.getByPlaceholder("value").fill("org-secret-value");
    await page.getByRole("button", { name: /add/i }).click();

    await expect(page.getByText(ORG_SECRET_KEY)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText("Set").first()).toBeVisible();

    await page.getByTitle("Edit value").click();
    await page.getByPlaceholder("new value").fill("org-secret-value-updated");
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByPlaceholder("new value")).not.toBeVisible({
      timeout: 10000,
    });
    await expect(page.getByText(ORG_SECRET_KEY)).toBeVisible();

    await page.getByRole("button", { name: `Rename secret ${ORG_SECRET_KEY}` }).click();
    await page.getByPlaceholder("NEW_KEY_NAME").fill(RENAMED_ORG_SECRET_KEY);
    await page.getByRole("button", { name: "Rename", exact: true }).click();
    await expect(page.getByText(RENAMED_ORG_SECRET_KEY)).toBeVisible({ timeout: 10000 });

    await page.getByRole("button", { name: `Delete secret ${RENAMED_ORG_SECRET_KEY}` }).click();
    await expect(page.getByText(RENAMED_ORG_SECRET_KEY)).not.toBeVisible({
      timeout: 10000,
    });
    for (const method of ["ListSecrets", "SetSecret", "RenameSecret", "DeleteSecret"]) {
      expect(connectRequests).toContain(`${SECRET_SERVICE_PATH}${method}`);
    }
    expect(restRequests).toEqual([]);
  });

  test("renders a Connect BadRequest validation error", async ({ page }) => {
    await page.route(`${SECRET_SERVICE_PATH}SetSecret`, (route) =>
      route.fulfill({
        status: 400,
        headers: { "content-type": "application/connect+json" },
        body: JSON.stringify(badRequestError("key", "must be a valid secret key")),
      }),
    );

    await gotoSecretBucket(page, "organization");
    await page.getByPlaceholder("KEY_NAME").fill("INVALID_KEY");
    await page.getByPlaceholder("value").fill("invalid-secret-value");
    await page.getByRole("button", { name: /add/i }).click();

    await expect(page.getByRole("alert")).toHaveText("validation failed");
  });

  test("should add and delete a user secret", async ({ page }) => {
    const { connectRequests, restRequests } = captureSecretTraffic(page);
    await gotoSecretBucket(page, "user");

    await expect(page.getByRole("heading", { name: "User Secrets" }))
      .toBeVisible({ timeout: 10000 });

    await page.getByPlaceholder("KEY_NAME").fill(USER_SECRET_KEY);
    await page.getByPlaceholder("value").fill("user-secret-value");
    await page.getByRole("button", { name: /add/i }).click();

    await expect(page.getByText(USER_SECRET_KEY)).toBeVisible({ timeout: 10000 });
    await expect(page.getByText("Set").first()).toBeVisible();

    await page.getByRole("button", { name: `Rename secret ${USER_SECRET_KEY}` }).click();
    await page.getByPlaceholder("NEW_KEY_NAME").fill(RENAMED_USER_SECRET_KEY);
    await page.getByRole("button", { name: "Rename", exact: true }).click();
    await expect(page.getByText(RENAMED_USER_SECRET_KEY)).toBeVisible({ timeout: 10000 });

    await page.getByRole("button", { name: `Delete secret ${RENAMED_USER_SECRET_KEY}` }).click();
    await expect(page.getByText(RENAMED_USER_SECRET_KEY)).not.toBeVisible({
      timeout: 10000,
    });
    for (const method of ["ListUserSecrets", "SetUserSecret", "RenameUserSecret", "DeleteUserSecret"]) {
      expect(connectRequests).toContain(`${SECRET_SERVICE_PATH}${method}`);
    }
    expect(restRequests).toEqual([]);
  });

  test("should be accessible from organization tabs", async ({ page }) => {
    await page.goto(`/dashboard/orgs/${TEST_ORG_SLUG}/environments`, {
      waitUntil: "commit",
    });
    await page.waitForLoadState("domcontentloaded");

    const secretsLink = page.getByRole("link", { name: /^Secrets$/ }).first();
    await expect(secretsLink).toBeVisible({ timeout: 10000 });
    await secretsLink.click();
    await expect(page).toHaveURL(new RegExp(`/dashboard/orgs/${TEST_ORG_SLUG}/secrets`));
  });
});
