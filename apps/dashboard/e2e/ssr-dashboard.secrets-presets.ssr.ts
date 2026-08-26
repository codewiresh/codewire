import { expect, test, type APIResponse, type Page } from "@playwright/test";
import postgres from "postgres";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getUserId } from "./helpers/db";
import { ensureTestSandboxPreset } from "./helpers/environment";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const sql = postgres(process.env.DATABASE_URL!);
const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const runId = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
const slug = `ssr-secrets-${runId}`;
const orgName = `SSR Secrets ${runId}`;
const projectName = `SSR Project ${runId}`;
const presetName = `ssr-preset-${runId}`;
const updatedPresetName = `SSR Updated Preset ${runId}`;
const secretPrefix = `SSR_SECRET_${runId.replaceAll("-", "_")}`;
const projectKey = `${secretPrefix}_PROJECT`;
const projectRenamedKey = `${secretPrefix}_PROJECT_RENAMED`;
const organizationKey = `${secretPrefix}_ORGANIZATION`;
const organizationRenamedKey = `${secretPrefix}_ORGANIZATION_RENAMED`;
const userKey = `${secretPrefix}_USER`;
const userRenamedKey = `${secretPrefix}_USER_RENAMED`;
const artifactSecretMarker = `ssr-write-only-${runId}-${crypto.randomUUID()}`;

let orgId = "";
let ownerId = "";
let presetId = "";
let activeEnvironmentId = "";

// The values exercised here are intentionally sent through APIRequestContext.
// Browser screenshots and traces must never become a second secret store.
test.use({ screenshot: "off", trace: "off" });

function secretValue(suffix: string) {
  return `${artifactSecretMarker}-${suffix}`;
}

async function responseBodyExcludesSecret(response: APIResponse, value: string) {
  let body = await response.text();
  const leaked = body.includes(value) || response.url().includes(value);
  body = "";
  expect(leaked).toBe(false);
}

async function csrfFor(page: Page, pathname: string) {
  const response = await page.goto(pathname);
  expect(response?.status()).toBe(200);
  return page.locator('input[name="_csrf"]').first().inputValue();
}

async function setSecret(
  page: Page,
  bucket: string,
  key: string,
  value: string,
  useHtmx = true,
) {
  const pathname = `/${slug}/secrets/${bucket}`;
  const csrf = await csrfFor(page, pathname);
  const headers: Record<string, string> = { Origin: ssrUrl };
  if (useHtmx) {
    headers["HX-Request"] = "true";
    headers["HX-Current-URL"] = `${ssrUrl}${pathname}/`;
  }
  const response = await page.request.post(`${pathname}/_actions/set`, {
    form: { _csrf: csrf, key, value },
    headers,
  });
  expect(response.status()).toBe(200);
  if (useHtmx) {
    expect(response.headers()["hx-redirect"]).toBe(`${pathname}/?message=secret-saved`);
  } else {
    expect(response.url()).toBe(`${ssrUrl}${pathname}/?message=secret-saved`);
  }
  await responseBodyExcludesSecret(response, value);
}

async function renameAndDeleteSecret(page: Page, bucket: string, key: string, renamedKey: string) {
  await page.goto(`/${slug}/secrets/${bucket}`);
  let row = page.locator(".cw-list-row", { hasText: key });
  await row.getByText("Rename", { exact: true }).click();
  await row.getByLabel("New key").fill(renamedKey);
  await row.getByRole("button", { name: "Rename key" }).click();
  await expect(page.getByRole("status")).toContainText("Secret key renamed");

  row = page.locator(".cw-list-row", { hasText: renamedKey });
  await row.getByText("Delete", { exact: true }).click();
  await row.getByRole("button", { name: `Delete secret ${renamedKey} permanently` }).click();
  await expect(page.getByRole("status")).toContainText("Secret deleted");
  await expect(page.locator(".cw-list-row", { hasText: renamedKey })).toHaveCount(0);
}

test.describe.serial("server-rendered secrets and presets", () => {
  test.beforeAll(async () => {
    const seededOwnerId = await getUserId(USERS.master.email);
    if (!seededOwnerId) throw new Error("E2E owner was not seeded");
    ownerId = seededOwnerId;
    orgId = await ensureTestOrg(orgName, slug, ownerId);
    presetId = await ensureTestSandboxPreset(orgId, presetName);
  });

  test.afterAll(async () => {
    if (orgId) {
      await sql`
        DELETE FROM local_secrets
        WHERE path = ${`/org-secrets/${orgId}`}
           OR path LIKE ${`/projects/${orgId}/%`}
      `;
    }
    if (ownerId) {
      await sql`
        DELETE FROM local_secrets
        WHERE path = ${`/users/${ownerId}`}
          AND key LIKE ${`${secretPrefix}%`}
      `;
    }
    await cleanupTestOrg(slug);
  });

  test("manages organization, user, and project secrets without exposing their values", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop mutation and secret-artifact contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(new URL(request.url()).pathname));

    await page.goto(`/${slug}/secrets/`);
    await expect(page.getByRole("heading", { name: orgName })).toBeVisible();
    await expect(page.getByLabel("Organization navigation").getByRole("link", {
      name: "Secrets",
      exact: true,
    })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await page.getByText("New Project", { exact: true }).click();
    await page.getByLabel("Project name").fill(projectName);
    await page.getByRole("button", { name: "Create Project" }).click();
    await expect(page.getByRole("status")).toContainText("Secret project created");

    const [project] = await sql`
      SELECT id FROM secret_projects WHERE org_id = ${orgId} AND name = ${projectName}
    `;
    expect(project?.id).toBeTruthy();
    const projectId = project.id as string;

    const projectInitialValue = secretValue("project-initial");
    await setSecret(page, projectId, projectKey, projectInitialValue);
    const projectReplacementValue = secretValue("project-replacement");
    await setSecret(page, projectId, projectKey, projectReplacementValue);
    await page.goto(`/${slug}/secrets/${projectId}/`);
    await expect(
      page.locator(".cw-secret-metadata").getByText(projectKey, { exact: true }),
    ).toBeVisible();
    await expect(page.locator("body")).not.toContainText(artifactSecretMarker);
    await renameAndDeleteSecret(page, projectId, projectKey, projectRenamedKey);

    const organizationValue = secretValue("organization");
    await setSecret(page, "organization", organizationKey, organizationValue, false);
    await expect(page.locator("body")).not.toContainText(artifactSecretMarker);
    await renameAndDeleteSecret(
      page,
      "organization",
      organizationKey,
      organizationRenamedKey,
    );

    const userValue = secretValue("user");
    await setSecret(page, "user", userKey, userValue);
    await page.goto(`/${slug}/secrets/user/`);
    await expect(page.locator("body")).not.toContainText(artifactSecretMarker);
    await renameAndDeleteSecret(page, "user", userKey, userRenamedKey);

    await page.goto(`/${slug}/secrets/`);
    const projectRow = page.locator(".cw-list-row", { hasText: projectName });
    await projectRow.getByText("Delete", { exact: true }).click();
    await projectRow
      .getByRole("button", { name: `Delete secret project ${projectName} permanently` })
      .click();
    await expect(page.getByRole("status")).toContainText("stored values deleted");
    await expect(page.locator(".cw-list-row", { hasText: projectName })).toHaveCount(0);

    expect(browserRequests.some((request) => request.includes("/codewire.v1."))).toBe(false);
    expect(browserRequests.some((request) => request.startsWith("/api/v1/secrets"))).toBe(false);
    expect(
      browserRequests.some(
        (request) => request.startsWith("/api/v1/organizations/") && request.includes("/secret-projects"),
      ),
    ).toBe(false);
  });

  test("updates presets and refuses deletion while an active environment uses one", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop preset lifecycle contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(new URL(request.url()).pathname));

    await page.goto(`/${slug}/presets/`);
    await expect(page.getByLabel("Organization navigation").getByRole("link", {
      name: "Presets",
      exact: true,
    })).toHaveAttribute(
      "aria-current",
      "page",
    );
    let preset = page.locator(".cw-preset-card", { hasText: presetName });
    await preset.getByText("Edit", { exact: true }).click();
    await preset.getByLabel("Name").fill(updatedPresetName);
    await preset.getByLabel("Description").fill("Updated through the Rust SSR preset form");
    await preset.getByLabel("CPU (millicores)").fill("1500");
    await preset.getByLabel("Memory (MB)").fill("3072");
    await preset.getByLabel("Disk (GB)").fill("12");
    await preset.getByLabel("TTL (seconds)").fill("5400");
    await preset.getByRole("button", { name: "Save Preset" }).click();
    await expect(page.getByRole("status")).toContainText("Preset updated");
    preset = page.locator(".cw-preset-card", { hasText: updatedPresetName });
    await expect(preset).toContainText("1.5 vCPU");
    await expect(preset).toContainText("3 GiB");
    await expect(preset).toContainText("12 GB");

    activeEnvironmentId = crypto.randomUUID();
    await sql`
      INSERT INTO environments
        (id, org_id, created_by, type, preset_id, name, state, desired_state)
      VALUES
        (${activeEnvironmentId}, ${orgId}, ${ownerId}, 'sandbox', ${presetId},
         ${`ssr-preset-in-use-${runId}`}, 'running', 'started')
    `;
    await page.reload();
    preset = page.locator(".cw-preset-card", { hasText: updatedPresetName });
    await preset.getByText("Delete", { exact: true }).click();
    await preset
      .getByRole("button", { name: `Delete preset ${updatedPresetName} permanently` })
      .click();
    await expect(page.getByRole("alert")).toContainText("still used by an active Sandbox");
    await expect(page.locator(".cw-preset-card", { hasText: updatedPresetName })).toBeVisible();

    await sql`DELETE FROM environments WHERE id = ${activeEnvironmentId}`;
    activeEnvironmentId = "";
    preset = page.locator(".cw-preset-card", { hasText: updatedPresetName });
    await preset.getByText("Delete", { exact: true }).click();
    await preset
      .getByRole("button", { name: `Delete preset ${updatedPresetName} permanently` })
      .click();
    await expect(page.getByRole("status")).toContainText("Preset deleted");
    await expect(page.locator(".cw-preset-card", { hasText: updatedPresetName })).toHaveCount(0);

    expect(browserRequests.some((request) => request.includes("/codewire.v1."))).toBe(false);
    expect(browserRequests.some((request) => request.includes("/api/v1/organizations/"))).toBe(false);
  });

  test("normal form secret submission works with JavaScript disabled", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "desktop no-JavaScript contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: authState,
    });
    const page = await context.newPage();
    const key = `${secretPrefix}_NO_JS`;
    const value = secretValue("no-js");
    const pathname = `/${slug}/secrets/user/`;
    const csrf = await csrfFor(page, pathname);
    const response = await context.request.post(`${pathname}_actions/set`, {
      form: { _csrf: csrf, key, value },
      headers: { Origin: ssrUrl },
    });
    expect(response.status()).toBe(200);
    expect(response.url()).toBe(`${ssrUrl}${pathname}?message=secret-saved`);
    await responseBodyExcludesSecret(response, value);
    let body = await response.text();
    expect(body).toContain("<!doctype html>");
    expect(body).toContain(key);
    expect(body).not.toContain(artifactSecretMarker);
    body = "";
    await context.close();
  });

  test("secret and preset navigation stays usable on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile responsive contract");
    await page.goto(`/${slug}/secrets/`);
    await expect(page.getByRole("heading", { name: orgName })).toBeVisible();
    await expect(page.getByText("New Project", { exact: true })).toBeInViewport();
    await expect(page.getByRole("link", { name: "Presets", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Presets", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Presets" })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(artifactSecretMarker);
  });
});
