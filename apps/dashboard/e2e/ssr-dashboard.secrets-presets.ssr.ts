// covers: src/routes/personal_secrets.rs src/routes/secrets_presets.rs
// covers: src/secrets_presets_connect.rs templates/organization-presets-content.html
// covers: templates/organization-presets.html templates/organization-secret-bucket-content.html
// covers: templates/organization-secret-bucket.html templates/organization-secrets-content.html
// covers: templates/organization-secrets.html templates/organization-settings-nav.html
// covers: templates/settings-navigation.html templates/settings-secrets.html
import { expect, test } from "./helpers/test";
import type { APIResponse, Page } from "@playwright/test";
import postgres from "postgres";
import { ensureWorkerIdentity } from "./helpers/worker-identity";
import { ensureTestSandboxPreset } from "./helpers/environment";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

const sql = postgres(process.env.DATABASE_URL!);
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

// Values normally use APIRequestContext. The explicit no-JavaScript case uses
// a synthetic-only value through the actual native form; screenshots and
// traces remain disabled so neither path becomes a second secret store.
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
  const pathname = bucket === "user" ? "/settings/secrets" : `/${slug}/secrets/${bucket}`;
  const csrf = await csrfFor(page, pathname);
  const account: Record<string, string> = bucket === "user"
    ? { account_id: await page.locator('input[name="account_id"]').first().inputValue(), mode: "add" }
    : {};
  const headers: Record<string, string> = { Origin: ssrUrl };
  if (useHtmx) {
    headers["HX-Request"] = "true";
    headers["HX-Current-URL"] = `${ssrUrl}${pathname}/`;
  }
  const response = await page.request.post(`${pathname}/_actions/set`, {
    form: { _csrf: csrf, key, value, ...account },
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
  if (bucket === "user") {
    await page.goto(`/${slug}/secrets/user/`);
    await expect(page).toHaveURL("/settings/secrets/");
    let row = page.locator(".cw-personal-secret-row", { hasText: key });
    await row.getByRole("button", { name: "Rename", exact: true }).click();
    const rename = page.getByRole("dialog", { name: `Rename ${key}`, exact: true });
    await rename.getByLabel("New key").fill(renamedKey);
    const [request] = await Promise.all([
      page.waitForRequest((request) => request.method() === "POST" && new URL(request.url()).pathname === "/settings/secrets/_actions/rename"),
      rename.getByRole("button", { name: "Save name", exact: true }).click(),
    ]);
    expect(request.headers().origin).toBe(ssrUrl);
    await expect(page).toHaveURL(`${ssrUrl}/settings/secrets/?message=secret-renamed`);
    await expect(page.getByRole("status")).toContainText("Secret renamed");
    row = page.locator(".cw-personal-secret-row", { hasText: renamedKey });
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    const deletion = page.getByRole("dialog", { name: `Delete ${renamedKey}?`, exact: true });
    await expect(deletion.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
    await Promise.all([
      page.waitForURL(`${ssrUrl}/settings/secrets/?message=secret-deleted`),
      deletion.getByRole("button", { name: "Delete secret", exact: true }).click(),
    ]);
    await expect(page.getByRole("status")).toContainText("Secret deleted");
    await expect(page.locator(".cw-personal-secret-row", { hasText: renamedKey })).toHaveCount(0);
    return;
  }
  const bucketPath = `/${slug}/secrets/${bucket}/`;
  await page.goto(`/${slug}/secrets/${bucket}`);
  let row = page.locator(".cw-list-row", { hasText: key });
  await row.getByText("Rename", { exact: true }).click();
  await row.getByLabel("New key").fill(renamedKey);
  await Promise.all([
    page.waitForURL(`${ssrUrl}${bucketPath}?message=secret-renamed`),
    row.getByRole("button", { name: "Rename key" }).click(),
  ]);
  await expect(page.getByRole("status")).toContainText("Secret key renamed");

  row = page.locator(".cw-list-row", { hasText: renamedKey });
  await row.getByText("Delete", { exact: true }).click();
  await Promise.all([
    page.waitForURL(`${ssrUrl}${bucketPath}?message=secret-deleted`),
    row.getByRole("button", { name: `Delete secret ${renamedKey} permanently` }).click(),
  ]);
  await expect(page.getByRole("status")).toContainText("Secret deleted");
  await expect(page.locator(".cw-list-row", { hasText: renamedKey })).toHaveCount(0);
}

test.describe.serial("server-rendered secrets and presets", () => {
  test.beforeAll(async ({}, testInfo) => {
    ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
    orgId = await ensureTestOrg(orgName, slug, ownerId);
    presetId = await ensureTestSandboxPreset(orgId, presetName);
  });

  test.afterAll(async () => {
    if (orgId) {
      await sql`
        DELETE FROM tenant_secrets
        WHERE path = ${`/org-secrets/${orgId}`}
           OR path LIKE ${`/projects/${orgId}/%`}
      `;
      await sql`
        DELETE FROM tenant_secret_deks
        WHERE scope = 'org' AND scope_id = ${orgId}
          AND NOT EXISTS (
            SELECT 1 FROM tenant_secrets
            WHERE tenant_secrets.dek_id = tenant_secret_deks.dek_id
          )
      `;
    }
    if (ownerId) {
      await sql`
        DELETE FROM tenant_secrets
        WHERE path = ${`/users/${ownerId}`}
          AND key LIKE ${`${secretPrefix}%`}
      `;
      await sql`
        DELETE FROM tenant_secret_deks
        WHERE scope = 'user' AND scope_id = ${ownerId}
          AND NOT EXISTS (
            SELECT 1 FROM tenant_secrets
            WHERE tenant_secrets.dek_id = tenant_secret_deks.dek_id
          )
      `;
    }
    await cleanupTestOrg(slug);
  });

  test("manages organization, user, and project secrets without exposing their values", { tag: "@smoke" }, async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop mutation and secret-artifact contract");
    const browserRequests: string[] = [];
    page.on("request", (request) => browserRequests.push(new URL(request.url()).pathname));

    await page.goto(`/${slug}/secrets/`);
    await expect(page.getByRole("link", { name: "Personal Your personal application secrets" })).toBeVisible();
    await expect(page.locator("#organization-content")).toContainText("Write-only application secrets");
    await expect(page.locator("#organization-content")).not.toContainText("Write-only credentials");
    await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(orgName);
    await expect(page.getByRole("list", { name: `Organization · ${orgName}`, exact: true }).getByRole("link", {
      name: "Secrets",
      exact: true,
    })).toHaveAttribute(
      "aria-current",
      "page",
    );
    await page.getByText("New Project", { exact: true }).click();
    await expect(page.getByText("A project is not a deployment stage.", { exact: false })).toBeVisible();
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
    await expect(preset).toContainText("12 GiB");

    activeEnvironmentId = crypto.randomUUID();
    await sql`
      INSERT INTO environments
        (id, org_id, created_by, type, preset_id, name, state, desired_state,
         project_spec)
      VALUES
        (${activeEnvironmentId}, ${orgId}, ${ownerId}, 'sandbox', ${presetId},
         ${`ssr-preset-in-use-${runId}`}, 'running', 'started',
         ${sql.json({
           schema_version: 1,
           image: "python:3.12-slim",
           working_directory: "/workspace",
           resources: { cpu_millicores: 1500, memory_mib: 3072, disk_gib: 12 },
         })})
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

  test("normal form secret submission works with JavaScript disabled", async ({ browser, isMobile, workerStorageState }) => {
    test.skip(!!isMobile, "desktop no-JavaScript contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: workerStorageState,
    });
    const page = await context.newPage();
    const key = `${secretPrefix}_NO_JS`;
    const renamedKey = `${key}_RENAMED`;
    const value = secretValue("no-js");
    const pathname = "/settings/secrets/";
    expect((await page.goto(pathname))?.status()).toBe(200);
    const add = page.locator("#fallback-add-secret-form");
    await expect(add).toBeVisible();
    await add.getByLabel("Key", { exact: true }).fill(key);
    await add.getByLabel("Value", { exact: true }).fill(value);
    await add.getByRole("button", { name: "Add secret", exact: true }).click();
    await expect(page).toHaveURL(`${pathname}?message=secret-saved`);
    await expect(page.getByRole("status")).toContainText("Secret saved");
    let body = await page.content();
    expect(body.includes(value) || page.url().includes(value)).toBe(false);
    expect(body.includes(artifactSecretMarker)).toBe(false);
    body = "";

    let row = page.locator(".cw-personal-secret-row", {
      has: page.getByRole("heading", { name: key, exact: true }),
    });
    const rename = row.locator('details[id$="-rename"]');
    await rename.locator("summary").click();
    await rename.getByLabel("New key", { exact: true }).fill(renamedKey);
    await rename.getByRole("button", { name: "Save name", exact: true }).click();
    await expect(page).toHaveURL(`${pathname}?message=secret-renamed`);
    row = page.locator(".cw-personal-secret-row", {
      has: page.getByRole("heading", { name: renamedKey, exact: true }),
    });
    const remove = row.locator('details[id$="-delete"]');
    await expect(remove.getByRole("button", { name: "Delete secret", exact: true })).toBeHidden();
    await remove.locator("summary").click();
    await expect(remove).toContainText("does not revoke access at an external service");
    await remove.getByRole("button", { name: "Delete secret", exact: true }).click();
    await expect(page).toHaveURL(`${pathname}?message=secret-deleted`);
    await expect(page.getByRole("heading", { name: renamedKey, exact: true })).toHaveCount(0);
    await context.close();
  });

  test("secret and preset navigation stays usable on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile responsive contract");
    await page.goto(`/${slug}/secrets/`);
    await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(orgName);
    await expect(page.getByText("New Project", { exact: true })).toBeInViewport();
    const presetsLink = page.getByRole("link", { name: "Presets", exact: true });
    await expect(presetsLink).toBeVisible();
    await presetsLink.click();
    await expect(page.getByRole("heading", { name: "Presets" }).first()).toBeVisible();
    await expect(page.locator("body")).not.toContainText(artifactSecretMarker);
  });
});
