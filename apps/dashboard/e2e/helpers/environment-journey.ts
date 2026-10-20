import { expect } from "@playwright/test";
import type { Locator, Page, TestInfo } from "@playwright/test";
import postgres from "postgres";
import { cleanupEnvironments, saveSandboxDaemonLogs } from "./environment";
import { cleanupTestOrg, ensureTestOrg } from "./org";
import { defaultWorkspaceImage } from "./runtime-images";
import { ensureWorkerIdentity } from "./worker-identity";

// The Kind environment browser journeys: the serial Create checks
// (ssr-dashboard.environments.ssr.ts) and the real Sandbox lifecycle
// (ssr-dashboard.environment-lifecycle.ssr.ts). Each spec owns one journey: its
// own organization, pinned preset and Sandboxes, so the two files run on
// separate workers at the same time (#2974).

export const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
export const serverUrl = process.env.SERVER_URL || "http://127.0.0.1:8080";
const fixtureRunIdOverride = process.env.CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID;
if (
  fixtureRunIdOverride !== undefined
  && !/^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/.test(fixtureRunIdOverride)
) {
  throw new Error(
    "CODEWIRE_PLAYWRIGHT_ENVIRONMENTS_FIXTURE_RUN_ID must be 1-32 lowercase letters, digits, or internal hyphens",
  );
}
export const presetName = "ssr-environment-preset";
// Current published immutable Codewire workspace image in Harbor.
// This browser proof must never turn a floating registry tag into a test input.
export const workspaceImage = defaultWorkspaceImage;
// Sealed Kind runs side-load the Forgejo-proven workspace under a disposable
// local alias. Only the test-owned preset may use that alias; browser assertions
// above the product's canonical workspace choice continue to use workspaceImage.
export const workspaceRuntimeImage = process.env.PLAYWRIGHT_RUNTIME_WORKSPACE_IMAGE || workspaceImage;

export type EnvironmentJourney = {
  readonly sql: postgres.Sql;
  readonly runId: string;
  readonly slug: string;
  readonly orgName: string;
  readonly templatePrefix: string;
  readonly repositoryUrl: string;
  ownerId: string;
  orgId: string;
  presetId: string;
};

/** One spec's organization, named `<slugPrefix>-<run>`. */
export function environmentJourney(options: {
  slugPrefix: string;
  templatePrefix: string;
  orgName: string;
}): EnvironmentJourney {
  const runId = fixtureRunIdOverride ?? `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const slug = `${options.slugPrefix}-${runId}`;
  return {
    sql: postgres(process.env.DATABASE_URL!),
    runId,
    slug,
    orgName: options.orgName,
    templatePrefix: options.templatePrefix,
    repositoryUrl: `https://example.test/codewire/${slug}`,
    ownerId: "",
    orgId: "",
    presetId: "",
  };
}

/** beforeAll: the worker's identity owns a fresh organization with the pinned preset. */
export async function setUpEnvironmentJourney(journey: EnvironmentJourney, testInfo: TestInfo) {
  journey.ownerId = await ensureWorkerIdentity(testInfo.workerIndex);
  journey.orgId = await ensureTestOrg(journey.orgName, journey.slug, journey.ownerId);
  await seedPinnedPreset(journey);
}

/** afterEach: keep a failed Sandbox's daemon log as evidence before cleanup removes it. */
export async function keepEnvironmentJourneyEvidence(journey: EnvironmentJourney, testInfo: TestInfo) {
  if (testInfo.status !== testInfo.expectedStatus && process.env.CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE !== "prepared-kind-terminal") {
    await saveSandboxDaemonLogs(journey.slug, testInfo);
  }
}

/** afterAll: remove the journey's Sandboxes and organization. */
export async function tearDownEnvironmentJourney(journey: EnvironmentJourney) {
  const { sql, orgId, slug } = journey;
  if (process.env.CODEWIRE_PLAYWRIGHT_SNAPSHOT_PROFILE === "prepared-kind-terminal") {
    // The isolated renderer has no Kubernetes authority. Only remove SQL
    // fixture data once product Destroy has proved external resource absence.
    // A failed live fixture remains intact for the owning host to diagnose.
    const unsafe = await sql`
      SELECT id FROM environments WHERE org_id = ${orgId}
        AND (state IS DISTINCT FROM 'destroyed' OR external_cleanup_completed_at IS NULL)
    `;
    if (unsafe.length !== 0) throw new Error("Terminal renderer retained an environment without external cleanup proof; host cleanup is required");
    await cleanupTestOrg(slug);
    return;
  }
  await cleanupEnvironments(slug);
  await cleanupTestOrg(slug);
}

export function watchDisallowedBrowserCalls(page: Page) {
  const calls: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    const terminalEdge = new URL(serverUrl);
    const isTerminalSocket = ["ws:", "wss:"].includes(url.protocol)
      && url.hostname === terminalEdge.hostname
      && url.port === terminalEdge.port
      && /^\/api\/v1\/organizations\/[^/]+\/environments\/[^/]+\/terminal$/.test(url.pathname);
    if (!isTerminalSocket && (
      url.origin !== ssrUrl
      || url.pathname.includes("/codewire.")
      || url.pathname.startsWith("/api/v1/")
    )) {
      calls.push(request.url());
    }
  });
  return calls;
}

export async function openRowActions(row: Locator) {
  const trigger = row.locator('summary[aria-label^="Actions for "]');
  await expect(trigger).toBeVisible();
  await trigger.click();
}

export async function seedPinnedPreset(journey: EnvironmentJourney) {
  const { sql, orgId, ownerId, runId, repositoryUrl } = journey;
  journey.presetId = crypto.randomUUID();
  const presetId = journey.presetId;
  await sql`
    INSERT INTO environment_presets
      (id, org_id, name, slug, description, build_status, default_ttl_seconds, auto_image_ref, project_spec)
    VALUES
      (${presetId}, ${orgId}, ${presetName}, ${presetName},
       'Pinned SSR environment lifecycle preset', 'ready', 3600, ${workspaceRuntimeImage},
       ${sql.json({
         schema_version: 1,
         image: workspaceRuntimeImage,
         working_directory: "/workspace",
         install_command: "printf 'prepared-by-preset\\n'",
         startup_script: "printf 'started-by-preset\\n'",
         agents: { tools: ["codex"] },
         application_ports: [{ port: 3000, label: "web", access: "creator" }],
         resources: { cpu_millicores: 1000, memory_mib: 2048, disk_gib: 10 },
       })})
  `;
  await sql`
    INSERT INTO sandbox_template_config
      (preset_id, image_ref, sandbox_template_name, persistent_storage)
    VALUES
      (${presetId}, ${workspaceRuntimeImage}, ${`${journey.templatePrefix}-${runId}`}, false)
  `;
  await sql`
    INSERT INTO repo_configs (id, org_id, repo_url, project_spec, created_by)
    VALUES (
      ${crypto.randomUUID()}, ${orgId}, ${repositoryUrl},
      ${sql.json({
        schema_version: 1,
        preset: presetName,
        working_directory: "/workspace",
      })},
      ${ownerId}
    )
  `;
}

export async function openConfiguredImageForm(page: Page, journey: EnvironmentJourney) {
  await page.goto(`/${journey.slug}/new/`);
  await page.getByLabel("Workspace image").fill(workspaceRuntimeImage);
  await page.locator("[data-create-runtime] > summary").click();
  await page.getByLabel("Install Command").fill("printf 'configured-explicitly\\n'");
  await page.getByLabel("Startup Script").fill("printf 'started-explicitly\\n'");
  await page.getByLabel("Delete after").fill("3600s");
  await page.locator('input[name="agent"][value="codex"]').check();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Internal port", { exact: true }).fill("3000");
  await page.getByLabel("Preview label", { exact: true }).fill("web");
}
