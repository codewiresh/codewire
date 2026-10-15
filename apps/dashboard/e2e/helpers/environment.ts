import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { TestInfo } from "@playwright/test";
import postgres from "postgres";

const sql = postgres(process.env.DATABASE_URL!);
const execFileAsync = promisify(execFile);

async function hasTable(tableName: string): Promise<boolean> {
  const [row] = await sql`
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name = ${tableName}
    LIMIT 1
  `;
  return Boolean(row);
}

/**
 * Seed a sandbox environment preset for testing.
 * Returns the preset ID. Idempotent by name within org.
 */
export async function ensureTestSandboxPreset(
  orgId: string,
  name = "e2e-sandbox-preset",
): Promise<string> {
  const [existing] = await sql`
    SELECT id FROM environment_presets
    WHERE org_id = ${orgId} AND name = ${name}
  `;
  if (existing) return existing.id;

  const presetId = crypto.randomUUID();
  await sql`
    INSERT INTO environment_presets
      (id, org_id, name, description, build_status,
       default_ttl_seconds, project_spec)
    VALUES (${presetId}, ${orgId}, ${name}, 'E2E test preset', 'ready',
            3600, jsonb_build_object(
              'schema_version', 1,
              'working_directory', '/workspace',
              'image', 'python:3.12-slim',
              'resources', jsonb_build_object(
                'cpu_millicores', 1000,
                'memory_mib', 2048,
                'disk_gib', 5
              )
            ))
  `;
  await sql`
    INSERT INTO sandbox_template_config
      (preset_id, image_ref, sandbox_template_name, persistent_storage)
    VALUES (${presetId}, 'python:3.12-slim', 'e2e-sandbox', false)
  `;
  return presetId;
}

/**
 * Poll environment state until it reaches one of the target states.
 */
export async function waitForEnvironmentState(
  envId: string,
  targetStates: string[],
  timeoutMs = 60000,
  intervalMs = 2000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const [row] = await sql`
      SELECT state, error_reason FROM environments WHERE id = ${envId}
    `;
    if (!row) throw new Error(`Environment ${envId} not found`);
    if (targetStates.includes(row.state)) return row.state;
    if (row.state === "error" && !targetStates.includes("error")) {
      throw new Error(`Environment ${envId} errored: ${row.error_reason}`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `Environment ${envId} did not reach ${targetStates.join("/")} within ${timeoutMs}ms`,
  );
}

/**
 * Force an environment to "running" state with mock sandbox backend data.
 * Used in CI where k8s is not available.
 */
export async function forceEnvironmentRunning(
  envId: string,
  podName = "e2e-mock-pod",
): Promise<void> {
  await sql`
    UPDATE environments
    SET state = 'running', desired_state = 'started',
        started_at = NOW(), state_changed_at = NOW()
    WHERE id = ${envId}
  `;
  // Upsert sandbox backend
  await sql`
    INSERT INTO sandbox_environment_backend
      (environment_id, namespace, sandbox_claim_name, pod_name, pod_ip, agent_port)
    VALUES (${envId}, 'dev', ${podName}, ${podName}, '10.42.0.99', 9090)
    ON CONFLICT (environment_id)
    DO UPDATE SET pod_name = ${podName}, pod_ip = '10.42.0.99', namespace = 'dev'
  `;
}

/**
 * Seed an official (system) preset for testing.
 * Returns the preset ID. Idempotent by name.
 */
export async function ensureSystemPreset(
  name = "e2e-system-preset",
  image = "python:3.12-slim",
): Promise<string> {
  const [existing] = await sql`
    SELECT id FROM environment_presets
    WHERE org_id IS NULL AND name = ${name} AND official = true
  `;
  if (existing) return existing.id;

  const presetId = crypto.randomUUID();
  await sql`
    INSERT INTO environment_presets
      (id, org_id, name, description, build_status, official,
       default_ttl_seconds, project_spec)
    VALUES (${presetId}, NULL, ${name}, 'E2E system preset', 'ready', true,
            7200, jsonb_build_object(
              'schema_version', 1,
              'working_directory', '/workspace',
              'image', ${image},
              'resources', jsonb_build_object(
                'cpu_millicores', 2000,
                'memory_mib', 4096,
                'disk_gib', 10
              )
            ))
  `;
  await sql`
    INSERT INTO sandbox_template_config
      (preset_id, image_ref, sandbox_template_name, persistent_storage)
    VALUES (${presetId}, ${image}, 'e2e-system', false)
  `;
  return presetId;
}

/**
 * Clean up e2e system presets (official presets created by tests).
 */
export async function cleanupSystemPresets(): Promise<void> {
  await sql`
    DELETE FROM sandbox_template_config WHERE preset_id IN (
      SELECT id FROM environment_presets
      WHERE official = true AND name LIKE 'e2e-%'
    )
  `;
  await sql`
    DELETE FROM environment_presets
    WHERE official = true AND name LIKE 'e2e-%'
  `;
}

/**
 * Save the daemon log of each Sandbox of the orgs matching `slugPrefix` into
 * the test's output directory, which a failed Kind dashboard shard uploads.
 * Call it from a failed test, before cleanup removes the Sandboxes: their
 * daemon log is otherwise lost with them.
 */
export async function saveSandboxDaemonLogs(slugPrefix: string, testInfo: TestInfo): Promise<void> {
  const rows = await sql`
    SELECT e.id
    FROM environments e
    JOIN organizations o ON e.org_id = o.id
    WHERE o.slug LIKE ${slugPrefix + "%"}
  `;
  const context = process.env.PLAYWRIGHT_KUBE_CONTEXT || "kind-codewire";
  const namespace = process.env.PLAYWRIGHT_SANDBOX_NAMESPACE || "dev-sandboxes";
  for (const row of rows) {
    try {
      const { stdout } = await execFileAsync("kubectl", [
        "--context",
        context,
        "-n",
        namespace,
        "logs",
        "-l",
        `codewire.sh/environment-id=${row.id}`,
        "-c",
        "workspace",
        "--tail=-1",
        "--prefix",
      ], { maxBuffer: 32 * 1024 * 1024 });
      if (stdout) await writeFile(testInfo.outputPath(`sandbox-daemon-${row.id}.log`), stdout);
    } catch (err) {
      console.warn(`  [diagnostics] no daemon log for Sandbox ${row.id}: ${(err as Error).message}`);
    }
  }
}

export async function cleanupKubernetesSandboxes(slugPrefix: string): Promise<void> {
  const rows = await sql`
    SELECT e.id, stc.sandbox_template_name
    FROM environments e
    JOIN organizations o ON e.org_id = o.id
    LEFT JOIN sandbox_template_config stc ON stc.preset_id = e.preset_id
    WHERE o.slug LIKE ${slugPrefix + "%"}
  `;
  const names = rows.map((row) => `sandbox-${row.id}`);
  const templateNames = rows
    .map((row) => row.sandbox_template_name ? `${row.sandbox_template_name}-${row.id}` : "")
    .filter(Boolean);
  if (names.length === 0) return;

  const context = process.env.PLAYWRIGHT_KUBE_CONTEXT || "kind-codewire";
  const namespace = process.env.PLAYWRIGHT_SANDBOX_NAMESPACE || "dev-sandboxes";
  try {
    for (const name of names) {
      await execFileAsync("kubectl", [
        "--context",
        context,
        "-n",
        namespace,
        "patch",
        "sandboxclaim",
        name,
        "--type=merge",
        "-p",
        '{"metadata":{"finalizers":[]}}',
      ]).catch(() => undefined);
    }
    await execFileAsync("kubectl", [
      "--context",
      context,
      "-n",
      namespace,
      "delete",
      "sandboxclaim",
      ...names,
      "--ignore-not-found=true",
      "--wait=false",
    ]);
    await execFileAsync("kubectl", [
      "--context",
      context,
      "-n",
      namespace,
      "delete",
      "sandbox",
      ...names,
      "--ignore-not-found=true",
      "--wait=false",
    ]);
    if (templateNames.length > 0) {
      await execFileAsync("kubectl", [
        "--context",
        context,
        "-n",
        namespace,
        "delete",
        "sandboxtemplate",
        ...templateNames,
        "--ignore-not-found=true",
        "--wait=false",
      ]);
    }
    console.log(`  [seed] deleted ${names.length} Kubernetes sandbox(s) in ${context}/${namespace}`);
  } catch (err) {
    console.warn(`  [seed] skipped Kubernetes sandbox cleanup: ${(err as Error).message}`);
  }
}

/**
 * Clean up environment-related data for orgs matching a slug prefix.
 */
export async function cleanupEnvironments(slugPrefix: string): Promise<void> {
  await cleanupKubernetesSandboxes(slugPrefix);

  await sql`
    DELETE FROM environment_ports WHERE environment_id IN (
      SELECT e.id FROM environments e
      JOIN organizations o ON e.org_id = o.id
      WHERE o.slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM sandbox_environment_backend WHERE environment_id IN (
      SELECT e.id FROM environments e
      JOIN organizations o ON e.org_id = o.id
      WHERE o.slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM environment_sessions WHERE environment_id IN (
      SELECT e.id FROM environments e
      JOIN organizations o ON e.org_id = o.id
      WHERE o.slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM environments WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM repo_configs WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM sandbox_template_config WHERE preset_id IN (
      SELECT ep.id FROM environment_presets ep
      JOIN organizations o ON ep.org_id = o.id
      WHERE o.slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM environment_presets WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    )
  `;
}
