import postgres from "postgres";
import type { FullConfig } from "@playwright/test";
import { cleanupKubernetesSandboxes } from "./helpers/environment";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { assertIdentityTopology } from "./helpers/topology";
import { seedSyntheticIdentity, seedWorkerIdentities, WORKER_IDENTITY_CEILING } from "./helpers/synthetic-users";
import { randomBytes } from "node:crypto";

const SERVER_URL = process.env.SERVER_URL || "http://127.0.0.1:8080";
const TOPOLOGY_PROBE_EMAIL = `e2e-topology-probe-${randomBytes(16).toString("hex")}@codewire.sh`;

function directDatabaseEndpoint(databaseUrl: string): string {
  const url = new URL(databaseUrl);
  return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}${url.pathname}`;
}

async function globalSetup(config: FullConfig) {
  const databaseUrl = process.env.DATABASE_URL!;
  const sql = postgres(databaseUrl);

  const cleanupTopologyProbe = async () => {
    const [user] = await sql`SELECT id FROM users WHERE email = ${TOPOLOGY_PROBE_EMAIL}`;
    if (!user) return;
    await sql`DELETE FROM sessions WHERE user_id = ${user.id}`;
    await sql`DELETE FROM accounts WHERE user_id = ${user.id}`;
    await sql`DELETE FROM users WHERE id = ${user.id}`;
  };

  try {
    // Clear rate limits so we can seed all users without hitting limits
    await sql`DELETE FROM rate_limit`;

    await assertIdentityTopology({
      email: TOPOLOGY_PROBE_EMAIL,
      serverUrl: SERVER_URL,
      directDatabaseEndpoint: directDatabaseEndpoint(databaseUrl),
      kubeContext: process.env.KUBE_CONTEXT || "kind-codewire",
      removeDirectFixture: cleanupTopologyProbe,
      seedDirectFixture: () => seedSyntheticIdentity(sql, TOPOLOGY_PROBE_EMAIL, "E2E Topology Probe"),
      signInThroughServer: () => fetch(`${SERVER_URL}/api/auth/sign-in`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: TOPOLOGY_PROBE_EMAIL,
          password: TEST_PASSWORD,
        }),
      }),
      directSessionExists: async () => {
        const [session] = await sql`
          SELECT s.id FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE u.email = ${TOPOLOGY_PROBE_EMAIL} AND s.expires_at > NOW()
        `;
        return Boolean(session);
      },
    });

    for (const [role, user] of Object.entries(USERS)) {
      await seedSyntheticIdentity(sql, user.email, user.name, user.isAdmin);
      console.log(`  [seed] ${role}: ${user.email} prepared`);
    }
    // One master-class identity per worker process. A percentage string has
    // no fixed count, so seed the ceiling; higher counts self-seed lazily.
    const workerCount = typeof config.workers === "number"
      ? Math.max(config.workers, WORKER_IDENTITY_CEILING)
      : WORKER_IDENTITY_CEILING;
    await seedWorkerIdentities(sql, workerCount);
    console.log(`  [seed] ${workerCount} per-worker identities prepared`);

    // Clean environment data from previous runs
    await cleanupKubernetesSandboxes("e2e-");

    await sql`
      DELETE FROM environment_ports WHERE environment_id IN (
        SELECT e.id FROM environments e
        JOIN organizations o ON e.org_id = o.id
        WHERE o.slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM sandbox_environment_backend WHERE environment_id IN (
        SELECT e.id FROM environments e
        JOIN organizations o ON e.org_id = o.id
        WHERE o.slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM environment_sessions WHERE environment_id IN (
        SELECT e.id FROM environments e
        JOIN organizations o ON e.org_id = o.id
        WHERE o.slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM environments WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM repo_configs WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM sandbox_template_config WHERE preset_id IN (
        SELECT ep.id FROM environment_presets ep
        JOIN organizations o ON ep.org_id = o.id
        WHERE o.slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM environment_presets WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;

    // Clean stale e2e system presets (official presets from previous runs)
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

    // Clean transient data from previous runs (orgs with e2e- prefix slugs)
    await sql`
      DELETE FROM billing_events WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM environment_usage_billing WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM api_keys WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM environment_quotas WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM secret_projects WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM org_invitations WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`
      DELETE FROM org_members WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE 'e2e-%'
      )
    `;
    await sql`DELETE FROM organizations WHERE slug LIKE 'e2e-%'`;

    // Clear the topology sign-in rate limit before browser authentication.
    await sql`DELETE FROM rate_limit`;

    console.log("  [seed] global setup complete");
  } finally {
    await sql.end();
  }
}

export default globalSetup;
