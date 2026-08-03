import postgres from "postgres";
import { cleanupKubernetesSandboxes } from "./helpers/environment";
import { USERS, TEST_PASSWORD } from "./helpers/seed";
import { assertIdentityTopology } from "./helpers/topology";

const SERVER_URL = process.env.SERVER_URL || "http://127.0.0.1:8080";
const TOPOLOGY_PROBE_EMAIL = "e2e-topology-probe@codewire.sh";

function directDatabaseEndpoint(databaseUrl: string): string {
  const url = new URL(databaseUrl);
  return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}${url.pathname}`;
}

async function globalSetup() {
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
      createThroughServer: () => fetch(`${SERVER_URL}/api/auth/sign-up`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: TOPOLOGY_PROBE_EMAIL,
          password: TEST_PASSWORD,
          name: "E2E Topology Probe",
          invite_code: "BETA-001",
        }),
      }),
      directFixtureExists: async () => {
        const [user] = await sql`SELECT id FROM users WHERE email = ${TOPOLOGY_PROBE_EMAIL}`;
        return Boolean(user);
      },
    });

    for (const [role, user] of Object.entries(USERS)) {
      const [existing] = await sql`SELECT id FROM users WHERE email = ${user.email}`;
      if (existing) {
        console.log(`  [seed] ${role}: ${user.email} exists`);
      } else {
        // Create via the auth API so password hashing matches production.
        const res = await fetch(`${SERVER_URL}/api/auth/sign-up`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: user.email,
            password: TEST_PASSWORD,
            name: user.name,
            invite_code: "BETA-001",
          }),
        });
        if (!res.ok && res.status !== 409) {
          throw new Error(
            `Failed to create ${user.email}: ${res.status} ${await res.text()}`
          );
        }
        console.log(`  [seed] ${role}: ${user.email} created`);

        // Clear rate limits after each signup
        await sql`DELETE FROM rate_limit`;
      }

      // Ensure email is verified and 2FA is disabled (clean state for tests)
      await sql`UPDATE users SET email_verified = true, two_factor_enabled = false WHERE email = ${user.email}`;
      await sql`DELETE FROM two_factor WHERE user_id = (SELECT id FROM users WHERE email = ${user.email})`;

      // Set admin flag if needed
      if (user.isAdmin) {
        await sql`UPDATE users SET is_admin = true WHERE email = ${user.email}`;
      }
    }

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

    // Clear rate limits again for signup.spec.ts that runs after
    await sql`DELETE FROM rate_limit`;

    console.log("  [seed] global setup complete");
  } finally {
    await sql.end();
  }
}

export default globalSetup;
