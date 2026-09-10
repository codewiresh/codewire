import { createHash, randomBytes, randomUUID } from "node:crypto";
import postgres from "postgres";
import { seedSyntheticIdentity } from "./synthetic-users";

const sql = postgres(process.env.DATABASE_URL!);

export async function seedSyntheticUser(email: string, name: string, isAdmin = false) {
  await seedSyntheticIdentity(sql, email, name, isAdmin);
}

export async function clearRateLimits() {
  await sql`DELETE FROM rate_limit`;
}

export async function verifyUserEmail(email: string) {
  await sql`UPDATE users SET email_verified = true WHERE email = ${email}`;
}

export async function bypassTwoFactor(email: string) {
  await sql`UPDATE users SET two_factor_enabled = true WHERE email = ${email}`;
}

export async function disableTwoFactor(email: string) {
  await sql`
    DELETE FROM two_factor
    WHERE user_id = (SELECT id FROM users WHERE email = ${email})
  `;
  await sql`UPDATE users SET two_factor_enabled = false WHERE email = ${email}`;
}

export async function createAuthenticatedSession(email: string) {
  const [user] = await sql`SELECT id FROM users WHERE email = ${email}`;
  if (!user) throw new Error(`Cannot create an E2E session for missing user ${email}`);

  const id = `e2e_${randomUUID()}`;
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  await sql`
    INSERT INTO sessions (id, user_id, token_hash, expires_at, ip_address, user_agent)
    VALUES (${id}, ${user.id}, ${tokenHash}, NOW() + interval '1 hour', '127.0.0.1', 'Playwright E2E')
  `;
  return { id, token };
}

export async function deleteSession(id: string) {
  await sql`DELETE FROM sessions WHERE id = ${id}`;
}

// Note: BETA-001 is the accepted local E2E invite contract.
// Valid codes: BETA2024, EARLYBIRD, CODEWIRE1, PRIVATEBETA, DEVACCESS
export const TEST_INVITE_CODE = "BETA2024";

export async function makeUserAdmin(email: string) {
  await sql`UPDATE users SET is_admin = true WHERE email = ${email}`;
}

// Bind a test-owned capability to the row issued by the real password-reset
// request. Production stores only a purpose-bound digest, so the original raw
// capability is intentionally unrecoverable from the database.
export async function bindSyntheticPasswordResetToken(
  identifier: string,
): Promise<string | null> {
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256")
    .update("codewire/idp/verification/v1\0")
    .update("password_reset")
    .update("\0")
    .update(token)
    .digest("hex");
  const [row] = await sql`
    UPDATE verifications
    SET token_hash = ${tokenHash}, updated_at = NOW()
    WHERE id = (
      SELECT id FROM verifications
      WHERE identifier = ${identifier}
        AND purpose = 'password_reset'
        AND expires_at > NOW()
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    )
    RETURNING id
  `;
  return row ? token : null;
}

// Get user ID by email
export async function getUserId(email: string): Promise<string | null> {
  const [result] = await sql`
    SELECT id FROM users WHERE email = ${email}
  `;
  return result?.id ?? null;
}

// Clean up a single user and all associated auth records
export async function cleanupUser(email: string): Promise<void> {
  await sql`DELETE FROM verifications WHERE identifier = ${email}`;
  const [user] = await sql`SELECT id FROM users WHERE email = ${email}`;
  if (!user) return;
  await sql`DELETE FROM sessions WHERE user_id = ${user.id}`;
  await sql`DELETE FROM accounts WHERE user_id = ${user.id}`;
  await sql`DELETE FROM users WHERE id = ${user.id}`;
}

// Clean up organization test data by slug prefix using the current org/environment schema.
export async function cleanupOrgs(slugPrefix: string): Promise<void> {
  const slugLike = slugPrefix + "%";
  await sql`
    DELETE FROM billing_events WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM environment_usage_billing WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM api_keys WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM repo_configs WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM environments WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM environment_quotas WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM sandbox_template_config WHERE preset_id IN (
      SELECT id FROM environment_presets WHERE org_id IN (
        SELECT id FROM organizations WHERE slug LIKE ${slugLike}
      )
    )
  `;
  await sql`
    DELETE FROM environment_presets WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM secret_projects WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM org_invitations WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`
    DELETE FROM org_members WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugLike}
    )
  `;
  await sql`DELETE FROM organizations WHERE slug LIKE ${slugLike}`;
}

// Clean up billing test orgs (subscriptions, invoices, members, orgs)
export async function cleanupBillingOrg(slugPrefix: string): Promise<void> {
  await cleanupOrgs(slugPrefix);
}

// ---------------------------------------------------------------------------
// Environment billing test helpers
// ---------------------------------------------------------------------------

/** Insert synthetic environment billing_events (simulates metering loop output) */
export async function insertEnvBillingEvents(
  orgId: string,
  envId: string,
  elapsedSeconds: number,
  cpuMillicores: number,
  memoryMb: number,
  diskGb: number,
): Promise<void> {
  void envId;
  const metadata = {
    elapsed_seconds: elapsedSeconds,
    cpu_millicores: cpuMillicores,
    memory_mb: memoryMb,
    disk_gb: diskGb,
    type: "sandbox",
  };
  await sql`
    INSERT INTO billing_events (event_type, org_id, metadata)
    VALUES ('environment_usage', ${orgId}, ${sql.json(metadata)})
  `;

  const endedAt = new Date();
  const startedAt = new Date(endedAt.getTime() - elapsedSeconds * 1000);
  const runtimeName = `playwright-${envId.slice(0, 8)}`;

  await sql`
    INSERT INTO sandbox_running_sessions (
      environment_id,
      organization_id,
      runtime_type,
      runtime_uid,
      runtime_name,
      runtime_namespace,
      cpu_millicores,
      memory_mib,
      disk_gib,
      started_at,
      last_observed_at,
      ended_at,
      end_reason
    )
    VALUES (
      ${envId},
      ${orgId},
      'sandbox',
      ${`playwright-${crypto.randomUUID()}`},
      ${runtimeName},
      'dev-sandboxes',
      ${cpuMillicores},
      ${memoryMb},
      ${diskGb},
      ${startedAt},
      ${endedAt},
      ${endedAt},
      'playwright-seed'
    )
  `;
}

/** Get environment_usage_billing record for an org */
export async function getEnvUsageBilling(
  orgId: string,
): Promise<{ last_overage_cents: number; last_cpu_hours: number } | null> {
  const [result] = await sql`
    SELECT last_overage_cents, last_cpu_hours
    FROM environment_usage_billing
    WHERE org_id = ${orgId}
    ORDER BY billing_period_start DESC LIMIT 1
  `;
  return result ? {
    last_overage_cents: Number(result.last_overage_cents),
    last_cpu_hours: Number(result.last_cpu_hours),
  } : null;
}

/** Insert an environment_subscriptions row */
export async function insertEnvSubscription(
  orgId: string,
  plan: string,
): Promise<string> {
  const id = crypto.randomUUID();
  await sql`
    INSERT INTO environment_subscriptions (id, org_id, plan, status)
    VALUES (${id}, ${orgId}, ${plan}, 'active')
    ON CONFLICT (org_id) DO UPDATE SET plan = ${plan}, status = 'active'
  `;
  return id;
}

/** Clean up environment billing data by org slug prefix */
export async function cleanupEnvBilling(slugPrefix: string): Promise<void> {
  await sql`
    DELETE FROM billing_events WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    ) AND event_type = 'environment_usage'
  `;
  await sql`
    DELETE FROM environment_usage_billing WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    )
  `;
  await sql`
    DELETE FROM environment_subscriptions WHERE org_id IN (
      SELECT id FROM organizations WHERE slug LIKE ${slugPrefix + "%"}
    )
  `;
}
