import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import postgres from "postgres";
import { seedSyntheticIdentity, TEST_PASSWORD_HASH } from "./synthetic-users";

// Run only against an explicitly supplied disposable, migrated test database.
// Ordinary fixture unit tests never discover a database from ambient app config.
const databaseUrl = process.env.CODEWIRE_DASHBOARD_FIXTURE_DATABASE_URL;
if (!databaseUrl) {
  throw new Error("CODEWIRE_DASHBOARD_FIXTURE_DATABASE_URL must name a disposable migrated test database");
}

test("synthetic credential reseeding resets only its identity without duplicating accounts", async () => {
  const sql = postgres(databaseUrl!);
  const email = `e2e-fixture-${randomBytes(16).toString("hex")}@codewire.sh`;
  try {
    await seedSyntheticIdentity(sql, email, "Synthetic fixture", true);
    const [initial] = await sql`SELECT * FROM users WHERE email = ${email}`;
    assert.equal(initial.enabled, true);
    assert.equal(initial.email_verified, true);
    assert.equal(initial.is_admin, true);
    const providerId = randomBytes(16).toString("hex");
    await sql`
      INSERT INTO accounts (id, user_id, provider_id, account_id)
      VALUES (${providerId}, ${initial.id}, 'synthetic-other-provider', 'fixture')
    `;
    await sql`
      UPDATE users SET locked_until = NOW() + interval '1 hour',
        failed_login_attempts = 4, two_factor_enabled = true
      WHERE id = ${initial.id}
    `;
    await seedSyntheticIdentity(sql, email, "Reset fixture");
    const [reset] = await sql`SELECT * FROM users WHERE email = ${email}`;
    assert.equal(reset.id, initial.id);
    assert.equal(reset.name, "Reset fixture");
    assert.equal(reset.is_admin, false);
    assert.equal(reset.locked_until, null);
    assert.equal(reset.failed_login_attempts, 0);
    assert.equal(reset.two_factor_enabled, false);
    const credentials = await sql`
      SELECT account_id, password FROM accounts
      WHERE user_id = ${initial.id} AND provider_id = 'credential'
    `;
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].account_id, email);
    assert.equal(credentials[0].password, TEST_PASSWORD_HASH);
    const [preserved] = await sql`SELECT id FROM accounts WHERE id = ${providerId}`;
    assert.equal(preserved.id, providerId);

    const before = await sql`SELECT id, name FROM users WHERE email = ${email}`;
    await assert.rejects(seedSyntheticIdentity(sql, "owner@example.com", "Rejected"));
    const after = await sql`SELECT id, name FROM users WHERE email = ${email}`;
    assert.deepEqual([...after], [...before]);
  } finally {
    await sql`DELETE FROM users WHERE email = ${email}`;
    await sql.end();
  }
});
