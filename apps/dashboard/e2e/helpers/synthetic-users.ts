import { randomBytes } from "node:crypto";
import type postgres from "postgres";

// Argon2id PHC for the public TEST_PASSWORD fixture in seed.ts. This is not a
// provider credential. Production sign-in verifies the encoded parameters.
export const TEST_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=1$ajS0+W4G4VKEvSmIJj2ZSiPnNdORFB0LmKXmXIXahes$7XWR9Ucge0x9Y/Iz/RLyH1YXdrFNtyxM9g8KImRswkE";

// Each Playwright worker process acts as its own master-class identity so
// org and personal-store mutations never cross between concurrent specs.
// The ceiling is seeded eagerly; a higher --workers count self-seeds lazily.
export const WORKER_IDENTITY_CEILING = 4;
export const workerIdentityEmail = (index: number) => `e2e-worker-${index}@codewire.sh`;
export const workerIdentityName = (index: number) => `E2E Worker ${index}`;

/** Test-database fixture authority, never a production signup bypass. */
export async function seedSyntheticIdentity(
  sql: postgres.Sql,
  email: string,
  name: string,
  isAdmin = false,
): Promise<void> {
  if (!/^e2e-[a-z0-9-]+@codewire\.sh$/.test(email)) {
    throw new Error("Refusing to seed a non-synthetic dashboard identity");
  }
  await sql.begin(async (tx) => {
    const [user] = await tx.unsafe(`
      INSERT INTO users
        (id, email, name, email_verified, enabled, two_factor_enabled, is_admin)
      VALUES ($1, $2, $3, true, true, false, $4)
      ON CONFLICT (email) DO UPDATE SET
        name = EXCLUDED.name, email_verified = true, enabled = true,
        two_factor_enabled = false, is_admin = EXCLUDED.is_admin,
        locked_until = NULL, failed_login_attempts = 0, updated_at = NOW()
      RETURNING id
    `, [randomBytes(16).toString("hex"), email, name, isAdmin]);
    await tx.unsafe("DELETE FROM sessions WHERE user_id = $1", [user.id]);
    await tx.unsafe("DELETE FROM two_factor WHERE user_id = $1", [user.id]);
    await tx.unsafe("DELETE FROM two_factor_tokens WHERE user_id = $1", [user.id]);
    await tx.unsafe("DELETE FROM accounts WHERE user_id = $1 AND provider_id = 'credential'", [user.id]);
    await tx.unsafe(`
      INSERT INTO accounts (id, user_id, provider_id, account_id, password)
      VALUES ($1, $2, 'credential', $3, $4)
    `, [randomBytes(16).toString("hex"), user.id, email, TEST_PASSWORD_HASH]);
  });
}

/** Seed the per-worker dashboard identities 0..count-1 (idempotent). */
export async function seedWorkerIdentities(
  sql: postgres.Sql,
  count: number,
): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    await seedSyntheticIdentity(sql, workerIdentityEmail(index), workerIdentityName(index));
  }
}
