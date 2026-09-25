// Seed the synthetic owner login into the retained local Kind cluster, with
// one organization so Create works right away. Test-fixture authority only:
// seedSyntheticIdentity refuses any non-e2e-*@codewire.sh email.
import { randomUUID } from "node:crypto";
import postgres from "postgres";
import { USERS } from "../../../apps/dashboard/e2e/helpers/seed";
import { seedSyntheticIdentity } from "../../../apps/dashboard/e2e/helpers/synthetic-users";

const ORGANIZATION_SLUG = "e2e-owner";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
const sql = postgres(databaseUrl, { max: 1 });
try {
  await seedSyntheticIdentity(sql, USERS.owner.email, USERS.owner.name, USERS.owner.isAdmin);
  const [owner] = await sql`SELECT id FROM users WHERE email = ${USERS.owner.email}`;
  const [existing] = await sql`SELECT id FROM organizations WHERE slug = ${ORGANIZATION_SLUG}`;
  // Match product organization IDs: opaque 32-hex strings, not hyphenated UUIDs.
  const organization = existing?.id ?? randomUUID().replaceAll("-", "");
  if (!existing) {
    await sql`INSERT INTO organizations (id, name, slug, created_by)
              VALUES (${organization}, ${USERS.owner.name}, ${ORGANIZATION_SLUG}, ${owner.id})`;
  }
  await sql`INSERT INTO org_members (id, org_id, user_id, role)
            SELECT ${randomUUID()}, ${organization}, ${owner.id}, 'owner'
            WHERE NOT EXISTS (
              SELECT 1 FROM org_members WHERE org_id = ${organization} AND user_id = ${owner.id})`;
  console.log(`[kind-dev] seeded ${USERS.owner.email} with organization ${ORGANIZATION_SLUG}`);
} finally {
  await sql.end();
}
