// Seed the synthetic owner login into the retained local Kind cluster. Test-fixture
// authority only: seedSyntheticIdentity refuses any non-e2e-*@codewire.sh email.
import postgres from "postgres";
import { USERS } from "../../../apps/dashboard/e2e/helpers/seed";
import { seedSyntheticIdentity } from "../../../apps/dashboard/e2e/helpers/synthetic-users";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");
const sql = postgres(databaseUrl, { max: 1 });
try {
  await seedSyntheticIdentity(sql, USERS.owner.email, USERS.owner.name, USERS.owner.isAdmin);
  console.log(`[kind-dev] seeded ${USERS.owner.email}`);
} finally {
  await sql.end();
}
