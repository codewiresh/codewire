import postgres from "postgres";
import { USERS } from "./helpers/seed";
import { seedSyntheticIdentity, seedWorkerIdentities, WORKER_IDENTITY_CEILING } from "./helpers/synthetic-users";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("DATABASE_URL is required for the local Kind synthetic user seed");
}

const sql = postgres(databaseUrl);

try {
  await sql`DELETE FROM rate_limit`;
  for (const [role, user] of Object.entries(USERS)) {
    await seedSyntheticIdentity(sql, user.email, user.name, user.isAdmin);
    console.log(`  [seed] ${role}: ${user.email} ready`);
  }
  await seedWorkerIdentities(sql, WORKER_IDENTITY_CEILING);
  console.log(`  [seed] ${WORKER_IDENTITY_CEILING} per-worker identities ready`);
  await sql`DELETE FROM rate_limit`;
} finally {
  await sql.end();
}
