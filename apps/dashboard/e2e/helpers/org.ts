import postgres from "postgres";
import { cleanupOrgs } from "./db";

const sql = postgres(process.env.DATABASE_URL!);

export async function ensureTestOrg(
  name: string,
  slug: string,
  ownerId: string
): Promise<string> {
  // Check if org already exists
  const [existing] = await sql`
    SELECT id FROM organizations WHERE slug = ${slug}
  `;
  if (existing) return existing.id;

  // Create org with a product-format ID: opaque 32 hex, not a hyphenated UUID.
  const orgId = crypto.randomUUID().replaceAll("-", "");
  await sql`
    INSERT INTO organizations (id, name, slug, created_by, created_at, updated_at)
    VALUES (${orgId}, ${name}, ${slug}, ${ownerId}, NOW(), NOW())
  `;

  // Add owner as member
  await sql`
    INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
    VALUES (${crypto.randomUUID()}, ${orgId}, ${ownerId}, 'owner', NOW(), NOW())
    ON CONFLICT DO NOTHING
  `;

  return orgId;
}

export async function addOrgMember(
  orgId: string,
  userId: string,
  role: "owner" | "admin" | "member"
): Promise<void> {
  await sql`
    INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
    VALUES (${crypto.randomUUID()}, ${orgId}, ${userId}, ${role}, NOW(), NOW())
    ON CONFLICT DO NOTHING
  `;
}

export async function cleanupTestOrg(slug: string): Promise<void> {
  await cleanupOrgs(slug);
}

export async function getOrgForUser(
  email: string
): Promise<{ id: string; name: string; slug: string } | null> {
  const [result] = await sql`
    SELECT o.id, o.name, o.slug FROM organizations o
    JOIN org_members om ON o.id = om.org_id
    JOIN users u ON om.user_id = u.id
    WHERE u.email = ${email}
    ORDER BY o.created_at DESC LIMIT 1
  `;
  return result ? {
    id: String(result.id),
    name: String(result.name),
    slug: String(result.slug),
  } : null;
}
