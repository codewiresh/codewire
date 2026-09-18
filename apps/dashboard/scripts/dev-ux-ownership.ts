// Value-blind ownership and cleanup for the protected Dev browser walkthrough.
// Never accept resource selectors from rendered error text or sweep an account.
export class DevUxError extends Error {
  constructor(readonly stage: string) { super(stage); }
}

type Command = (args: string[], deadline: number) => Promise<unknown>;
type OwnedEnvironment = { id: string; state: string };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function uxOrganizationSlug(organizations: unknown, id: string): string {
  if (!Array.isArray(organizations)) throw new DevUxError("ux-organization");
  const rows = organizations.filter((row) => row?.id === id);
  if (rows.length !== 1 || rows[0].role !== "owner" || typeof rows[0].slug !== "string"
    || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(rows[0].slug)) throw new DevUxError("ux-organization");
  return rows[0].slug;
}

export class OwnedUxSandbox {
  readonly name = `dev-ux-${crypto.randomUUID()}`;
  attempted = false;
  private id = "";
  private admitted = false;
  constructor(private readonly userId: string, private readonly orgId: string,
    private readonly command: Command) {}

  private async lookup(deadline: number): Promise<OwnedEnvironment | undefined> {
    const result = await this.command(["env", "--platform", "list", "--all", "--output", "json"], deadline);
    if (!Array.isArray(result) || result.some((row) => !row || typeof row !== "object")) {
      throw new DevUxError("ux-owned-resource-list");
    }
    const rows = result.filter((row) => row.name === this.name);
    if (rows.length > 1) throw new DevUxError("ux-owned-resource-ambiguous");
    const row = rows[0];
    if (!row) return undefined;
    if (row.org_id !== this.orgId || row.created_by !== this.userId || !UUID.test(row.id)
      || typeof row.state !== "string" || (this.id && row.id !== this.id)) {
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    this.id = row.id;
    return { id: row.id, state: row.state };
  }

  async admit(deadline: number): Promise<void> {
    if (await this.lookup(deadline)) throw new DevUxError("ux-owned-name-collision");
    this.admitted = true;
  }

  beforeCreate(): void {
    if (!this.admitted || this.attempted) throw new DevUxError("ux-create-not-admitted");
    this.attempted = true;
  }

  async createdId(deadline: number): Promise<string> {
    const row = await this.lookup(deadline);
    if (!this.attempted || !row) throw new DevUxError("ux-create-unconfirmed");
    return row.id;
  }

  async cleanup(deadline: number): Promise<void> {
    if (!this.attempted) return;
    // An unacknowledged Create may have succeeded. Resolve only the pre-claimed
    // random name; absence is uncertainty, never successful cleanup evidence.
    let row = await this.lookup(deadline);
    if (!row) throw new DevUxError("ux-cleanup-create-unconfirmed");
    if (row.state !== "destroyed" && row.state !== "destroying") {
      await this.command(["env", "--platform", "rm", "--yes", row.id], deadline);
    }
    while (row.state !== "destroyed") {
      if (Date.now() >= deadline) throw new DevUxError("ux-cleanup-timeout");
      await new Promise((resolve) => setTimeout(resolve, Math.min(2000, deadline - Date.now())));
      row = await this.lookup(deadline);
      if (!row) throw new DevUxError("ux-cleanup-unconfirmed");
    }
  }
}
