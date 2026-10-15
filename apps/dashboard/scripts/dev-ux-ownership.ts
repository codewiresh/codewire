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

  // Every read is bounded by what this run owns, never by the organization's
  // history: `list` without `--all` returns only live rows (the server omits
  // destroying and destroyed ones), and the terminal read names one exact ID.
  private async lookup(deadline: number, retryBound = true): Promise<OwnedEnvironment | undefined> {
    const result = await this.command(["env", "--cloud", "list", "--output", "json"], deadline);
    if (!Array.isArray(result) || result.some((row) => !row || typeof row !== "object")) {
      throw new DevUxError("ux-owned-resource-list");
    }
    const rows = result.filter((row) => row.name === this.name);
    if (rows.length > 1) throw new DevUxError("ux-owned-resource-ambiguous");
    const row = rows[0];
    // Unbound absence is uncertainty. A bound ID that left the live list is
    // read by that exact ID for its terminal state.
    if (!row) return this.id ? this.terminal(deadline, retryBound) : undefined;
    if (row.placement !== "platform" || typeof row.id !== "string" || !UUID.test(row.id)
      || typeof row.state !== "string" || (this.id && row.id !== this.id)) {
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    // Unified list is discovery, not ownership evidence: it omits org/creator.
    // CLI info cannot resolve destroying/destroyed environments. Those states
    // are terminal evidence only after this exact ID's full ownership binding.
    if (this.id && ["destroying", "destroyed"].includes(row.state)) {
      return { id: row.id, state: row.state };
    }
    let value: unknown;
    try {
      value = await this.command(["env", "--cloud", "info", row.id, "--output", "json"], deadline);
    } catch {
      // A bound environment may enter destruction between list and info.
      if (this.id && retryBound) return this.lookup(deadline, false);
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    const detail = value as Record<string, unknown> | null;
    if (!detail || Array.isArray(detail) || typeof detail !== "object"
      || detail.id !== row.id || detail.name !== this.name
      || detail.org_id !== this.orgId || detail.created_by !== this.userId
      || typeof detail.state !== "string") {
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    this.id = row.id;
    return { id: row.id, state: detail.state };
  }

  // `cw env report` resolves an exact ID with GetEnvironment, which, unlike
  // info's name resolution, includes destroying and destroyed environments.
  // It takes no placement flag. Only states the live list omits are accepted:
  // anything else moved between the two reads, so read once more.
  private async terminal(deadline: number, retryBound: boolean): Promise<OwnedEnvironment | undefined> {
    const value = await this.command(["env", "report", this.id, "--output", "json"], deadline);
    const environment = value && typeof value === "object" && !Array.isArray(value)
      ? (value as Record<string, unknown>).environment as Record<string, unknown> | null | undefined
      : undefined;
    if (!environment || typeof environment !== "object" || Array.isArray(environment)
      || environment.id !== this.id || environment.org_id !== this.orgId
      || typeof environment.state !== "string") {
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    if (!["destroying", "destroyed"].includes(environment.state)) {
      if (retryBound) return this.lookup(deadline, false);
      throw new DevUxError("ux-owned-resource-mismatch");
    }
    return { id: this.id, state: environment.state };
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
      await this.command(["env", "--cloud", "rm", "--yes", row.id], deadline);
    }
    while (row.state !== "destroyed") {
      if (Date.now() >= deadline) throw new DevUxError("ux-cleanup-timeout");
      await new Promise((resolve) => setTimeout(resolve, Math.min(2000, deadline - Date.now())));
      row = await this.lookup(deadline);
      if (!row) throw new DevUxError("ux-cleanup-unconfirmed");
    }
  }
}
