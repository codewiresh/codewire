// Value-blind ownership and cleanup for the protected Dev browser walkthrough.
// Never accept resource selectors from rendered error text or sweep an account.

// Closed failure classes for the helper's one failure-class line (#3132). A
// failed cw command adds the shell smoke's cw_failure_class set: dns, tls,
// refused, conn_reset, conn_pipe, conn_tcp, conn_closed, conn_http2, conn_send,
// http_NNN or exit_N.
export type FailureClass = "timeout" | "assertion" | "navigation" | "unexpected"
  | "dns" | "tls" | "refused" | "conn_reset" | "conn_pipe" | "conn_tcp" | "conn_closed" | "conn_http2" | "conn_send"
  | `http_${number}` | `exit_${number}`;
const FAILURE_CLASS = /^(?:timeout|assertion|navigation|unexpected|dns|tls|refused|conn_(?:reset|pipe|tcp|closed|http2|send)|http_[1-5][0-9]{2}|exit_[0-9]{1,3})$/;

export function isFailureClass(value: unknown): value is FailureClass {
  return typeof value === "string" && FAILURE_CLASS.test(value);
}

// The class of one failed cw command, from its exit status and fixed patterns
// in its private stderr, exactly as the shell smoke's cw_failure_class reads
// them. The stderr is only tested, never repeated.
export function cwFailureClass(status: number, stderr: string): FailureClass {
  if (status === 124 || status === 137) return "timeout";
  const code = /HTTP (?:error|status (?:client|server) error \() ?([1-5][0-9]{2})/.exec(stderr)?.[1];
  if (code) return `http_${Number(code)}`;
  if (/dns error|failed to lookup address|name or service not known|temporary failure in name resolution/i.test(stderr)) return "dns";
  if (/tls error|certificate|tls handshake/i.test(stderr)) return "tls";
  if (/timed out|deadline exceeded|deadline_exceeded/i.test(stderr)) return "timeout";
  if (/connection refused/i.test(stderr)) return "refused";
  if (/connection reset/i.test(stderr)) return "conn_reset";
  if (/broken pipe/i.test(stderr)) return "conn_pipe";
  if (/tcp connect error|client error \(Connect\)/i.test(stderr)) return "conn_tcp";
  if (/connection closed before message completed/i.test(stderr)) return "conn_closed";
  if (/http2 error/i.test(stderr)) return "conn_http2";
  if (/error sending request/i.test(stderr)) return "conn_send";
  return `exit_${Math.min(Math.max(Math.trunc(status), 0), 255)}`;
}
// Playwright navigation failures: a Chromium net error, or a goto or reload
// that failed or was interrupted. The message is only tested, never repeated.
const NAVIGATION_FAILURE = /net::ERR_[A-Z0-9_]+|^(?:page|frame)\.(?:goto|reload|goBack|goForward):|interrupted by another navigation/;
// An expect.poll failure is a plain Error whose message is the matcher's.
const POLLED_EXPECTATION = /^expect\(/;

// The class of one failure, from its type and fixed patterns only. A failure
// that already carries a class keeps it; Playwright's TimeoutError is a
// timeout; an expect failure (it carries matcherResult) is an assertion.
export function failureClassOf(error: unknown): FailureClass {
  if (!(error instanceof Error)) return "unexpected";
  const carried = (error as { failureClass?: unknown }).failureClass;
  if (isFailureClass(carried)) return carried;
  if (error.name === "TimeoutError") return "timeout";
  if ("matcherResult" in error && (error as { matcherResult?: unknown }).matcherResult) return "assertion";
  if (POLLED_EXPECTATION.test(error.message)) return "assertion";
  if (NAVIGATION_FAILURE.test(error.message)) return "navigation";
  return "unexpected";
}

export class DevUxError extends Error {
  constructor(readonly stage: string, readonly failureClass: FailureClass = "assertion") { super(stage); }
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
  // history: `ls` without `--all` returns only live rows (the server omits
  // destroying and destroyed ones), and the terminal read names one exact ID.
  private async lookup(deadline: number, retryBound = true): Promise<OwnedEnvironment | undefined> {
    const result = await this.command(["--cloud", "ls", "--output", "json"], deadline);
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
      value = await this.command(["--cloud", "info", row.id, "--output", "json"], deadline);
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

  // `cw report` resolves an exact ID with GetEnvironment, which, unlike
  // info's name resolution, includes destroying and destroyed environments.
  // It takes no placement flag. Only states the live list omits are accepted:
  // anything else moved between the two reads, so read once more.
  private async terminal(deadline: number, retryBound: boolean): Promise<OwnedEnvironment | undefined> {
    const value = await this.command(["report", this.id, "--output", "json"], deadline);
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
      await this.command(["--cloud", "rm", "--yes", row.id], deadline);
    }
    while (row.state !== "destroyed") {
      if (Date.now() >= deadline) throw new DevUxError("ux-cleanup-timeout");
      await new Promise((resolve) => setTimeout(resolve, Math.min(2000, deadline - Date.now())));
      row = await this.lookup(deadline);
      if (!row) throw new DevUxError("ux-cleanup-unconfirmed");
    }
  }
}
