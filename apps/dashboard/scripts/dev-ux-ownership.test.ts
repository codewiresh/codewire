import { expect, test } from "bun:test";
import { OwnedUxSandbox, uxOrganizationSlug } from "./dev-ux-ownership";

const USER = "1".repeat(32);
const ORG = "2".repeat(32);
const ID = "00000000-0000-4000-8000-000000000001";
const deadline = () => Date.now() + 1000;

const TERMINAL = ["destroying", "destroyed"];
// Rendered as the CLI renders `cw env list --output json`: pretty JSON, one
// unified entry per row, about 250 bytes each.
const listed = (rows: Record<string, unknown>[]) => rows.map((row) => ({
  type: "sandbox", name: row.name, placement: row.placement, selected: false,
  state: row.state, daemon_health: "unavailable", id: row.id,
}));

// Mirrors the server: `list` without `--all` omits destroying and destroyed
// rows; `report` resolves one exact ID in any state.
function fixture(options: { history?: Record<string, unknown>[]; liveIncludesTerminal?: boolean } = {}) {
  let rows: unknown = [];
  let detailOverride: unknown;
  let overrideDetail = false;
  let reportOverride: unknown;
  let overrideReport = false;
  let infoFailureState = "";
  let largestList = 0;
  const calls: string[][] = [];
  const owned = new OwnedUxSandbox(USER, ORG, async (args) => {
    calls.push(args);
    const all = Array.isArray(rows) ? [...(options.history ?? []), ...rows] : rows;
    if (args.includes("rm")) {
      rows = [{ ...row(), state: "destroyed" }];
      return "";
    }
    if (args.includes("report")) {
      if (overrideReport) return reportOverride;
      const matched = Array.isArray(all) ? all.find((row) => row.id === args[2]) : undefined;
      if (!matched) throw new Error("not found");
      return { environment: { id: matched.id, org_id: matched.org_id, type: "sandbox",
        state: matched.state, isolation_tier: "standard" } };
    }
    if (args.includes("info")) {
      if (infoFailureState) {
        rows = [{ ...row(), state: infoFailureState }];
        throw new Error("not found");
      }
      if (overrideDetail) return detailOverride;
      const matched = Array.isArray(rows) ? rows.find((row) => row.id === args[3]) : undefined;
      if (!matched || TERMINAL.includes(matched.state)) throw new Error("not found");
      return matched;
    }
    if (!Array.isArray(all)) return all;
    const visible = args.includes("--all") || options.liveIncludesTerminal
      ? all : all.filter((row) => !TERMINAL.includes(row.state));
    const response = JSON.parse(JSON.stringify(listed(visible), null, 2));
    largestList = Math.max(largestList, JSON.stringify(listed(visible), null, 2).length);
    return response;
  });
  const row = () => ({ id: ID, name: owned.name, placement: "platform", org_id: ORG, created_by: USER, state: "running" });
  return { owned, calls, row, set: (value: unknown) => { rows = value; },
    detail: (value: unknown) => { overrideDetail = true; detailOverride = value; },
    report: (value: unknown) => { overrideReport = true; reportOverride = value; },
    failInfo: (state: string) => { infoFailureState = state; },
    largestList: () => largestList };
}

test("organization routes require exact unique owner and a path-safe slug", () => {
  expect(uxOrganizationSlug([{ id: ORG, role: "owner", slug: "dedicated-smoke" }], ORG)).toBe("dedicated-smoke");
  for (const rows of [null, [], [{ id: ORG, role: "member", slug: "safe" }],
    [{ id: ORG, role: "owner", slug: "../other" }],
    [{ id: ORG, role: "owner", slug: "safe" }, { id: ORG, role: "owner", slug: "safe" }]]) {
    expect(() => uxOrganizationSlug(rows, ORG)).toThrow("ux-organization");
  }
});

test("unadmitted or repeated create is refused and no-submit cleanup is read-only", async () => {
  const f = fixture();
  expect(() => f.owned.beforeCreate()).toThrow("ux-create-not-admitted");
  await f.owned.cleanup(deadline());
  expect(f.calls).toHaveLength(0);
  await f.owned.admit(deadline());
  f.owned.beforeCreate();
  expect(() => f.owned.beforeCreate()).toThrow("ux-create-not-admitted");
});

test("preexisting random-name collision refuses admission without deletion", async () => {
  const f = fixture(); f.set([f.row()]);
  await expect(f.owned.admit(deadline())).rejects.toThrow("ux-owned-name-collision");
  await f.owned.cleanup(deadline());
  expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
});

test("ambiguous Create response reconciles only exact claimed name, actor and org", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([{ ...f.row(), id: "00000000-0000-4000-8000-000000000002", name: "unrelated" }, f.row()]);
  await f.owned.cleanup(deadline());
  expect(f.calls.filter((args) => args.includes("rm"))).toEqual([["env", "--platform", "rm", "--yes", ID]]);
});

test("missing, duplicate, foreign or malformed records fail closed without deletion", async () => {
  for (const kind of ["missing", "duplicate", "org", "actor", "id", "list"] as const) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    const row = f.row();
    f.set(kind === "missing" ? [] : kind === "duplicate" ? [row, row] : kind === "list" ? {} : [{
      ...row, ...(kind === "org" ? { org_id: "3".repeat(32) } : kind === "actor"
        ? { created_by: "3".repeat(32) } : { id: "--all" }),
    }]);
    await expect(f.owned.cleanup(deadline())).rejects.toThrow();
    expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  }
});

test("once acknowledged, a changed ID never becomes a cleanup target", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate(); f.set([f.row()]);
  expect(await f.owned.createdId(deadline())).toBe(ID);
  f.set([{ ...f.row(), id: "00000000-0000-4000-8000-000000000002" }]);
  await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
  expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
});

test("terminal destruction is reusable; pending destruction must finish within reserve", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([f.row()]);
  await f.owned.createdId(deadline());
  f.set([{ ...f.row(), state: "destroying" }]);
  await expect(f.owned.cleanup(Date.now() - 1)).rejects.toThrow("ux-cleanup-timeout");
  f.set([{ ...f.row(), state: "destroyed" }]);
  await f.owned.cleanup(deadline());
  expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
});

test("skinny unified list requires full info ownership before any deletion", async () => {
  for (const detail of [null, [], {}, { id: ID }, "unexpected"]) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([f.row()]); f.detail(detail);
    await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
    expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  }
  for (const field of ["id", "name", "org_id", "created_by", "state"]) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([f.row()]); f.detail({ ...f.row(), [field]: field === "state" ? null : "foreign" });
    await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
    expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  }
});

test("terminal rows cannot establish ownership and local placement is rejected", async () => {
  // The live list omits terminal rows, so an unbound one is unconfirmed.
  for (const state of TERMINAL) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([{ ...f.row(), state }]);
    await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-cleanup-create-unconfirmed");
    expect(f.calls.some((args) => args.includes("rm") || args.includes("report"))).toBe(false);
  }
  // Should a list ever return them, info still refuses to bind them.
  for (const change of [{ state: "destroying" }, { state: "destroyed" }, { placement: "local" }]) {
    const f = fixture({ liveIncludesTerminal: true }); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([{ ...f.row(), ...change }]);
    await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
    expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  }
});

test("bound terminal cleanup does not call info or repeat deletion", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([f.row()]); await f.owned.createdId(deadline());
  const calls = f.calls.length;
  f.set([{ ...f.row(), state: "destroyed" }]);
  await f.owned.cleanup(deadline());
  expect(f.calls.slice(calls)).toEqual([
    ["env", "--platform", "list", "--output", "json"],
    ["env", "report", ID, "--output", "json"],
  ]);
});

test("bound list-info destruction race rechecks once, never treating an info error as cleanup", async () => {
  for (const nextState of ["running", "destroyed"]) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([f.row()]); await f.owned.createdId(deadline());
    const before = f.calls.length;
    f.failInfo(nextState);
    if (nextState === "destroyed") await f.owned.cleanup(deadline());
    else await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
    const calls = f.calls.slice(before);
    expect(calls.filter(args => args.includes("list"))).toHaveLength(2);
    expect(calls.filter(args => args.includes("info"))).toHaveLength(nextState === "destroyed" ? 1 : 2);
    expect(calls.some(args => args.includes("rm"))).toBe(false);
  }
});

test("a destroyed history too large for one private output never enters admit, createdId or cleanup", async () => {
  const history = Array.from({ length: 300 }, (_, index) => ({
    id: `00000000-0000-4000-8000-${(index + 100).toString().padStart(12, "0")}`,
    name: `dev-ux-${crypto.randomUUID()}`, placement: "platform", org_id: ORG, created_by: USER,
    state: "destroyed",
  }));
  // The whole-history list this replaces no longer fits the 64 KiB cap.
  expect(JSON.stringify(listed(history), null, 2).length).toBeGreaterThan(64 * 1024);
  const f = fixture({ history });
  await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([f.row()]);
  expect(await f.owned.createdId(deadline())).toBe(ID);
  await f.owned.cleanup(deadline());
  expect(f.calls.filter((args) => args.includes("rm"))).toEqual([["env", "--platform", "rm", "--yes", ID]]);
  expect(f.calls.at(-1)).toEqual(["env", "report", ID, "--output", "json"]);
  expect(f.calls.some((args) => args.includes("--all"))).toBe(false);
  expect(f.largestList()).toBeLessThan(1024);
});

test("a cleanup after the walkthrough's own delete waits on the exact ID's report", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([f.row()]); await f.owned.createdId(deadline());
  f.set([{ ...f.row(), state: "destroying" }]);
  const pending = f.owned.cleanup(deadline() + 4000);
  setTimeout(() => f.set([{ ...f.row(), state: "destroyed" }]), 100);
  await pending;
  expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  expect(f.calls.filter((args) => args.includes("report")).length).toBeGreaterThanOrEqual(2);
});

test("the terminal report must name the bound ID and organization", async () => {
  for (const environment of [null, {}, { id: ID, org_id: "3".repeat(32), state: "destroyed" },
    { id: "00000000-0000-4000-8000-000000000002", org_id: ORG, state: "destroyed" },
    { id: ID, org_id: ORG, state: null }]) {
    const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
    f.set([f.row()]); await f.owned.createdId(deadline());
    f.set([{ ...f.row(), state: "destroyed" }]); f.report({ environment });
    await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
    expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
  }
});

test("a live state in the terminal report rereads once, then fails closed", async () => {
  const f = fixture(); await f.owned.admit(deadline()); f.owned.beforeCreate();
  f.set([f.row()]); await f.owned.createdId(deadline());
  const before = f.calls.length;
  f.set([{ ...f.row(), state: "destroying" }]);
  f.report({ environment: { id: ID, org_id: ORG, state: "running" } });
  await expect(f.owned.cleanup(deadline())).rejects.toThrow("ux-owned-resource-mismatch");
  const calls = f.calls.slice(before);
  expect(calls.filter((args) => args.includes("list"))).toHaveLength(2);
  expect(calls.filter((args) => args.includes("report"))).toHaveLength(2);
  expect(calls.some((args) => args.includes("rm"))).toBe(false);
});
