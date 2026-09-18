import { expect, test } from "bun:test";
import { OwnedUxSandbox, uxOrganizationSlug } from "./dev-ux-ownership";

const USER = "1".repeat(32);
const ORG = "2".repeat(32);
const ID = "00000000-0000-4000-8000-000000000001";
const deadline = () => Date.now() + 1000;

function fixture() {
  let rows: unknown = [];
  const calls: string[][] = [];
  const owned = new OwnedUxSandbox(USER, ORG, async (args) => {
    calls.push(args);
    if (args.includes("rm")) {
      rows = [{ ...row(), state: "destroyed" }];
      return "";
    }
    return rows;
  });
  const row = () => ({ id: ID, name: owned.name, org_id: ORG, created_by: USER, state: "running" });
  return { owned, calls, row, set: (value: unknown) => { rows = value; } };
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
  f.set([{ ...f.row(), name: "unrelated" }, f.row()]);
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
  f.set([{ ...f.row(), state: "destroying" }]);
  await expect(f.owned.cleanup(Date.now() - 1)).rejects.toThrow("ux-cleanup-timeout");
  f.set([{ ...f.row(), state: "destroyed" }]);
  await f.owned.cleanup(deadline());
  expect(f.calls.some((args) => args.includes("rm"))).toBe(false);
});
