import { describe, expect, test } from "bun:test";
import { assertIdentityTopology } from "../e2e/helpers/topology";

function probe(overrides: Partial<Parameters<typeof assertIdentityTopology>[0]> = {}) {
  const calls: string[] = [];
  return {
    calls,
    value: {
      email: "e2e-topology-probe@codewire.sh",
      serverUrl: "http://127.0.0.1:8080",
      directDatabaseEndpoint: "postgres://127.0.0.1:25432/codewire",
      kubeContext: "kind-codewire",
      removeDirectFixture: async () => {
        calls.push("remove");
      },
      createThroughServer: async () => {
        calls.push("create");
        return new Response(null, { status: 201 });
      },
      directFixtureExists: async () => {
        calls.push("observe");
        return true;
      },
      ...overrides,
    },
  };
}

describe("dashboard E2E identity topology sentinel", () => {
  test("requires a server-created fixture to be visible through direct SQL", async () => {
    const fixture = probe();

    await assertIdentityTopology(fixture.value);

    expect(fixture.calls).toEqual(["remove", "create", "observe", "remove"]);
  });

  test("fails before browser setup when the server and direct SQL are split", async () => {
    const fixture = probe({ directFixtureExists: async () => false });

    await expect(assertIdentityTopology(fixture.value)).rejects.toThrow(
      "Refusing to run browser tests against split identity planes",
    );
    expect(fixture.calls).toEqual(["remove", "create"]);
  });

  test("fails on server setup errors without treating a direct fixture as coherent", async () => {
    const fixture = probe({
      createThroughServer: async () => new Response("unavailable", { status: 503 }),
    });

    await expect(assertIdentityTopology(fixture.value)).rejects.toThrow(
      "could not create",
    );
    expect(fixture.calls).toEqual(["remove"]);
  });
});
