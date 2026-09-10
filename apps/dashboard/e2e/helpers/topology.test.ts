import assert from "node:assert/strict";
import test from "node:test";
import { assertIdentityTopology, type IdentityTopologyProbe } from "./topology";

function probe(
  events: string[],
  overrides: Partial<IdentityTopologyProbe> = {},
): IdentityTopologyProbe {
  return {
    email: "e2e-topology-probe@codewire.sh",
    serverUrl: "http://127.0.0.1:8080",
    directDatabaseEndpoint: "postgres://127.0.0.1:25432/codewire",
    kubeContext: "kind-codewire",
    removeDirectFixture: async () => {
      events.push("cleanup");
    },
    seedDirectFixture: async () => {
      events.push("seed");
    },
    signInThroughServer: async () => {
      events.push("sign-in");
      return new Response(null, { status: 204 });
    },
    directSessionExists: async () => {
      events.push("session");
      return true;
    },
    ...overrides,
  };
}

test("topology proof cleans first and last around a successful session observation", async () => {
  const events: string[] = [];

  await assertIdentityTopology(probe(events));

  assert.deepEqual(events, ["cleanup", "seed", "sign-in", "session", "cleanup"]);
});

test("rejected sign-in is cleaned and reports every actionable endpoint", async () => {
  const events: string[] = [];
  const value = probe(events, {
    signInThroughServer: async () => {
      events.push("sign-in");
      return new Response("synthetic rejection", { status: 401 });
    },
  });

  await assert.rejects(
    assertIdentityTopology(value),
    (error: Error) => {
      assert.match(error.message, /could not sign in e2e-topology-probe@codewire\.sh/);
      assert.match(error.message, /SERVER_URL=http:\/\/127\.0\.0\.1:8080/);
      assert.match(error.message, /401 synthetic rejection/);
      assert.match(error.message, /DATABASE_URL=postgres:\/\/127\.0\.0\.1:25432\/codewire/);
      assert.match(error.message, /KUBE_CONTEXT=kind-codewire/);
      return true;
    },
  );
  assert.deepEqual(events, ["cleanup", "seed", "sign-in", "cleanup"]);
});

test("split identity planes clean without claiming a server-side session cleanup", async () => {
  const events: string[] = [];
  const value = probe(events, {
    directSessionExists: async () => {
      events.push("session-missing");
      return false;
    },
  });

  await assert.rejects(
    assertIdentityTopology(value),
    (error: Error) => {
      assert.match(error.message, /identity topology mismatch/);
      assert.match(error.message, /accepted e2e-topology-probe@codewire\.sh/);
      assert.match(error.message, /cannot observe its new session/);
      assert.match(error.message, /split identity planes/);
      return true;
    },
  );
  assert.deepEqual(events, ["cleanup", "seed", "sign-in", "session-missing", "cleanup"]);
});

test("a direct seed failure still performs final fixture cleanup", async () => {
  const events: string[] = [];
  const failure = new Error("synthetic seed failed");
  const value = probe(events, {
    seedDirectFixture: async () => {
      events.push("seed");
      throw failure;
    },
  });

  await assert.rejects(assertIdentityTopology(value), failure);
  assert.deepEqual(events, ["cleanup", "seed", "cleanup"]);
});
