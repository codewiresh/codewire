import { MeshClient } from "./mesh.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${message}`);
  }
}

const calls: Array<{ url: string; init?: RequestInit }> = [];
const client = new MeshClient("https://mesh.example/", "cw_mesh_test", {
  fetch: async (input, init) => {
    calls.push({ url: String(input), init });
    if (init?.method === "POST") return new Response(null, { status: 200 });
    return Response.json([
      {
        id: "network-one",
        org_id: "org space/one",
        created_at: "2026-01-01T00:00:00Z",
        node_count: 0,
        invite_count: 0,
      },
    ]);
  },
});

await client.networks.create("org space/one", "network-one");
const networks = await client.networks.list("org space/one");

assert(calls.length === 2, "network calls should issue exactly one create and one list");
assert(calls[0]?.url === "https://mesh.example/api/v1/networks", "create uses the Mesh network path");
assert(calls[0]?.init?.method === "POST", "create uses POST");
const createHeaders = calls[0]?.init?.headers;
assert(
  createHeaders instanceof Headers
    ? createHeaders.get("authorization") === "Bearer cw_mesh_test"
    : (createHeaders as Record<string, string> | undefined)?.Authorization === "Bearer cw_mesh_test",
  "create forwards the existing product credential",
);
assert(
  calls[0]?.init?.body === '{"org_id":"org space/one","network_id":"network-one"}',
  "create includes the exact explicit organization",
);
assert(
  calls[1]?.url === "https://mesh.example/api/v1/networks?org_id=org%20space%2Fone",
  "list encodes and transmits the exact explicit organization",
);
assert(networks.length === 1 && networks[0]?.org_id === "org space/one", "list preserves owner");

if (failed > 0) process.exitCode = 1;
console.log(`${passed} passed, ${failed} failed`);
