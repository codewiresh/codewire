import assert from "node:assert/strict";
import { Codewire, CodewireError } from "./index.js";

/** Fake HTTP boundary still exercises the actual generated Connect JSON codec. */
export async function runNetworkPolicyTests(): Promise<void> {
  const calls: { method: string; body: Record<string, any> }[] = [];
  const policy = {
    id: "6b1f7c55-2a4f-4b8e-9d4b-1f2e3d4c5b6a", orgId: "org-one", name: "web", revision: 2, currentRevision: 2,
    rules: [{ target: "github.com", ports: [22, 443] }], digest: "ab".repeat(32),
    createdAt: "2026-11-11T18:00:00Z", createdBy: "user-one",
  };
  const cw = new Codewire({
    apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test", orgId: "org-one",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      assert.ok(url.pathname.startsWith("/codewire.v1.NetworkPolicyService/"));
      const method = url.pathname.split("/").at(-1)!;
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
      calls.push({ method, body });
      const response = (value: object, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
      if (method === "ListNetworkPolicies") return response({ policies: [policy] });
      if (method === "GetNetworkPolicy" && body.policy?.name === "off") {
        return response({ code: "unavailable", message: "platform network policies are not enabled on this deployment" }, 503);
      }
      if (method === "UpdateEnvironmentNetworkPolicy" && body.environmentId === "future") {
        return response({ networkPolicy: { reference: "hosted-default", name: "hosted-default", digest: "cd".repeat(32), enforcement: 99 } });
      }
      if (method === "UpdateEnvironmentNetworkPolicy") {
        return response({ networkPolicy: { reference: "hosted-default", name: "hosted-default", digest: "cd".repeat(32), enforcement: "NETWORK_POLICY_ENFORCEMENT_NOT_ENFORCED" } });
      }
      return response({ policy });
    },
  });

  const listed = await cw.networkPolicies.list();
  assert.deepEqual(listed[0].rules, [{ target: "github.com", ports: [22, 443] }]);
  assert.equal(listed[0].current_revision, 2);
  assert.equal(listed[0].created_at?.toISOString(), "2026-11-11T18:00:00.000Z");
  assert.equal(calls[0].body.orgId, "org-one");

  await cw.networkPolicies.create("web", [{ target: "github.com", ports: [443] }], "base");
  assert.deepEqual(calls.at(-1)!.body.from, { name: "base" });
  assert.deepEqual(calls.at(-1)!.body.allow, [{ target: "github.com", ports: [443] }]);

  await cw.networkPolicies.get({ id: policy.id }, 1);
  assert.deepEqual(calls.at(-1)!.body.policy, { id: policy.id });
  assert.equal(calls.at(-1)!.body.revision, 1);

  await cw.networkPolicies.update("web", { remove: ["pypi.org"], expectedRevision: 2 });
  assert.deepEqual(calls.at(-1)!.body.remove, ["pypi.org"]);
  assert.equal(calls.at(-1)!.body.expectedRevision, 2);

  await cw.networkPolicies.delete("web");
  assert.equal(calls.at(-1)!.method, "DeleteNetworkPolicy");

  const selected = await cw.networkPolicies.select("environment-one", "hosted-default");
  assert.equal(selected.enforcement, "not_enforced");
  assert.equal(selected.revision, 0);
  assert.equal(calls.at(-1)!.body.networkPolicy, "hosted-default");

  // A state this SDK does not know yet never fails the read.
  assert.equal((await cw.networkPolicies.select("future", "hosted-default")).enforcement, "unknown");

  await assert.rejects(cw.networkPolicies.get("off"), (error) => error instanceof CodewireError);
}
