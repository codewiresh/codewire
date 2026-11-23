import assert from "node:assert/strict";
import { Codewire, CodewireError } from "./index.js";
import { assertSandboxIdentityConverterCoverage } from "./sandbox-identity.js";

/** Fake HTTP boundary still exercises the actual generated Connect JSON codec. */
export async function runSandboxIdentityTests(): Promise<void> {
  assertSandboxIdentityConverterCoverage();

  const calls: { method: string; body: Record<string, any> }[] = [];
  const audience = {
    orgId: "org-one", audience: "https://vault.example.com/v1/auth/jwt", visibleGroups: { names: ["readers"] },
    lifetime: "300s", claimCreatedBy: true, fileName: "vault", version: "1794600000000000",
    createdBy: "user-one", createdAt: "2026-11-21T18:00:00Z",
  };
  const cw = new Codewire({
    apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test", orgId: "org-one",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      assert.ok(url.pathname.startsWith("/codewire.v1.SandboxIdentityService/"));
      const method = url.pathname.split("/").at(-1)!;
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
      calls.push({ method, body });
      const response = (value: object, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
      switch (method) {
        case "GetEnvironmentIdentityGroups":
          return response({ groups: { environmentId: body.environmentId, groups: ["builders"], version: "2", updatedAt: "2026-11-21T18:00:00Z" } });
        case "SetEnvironmentIdentityGroups":
          if (body.groups?.includes("all")) {
            return response({ code: "invalid_argument", message: "group name `all` is reserved: every token carries it" }, 400);
          }
          return response({
            groups: { environmentId: body.environmentId, groups: body.groups ?? [], version: "3" },
            previousGroups: ["builders"], changed: true,
            canRunCode: [
              { userId: "user-one", email: "one@example.com", reason: "IDENTITY_GROUP_USER_REASON_CREATOR" },
              { userId: "user-two", email: "two@example.com", reason: 99 },
            ],
          });
        case "RegisterIdentityAudience":
          return response({ audience });
        case "ListIdentityAudiences":
          return response({ audiences: [audience, { orgId: "org-one", audience: "https://k8s.example", version: "2" }] });
        case "RemoveIdentityAudience":
          return response({ audience: "https://k8s.example" });
        case "StopIdentityMinting":
          return response({ changed: true });
        default:
          return response({});
      }
    },
  });

  const read = await cw.sandboxIdentity.getGroups("env-one");
  assert.deepEqual(read, { environment_id: "env-one", groups: ["builders"], version: 2, updated_at: new Date("2026-11-21T18:00:00Z") });
  assert.equal(calls.at(-1)!.body.orgId, "org-one");

  const set = await cw.sandboxIdentity.setGroups("env-one", ["data-readers"]);
  assert.deepEqual(calls.at(-1)!.body.groups, ["data-readers"]);
  assert.equal(set.changed, true);
  assert.deepEqual(set.previous_groups, ["builders"]);
  assert.deepEqual(set.groups.groups, ["data-readers"]);
  // A reason this SDK does not know yet never fails the call.
  assert.deepEqual(set.can_run_code.map((user) => [user.email, user.reason]), [
    ["one@example.com", "creator"], ["two@example.com", "unknown"],
  ]);
  await assert.rejects(cw.sandboxIdentity.setGroups("env-one", ["all"]), (error) => error instanceof CodewireError);

  const registered = await cw.sandboxIdentity.registerAudience("https://vault.example.com/v1/auth/jwt", {
    visibleGroups: ["readers"], lifetimeSeconds: 300, claimCreatedBy: true, fileName: "vault",
  });
  assert.deepEqual(calls.at(-1)!.body.visibleGroups, { names: ["readers"] });
  assert.equal(calls.at(-1)!.body.lifetime, "300s");
  assert.equal(calls.at(-1)!.body.fileName, "vault");
  assert.equal(calls.at(-1)!.body.claimEnvironmentName, undefined);
  assert.deepEqual(registered, {
    org_id: "org-one", audience: "https://vault.example.com/v1/auth/jwt", visible_groups: ["readers"],
    lifetime_seconds: 300, claim_created_by: true, claim_environment_name: false, file_name: "vault",
    version: 1794600000000000, created_by: "user-one", created_at: new Date("2026-11-21T18:00:00Z"),
  });
  await cw.sandboxIdentity.registerAudience("https://k8s.example");
  assert.equal(calls.at(-1)!.body.visibleGroups, undefined, "every group unless named");
  assert.equal(calls.at(-1)!.body.lifetime, undefined, "ten minutes unless named");

  const listed = await cw.sandboxIdentity.listAudiences();
  assert.equal(listed.length, 2);
  assert.equal(listed[1].visible_groups, undefined);
  assert.equal(listed[1].lifetime_seconds, 600);
  assert.equal(await cw.sandboxIdentity.removeAudience("HTTPS://K8S.EXAMPLE:443"), "https://k8s.example");

  assert.equal(await cw.sandboxIdentity.stopMinting("env-one"), true);
  assert.equal(calls.at(-1)!.body.environmentId, "env-one");
  await cw.sandboxIdentity.stopMinting();
  assert.equal(calls.at(-1)!.body.environmentId, undefined, "no Sandbox stops the organization");
  assert.equal(await cw.sandboxIdentity.resumeMinting("env-one"), false);
  assert.equal(calls.at(-1)!.method, "ResumeIdentityMinting");
}
