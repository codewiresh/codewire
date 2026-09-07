import assert from "node:assert/strict";
import { Codewire, CodewireError, type EnvironmentAccessProfileBinding } from "./index.js";

/** Fake HTTP boundary still exercises the actual generated Connect JSON codec. */
export async function runAccessProfileTests(): Promise<void> {
  const exact = 9_007_199_254_741_009n;
  const maximum = 0xffff_ffff_ffff_ffffn;
  const calls: { method: string; body: Record<string, any> }[] = [];
  const profile = { id: "profile-one", name: "personal", revision: exact.toString(), entries: [{ capabilitySlot: "codex", credentialId: "credential-one" }] };
  const wireBinding = { environmentId: "environment-one", accessProfileId: "profile-one", accessProfileRevision: exact.toString() };
  const binding: EnvironmentAccessProfileBinding = { environment_id: "environment-one", access_profile_id: "profile-one", access_profile_revision: exact };
  const cw = new Codewire({
    apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      assert.equal(request.headers.get("authorization"), "Bearer synthetic-opaque-oauth");
      const url = new URL(request.url);
      assert.ok(url.pathname.startsWith("/codewire.v1.AccessProfileService/"));
      const method = url.pathname.split("/").at(-1)!;
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
      assert.ok(!("orgId" in body), "personal profiles must not inherit organization scope");
      calls.push({ method, body });
      const response = (value: object, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
      if (method === "ListAccessProfiles") {
        assert.equal(body.pageSize ?? 0, 0);
        return response(body.pageToken ? { accessProfiles: [{ ...profile, id: "profile-two" }] } : { accessProfiles: [profile], nextPageToken: "page-two" });
      }
      if (method === "GetAccessProfile") {
        if (body.accessProfileId === "missing-response") return response({});
        if (body.accessProfileId === "missing") return response({ code: "not_found", message: "not found" }, 404);
        return response({ accessProfile: profile });
      }
      if (method === "UpdateAccessProfile" && body.accessProfileId === "stale") {
        return response({ code: "aborted", message: "stale revision" }, 409);
      }
      if (method === "CreateAccessProfile" || method === "UpdateAccessProfile") return response({ accessProfile: profile });
      if (method === "GetEnvironmentAccessProfile") return response(body.environmentId === "unbound" ? {} : { binding: wireBinding, personalCredentialsConfirmed: true });
      if (method === "SetEnvironmentAccessProfile") {
        if (!body.confirmPersonalCredentials) return response({ code: "failed_precondition", message: "explicit consent required" }, 400);
        return response({ binding: wireBinding });
      }
      if (method === "DeleteAccessProfile" || method === "ClearEnvironmentAccessProfile") return response({});
      throw new Error("unexpected access profile method");
    },
  });
  const profiles = await cw.accessProfiles.list();
  assert.equal(profiles.length, 2);
  assert.equal(profiles[0].revision, exact);
  assert.deepEqual(profiles[0].entries, [{ capability_slot: "codex", credential_id: "credential-one" }]);
  assert.equal(calls[1].body.pageToken, "page-two");
  assert.equal((await cw.accessProfiles.get("profile-one")).revision, exact);
  assert.equal(calls.at(-1)!.body.accessProfileId, "profile-one");
  assert.ok(!("name" in calls.at(-1)!.body));
  assert.ok(!("revision" in calls.at(-1)!.body));
  await cw.accessProfiles.getByName("personal", exact);
  assert.equal(calls.at(-1)!.body.name, "personal");
  assert.equal(calls.at(-1)!.body.revision, exact.toString());
  assert.ok(!("accessProfileId" in calls.at(-1)!.body));
  const entries = [{ capability_slot: "codex", credential_id: "credential-one" }];
  await cw.accessProfiles.create("personal", entries);
  assert.equal(calls.at(-1)!.body.name, "personal");
  assert.deepEqual(calls.at(-1)!.body.entries, [{ capabilitySlot: "codex", credentialId: "credential-one" }]);
  await cw.accessProfiles.update("profile-one", exact, []);
  assert.equal(calls.at(-1)!.body.expectedRevision, exact.toString());
  assert.deepEqual(calls.at(-1)!.body.entries ?? [], []);
  await cw.accessProfiles.delete("profile-one", exact);
  assert.equal(calls.at(-1)!.body.expectedRevision, exact.toString());
  assert.equal((await cw.accessProfiles.getEnvironmentBinding("environment-one")).personal_credentials_confirmed, true);
  assert.deepEqual(await cw.accessProfiles.getEnvironmentBinding("unbound"), { binding: undefined, personal_credentials_confirmed: false });
  await assert.rejects(cw.accessProfiles.setEnvironmentBinding({ binding, confirm_personal_credentials: false }), (error: unknown) => error instanceof CodewireError && error.status === 400);
  assert.equal(calls.at(-1)!.body.confirmPersonalCredentials ?? false, false);
  assert.ok(!("expectedBinding" in calls.at(-1)!.body));
  const expected = { ...binding, access_profile_id: "previous-profile", access_profile_revision: exact - 3n };
  const wireExpected = { ...wireBinding, accessProfileId: "previous-profile", accessProfileRevision: (exact - 3n).toString() };
  await cw.accessProfiles.setEnvironmentBinding({ binding, expected_binding: expected, confirm_personal_credentials: true });
  assert.equal(calls.at(-1)!.body.confirmPersonalCredentials, true);
  assert.deepEqual(calls.at(-1)!.body.expectedBinding, wireExpected);
  await cw.accessProfiles.clearEnvironmentBinding(expected);
  assert.deepEqual(calls.at(-1)!.body.expectedBinding, wireExpected);
  const beforeErrors = calls.length;
  await assert.rejects(cw.accessProfiles.update("stale", exact, []), (error: unknown) => error instanceof CodewireError && error.status === 409);
  assert.equal(calls.length, beforeErrors + 1, "stale CAS must not fetch and retry");
  const callsBeforeValidation = calls.length;
  await assert.rejects(cw.accessProfiles.create("duplicate", [entries[0], entries[0]]), /duplicate/);
  await assert.rejects(cw.accessProfiles.update("profile-one", exact, [entries[0], entries[0]]), /duplicate/);
  await assert.rejects(cw.accessProfiles.get("profile-one", 0n), /positive uint64 bigint/);
  await assert.rejects(cw.accessProfiles.delete("profile-one", 42 as unknown as bigint), /positive uint64 bigint/);
  await assert.rejects(cw.accessProfiles.delete("profile-one", maximum + 1n), /positive uint64 bigint/);
  await assert.rejects(cw.accessProfiles.setEnvironmentBinding({ binding } as never), /explicit boolean/);
  assert.equal(calls.length, callsBeforeValidation);
  await assert.rejects(cw.accessProfiles.get("missing-response"), /omitted access_profile/);
  await assert.rejects(cw.accessProfiles.get("missing"), (error: unknown) => error instanceof CodewireError && error.status === 404);
  await cw.accessProfiles.delete("profile-one", maximum);
  assert.equal(calls.at(-1)!.body.expectedRevision, maximum.toString());
  assert.equal(calls.length, 16);
  assert.deepEqual(new Set(calls.map((call) => call.method)), new Set([
    "ListAccessProfiles", "GetAccessProfile", "CreateAccessProfile", "UpdateAccessProfile", "DeleteAccessProfile",
    "GetEnvironmentAccessProfile", "SetEnvironmentAccessProfile", "ClearEnvironmentAccessProfile",
  ]));
  console.log("Access profiles: all 8 generated methods, exact uint64/CAS, consent, pagination and errors passed");
}
