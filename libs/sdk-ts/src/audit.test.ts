import assert from "node:assert/strict";
import {
  AuditCredentials_Action,
  AuditEventKind,
  AuditLifecycle_Action,
  AuditPlatformReason,
  AuditPolicyChange_Action,
  AuditProtocol,
  AuditRole,
  AuditSurface,
} from "@codewire/proto-ts/gen/codewire/v1/audit_pb";
import { Codewire, CodewireError } from "./index.js";
import { assertAuditConverterCoverage, auditEnumName } from "./audit.js";

/** Fake HTTP boundary still exercises the actual generated Connect JSON codec. */
export async function runAuditTests(): Promise<void> {
  assertAuditConverterCoverage();
  for (const enumObject of [
    AuditEventKind, AuditRole, AuditSurface, AuditPlatformReason, AuditProtocol,
    AuditLifecycle_Action, AuditPolicyChange_Action, AuditCredentials_Action,
  ] as unknown as Record<string, string | number>[]) {
    for (const [name, value] of Object.entries(enumObject)) {
      if (typeof value !== "number") continue;
      assert.equal(auditEnumName(enumObject as unknown as Record<number, string>, value), value === 0 ? "" : name.toLowerCase());
    }
    assert.equal(auditEnumName(enumObject as unknown as Record<number, string>, 99), "unknown");
  }

  const calls: { method: string; body: Record<string, any> }[] = [];
  const sandbox = { sandbox: {} };
  const cw = new Codewire({
    apiKey: "synthetic-opaque-oauth", baseUrl: "https://sdk.example.test", orgId: "org-one",
    fetch: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      assert.ok(url.pathname.startsWith("/codewire.v1.AuditService/"));
      const method = url.pathname.split("/").at(-1)!;
      const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
      calls.push({ method, body });
      const response = (value: object, status = 200) => new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
      if (body.environmentName === "missing") return response({ code: "not_found", message: "environment not found" }, 404);
      if (body.environmentName === "unselected") return response({ environment: { id: "env-two", name: "unselected" } });
      return response({
        environment: { id: "env-one", name: "web", deleted: true },
        policy: { name: "web", revision: 3 },
        nextCursor: "cursor-two", leftOut: "5",
        events: [
          { id: "event-access", kind: "AUDIT_EVENT_KIND_ACCESS", first: "2026-11-24T09:00:00Z", count: "1",
            actor: { user: { id: "user-one", email: "one@example.com", role: "AUDIT_ROLE_ADMIN" } },
            access: { surface: "AUDIT_SURFACE_SSH", clientIp: "203.0.113.7" } },
          { id: "event-lifecycle", kind: "AUDIT_EVENT_KIND_LIFECYCLE", first: "2026-11-24T09:00:00Z",
            last: "2026-11-24T09:00:01Z", count: "1", actor: { platform: {} },
            lifecycle: { action: "ACTION_STOPPED", reason: "AUDIT_PLATFORM_REASON_IDLE", preset: "go",
              fromSnapshot: "snap-one", from: { vcpu: 2, memoryMib: "4096" }, to: { vcpu: 4, memoryMib: "8192" },
              snapshot: "snap-two", idleStopSeconds: 1800 } },
          { id: "event-policy", kind: "AUDIT_EVENT_KIND_POLICY", count: "1", actor: { apiKey: { id: "key-one", name: "ci" } },
            policy: { action: "ACTION_EDITED", from: "open", to: "web", policy: "web", fromRevision: 2, toRevision: 3,
              added: ["github.com:443"], removed: ["example.com:80"], revision: 3, failureCode: "self_check_failed" } },
          { id: "event-refused", kind: "AUDIT_EVENT_KIND_REFUSED", count: "7", actor: sandbox,
            refused: { destination: "evil.example", address: "198.51.100.9", port: 443, protocol: "AUDIT_PROTOCOL_TCP",
              reason: "name_not_allowed", source: "egress", policy: "web", revision: 3, allowedSinceRevision: 4 } },
          { id: "event-dns", kind: "AUDIT_EVENT_KIND_REFUSED", count: "1", actor: sandbox,
            refused: { withheld: true, protocol: "AUDIT_PROTOCOL_DNS", reason: "host_check_failed" } },
          { id: "event-credentials", kind: "AUDIT_EVENT_KIND_CREDENTIALS", count: "2", actor: sandbox,
            credentials: { action: "ACTION_USED", provider: "github", name: "work", host: "api.github.com", withheld: true } },
          { id: "event-overflow", kind: "AUDIT_EVENT_KIND_REFUSED", count: "4200", actor: sandbox,
            refusedOverflow: { subjects: "1000", atLeast: true } },
          { id: "event-future", kind: 99, actor: {} },
        ],
      });
    },
  });

  const page = await cw.audit.listAuditEvents({
    environmentId: "env-one", kinds: ["refused", "credentials"], since: new Date("2026-11-24T08:00:00Z"),
    until: new Date("2026-11-24T09:00:00Z"), limit: 50, cursor: "cursor-one", groupBySubject: true,
  });
  assert.deepEqual(calls.at(-1)!.body, {
    orgId: "org-one", environmentId: "env-one", kinds: ["AUDIT_EVENT_KIND_REFUSED", "AUDIT_EVENT_KIND_CREDENTIALS"],
    since: "2026-11-24T08:00:00Z", until: "2026-11-24T09:00:00Z", limit: 50, cursor: "cursor-one", groupBySubject: true,
  });
  assert.deepEqual(page.environment, { id: "env-one", name: "web", deleted: true });
  assert.deepEqual(page.policy, { name: "web", revision: 3 });
  assert.equal(page.next_cursor, "cursor-two");
  assert.equal(page.left_out, 5);
  const first = new Date("2026-11-24T09:00:00Z");
  const none = { first: undefined, last: undefined };
  assert.deepEqual(page.events, [
    { id: "event-access", kind: "access", first, last: undefined, count: 1,
      actor: { user: { id: "user-one", email: "one@example.com", role: "admin" } },
      access: { surface: "ssh", client_ip: "203.0.113.7" } },
    { id: "event-lifecycle", kind: "lifecycle", first, last: new Date("2026-11-24T09:00:01Z"), count: 1,
      actor: { platform: {} },
      lifecycle: { action: "stopped", reason: "idle", preset: "go", from_snapshot: "snap-one",
        from: { vcpu: 2, memory_mib: 4096 }, to: { vcpu: 4, memory_mib: 8192 }, snapshot: "snap-two",
        idle_stop_seconds: 1800 } },
    { id: "event-policy", kind: "policy", ...none, count: 1, actor: { api_key: { id: "key-one", name: "ci" } },
      policy: { action: "edited", from: "open", to: "web", policy: "web", from_revision: 2, to_revision: 3,
        added: ["github.com:443"], removed: ["example.com:80"], revision: 3, failure_code: "self_check_failed" } },
    { id: "event-refused", kind: "refused", ...none, count: 7, actor: sandbox,
      refused: { destination: "evil.example", withheld: false, address: "198.51.100.9", port: 443, protocol: "tcp",
        reason: "name_not_allowed", source: "egress", policy: "web", revision: 3, allowed_since_revision: 4 } },
    { id: "event-dns", kind: "refused", ...none, count: 1, actor: sandbox,
      refused: { destination: "", withheld: true, address: "", port: undefined, protocol: "dns",
        reason: "host_check_failed", source: "", policy: "", revision: 0, allowed_since_revision: undefined } },
    { id: "event-credentials", kind: "credentials", ...none, count: 2, actor: sandbox,
      credentials: { action: "used", provider: "github", name: "work", host: "api.github.com", withheld: true } },
    { id: "event-overflow", kind: "refused", ...none, count: 4200, actor: sandbox,
      refused_overflow: { subjects: 1000, at_least: true } },
    // A kind or actor this SDK does not know yet never fails the read.
    { id: "event-future", kind: "unknown", ...none, count: 0, actor: {} },
  ]);

  const unselected = await cw.audit.listAuditEvents({ environmentName: "unselected" });
  assert.equal(unselected.policy, undefined);
  assert.deepEqual(unselected.events, []);
  assert.deepEqual(calls.at(-1)!.body, { orgId: "org-one", environmentName: "unselected" }, "defaults are left to the server");

  const before = calls.length;
  await assert.rejects(cw.audit.listAuditEvents({}), /exactly one/);
  await assert.rejects(cw.audit.listAuditEvents({ environmentId: "env-one", environmentName: "web" }), /exactly one/);
  for (const kind of ["unspecified", "", "logins"]) {
    await assert.rejects(cw.audit.listAuditEvents({ environmentId: "env-one", kinds: [kind as any] }), /unknown audit event kind/);
  }
  assert.equal(calls.length, before, "a refused option reached the server");
  await assert.rejects(cw.audit.listAuditEvents({ environmentName: "missing" }), (error) => error instanceof CodewireError);
}
