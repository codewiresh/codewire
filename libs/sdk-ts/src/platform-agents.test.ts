import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import {
  EnvironmentAgentScopeSchema, EnvironmentAgentOperationSchema, EnvironmentAgentPhase,
  MutateEnvironmentAgentRequestSchema, ReadEnvironmentAgentRequestSchema,
  ReadEnvironmentAgentResponseSchema, EnvironmentAgentAction, EnvironmentAgentRecordKind,
} from "@codewire/proto-ts/gen/codewire/v1/environment_agent_pb";
import { PlatformAgents, PlatformAgentOutcomeUnknownError } from "./platform-agents.js";
import { createCodewireClients, type EnvironmentAgentClient } from "./transport.js";

const id = "6a162b2b-a758-4c8c-bccb-794502c82f09";
const maximum = (1n << 64n) - 1n;
const scope = () => create(EnvironmentAgentScopeSchema, {
  incarnation: { orgId: "org", environmentId: "env", podUid: "original-pod", bindingGeneration: maximum },
  supportImageSha256: new Uint8Array(32).fill(7), supportImageSize: 123n,
});
const mutation = () => create(MutateEnvironmentAgentRequestSchema, {
  orgId: "org", environmentId: "env", requestId: id, expectedScope: scope(),
  operation: { case: "control", value: { action: EnvironmentAgentAction.STOP, sessionId: "session", driverId: "driver", expectedLaunchGeneration: maximum } },
});
let count = 0;
async function test(name: string, run: () => Promise<void>) { await run(); count++; console.log(`ok ${count} - ${name}`); }

await test("lost mutation response is observed with original UUID, without retry", async () => {
  let mutations = 0; let observations = 0;
  const client = {
    async mutateEnvironmentAgent(request: ReturnType<typeof mutation>) {
      mutations++; assert.equal(request.operation.case, "control");
      if (request.operation.case === "control") assert.equal(request.operation.value.expectedLaunchGeneration, maximum);
      throw new Error("synthetic lost response after dispatch");
    },
    async observeEnvironmentAgent(request: { requestId: string }) {
      observations++; assert.equal(request.requestId, id);
      return { operation: create(EnvironmentAgentOperationSchema, { requestId: id, scope: scope(), phase: EnvironmentAgentPhase.UNKNOWN }) };
    },
  } as unknown as EnvironmentAgentClient;
  const agents = new PlatformAgents(client, "org", "env");
  await assert.rejects(agents.mutate(mutation()), (e: unknown) => e instanceof PlatformAgentOutcomeUnknownError && e.requestId === id);
  assert.equal((await agents.observe(id)).phase, EnvironmentAgentPhase.UNKNOWN);
  assert.equal(mutations, 1); assert.equal(observations, 1);
});

await test("wrong original UUID or Pod becomes uncertain without retry", async () => {
  for (const mismatch of ["uuid", "pod"]) {
    let calls = 0;
    const client = { async mutateEnvironmentAgent() {
      calls++;
      const original = scope();
      if (mismatch === "pod") original.incarnation!.podUid = "replacement-pod";
      return { operation: create(EnvironmentAgentOperationSchema, { requestId: mismatch === "uuid" ? "6d370dab-3d67-4d76-93c3-3bd31581fbe9" : id, scope: original }) };
    } } as unknown as EnvironmentAgentClient;
    await assert.rejects(new PlatformAgents(client, "org", "env").mutate(mutation()),
      (e: unknown) => e instanceof PlatformAgentOutcomeUnknownError && e.requestId === id);
    assert.equal(calls, 1);
  }
});

await test("scope and size refusals precede transport", async () => {
  let calls = 0;
  const client = { async mutateEnvironmentAgent() { calls++; } } as unknown as EnvironmentAgentClient;
  for (const mismatch of ["scope", "bound", "id"]) {
    const request = mutation();
    if (mismatch === "scope") request.expectedScope!.incarnation!.environmentId = "other";
    if (mismatch === "id") request.requestId = "invalid";
    if (mismatch === "bound" && request.operation.case === "control") request.operation.value.text = "x".repeat(256 * 1024);
    await assert.rejects(new PlatformAgents(client, "org", "env").mutate(request));
  }
  assert.equal(calls, 0);
});

await test("read preserves exact uint64 generation and verifies digest", async () => {
  const request = create(ReadEnvironmentAgentRequestSchema, {
    orgId: "org", environmentId: "env", expectedScope: scope(), sessionId: "session", driverId: "driver",
    expectedLaunchGeneration: maximum, kind: EnvironmentAgentRecordKind.MESSAGE, messageId: id,
  });
  const data = new TextEncoder().encode('{"record":"synthetic"}');
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", data));
  for (const mismatch of ["none", "generation", "digest"]) {
    const client = { async readEnvironmentAgent() {
      return create(ReadEnvironmentAgentResponseSchema, {
        scope: scope(), sessionId: "session", driverId: "driver", launchGeneration: mismatch === "generation" ? maximum - 1n : maximum,
        kind: EnvironmentAgentRecordKind.MESSAGE, messageId: id, recordJson: data,
        recordSha256: mismatch === "digest" ? new Uint8Array(32) : digest,
      });
    } } as unknown as EnvironmentAgentClient;
    const agents = new PlatformAgents(client, "org", "env");
    if (mismatch !== "none") await assert.rejects(agents.read(request));
    else {
      const result = await agents.read(request);
      assert.equal(result.launchGeneration, maximum);
      assert.equal(result.scope!.incarnation!.bindingGeneration, maximum);
    }
  }
});

await test("agent transport refuses excess bytes before buffering", async () => {
  let cancelled = false;
  const fetcher = (async () => new Response(new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new Uint8Array(5 * 1024 * 1024 + 32 * 1024 + 1)); },
    cancel() { cancelled = true; },
  }), { headers: { "Content-Type": "application/proto" } })) as typeof globalThis.fetch;
  const clients = createCodewireClients({ apiKey: "synthetic", baseUrl: "http://in-memory.invalid", fetch: fetcher });
  await assert.rejects(clients.environmentAgents.getEnvironmentAgentInfo({ orgId: "org", environmentId: "env" }));
  assert.equal(cancelled, true);
});
console.log(`platform-agents focused: ${count} passed`);
