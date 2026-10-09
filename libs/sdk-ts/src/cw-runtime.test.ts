import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { UpdateEnvironmentCwRuntimeHeaderSchema, EnvironmentCwRuntimeOperationSchema, UpdateEnvironmentCwRuntimeRequestSchema, RollbackEnvironmentCwRuntimeRequestSchema } from "@codewire/proto-ts/gen/codewire/v1/environment_cw_runtime_pb";
import { CwRuntime, CwRuntimeOutcomeUnknownError, cwRuntimeRequests, CW_RUNTIME_CHUNK_BYTES } from "./cw-runtime.js";
import type { CwRuntimeClient } from "./transport.js";
import { boundedRuntimeFetch } from "./transport.js";

const maximum = (1n << 64n) - 1n;
const header = (size = 64n) => create(UpdateEnvironmentCwRuntimeHeaderSchema, {
  orgId: "org", environmentId: "env", requestId: "original",
  identity: { size }, expectedSelection: { generation: maximum },
});
let count = 0;
async function test(name: string, run: () => Promise<void>) { await run(); count++; console.log(`ok ${count} - ${name}`); }
async function* data(...sizes: number[]) { for (const size of sizes) yield new Uint8Array(size); }
async function drain(iterable: AsyncIterable<unknown>) { for await (const _ of iterable) { /* consume bounded fixtures */ } }

await test("lazy chunks and full uint64", async () => {
  let read = 0;
  async function* source() { read++; yield new Uint8Array(CW_RUNTIME_CHUNK_BYTES); read++; yield new Uint8Array(64); }
  const stream = cwRuntimeRequests(header(BigInt(CW_RUNTIME_CHUNK_BYTES + 64)), source());
  assert.equal(read, 0); const first = (await stream.next()).value!; assert.equal(read, 0);
  const encoded = toBinary(UpdateEnvironmentCwRuntimeRequestSchema, first);
  const decoded = fromBinary(UpdateEnvironmentCwRuntimeRequestSchema, encoded);
  assert.equal(decoded.payload.case, "header");
  if (decoded.payload.case === "header") assert.equal(decoded.payload.value.expectedSelection?.generation, maximum);
  await drain(stream); assert.equal(read, 2);
});
await test("short extra empty and oversized chunks refuse", async () => {
  for (const source of [data(63), data(65), data(0), data(CW_RUNTIME_CHUNK_BYTES + 1)]) await assert.rejects(drain(cwRuntimeRequests(header(), source)));
  await assert.rejects(drain(cwRuntimeRequests(header(256n * 1024n * 1024n + 1n), data(64))));
});
await test("lost ACK is observe-only original UUID", async () => {
  let updates = 0; let observations = 0;
  const client = {
    async updateEnvironmentCwRuntime(requests: AsyncIterable<unknown>) { updates++; await drain(requests); throw new Error("synthetic lost ACK"); },
    async observeEnvironmentCwRuntime(request: { requestId: string }) { observations++; assert.equal(request.requestId, "original"); return { operation: create(EnvironmentCwRuntimeOperationSchema, { requestId: "original", phase: "unknown" }) }; },
  } as unknown as CwRuntimeClient;
  const runtime = new CwRuntime(client, client, "org", "env");
  await assert.rejects(runtime.update(header(), data(64)), (error: unknown) => error instanceof CwRuntimeOutcomeUnknownError && error.requestId === "original");
  assert.equal((await runtime.observe("original")).phase, "unknown"); assert.equal(updates, 1); assert.equal(observations, 1);
});
await test("scope mismatch has no read or transport effects", async () => {
  let calls = 0; const client = { async updateEnvironmentCwRuntime() { calls++; } } as unknown as CwRuntimeClient;
  const runtime = new CwRuntime(client, client, "org", "env"); const wrong = header(); wrong.environmentId = "other";
  await assert.rejects(runtime.update(wrong, data(64))); assert.equal(calls, 0);
});
await test("rollback is bounded and retains an owned immutable request", async () => {
  let calls = 0;
  const client = {
    async rollbackEnvironmentCwRuntime(forwarded: { requestId: string }) {
      calls++;
      assert.notEqual(forwarded, request);
      request.requestId = "caller-mutated-after-dispatch";
      return { operation: create(EnvironmentCwRuntimeOperationSchema, { requestId: forwarded.requestId, phase: "succeeded" }) };
    },
  } as unknown as CwRuntimeClient;
  const runtime = new CwRuntime(client, client, "org", "env");
  const request = create(RollbackEnvironmentCwRuntimeRequestSchema, {
    orgId: "org", environmentId: "env", requestId: "original",
    identity: { packageVersion: "x".repeat(32 * 1024 + 1) },
  });
  await assert.rejects(runtime.rollback(request)); assert.equal(calls, 0);
  request.identity!.packageVersion = "synthetic";
  assert.equal((await runtime.rollback(request)).requestId, "original"); assert.equal(calls, 1);
});
await test("runtime unary response is bounded before buffering", async () => {
  let cancelled = false;
  const fake = (async () => new Response(new ReadableStream<Uint8Array>({
    start(controller) { controller.enqueue(new Uint8Array(32 * 1024 + 1)); },
    cancel() { cancelled = true; },
  }))) as typeof globalThis.fetch;
  const response = await boundedRuntimeFetch(fake)("http://in-memory.invalid");
  await assert.rejects(response.arrayBuffer()); assert.equal(cancelled, true);
  const small = (async () => new Response(new Uint8Array(32 * 1024))) as typeof globalThis.fetch;
  assert.equal((await (await boundedRuntimeFetch(small)("http://in-memory.invalid")).arrayBuffer()).byteLength, 32 * 1024);
});
console.log(`cw-runtime focused: ${count} passed`);
