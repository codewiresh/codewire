import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

const design = new URL("../../../../packages/codewire-design/", import.meta.url);
const contract = JSON.parse(readFileSync(new URL("reference/contracts/durable-terminal-v1.json", design), "utf8"));
const scope = { TextEncoder, atob, btoa } as Record<string, unknown>;
runInNewContext(readFileSync(new URL("terminal-protocol.js", design), "utf8"), scope);
const protocol = scope.CodewireTerminalProtocol as {
  protocol: string; limits: Record<string, number>; states: string[];
  offset(value: unknown): bigint; encodeClient(value: unknown): string;
  decodeServer(value: unknown): { type: string; offset: bigint; nextOffset: bigint; data: Uint8Array; requestedOffset?: bigint; retainedStartOffset?: bigint };
  inventory(value: unknown): unknown;
};

test("browser terminal protocol consumes the shared wire examples and bounds", () => {
  assert.equal(protocol.protocol, contract.protocol);
  assert.deepEqual(JSON.parse(JSON.stringify(protocol.limits)), contract.limits);
  assert.deepEqual([...protocol.states].sort(), [...contract.states].sort());
  for (const frame of contract.client) assert.deepEqual(JSON.parse(protocol.encodeClient(frame)), frame);
  for (const frame of contract.server) assert.equal(protocol.decodeServer(JSON.stringify(frame)).type, frame.type);
  const output = protocol.decodeServer(JSON.stringify(contract.server[0]));
  assert.equal(new TextDecoder().decode(output.data), "hello\n");
  assert.equal(output.nextOffset, 6n);
});

test("terminal offsets retain exact u64 values beyond Number precision", () => {
  for (const offset of contract.invalidOffsets) assert.throws(() => protocol.offset(offset));
  for (const offset of [0, null, {}, 1n]) assert.throws(() => protocol.offset(offset));
  const frame = protocol.decodeServer(JSON.stringify({ type: "output", offset: "9007199254740993", nextOffset: "9007199254740994", data: "YQ==" }));
  assert.equal(frame.offset, 9007199254740993n);
  assert.equal(frame.nextOffset, 9007199254740994n);
  assert.equal(protocol.offset("18446744073709551615"), 18446744073709551615n);
});

test("client frames reject extra fields, invalid dimensions, empty and oversized UTF-8 input", () => {
  for (const frame of [
    { type: "input", data: "" }, { type: "input", data: "\ud800" },
    { type: "input", data: "é".repeat(8193) }, { type: "input", data: "x", token: "not-allowed" },
    { type: "input", data: "\u0000".repeat(12000) },
    { type: "resize", columns: 0, rows: 24 }, { type: "resize", columns: 80, rows: 65536 },
    { type: "resize", columns: 80.5, rows: 24 }, { type: "ack", offset: "01" },
  ]) assert.throws(() => protocol.encodeClient(frame));
  assert.doesNotThrow(() => protocol.encodeClient({ type: "input", data: "é".repeat(8192) }));
  assert.doesNotThrow(() => protocol.encodeClient({ type: "resize", columns: 1, rows: 65535 }));
});

test("server frames reject noncanonical base64, cursor mismatches and inconsistent closed states", () => {
  for (const frame of [
    { type: "output", offset: "0", nextOffset: "1", data: "YR==" },
    { type: "output", offset: "0", nextOffset: "1", data: "YQ" },
    { type: "output", offset: "0", nextOffset: "2", data: "YQ==" },
    { type: "output", offset: "0", nextOffset: "0", data: "" },
    { type: "output", offset: "18446744073709551615", nextOffset: "0", data: "YQ==" },
    { type: "status", state: "unknown" }, { type: "status", state: "running", exitCode: 0 },
    { type: "status", state: "exited", exitCode: 2147483648 },
    { type: "status", state: "failed", statusMessage: "not-allowed" },
  ]) assert.throws(() => protocol.decodeServer(JSON.stringify(frame)));
  const data = Buffer.alloc(32769).toString("base64");
  assert.throws(() => protocol.decodeServer(JSON.stringify({ type: "output", offset: "0", nextOffset: "32769", data })));
  assert.throws(() => protocol.decodeServer(new Uint8Array(2)));
  assert.throws(() => protocol.decodeServer(" ".repeat(65537)));
});

test("session inventory is closed, bounded, and has unique canonical references", () => {
  const session = { sessionId: "session-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", state: "running" };
  assert.doesNotThrow(() => protocol.inventory({ accountId: "account-a", sessions: [session] }));
  for (const value of [
    { accountId: "account-a", sessions: [session, session] },
    { accountId: "account-a", sessions: Array(257).fill(session) },
    { accountId: "account-a", sessions: [{ ...session, command: "not-allowed" }] },
    { accountId: "account-a", sessions: [{ ...session, sessionId: session.sessionId.toUpperCase() }] },
    { accountId: "", sessions: [] }, { accountId: "account-a", sessions: [], csrf: "not-allowed" },
  ]) assert.throws(() => protocol.inventory(value));
});

test("history gaps carry strict exact u64 cursor advances without permitting extra fields", () => {
  const frame = protocol.decodeServer(JSON.stringify({
    type: "historyGap", requestedOffset: "9007199254740993", retainedStartOffset: "9007199254740995",
  }));
  assert.equal(frame.requestedOffset, 9007199254740993n);
  assert.equal(frame.retainedStartOffset, 9007199254740995n);
  for (const value of [
    { type: "historyGap", requestedOffset: "1", retainedStartOffset: "1" },
    { type: "historyGap", requestedOffset: "2", retainedStartOffset: "1" },
    { type: "historyGap", requestedOffset: 0, retainedStartOffset: "1" },
    { type: "historyGap", requestedOffset: "01", retainedStartOffset: "2" },
    { type: "historyGap", requestedOffset: "0", retainedStartOffset: "18446744073709551616" },
    { type: "historyGap", requestedOffset: "0", retainedStartOffset: "1", token: "not-allowed" },
    { type: "historyGap", retainedStartOffset: "1" },
  ]) assert.throws(() => protocol.decodeServer(JSON.stringify(value)));
  assert.throws(() => protocol.encodeClient({ type: "historyGap", requestedOffset: "0", retainedStartOffset: "1" }));
});
