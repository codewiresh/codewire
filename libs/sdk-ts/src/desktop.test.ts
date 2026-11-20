import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  EnvironmentDesktopSchema,
  EnvironmentDesktopState,
} from "@codewire/proto-ts/gen/codewire/v1/environment_desktop_pb";
import { Desktop, fromProtoDesktop } from "./desktop.js";
import type { DesktopClient } from "./transport.js";
import { CodewireError } from "./types.js";

let count = 0;
async function test(name: string, run: () => Promise<void>) { await run(); count++; console.log(`ok ${count} - ${name}`); }

const running = () => create(EnvironmentDesktopSchema, {
  state: EnvironmentDesktopState.RUNNING,
  running: {
    display: ":1",
    port: 5901,
    startedAt: timestampFromDate(new Date("2026-11-20T10:00:00Z")),
    viewerPassword: "a1b2c3d4",
  },
});

await test("each call names its environment and a running desktop arrives whole", async () => {
  const seen: string[] = [];
  let startTimeout: number | undefined;
  const scoped = (rpc: string, request: { orgId: string; environmentId: string }) => {
    assert.deepEqual(request, { orgId: "org_123", environmentId: "env_123" });
    seen.push(rpc);
  };
  const client = {
    async startDesktop(request: { orgId: string; environmentId: string }, options?: { timeoutMs?: number }) {
      scoped("start", request);
      startTimeout = options?.timeoutMs;
      return { desktop: running() };
    },
    async getDesktop(request: { orgId: string; environmentId: string }) {
      scoped("get", request);
      return { desktop: running() };
    },
    async stopDesktop(request: { orgId: string; environmentId: string }) {
      scoped("stop", request);
      return { desktop: create(EnvironmentDesktopSchema, { state: EnvironmentDesktopState.STOPPED }) };
    },
  } as unknown as DesktopClient;
  const desktop = new Desktop(client, "org_123", "env_123");

  const expected = {
    state: "running",
    unavailable_reason: undefined,
    running: {
      display: ":1",
      port: 5901,
      started_at: "2026-11-20T10:00:00Z",
      viewer_password: "a1b2c3d4",
    },
  };
  assert.deepEqual(await desktop.start(), expected);
  // Longer than the server's own 40 seconds, so its answer is the one seen.
  assert.equal(startTimeout, 45_000);
  assert.deepEqual(await desktop.get(), expected);
  assert.deepEqual(await desktop.stop(), {
    state: "stopped",
    unavailable_reason: undefined,
    running: undefined,
  });
  assert.deepEqual(seen, ["start", "get", "stop"]);
});

await test("an image without a desktop says what it lacks, and each state has its name", async () => {
  assert.deepEqual(
    fromProtoDesktop(create(EnvironmentDesktopSchema, {
      state: EnvironmentDesktopState.UNAVAILABLE,
      unavailableReason: "its launcher (/opt/codewire/desktop/start) is not in the image",
    })),
    {
      state: "unavailable",
      unavailable_reason: "its launcher (/opt/codewire/desktop/start) is not in the image",
      running: undefined,
    },
  );
  for (const [state, name] of [
    [EnvironmentDesktopState.STOPPED, "stopped"],
    [EnvironmentDesktopState.STARTING, "starting"],
    [EnvironmentDesktopState.RUNNING, "running"],
    [EnvironmentDesktopState.UNSPECIFIED, "unknown"],
  ] as const) {
    assert.equal(fromProtoDesktop(create(EnvironmentDesktopSchema, { state })).state, name);
  }
  assert.throws(() => fromProtoDesktop(undefined), /omitted desktop/);
});

await test("a refusal reaches the caller as the SDK's error with the server's reason", async () => {
  const reason = "this environment's image has no desktop: its launcher is not in the image";
  const client = {
    async startDesktop() { throw new ConnectError(reason, Code.FailedPrecondition); },
  } as unknown as DesktopClient;
  await assert.rejects(new Desktop(client, "org_123", "env_123").start(), (error: unknown) =>
    error instanceof CodewireError && error.message.includes("has no desktop"));
});
