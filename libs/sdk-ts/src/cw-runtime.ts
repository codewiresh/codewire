import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  UpdateEnvironmentCwRuntimeHeaderSchema,
  UpdateEnvironmentCwRuntimeRequestSchema,
  RollbackEnvironmentCwRuntimeRequestSchema,
  type UpdateEnvironmentCwRuntimeHeader,
  type UpdateEnvironmentCwRuntimeRequest,
  type RollbackEnvironmentCwRuntimeRequest,
  type EnvironmentCwRuntimeOperation,
} from "@codewire/proto-ts/gen/codewire/v1/environment_cw_runtime_pb";
import { mapConnectError } from "./types.js";
import type { CwRuntimeClient } from "./transport.js";

export const CW_RUNTIME_CHUNK_BYTES = 64 * 1024;
const MAX_BYTES = 256n * 1024n * 1024n;
const MUTATION_TIMEOUT_MS = 960_000;

export class CwRuntimeOutcomeUnknownError extends Error {
  constructor(readonly requestId: string, options?: ErrorOptions) {
    super("cw runtime outcome is uncertain; observe the original requestId", options);
    this.name = "CwRuntimeOutcomeUnknownError";
  }
}

/** Lazy, bounded Connect messages. All uint64 fields stay bigint. */
export async function* cwRuntimeRequests(
  header: UpdateEnvironmentCwRuntimeHeader,
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<UpdateEnvironmentCwRuntimeRequest> {
  const size = header.identity?.size;
  if (typeof size !== "bigint" || size < 64n || size > MAX_BYTES) {
    throw new Error("cw runtime candidate size is invalid");
  }
  const encoded = toBinary(UpdateEnvironmentCwRuntimeHeaderSchema, header);
  if (encoded.length > 32 * 1024) throw new Error("cw runtime header exceeds its bound");
  const owned = fromBinary(UpdateEnvironmentCwRuntimeHeaderSchema, encoded);
  yield create(UpdateEnvironmentCwRuntimeRequestSchema, { payload: { case: "header", value: owned } });
  let count = 0n;
  let chunks = 0;
  for await (const chunk of source) {
    if (!(chunk instanceof Uint8Array) || chunk.length === 0 || chunk.length > CW_RUNTIME_CHUNK_BYTES) {
      throw new Error("cw runtime chunk is empty or exceeds its bound");
    }
    count += BigInt(chunk.length);
    if (++chunks > 8192) throw new Error("cw runtime candidate exceeds its chunk bound");
    if (count > size) throw new Error("cw runtime candidate stream exceeds its admitted size");
    // One owned chunk at a time; no collection/read-all fallback.
    yield create(UpdateEnvironmentCwRuntimeRequestSchema, { payload: { case: "chunk", value: chunk.slice() } });
  }
  if (count !== size) throw new Error("cw runtime candidate stream is incomplete");
}

/** Same-Pod ordinary invocation defaults; retained processes are unchanged. */
export class CwRuntime {
  constructor(
    private unary: CwRuntimeClient,
    private updates: CwRuntimeClient,
    private orgId: string,
    private environmentId: string,
  ) {}

  private scope(value: { orgId: string; environmentId: string }): void {
    if (value.orgId !== this.orgId || value.environmentId !== this.environmentId) {
      throw new Error("cw runtime request scope differs from this environment");
    }
  }

  async status() {
    try {
      const result = await this.unary.getEnvironmentCwRuntime({ orgId: this.orgId, environmentId: this.environmentId }, { timeoutMs: 180_000 });
      if (!result.incarnation || !result.selection) throw new Error("cw runtime status omitted required metadata");
      return result;
    } catch (error) { throw mapConnectError(error); }
  }

  /** Uses the official Node client-streaming transport, never fetch buffering. */
  async update(header: UpdateEnvironmentCwRuntimeHeader, source: AsyncIterable<Uint8Array>, signal?: AbortSignal): Promise<EnvironmentCwRuntimeOperation> {
    this.scope(header);
    if (!header.requestId) throw new Error("cw runtime requestId is required");
    const encoded = toBinary(UpdateEnvironmentCwRuntimeHeaderSchema, header);
    if (encoded.length > 32 * 1024) throw new Error("cw runtime header exceeds its bound");
    const owned = fromBinary(UpdateEnvironmentCwRuntimeHeaderSchema, encoded);
    const id = owned.requestId;
    try {
      const result = await this.updates.updateEnvironmentCwRuntime(cwRuntimeRequests(owned, source), { timeoutMs: MUTATION_TIMEOUT_MS, signal });
      if (!result.operation || result.operation.requestId !== id) throw new Error("cw runtime response omitted original request");
      return result.operation;
    } catch (error) { throw new CwRuntimeOutcomeUnknownError(id, { cause: error }); }
  }

  async rollback(request: RollbackEnvironmentCwRuntimeRequest, signal?: AbortSignal): Promise<EnvironmentCwRuntimeOperation> {
    this.scope(request);
    if (!request.requestId) throw new Error("cw runtime requestId is required");
    const encoded = toBinary(RollbackEnvironmentCwRuntimeRequestSchema, request);
    if (encoded.length > 32 * 1024) throw new Error("cw runtime request exceeds its bound");
    const owned = fromBinary(RollbackEnvironmentCwRuntimeRequestSchema, encoded);
    const id = owned.requestId;
    try {
      const result = await this.unary.rollbackEnvironmentCwRuntime(owned, { timeoutMs: MUTATION_TIMEOUT_MS, signal });
      if (!result.operation || result.operation.requestId !== id) throw new Error("cw runtime response omitted original request");
      return result.operation;
    } catch (error) { throw new CwRuntimeOutcomeUnknownError(id, { cause: error }); }
  }

  async observe(requestId: string): Promise<EnvironmentCwRuntimeOperation> {
    try {
      const result = await this.unary.observeEnvironmentCwRuntime({ orgId: this.orgId, environmentId: this.environmentId, requestId });
      if (!result.operation || result.operation.requestId !== requestId) throw new Error("cw runtime observation omitted original request");
      return result.operation;
    } catch (error) { throw mapConnectError(error); }
  }
}

export type {
  EnvironmentCwRuntimeIdentity, EnvironmentCwRuntimeIncarnation, EnvironmentCwRuntimeExpectation,
  EnvironmentCwRuntimeOperation, EnvironmentCwRuntimeSelection,
  UpdateEnvironmentCwRuntimeHeader, RollbackEnvironmentCwRuntimeRequest,
} from "@codewire/proto-ts/gen/codewire/v1/environment_cw_runtime_pb";
