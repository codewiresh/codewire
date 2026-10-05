import { equals, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  EnvironmentAgentScopeSchema,
  MutateEnvironmentAgentRequestSchema,
  ReadEnvironmentAgentRequestSchema,
  ListEnvironmentAgentsRequestSchema,
  type EnvironmentAgentScope,
  type EnvironmentAgentOperation,
  type MutateEnvironmentAgentRequest,
  type ListEnvironmentAgentsRequest,
  type ReadEnvironmentAgentRequest,
} from "@codewire/proto-ts/gen/codewire/v1/environment_agent_pb";
import type { EnvironmentAgentClient } from "./transport.js";
import { mapConnectError } from "./types.js";

const RECORD_BYTES = 5 * 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class PlatformAgentOutcomeUnknownError extends Error {
  constructor(readonly requestId: string, options?: ErrorOptions) {
    super(`agent outcome is uncertain; observe the original request ${requestId}`, options);
    this.name = "PlatformAgentOutcomeUnknownError";
  }
}

function sameScope(a: EnvironmentAgentScope | undefined, b: EnvironmentAgentScope | undefined): boolean {
  return a !== undefined && b !== undefined && equals(EnvironmentAgentScopeSchema, a, b);
}

/** One original scope per operation. Mutations are sent once; uint64 stays bigint. */
export class PlatformAgents {
  constructor(private client: EnvironmentAgentClient, private orgId: string, private environmentId: string) {}

  private scope(value: EnvironmentAgentScope | undefined): void {
    if (!value?.incarnation || value.incarnation.orgId !== this.orgId
      || value.incarnation.environmentId !== this.environmentId
      || value.supportImageSha256.length !== 32 || value.supportImageSize === 0n) {
      throw new Error("agent scope differs from this environment or omits support identity");
    }
  }

  private requestScope(value: { orgId: string; environmentId: string; expectedScope?: EnvironmentAgentScope }): void {
    if (value.orgId !== this.orgId || value.environmentId !== this.environmentId) {
      throw new Error("agent request scope differs from this environment");
    }
    this.scope(value.expectedScope);
  }

  async info() {
    try {
      const result = await this.client.getEnvironmentAgentInfo({ orgId: this.orgId, environmentId: this.environmentId }, { timeoutMs: 90_000 });
      this.scope(result.scope);
      return result;
    } catch (error) { throw mapConnectError(error); }
  }

  async mutate(request: MutateEnvironmentAgentRequest, signal?: AbortSignal): Promise<EnvironmentAgentOperation> {
    this.requestScope(request);
    if (!UUID.test(request.requestId) || request.operation.case === undefined) throw new Error("agent mutation requires a canonical UUID and action");
    const encoded = toBinary(MutateEnvironmentAgentRequestSchema, request);
    if (encoded.length > 256 * 1024) throw new Error("agent mutation exceeds its bound");
    const owned = fromBinary(MutateEnvironmentAgentRequestSchema, encoded);
    const id = owned.requestId;
    try {
      const result = await this.client.mutateEnvironmentAgent(owned, { timeoutMs: 240_000, signal });
      if (!result.operation || result.operation.requestId !== id || !sameScope(result.operation.scope, owned.expectedScope)) {
        throw new Error("agent response changed its original request or scope");
      }
      return result.operation;
    } catch (error) { throw new PlatformAgentOutcomeUnknownError(id, { cause: error }); }
  }

  async observe(requestId: string): Promise<EnvironmentAgentOperation> {
    if (!UUID.test(requestId)) throw new Error("agent requestId must be a canonical UUID");
    try {
      const result = await this.client.observeEnvironmentAgent({ orgId: this.orgId, environmentId: this.environmentId, requestId }, { timeoutMs: 90_000 });
      if (!result.operation || result.operation.requestId !== requestId) throw new Error("agent observation changed its original request");
      this.scope(result.operation.scope);
      return result.operation;
    } catch (error) { throw mapConnectError(error); }
  }

  async list(request: ListEnvironmentAgentsRequest) {
    this.requestScope(request);
    const bytes = toBinary(ListEnvironmentAgentsRequestSchema, request);
    if (bytes.length > 32 * 1024) throw new Error("agent list request exceeds its bound");
    const owned = fromBinary(ListEnvironmentAgentsRequestSchema, bytes);
    try {
      const result = await this.client.listEnvironmentAgents(owned, { timeoutMs: 90_000 });
      if (!sameScope(result.scope, owned.expectedScope) || result.sessions.length > 8) throw new Error("agent list changed its original scope or exceeded its page bound");
      return result;
    } catch (error) { throw mapConnectError(error); }
  }

  async read(request: ReadEnvironmentAgentRequest) {
    this.requestScope(request);
    const bytes = toBinary(ReadEnvironmentAgentRequestSchema, request);
    if (bytes.length > 32 * 1024) throw new Error("agent read request exceeds its bound");
    const owned = fromBinary(ReadEnvironmentAgentRequestSchema, bytes);
    try {
      const result = await this.client.readEnvironmentAgent(owned, { timeoutMs: 90_000 });
      if (!sameScope(result.scope, owned.expectedScope) || result.sessionId !== owned.sessionId || result.driverId !== owned.driverId
        || result.launchGeneration !== owned.expectedLaunchGeneration || result.kind !== owned.kind || result.messageId !== owned.messageId
        || result.recordJson.length > RECORD_BYTES || result.recordSha256.length !== 32) throw new Error("agent record changed its original scope or generation");
      const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(result.recordJson)));
      if (!digest.every((value, index) => value === result.recordSha256[index])) throw new Error("agent record digest differs");
      return result;
    } catch (error) { throw mapConnectError(error); }
  }
}

export type {
  EnvironmentAgentScope, EnvironmentAgentSupport, EnvironmentAgentOperation,
  EnvironmentAgentLaunch, EnvironmentAgentControl, MutateEnvironmentAgentRequest,
  ListEnvironmentAgentsRequest, ReadEnvironmentAgentRequest,
} from "@codewire/proto-ts/gen/codewire/v1/environment_agent_pb";
