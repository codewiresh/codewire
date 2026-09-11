// Mesh API client for the Codewire TypeScript SDK.
//
// The ergonomic layer wraps the generated Connect clients for every mounted
// product operation.

import type { Client, Interceptor } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { create } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { DurationSchema } from "@bufbuild/protobuf/wkt";
import { createConnectTransport } from "@connectrpc/connect-web";
import {
  MeshGroupDebugPolicy as ProtoMeshGroupDebugPolicy,
  MeshGroupDebugPolicySchema,
  MeshGroupMessagesPolicy as ProtoMeshGroupMessagesPolicy,
  MeshGroupMessagesPolicySchema,
  MeshGroupMemberSchema,
  MeshGroupPolicySchema,
  MeshGroupSchema,
  MeshGroupService as ProtoMeshGroupService,
  type MeshGroup as ProtoMeshGroup,
  type MeshGroupMember as ProtoMeshGroupMember,
  type MeshGroupPolicy as ProtoMeshGroupPolicy,
} from "@codewire/proto-ts/gen/codewire/v1/mesh_group_pb";
import {
  MeshKeyValueSchema,
  MeshKeyValueService as ProtoMeshKeyValueService,
  type MeshKeyValue as ProtoMeshKeyValue,
} from "@codewire/proto-ts/gen/codewire/v1/mesh_kv_pb";
import {
  MeshNetworkSchema,
  MeshNetworkService as ProtoMeshNetworkService,
  type MeshNetwork as ProtoMeshNetwork,
} from "@codewire/proto-ts/gen/codewire/v1/mesh_network_pb";
import {
  MeshNodeEnrollmentSchema,
  MeshNodeSchema,
  MeshNodeService as ProtoMeshNodeService,
  type MeshNode as ProtoMeshNode,
  type MeshNodeEnrollment as ProtoMeshNodeEnrollment,
} from "@codewire/proto-ts/gen/codewire/v1/mesh_node_pb";
import { mapConnectError } from "./types.js";

// -- Types --------------------------------------------------------------------

export interface MeshNetwork {
  id: string;
  org_id: string;
  created_at: string;
  node_count: number;
  invite_count: number;
}

export interface MeshNode {
  org_id: string;
  network_id: string;
  name: string;
  peer_url: string;
  connected: boolean;
}

export interface MeshEnrollment {
  id: string;
  org_id: string;
  network_id: string;
  node_name: string;
  owner_user_id: string;
  issued_by_user_id: string;
  expires_at: string;
  created_at: string;
  redeemed_at?: string;
  enrollment_code: string;
}

export interface MeshNodeRegistration {
  node: MeshNode;
  enrollment: MeshEnrollment;
}

export interface MeshKVEntry {
  org_id: string;
  network_id: string;
  namespace: string;
  key: string;
  value: Uint8Array;
  expires_at?: string;
}

export interface MeshGroupMember {
  org_id: string;
  network_id: string;
  group_name: string;
  node_name: string;
  session_name: string;
  created_at: string;
}

export type MeshGroupMessagesPolicy = "" | "internal-only" | "open";
export type MeshGroupDebugPolicy =
  | ""
  | "none"
  | "observe-only"
  | "full";

export interface MeshGroupPolicy {
  org_id: string;
  network_id: string;
  group_name: string;
  messages_policy: MeshGroupMessagesPolicy;
  debug_policy: MeshGroupDebugPolicy;
  updated_at: string;
}

export interface MeshGroup {
  org_id: string;
  network_id: string;
  name: string;
  created_at: string;
  created_by_user_id: string;
  members: MeshGroupMember[];
  policy?: MeshGroupPolicy;
}

export interface MeshClientOptions {
  /** Request timeout in milliseconds. Default 30_000. */
  timeout?: number;
  /** Custom fetch implementation; defaults to global `fetch`. */
  fetch?: typeof fetch;
}

export interface MeshTTL {
  /** Duration in milliseconds. Omit or use zero to select the server default. */
  ttlMs?: number;
}

type MeshNetworkClient = Client<typeof ProtoMeshNetworkService>;
type MeshNodeClient = Client<typeof ProtoMeshNodeService>;
type MeshGroupClient = Client<typeof ProtoMeshGroupService>;
type MeshKeyValueClient = Client<typeof ProtoMeshKeyValueService>;

// -- Conversion ---------------------------------------------------------------

function requiredTimestamp(name: string, value: Timestamp | undefined): string {
  if (!value) throw new Error(`codewire: Mesh ${name} is missing`);
  return new Date(
    Number(value.seconds) * 1_000 + Math.trunc(value.nanos / 1_000_000),
  )
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

function optionalTimestamp(value: Timestamp | undefined): string | undefined {
  return value ? requiredTimestamp("optional timestamp", value) : undefined;
}

function numberFromInt64(name: string, value: bigint): number {
  const converted = Number(value);
  if (!Number.isSafeInteger(converted)) {
    throw new Error(`codewire: Mesh ${name} is outside the safe integer range`);
  }
  return converted;
}

function durationFromMilliseconds(name: string, value: number | undefined) {
  if (value === undefined || value === 0) return undefined;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `codewire: Mesh ${name} must be a non-negative integer number of milliseconds`,
    );
  }
  return create(DurationSchema, {
    seconds: BigInt(Math.trunc(value / 1_000)),
    nanos: (value % 1_000) * 1_000_000,
  });
}

function required<T>(name: string, value: T | undefined): T {
  if (value === undefined) throw new Error(`codewire: Mesh ${name} is missing`);
  return value;
}

function fromProtoMessagesPolicy(
  value: ProtoMeshGroupMessagesPolicy,
): MeshGroupMessagesPolicy {
  switch (value) {
    case ProtoMeshGroupMessagesPolicy.UNSPECIFIED:
      return "";
    case ProtoMeshGroupMessagesPolicy.INTERNAL_ONLY:
      return "internal-only";
    case ProtoMeshGroupMessagesPolicy.OPEN:
      return "open";
    default:
      throw new Error(`codewire: unknown Mesh messages policy ${value}`);
  }
}

function toProtoMessagesPolicy(
  value: MeshGroupMessagesPolicy,
): ProtoMeshGroupMessagesPolicy {
  switch (value) {
    case "":
      return ProtoMeshGroupMessagesPolicy.UNSPECIFIED;
    case "internal-only":
      return ProtoMeshGroupMessagesPolicy.INTERNAL_ONLY;
    case "open":
      return ProtoMeshGroupMessagesPolicy.OPEN;
    default:
      throw new Error(`codewire: unknown Mesh messages policy ${value}`);
  }
}

function fromProtoDebugPolicy(
  value: ProtoMeshGroupDebugPolicy,
): MeshGroupDebugPolicy {
  switch (value) {
    case ProtoMeshGroupDebugPolicy.UNSPECIFIED:
      return "";
    case ProtoMeshGroupDebugPolicy.NONE:
      return "none";
    case ProtoMeshGroupDebugPolicy.OBSERVE_ONLY:
      return "observe-only";
    case ProtoMeshGroupDebugPolicy.FULL:
      return "full";
    default:
      throw new Error(`codewire: unknown Mesh debug policy ${value}`);
  }
}

function toProtoDebugPolicy(
  value: MeshGroupDebugPolicy,
): ProtoMeshGroupDebugPolicy {
  switch (value) {
    case "":
      return ProtoMeshGroupDebugPolicy.UNSPECIFIED;
    case "none":
      return ProtoMeshGroupDebugPolicy.NONE;
    case "observe-only":
      return ProtoMeshGroupDebugPolicy.OBSERVE_ONLY;
    case "full":
      return ProtoMeshGroupDebugPolicy.FULL;
    default:
      throw new Error(`codewire: unknown Mesh debug policy ${value}`);
  }
}

function fromProtoNetwork(network: ProtoMeshNetwork): MeshNetwork {
  return {
    id: network.id,
    org_id: network.orgId,
    created_at: requiredTimestamp("network created_at", network.createdAt),
    node_count: numberFromInt64("network node_count", network.nodeCount),
    invite_count: numberFromInt64("network invite_count", network.inviteCount),
  };
}

function fromProtoNode(node: ProtoMeshNode): MeshNode {
  return {
    org_id: node.orgId,
    network_id: node.networkId,
    name: node.name,
    peer_url: node.peerUrl,
    connected: node.connected,
  };
}

function fromProtoEnrollment(
  enrollment: ProtoMeshNodeEnrollment,
  enrollmentCode: string,
): MeshEnrollment {
  return {
    id: enrollment.id,
    org_id: enrollment.orgId,
    network_id: enrollment.networkId,
    node_name: enrollment.nodeName,
    owner_user_id: enrollment.ownerUserId,
    issued_by_user_id: enrollment.issuedByUserId,
    expires_at: requiredTimestamp(
      "enrollment expires_at",
      enrollment.expiresAt,
    ),
    created_at: requiredTimestamp(
      "enrollment created_at",
      enrollment.createdAt,
    ),
    redeemed_at: optionalTimestamp(enrollment.redeemedAt),
    enrollment_code: enrollmentCode,
  };
}

function fromProtoGroupMember(member: ProtoMeshGroupMember): MeshGroupMember {
  return {
    org_id: member.orgId,
    network_id: member.networkId,
    group_name: member.groupName,
    node_name: member.nodeName,
    session_name: member.sessionName,
    created_at: requiredTimestamp("group member created_at", member.createdAt),
  };
}

function fromProtoGroupPolicy(policy: ProtoMeshGroupPolicy): MeshGroupPolicy {
  return {
    org_id: policy.orgId,
    network_id: policy.networkId,
    group_name: policy.groupName,
    messages_policy: fromProtoMessagesPolicy(policy.messagesPolicy),
    debug_policy: fromProtoDebugPolicy(policy.debugPolicy),
    updated_at: requiredTimestamp("group policy updated_at", policy.updatedAt),
  };
}

function fromProtoGroup(group: ProtoMeshGroup): MeshGroup {
  return {
    org_id: group.orgId,
    network_id: group.networkId,
    name: group.name,
    created_at: requiredTimestamp("group created_at", group.createdAt),
    created_by_user_id: group.createdByUserId,
    members: group.members.map(fromProtoGroupMember),
    policy: group.policy ? fromProtoGroupPolicy(group.policy) : undefined,
  };
}

function fromProtoKeyValue(entry: ProtoMeshKeyValue): MeshKVEntry {
  return {
    org_id: entry.orgId,
    network_id: entry.networkId,
    namespace: entry.namespace,
    key: entry.key,
    value: new Uint8Array(entry.value),
    expires_at: optionalTimestamp(entry.expiresAt),
  };
}

function assertDescriptorFields(
  name: string,
  fields: ReadonlyArray<{ number: number; name: string }>,
  expected: ReadonlyArray<string>,
): void {
  if (fields.length !== expected.length) {
    throw new Error(
      `codewire: Mesh ${name} converter covers ${expected.length} descriptor fields, expected ${fields.length}`,
    );
  }
  for (let index = 0; index < expected.length; index++) {
    const field = fields[index];
    if (!field || field.number !== index + 1 || field.name !== expected[index]) {
      throw new Error(
        `codewire: Mesh ${name} converter does not cover descriptor field ${field?.name ?? "<missing>"}`,
      );
    }
  }
}

function assertDescriptorValues(
  name: string,
  values: ReadonlyArray<{ number: number; name: string }>,
  expected: ReadonlyArray<string>,
): void {
  if (values.length !== expected.length) {
    throw new Error(
      `codewire: Mesh ${name} converter covers ${expected.length} enum values, expected ${values.length}`,
    );
  }
  for (let index = 0; index < expected.length; index++) {
    const value = values[index];
    if (!value || value.number !== index || value.name !== expected[index]) {
      throw new Error(
        `codewire: Mesh ${name} converter does not cover enum value ${value?.name ?? "<missing>"}`,
      );
    }
  }
}

/** Throws when a future Mesh proto field or enum value lacks an SDK mapping. */
export function assertMeshConverterCoverage(): void {
  assertDescriptorFields("network", MeshNetworkSchema.fields, [
    "id",
    "org_id",
    "created_at",
    "node_count",
    "invite_count",
  ]);
  assertDescriptorFields("node", MeshNodeSchema.fields, [
    "org_id",
    "network_id",
    "name",
    "peer_url",
    "connected",
  ]);
  assertDescriptorFields("enrollment", MeshNodeEnrollmentSchema.fields, [
    "id",
    "org_id",
    "network_id",
    "node_name",
    "owner_user_id",
    "issued_by_user_id",
    "expires_at",
    "created_at",
    "redeemed_at",
  ]);
  assertDescriptorFields("group", MeshGroupSchema.fields, [
    "org_id",
    "network_id",
    "name",
    "created_at",
    "created_by_user_id",
    "members",
    "policy",
  ]);
  assertDescriptorFields("group member", MeshGroupMemberSchema.fields, [
    "org_id",
    "network_id",
    "group_name",
    "node_name",
    "session_name",
    "created_at",
  ]);
  assertDescriptorFields("group policy", MeshGroupPolicySchema.fields, [
    "org_id",
    "network_id",
    "group_name",
    "messages_policy",
    "debug_policy",
    "updated_at",
  ]);
  assertDescriptorFields("key value", MeshKeyValueSchema.fields, [
    "org_id",
    "network_id",
    "namespace",
    "key",
    "value",
    "expires_at",
  ]);
  assertDescriptorValues(
    "messages policy",
    MeshGroupMessagesPolicySchema.values,
    [
      "MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED",
      "MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY",
      "MESH_GROUP_MESSAGES_POLICY_OPEN",
    ],
  );
  assertDescriptorValues("debug policy", MeshGroupDebugPolicySchema.values, [
    "MESH_GROUP_DEBUG_POLICY_UNSPECIFIED",
    "MESH_GROUP_DEBUG_POLICY_NONE",
    "MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY",
    "MESH_GROUP_DEBUG_POLICY_FULL",
  ]);
}

async function connectCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw mapConnectError(error);
  }
}

// -- Services -----------------------------------------------------------------

export class MeshNetworksService {
  constructor(private readonly client: MeshNetworkClient) {}

  async create(orgId: string, networkId: string): Promise<MeshNetwork> {
    const response = await connectCall(() =>
      this.client.createMeshNetwork({ orgId, networkId }),
    );
    return fromProtoNetwork(required("created network", response.network));
  }

  async delete(orgId: string, networkId: string): Promise<void> {
    await connectCall(() =>
      this.client.deleteMeshNetwork({ orgId, networkId }),
    );
  }

  async list(orgId: string): Promise<MeshNetwork[]> {
    const networks: MeshNetwork[] = [];
    let pageToken = "";
    do {
      const response = await connectCall(() =>
        this.client.listMeshNetworks({ orgId, pageToken }),
      );
      networks.push(...response.networks.map(fromProtoNetwork));
      pageToken = response.nextPageToken;
    } while (pageToken !== "");
    return networks;
  }
}

export class MeshNodesService {
  constructor(
    private readonly client: MeshNodeClient,
    private readonly publicClient: MeshNodeClient,
  ) {}

  async list(orgId: string, networkId: string): Promise<MeshNode[]> {
    const nodes: MeshNode[] = [];
    let pageToken = "";
    do {
      const response = await connectCall(() =>
        this.client.listMeshNodes({ orgId, networkId, pageToken }),
      );
      nodes.push(...response.nodes.map(fromProtoNode));
      pageToken = response.nextPageToken;
    } while (pageToken !== "");
    return nodes;
  }

  async revoke(
    orgId: string,
    networkId: string,
    nodeName: string,
  ): Promise<void> {
    await connectCall(() =>
      this.client.revokeMeshNode({ orgId, networkId, nodeName }),
    );
  }

  async createEnrollment(
    orgId: string,
    networkId: string,
    nodeName: string,
    opts: MeshTTL = {},
  ): Promise<MeshEnrollment> {
    const response = await connectCall(() =>
      this.client.createMeshNodeEnrollment({
        orgId,
        networkId,
        nodeName,
        ttl: durationFromMilliseconds("enrollment ttl", opts.ttlMs),
      }),
    );
    return fromProtoEnrollment(
      required("created enrollment", response.enrollment),
      response.enrollmentCode,
    );
  }

  /** Consume a one-use capability without sending a bearer. */
  async redeemEnrollment(
    enrollmentCode: string,
    nodeName: string,
  ): Promise<MeshNodeRegistration> {
    const response = await connectCall(() =>
      this.publicClient.redeemMeshNodeEnrollment({
        enrollmentCode,
        nodeName,
      }),
    );
    return {
      node: fromProtoNode(required("redeemed node", response.node)),
      enrollment: fromProtoEnrollment(
        required("redeemed enrollment", response.enrollment),
        "",
      ),
    };
  }
}

export class MeshGroupsService {
  constructor(private readonly client: MeshGroupClient) {}

  async create(
    orgId: string,
    networkId: string,
    name: string,
  ): Promise<MeshGroup> {
    const response = await connectCall(() =>
      this.client.createMeshGroup({ orgId, networkId, name }),
    );
    return fromProtoGroup(required("created group", response.group));
  }

  async list(orgId: string, networkId: string): Promise<MeshGroup[]> {
    const groups: MeshGroup[] = [];
    let pageToken = "";
    do {
      const response = await connectCall(() =>
        this.client.listMeshGroups({ orgId, networkId, pageToken }),
      );
      groups.push(...response.groups.map(fromProtoGroup));
      pageToken = response.nextPageToken;
    } while (pageToken !== "");
    return groups;
  }

  async get(
    orgId: string,
    networkId: string,
    name: string,
  ): Promise<MeshGroup> {
    const response = await connectCall(() =>
      this.client.getMeshGroup({ orgId, networkId, groupName: name }),
    );
    return fromProtoGroup(required("group", response.group));
  }

  async delete(
    orgId: string,
    networkId: string,
    name: string,
  ): Promise<void> {
    await connectCall(() =>
      this.client.deleteMeshGroup({ orgId, networkId, groupName: name }),
    );
  }

  async addMember(
    orgId: string,
    networkId: string,
    groupName: string,
    nodeName: string,
    sessionName: string,
  ): Promise<MeshGroupMember> {
    const response = await connectCall(() =>
      this.client.addMeshGroupMember({
        orgId,
        networkId,
        groupName,
        nodeName,
        sessionName,
      }),
    );
    return fromProtoGroupMember(required("group member", response.member));
  }

  async removeMember(
    orgId: string,
    networkId: string,
    groupName: string,
    nodeName: string,
    sessionName: string,
  ): Promise<void> {
    await connectCall(() =>
      this.client.removeMeshGroupMember({
        orgId,
        networkId,
        groupName,
        nodeName,
        sessionName,
      }),
    );
  }

  async setPolicy(
    orgId: string,
    networkId: string,
    groupName: string,
    messagesPolicy: MeshGroupMessagesPolicy,
    debugPolicy: MeshGroupDebugPolicy,
  ): Promise<MeshGroupPolicy> {
    const response = await connectCall(() =>
      this.client.setMeshGroupPolicy({
        orgId,
        networkId,
        groupName,
        messagesPolicy: toProtoMessagesPolicy(messagesPolicy),
        debugPolicy: toProtoDebugPolicy(debugPolicy),
      }),
    );
    return fromProtoGroupPolicy(required("group policy", response.policy));
  }
}

export class MeshKVService {
  constructor(private readonly client: MeshKeyValueClient) {}

  async set(
    orgId: string,
    networkId: string,
    namespace: string,
    key: string,
    value: Uint8Array | string,
    opts: MeshTTL = {},
  ): Promise<MeshKVEntry> {
    const response = await connectCall(() =>
      this.client.setMeshKeyValue({
        orgId,
        networkId,
        namespace,
        key,
        value:
          typeof value === "string" ? new TextEncoder().encode(value) : value,
        ttl: durationFromMilliseconds("key value ttl", opts.ttlMs),
      }),
    );
    return fromProtoKeyValue(required("set key value", response.entry));
  }

  async get(
    orgId: string,
    networkId: string,
    namespace: string,
    key: string,
  ): Promise<MeshKVEntry> {
    const response = await connectCall(() =>
      this.client.getMeshKeyValue({ orgId, networkId, namespace, key }),
    );
    return fromProtoKeyValue(required("key value", response.entry));
  }

  async list(
    orgId: string,
    networkId: string,
    namespace: string,
    prefix = "",
  ): Promise<MeshKVEntry[]> {
    const entries: MeshKVEntry[] = [];
    let pageToken = "";
    do {
      const response = await connectCall(() =>
        this.client.listMeshKeyValues({
          orgId,
          networkId,
          namespace,
          prefix,
          pageToken,
        }),
      );
      entries.push(...response.entries.map(fromProtoKeyValue));
      pageToken = response.nextPageToken;
    } while (pageToken !== "");
    return entries;
  }

  async delete(
    orgId: string,
    networkId: string,
    namespace: string,
    key: string,
  ): Promise<void> {
    await connectCall(() =>
      this.client.deleteMeshKeyValue({ orgId, networkId, namespace, key }),
    );
  }
}

// -- Client -------------------------------------------------------------------

export class MeshClient {
  readonly networks: MeshNetworksService;
  readonly nodes: MeshNodesService;
  readonly groups: MeshGroupsService;
  readonly kv: MeshKVService;

  constructor(
    meshUrl: string,
    authToken: string,
    opts: MeshClientOptions = {},
  ) {
    const baseUrl = meshUrl.replace(/\/$/, "");
    const bearerInterceptor: Interceptor = (next) => async (request) => {
      request.header.set("Authorization", `Bearer ${authToken}`);
      return next(request);
    };
    const transport = createConnectTransport({
      baseUrl,
      defaultTimeoutMs: opts.timeout ?? 30_000,
      fetch: opts.fetch,
      interceptors: [bearerInterceptor],
      useBinaryFormat: false,
    });
    const publicTransport = createConnectTransport({
      baseUrl,
      defaultTimeoutMs: opts.timeout ?? 30_000,
      fetch: opts.fetch,
      useBinaryFormat: false,
    });
    this.networks = new MeshNetworksService(
      createClient(ProtoMeshNetworkService, transport),
    );
    this.nodes = new MeshNodesService(
      createClient(ProtoMeshNodeService, transport),
      createClient(ProtoMeshNodeService, publicTransport),
    );
    this.groups = new MeshGroupsService(
      createClient(ProtoMeshGroupService, transport),
    );
    this.kv = new MeshKVService(
      createClient(ProtoMeshKeyValueService, transport),
    );
  }
}
