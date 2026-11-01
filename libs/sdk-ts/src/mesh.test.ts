import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { Code, ConnectError, createConnectRouter } from "@connectrpc/connect";
import {
  MeshGroupDebugPolicy,
  MeshGroupService,
  MeshGroupMessagesPolicy,
} from "@codewire/proto-ts/gen/codewire/v1/mesh_group_pb";
import { MeshKeyValueService } from "@codewire/proto-ts/gen/codewire/v1/mesh_kv_pb";
import { MeshNetworkService } from "@codewire/proto-ts/gen/codewire/v1/mesh_network_pb";
import { MeshNodeService } from "@codewire/proto-ts/gen/codewire/v1/mesh_node_pb";
import { MeshClient, assertMeshConverterCoverage } from "./mesh.js";
import { CodewireError } from "./types.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, message: string) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${message}`);
  }
}

const orgId = "org-exact";
const networkId = "network-exact";
const createdAt = { seconds: 1_775_000_000n, nanos: 0 };
const updatedAt = { seconds: 1_775_003_600n, nanos: 0 };
const expiresAt = { seconds: 1_775_086_400n, nanos: 0 };
const redeemedAt = { seconds: 1_775_007_200n, nanos: 0 };
const calls = new Set<string>();

function requestHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value !== undefined) {
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
  }
  return headers;
}

function record(
  operation: string,
  context: { requestHeader: Headers },
  requestOrgId: string,
  requestNetworkId?: string,
) {
  calls.add(operation);
  assert(
    context.requestHeader.get("authorization") === "Bearer cw_mesh_test",
    `${operation} uses the product bearer`,
  );
  assert(requestOrgId === orgId, `${operation} uses the exact organization`);
  if (requestNetworkId !== undefined) {
    assert(
      requestNetworkId === networkId,
      `${operation} uses the exact network`,
    );
  }
}

const network = (id: string) => ({
  id,
  orgId,
  createdAt,
  nodeCount: 7n,
  inviteCount: 3n,
});
const node = (name: string) => ({
  orgId,
  networkId,
  name,
  peerUrl: `https://peer.example/${name}`,
  connected: true,
  lastSeenAt: createdAt,
});
const member = () => ({
  orgId,
  networkId,
  groupName: "group-one",
  nodeName: "node-one",
  sessionName: "session-one",
  createdAt,
});
const policy = (
  messagesPolicy: MeshGroupMessagesPolicy,
  debugPolicy: MeshGroupDebugPolicy,
) => ({
  orgId,
  networkId,
  groupName: "group-one",
  messagesPolicy,
  debugPolicy,
  updatedAt,
});
const group = (
  name: string,
  messagesPolicy = MeshGroupMessagesPolicy.OPEN,
  debugPolicy = MeshGroupDebugPolicy.FULL,
) => ({
  orgId,
  networkId,
  name,
  createdAt,
  createdByUserId: "creator-user",
  members: [member()],
  policy: policy(messagesPolicy, debugPolicy),
});
const entry = (key: string) => ({
  orgId,
  networkId,
  namespace: "namespace-one",
  key,
  value: new Uint8Array([0, 1, 2, 255]),
  expiresAt,
});

const router = createConnectRouter({
  connect: true,
  grpc: false,
  grpcWeb: false,
});
router.service(MeshNetworkService, {
  createMeshNetwork: (request, context) => {
    record("CreateMeshNetwork", context, request.orgId);
    if (request.networkId === "reject-me") {
      throw new ConnectError("invalid network", Code.InvalidArgument);
    }
    assert(
      request.networkId === networkId,
      "CreateMeshNetwork uses the exact network ID",
    );
    return { network: network(request.networkId) };
  },
  deleteMeshNetwork: (request, context) => {
    record("DeleteMeshNetwork", context, request.orgId, request.networkId);
    return {};
  },
  listMeshNetworks: (request, context) => {
    record("ListMeshNetworks", context, request.orgId);
    if (request.pageToken === "") {
      return {
        networks: [network("network-one")],
        nextPageToken: "network-page-two",
      };
    }
    assert(
      request.pageToken === "network-page-two",
      "ListMeshNetworks forwards the page token",
    );
    return { networks: [network("network-two")] };
  },
  joinMeshNetwork: () => {
    throw new ConnectError("not exercised by WI-7B", Code.Unimplemented);
  },
});
router.service(MeshNodeService, {
  listMeshNodes: (request, context) => {
    record("ListMeshNodes", context, request.orgId, request.networkId);
    if (request.pageToken === "") {
      return { nodes: [node("node-one")], nextPageToken: "node-page-two" };
    }
    assert(
      request.pageToken === "node-page-two",
      "ListMeshNodes forwards the page token",
    );
    return { nodes: [node("node-two")] };
  },
  revokeMeshNode: (request, context) => {
    record("RevokeMeshNode", context, request.orgId, request.networkId);
    assert(request.nodeName === "node-one", "RevokeMeshNode uses the node name");
    return {};
  },
  createMeshNodeEnrollment: (request, context) => {
    record(
      "CreateMeshNodeEnrollment",
      context,
      request.orgId,
      request.networkId,
    );
    assert(
      request.nodeName === "node-one",
      "CreateMeshNodeEnrollment uses the node name",
    );
    assert(
      request.ttl?.seconds === 1_020n && request.ttl.nanos === 0,
      "CreateMeshNodeEnrollment maps milliseconds to Duration",
    );
    return {
      enrollment: {
        id: "enrollment-one",
        orgId,
        networkId,
        nodeName: "node-one",
        ownerUserId: "owner-user",
        issuedByUserId: "issuer-user",
        expiresAt,
        createdAt,
        redeemedAt,
      },
      enrollmentCode: "secret-one-use-code",
    };
  },
  redeemMeshNodeEnrollment: (request, context) => {
    calls.add("RedeemMeshNodeEnrollment");
    assert(
      context.requestHeader.get("authorization") === null,
      "RedeemMeshNodeEnrollment sends no bearer",
    );
    assert(
      request.enrollmentCode === "one-use-token" &&
        request.nodeName === "node-one",
      "RedeemMeshNodeEnrollment uses the exact capability and node name",
    );
    return {
      node: node("node-one"),
      enrollment: {
        id: "enrollment-one",
        orgId,
        networkId,
        nodeName: "node-one",
        ownerUserId: "owner-user",
        issuedByUserId: "issuer-user",
        expiresAt,
        createdAt,
        redeemedAt,
      },
    };
  },
});
router.service(MeshGroupService, {
  createMeshGroup: (request, context) => {
    record("CreateMeshGroup", context, request.orgId, request.networkId);
    assert(request.name === "group-one", "CreateMeshGroup uses the group name");
    return { group: group(request.name) };
  },
  listMeshGroups: (request, context) => {
    record("ListMeshGroups", context, request.orgId, request.networkId);
    if (request.pageToken === "") {
      return {
        groups: [
          group(
            "group-one",
            MeshGroupMessagesPolicy.OPEN,
            MeshGroupDebugPolicy.FULL,
          ),
        ],
        nextPageToken: "group-page-two",
      };
    }
    assert(
      request.pageToken === "group-page-two",
      "ListMeshGroups forwards the page token",
    );
    return {
      groups: [
        group(
          "group-two",
          MeshGroupMessagesPolicy.INTERNAL_ONLY,
          MeshGroupDebugPolicy.NONE,
        ),
        group(
          "group-three",
          MeshGroupMessagesPolicy.UNSPECIFIED,
          MeshGroupDebugPolicy.OBSERVE_ONLY,
        ),
        group(
          "group-four",
          MeshGroupMessagesPolicy.OPEN,
          MeshGroupDebugPolicy.UNSPECIFIED,
        ),
      ],
    };
  },
  getMeshGroup: (request, context) => {
    record("GetMeshGroup", context, request.orgId, request.networkId);
    return { group: group(request.groupName) };
  },
  deleteMeshGroup: (request, context) => {
    record("DeleteMeshGroup", context, request.orgId, request.networkId);
    assert(
      request.groupName === "group-one",
      "DeleteMeshGroup uses the group name",
    );
    return {};
  },
  addMeshGroupMember: (request, context) => {
    record("AddMeshGroupMember", context, request.orgId, request.networkId);
    assert(
      request.groupName === "group-one" &&
        request.nodeName === "node-one" &&
        request.sessionName === "session-one",
      "AddMeshGroupMember uses the exact member identity",
    );
    return { member: member() };
  },
  removeMeshGroupMember: (request, context) => {
    record("RemoveMeshGroupMember", context, request.orgId, request.networkId);
    assert(
      request.groupName === "group-one" &&
        request.nodeName === "node-one" &&
        request.sessionName === "session-one",
      "RemoveMeshGroupMember uses the exact member identity",
    );
    return {};
  },
  setMeshGroupPolicy: (request, context) => {
    record("SetMeshGroupPolicy", context, request.orgId, request.networkId);
    return {
      policy: policy(request.messagesPolicy, request.debugPolicy),
    };
  },
});
router.service(MeshKeyValueService, {
  setMeshKeyValue: (request, context) => {
    record("SetMeshKeyValue", context, request.orgId, request.networkId);
    assert(
      request.namespace === "namespace-one" && request.key === "key-one",
      "SetMeshKeyValue uses the exact key identity",
    );
    assert(
      request.value.join(",") === "0,1,2,255",
      "SetMeshKeyValue preserves binary values",
    );
    assert(
      request.ttl?.seconds === 23n && request.ttl.nanos === 0,
      "SetMeshKeyValue maps milliseconds to Duration",
    );
    return { entry: entry(request.key) };
  },
  getMeshKeyValue: (request, context) => {
    record("GetMeshKeyValue", context, request.orgId, request.networkId);
    return { entry: entry(request.key) };
  },
  listMeshKeyValues: (request, context) => {
    record("ListMeshKeyValues", context, request.orgId, request.networkId);
    assert(
      request.namespace === "namespace-one" && request.prefix === "key",
      "ListMeshKeyValues uses the exact namespace and prefix",
    );
    if (request.pageToken === "") {
      return {
        entries: [entry("key-one")],
        nextPageToken: "kv-page-two",
      };
    }
    assert(
      request.pageToken === "kv-page-two",
      "ListMeshKeyValues forwards the page token",
    );
    return { entries: [entry("key-two")] };
  },
  deleteMeshKeyValue: (request, context) => {
    record("DeleteMeshKeyValue", context, request.orgId, request.networkId);
    return {};
  },
});

async function* rawBody(req: IncomingMessage): AsyncIterable<Uint8Array> {
  for await (const chunk of req) {
    yield chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
  }
}

async function handleConnectRequest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
): Promise<boolean> {
  const handler = router.handlers.find(
    (candidate) => candidate.requestPath === url.pathname,
  );
  if (!handler) return false;
  const response = await handler({
    body: rawBody(req),
    header: requestHeaders(req),
    httpVersion: "1.1",
    method: req.method ?? "POST",
    signal: new AbortController().signal,
    url: url.toString(),
  });
  res.writeHead(response.status, Object.fromEntries(response.header ?? []));
  if (response.body) {
    for await (const chunk of response.body) res.write(chunk);
  }
  res.end();
  return true;
}

const server = createServer(
  async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url!, `http://${req.headers.host}`);
    if (await handleConnectRequest(req, res, url)) return;
    res.writeHead(404);
    res.end();
  },
);

await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
if (!address || typeof address === "string") {
  throw new Error("Mesh test server did not bind a TCP port");
}
const baseUrl = `http://127.0.0.1:${address.port}`;

try {
  assertMeshConverterCoverage();
  const client = new MeshClient(baseUrl, "cw_mesh_test");

  const createdNetwork = await client.networks.create(orgId, networkId);
  assert(
    JSON.stringify(createdNetwork) ===
      JSON.stringify({
        id: networkId,
        org_id: orgId,
        created_at: "2026-03-31T23:33:20Z",
        node_count: 7,
        invite_count: 3,
      }),
    "network conversion preserves every field",
  );
  const networks = await client.networks.list(orgId);
  assert(
    networks.length === 2 && networks[1]?.id === "network-two",
    "network listing follows pagination",
  );

  const nodes = await client.nodes.list(orgId, networkId);
  assert(
    JSON.stringify(nodes[0]) ===
      JSON.stringify({
        org_id: orgId,
        network_id: networkId,
        name: "node-one",
        peer_url: "https://peer.example/node-one",
        connected: true,
        last_seen_at: "2026-03-31T23:33:20Z",
      }),
    "node conversion preserves every field",
  );
  assert(nodes.length === 2, "node listing follows pagination");
  await client.nodes.revoke(orgId, networkId, "node-one");
  const enrollment = await client.nodes.createEnrollment(
    orgId,
    networkId,
    "node-one",
    { ttlMs: 17 * 60 * 1_000 },
  );
  assert(
    enrollment.id === "enrollment-one" &&
      enrollment.org_id === orgId &&
      enrollment.network_id === networkId &&
      enrollment.node_name === "node-one" &&
      enrollment.owner_user_id === "owner-user" &&
      enrollment.issued_by_user_id === "issuer-user" &&
      enrollment.expires_at !== "" &&
      enrollment.created_at !== "" &&
      enrollment.redeemed_at !== undefined &&
      enrollment.enrollment_code === "secret-one-use-code",
    "enrollment conversion preserves every field and one-use code",
  );

  const createdGroup = await client.groups.create(
    orgId,
    networkId,
    "group-one",
  );
  assert(
    createdGroup.org_id === orgId &&
      createdGroup.network_id === networkId &&
      createdGroup.name === "group-one" &&
      createdGroup.created_at !== "" &&
      createdGroup.created_by_user_id === "creator-user" &&
      createdGroup.members.length === 1 &&
      createdGroup.policy?.updated_at !== "",
    "group conversion preserves every field",
  );
  const groups = await client.groups.list(orgId, networkId);
  assert(groups.length === 4, "group listing follows pagination");
  assert(
    JSON.stringify(
      groups.map((item) => [
        item.policy?.messages_policy,
        item.policy?.debug_policy,
      ]),
    ) ===
      JSON.stringify([
        ["open", "full"],
        ["internal-only", "none"],
        ["", "observe-only"],
        ["open", ""],
      ]),
    "group conversion covers every enum value",
  );
  const gotGroup = await client.groups.get(orgId, networkId, "group-one");
  assert(gotGroup.name === "group-one", "get group returns the converted group");
  await client.groups.delete(orgId, networkId, "group-one");
  const addedMember = await client.groups.addMember(
    orgId,
    networkId,
    "group-one",
    "node-one",
    "session-one",
  );
  assert(
    addedMember.org_id === orgId &&
      addedMember.network_id === networkId &&
      addedMember.group_name === "group-one" &&
      addedMember.node_name === "node-one" &&
      addedMember.session_name === "session-one" &&
      addedMember.created_at !== "",
    "group member conversion preserves every field",
  );
  await client.groups.removeMember(
    orgId,
    networkId,
    "group-one",
    "node-one",
    "session-one",
  );
  for (const [messagesPolicy, debugPolicy] of [
    ["", ""],
    ["internal-only", "none"],
    ["open", "observe-only"],
    ["open", "full"],
  ] as const) {
    const converted = await client.groups.setPolicy(
      orgId,
      networkId,
      "group-one",
      messagesPolicy,
      debugPolicy,
    );
    assert(
      converted.org_id === orgId &&
        converted.network_id === networkId &&
        converted.group_name === "group-one" &&
        converted.messages_policy === messagesPolicy &&
        converted.debug_policy === debugPolicy &&
        converted.updated_at !== "",
      `group policy round-trips ${messagesPolicy || "unspecified"}/${debugPolicy || "unspecified"}`,
    );
  }
  try {
    await client.groups.setPolicy(
      orgId,
      networkId,
      "group-one",
      "invalid" as never,
      "none",
    );
    assert(false, "invalid group policy should fail locally");
  } catch {
    assert(true, "invalid group policy fails locally");
  }

  const setEntry = await client.kv.set(
    orgId,
    networkId,
    "namespace-one",
    "key-one",
    new Uint8Array([0, 1, 2, 255]),
    { ttlMs: 23_000 },
  );
  assert(
    setEntry.org_id === orgId &&
      setEntry.network_id === networkId &&
      setEntry.namespace === "namespace-one" &&
      setEntry.key === "key-one" &&
      setEntry.value.join(",") === "0,1,2,255" &&
      setEntry.expires_at !== undefined,
    "key value conversion preserves every field",
  );
  const gotEntry = await client.kv.get(
    orgId,
    networkId,
    "namespace-one",
    "key-one",
  );
  assert(gotEntry.key === "key-one", "get key value returns the converted entry");
  const entries = await client.kv.list(
    orgId,
    networkId,
    "namespace-one",
    "key",
  );
  assert(entries.length === 2, "key value listing follows pagination");
  await client.kv.delete(
    orgId,
    networkId,
    "namespace-one",
    "key-one",
  );

  try {
    await client.networks.create(orgId, "reject-me");
    assert(false, "Connect error should map to CodewireError");
  } catch (error) {
    assert(
      error instanceof CodewireError &&
        error.status === 400 &&
        error.detail === "invalid network",
      "Connect error uses the canonical SDK error mapping",
    );
  }

  const registration = await client.nodes.redeemEnrollment(
    "one-use-token",
    "node-one",
  );
  assert(
    registration.node.org_id === orgId &&
      registration.node.network_id === networkId &&
      registration.node.name === "node-one" &&
      registration.enrollment.id === "enrollment-one" &&
      registration.enrollment.enrollment_code === "",
    "generated redemption returns credential-free node and enrollment metadata",
  );
  await client.networks.delete(orgId, networkId);

  const expectedOperations = [
    "AddMeshGroupMember",
    "CreateMeshGroup",
    "CreateMeshNetwork",
    "CreateMeshNodeEnrollment",
    "DeleteMeshGroup",
    "DeleteMeshKeyValue",
    "DeleteMeshNetwork",
    "GetMeshGroup",
    "GetMeshKeyValue",
    "ListMeshGroups",
    "ListMeshKeyValues",
    "ListMeshNetworks",
    "ListMeshNodes",
    "RedeemMeshNodeEnrollment",
    "RemoveMeshGroupMember",
    "RevokeMeshNode",
    "SetMeshGroupPolicy",
    "SetMeshKeyValue",
  ];
  assert(
    JSON.stringify([...calls].sort()) === JSON.stringify(expectedOperations),
    `generated clients cover exactly the eighteen mounted Mesh operations: got ${JSON.stringify([...calls].sort())}`,
  );
} finally {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}

if (failed > 0) process.exitCode = 1;
console.log(`${passed} passed, ${failed} failed`);
