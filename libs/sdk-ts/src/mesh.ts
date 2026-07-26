// Mesh API client for the Codewire TypeScript SDK.
//
// Mirrors the Go `codewire.MeshClient` surface: Networks, Nodes, Groups,
// Credentials, and KV. The mesh speaks its own HTTP API distinct from the
// platform — construct with `new MeshClient(meshUrl, authToken)`.

import { CodewireError } from "./types.js";

// -- Types --------------------------------------------------------------------

export interface MeshNetwork {
  id: string;
  created_at: string;
  node_count: number;
  invite_count: number;
}

export interface MeshNode {
  name: string;
  network_id?: string;
  peer_url?: string;
  connected: boolean;
}

export interface MeshEnrollment {
  id: string;
  network_id: string;
  enrollment_token: string;
  uses_remaining: number;
  expires_at: string;
  node_name?: string;
}

export interface MeshNodeCredentials {
  node_token: string;
  node_name: string;
  network_id: string;
  enrollment_id?: string;
}

export interface MeshKVEntry {
  key: string;
  value?: string;
}

export interface MeshGroupMember {
  network_id: string;
  group_name: string;
  node_name: string;
  session_name: string;
  created_at: string;
}

export interface MeshGroupPolicy {
  network_id: string;
  group_name: string;
  messages_policy: string;
  debug_policy: string;
}

export interface MeshGroup {
  network_id: string;
  name: string;
  created_at: string;
  created_by?: string;
  members?: MeshGroupMember[];
  policy?: MeshGroupPolicy;
}

export interface MeshRuntimeCredential {
  credential: string;
  network_id: string;
  subject_kind: string;
  subject_id: string;
  expires_at: string;
}

export interface MeshVerifierKey {
  key_id: string;
  algorithm: string;
  public_key: string;
}

export interface MeshVerifierBundle {
  network_id: string;
  issuer: string;
  keys: MeshVerifierKey[];
  version: number;
  expires_at: string;
}

export interface MeshSenderDelegation {
  delegation: string;
  network_id: string;
  source_node: string;
  expires_at: string;
  from_session_id?: number;
  from_session_name?: string;
  audience_node?: string;
}

export interface MeshClientOptions {
  /** Request timeout in milliseconds. Default 30_000. */
  timeout?: number;
  /** Custom fetch implementation; defaults to global `fetch`. */
  fetch?: typeof fetch;
}

// -- HTTP plumbing ------------------------------------------------------------

type RequestOptions = {
  body?: unknown;
  rawBody?: BodyInit;
  token?: string | null; // null => no auth; undefined => default client token
  extraHeaders?: Record<string, string>;
  contentType?: string;
};

class MeshHttp {
  constructor(
    private readonly baseUrl: string,
    private readonly authToken: string,
    private readonly timeout: number,
    private readonly fetchImpl: typeof fetch,
  ) {}

  async request(
    method: string,
    path: string,
    opts: RequestOptions = {},
  ): Promise<Response> {
    const headers: Record<string, string> = { ...(opts.extraHeaders ?? {}) };
    const bearer =
      opts.token === undefined
        ? this.authToken
        : opts.token === null
          ? ""
          : opts.token;
    if (bearer) headers["Authorization"] = `Bearer ${bearer}`;
    let body: BodyInit | undefined;
    if (opts.rawBody !== undefined) {
      body = opts.rawBody;
      if (opts.contentType) headers["Content-Type"] = opts.contentType;
    } else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers["Content-Type"] = "application/json";
    }

    const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(this.timeout),
    });
    if (!res.ok) {
      const detail = (await safeText(res)) || res.statusText;
      throw new CodewireError(
        res.status,
        detail,
        res.headers.get("x-request-id") ?? undefined,
      );
    }
    return res;
  }

  async json<T>(
    method: string,
    path: string,
    opts: RequestOptions = {},
  ): Promise<T | undefined> {
    const res = await this.request(method, path, opts);
    if (res.status === 204) return undefined;
    const text = await res.text();
    if (!text) return undefined;
    return JSON.parse(text) as T;
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return (await res.text()).trim();
  } catch {
    return "";
  }
}

function q(s: string): string {
  return encodeURIComponent(s);
}

// -- Services -----------------------------------------------------------------

export class MeshNetworksService {
  constructor(private readonly http: MeshHttp) {}

  /** Create or claim a network. */
  async create(networkId: string): Promise<void> {
    await this.http.request("POST", "/api/v1/networks", {
      body: { network_id: networkId },
    });
  }

  /** List all networks the authenticated user is a member of. */
  async list(): Promise<MeshNetwork[]> {
    return (
      (await this.http.json<MeshNetwork[]>("GET", "/api/v1/networks")) ?? []
    );
  }
}

export class MeshNodesService {
  constructor(private readonly http: MeshHttp) {}

  async list(networkId: string): Promise<MeshNode[]> {
    return (
      (await this.http.json<MeshNode[]>(
        "GET",
        `/api/v1/nodes?network_id=${q(networkId)}`,
      )) ?? []
    );
  }

  async revoke(networkId: string, nodeName: string): Promise<void> {
    await this.http.request(
      "DELETE",
      `/api/v1/nodes/${q(nodeName)}?network_id=${q(networkId)}`,
    );
  }

  async createEnrollment(
    networkId: string,
    nodeName: string,
    opts: { uses?: number; ttl?: string } = {},
  ): Promise<MeshEnrollment> {
    const body: Record<string, unknown> = {
      network_id: networkId,
      node_name: nodeName,
      uses: opts.uses ?? 1,
    };
    if (opts.ttl) body.ttl = opts.ttl;
    return (await this.http.json<MeshEnrollment>(
      "POST",
      "/api/v1/node-enrollments",
      { body },
    ))!;
  }

  /** Public endpoint (no auth) — redeem an enrollment token to register a node. */
  async redeemEnrollment(
    enrollmentToken: string,
    nodeName: string,
  ): Promise<MeshNodeCredentials> {
    return (await this.http.json<MeshNodeCredentials>(
      "POST",
      "/api/v1/node-enrollments/redeem",
      {
        body: { enrollment_token: enrollmentToken, node_name: nodeName },
        token: null,
      },
    ))!;
  }
}

export class MeshGroupsService {
  constructor(private readonly http: MeshHttp) {}

  async create(networkId: string, name: string): Promise<MeshGroup> {
    return (await this.http.json<MeshGroup>("POST", "/api/v1/groups", {
      body: { network_id: networkId, name },
    }))!;
  }

  async list(networkId: string): Promise<MeshGroup[]> {
    return (
      (await this.http.json<MeshGroup[]>(
        "GET",
        `/api/v1/groups?network_id=${q(networkId)}`,
      )) ?? []
    );
  }

  async get(networkId: string, name: string): Promise<MeshGroup> {
    return (await this.http.json<MeshGroup>(
      "GET",
      `/api/v1/groups/${q(name)}?network_id=${q(networkId)}`,
    ))!;
  }

  async delete(networkId: string, name: string): Promise<void> {
    await this.http.request(
      "DELETE",
      `/api/v1/groups/${q(name)}?network_id=${q(networkId)}`,
    );
  }

  async addMember(
    networkId: string,
    groupName: string,
    nodeName: string,
    sessionName: string,
  ): Promise<MeshGroupMember> {
    return (await this.http.json<MeshGroupMember>(
      "POST",
      `/api/v1/groups/${q(groupName)}/members`,
      {
        body: {
          network_id: networkId,
          node_name: nodeName,
          session_name: sessionName,
        },
      },
    ))!;
  }

  async removeMember(
    networkId: string,
    groupName: string,
    nodeName: string,
    sessionName: string,
  ): Promise<void> {
    const path =
      `/api/v1/groups/${q(groupName)}/members` +
      `?network_id=${q(networkId)}` +
      `&node_name=${q(nodeName)}` +
      `&session_name=${q(sessionName)}`;
    await this.http.request("DELETE", path);
  }

  async setPolicy(
    networkId: string,
    groupName: string,
    messagesPolicy: string,
    debugPolicy: string,
  ): Promise<MeshGroupPolicy> {
    return (await this.http.json<MeshGroupPolicy>(
      "PUT",
      `/api/v1/groups/${q(groupName)}/policy`,
      {
        body: {
          network_id: networkId,
          messages_policy: messagesPolicy,
          debug_policy: debugPolicy,
        },
      },
    ))!;
  }
}

export class MeshCredentialsService {
  constructor(private readonly http: MeshHttp) {}

  async issueRuntimeCredential(
    networkId: string,
  ): Promise<MeshRuntimeCredential> {
    return (await this.http.json<MeshRuntimeCredential>(
      "POST",
      `/api/v1/network-auth/runtime/client?network_id=${q(networkId)}`,
    ))!;
  }

  async fetchVerifierBundle(networkId: string): Promise<MeshVerifierBundle> {
    return (await this.http.json<MeshVerifierBundle>(
      "GET",
      `/api/v1/network-auth/bundle?network_id=${q(networkId)}`,
    ))!;
  }

  /** Runtime credential issued under node auth instead of client auth. */
  async issueNodeRuntimeCredential(
    nodeToken: string,
  ): Promise<MeshRuntimeCredential> {
    return (await this.http.json<MeshRuntimeCredential>(
      "POST",
      "/api/v1/network-auth/runtime/node",
      { token: nodeToken },
    ))!;
  }

  async issueSenderDelegation(
    nodeToken: string,
    sourceNode: string,
    opts: {
      fromSessionId?: number;
      fromSessionName?: string;
      verbs?: string[];
      audienceNode?: string;
    } = {},
  ): Promise<MeshSenderDelegation> {
    const body: Record<string, unknown> = {
      source_node: sourceNode,
      verbs: opts.verbs ?? [],
    };
    if (opts.fromSessionId !== undefined)
      body.from_session_id = opts.fromSessionId;
    if (opts.fromSessionName) body.from_session_name = opts.fromSessionName;
    if (opts.audienceNode) body.audience_node = opts.audienceNode;
    return (await this.http.json<MeshSenderDelegation>(
      "POST",
      "/api/v1/network-auth/delegation/node",
      { body, token: nodeToken },
    ))!;
  }
}

export class MeshKVService {
  constructor(private readonly http: MeshHttp) {}

  async set(
    networkId: string,
    namespace: string,
    key: string,
    value: Uint8Array | string,
    opts: { ttl?: string } = {},
  ): Promise<void> {
    const path = `/api/v1/kv/${q(namespace)}/${q(key)}?network_id=${q(networkId)}`;
    const body: BodyInit =
      typeof value === "string" ? value : new Blob([value as BlobPart]);
    await this.http.request("PUT", path, {
      rawBody: body,
      contentType: "application/octet-stream",
      extraHeaders: opts.ttl ? { "X-TTL": opts.ttl } : undefined,
    });
  }

  async get(
    networkId: string,
    namespace: string,
    key: string,
  ): Promise<Uint8Array> {
    const path = `/api/v1/kv/${q(namespace)}/${q(key)}?network_id=${q(networkId)}`;
    const res = await this.http.request("GET", path);
    const buf = await res.arrayBuffer();
    return new Uint8Array(buf);
  }

  async list(
    networkId: string,
    namespace: string,
    prefix = "",
  ): Promise<MeshKVEntry[]> {
    const path =
      `/api/v1/kv/${q(namespace)}` +
      `?prefix=${q(prefix)}` +
      `&network_id=${q(networkId)}`;
    return (await this.http.json<MeshKVEntry[]>("GET", path)) ?? [];
  }

  async delete(
    networkId: string,
    namespace: string,
    key: string,
  ): Promise<void> {
    const path = `/api/v1/kv/${q(namespace)}/${q(key)}?network_id=${q(networkId)}`;
    await this.http.request("DELETE", path);
  }
}

// -- Client -------------------------------------------------------------------

export class MeshClient {
  readonly networks: MeshNetworksService;
  readonly nodes: MeshNodesService;
  readonly groups: MeshGroupsService;
  readonly credentials: MeshCredentialsService;
  readonly kv: MeshKVService;

  constructor(
    meshUrl: string,
    authToken: string,
    opts: MeshClientOptions = {},
  ) {
    const http = new MeshHttp(
      meshUrl.replace(/\/$/, ""),
      authToken,
      opts.timeout ?? 30_000,
      opts.fetch ?? fetch,
    );
    this.networks = new MeshNetworksService(http);
    this.nodes = new MeshNodesService(http);
    this.groups = new MeshGroupsService(http);
    this.credentials = new MeshCredentialsService(http);
    this.kv = new MeshKVService(http);
  }
}
