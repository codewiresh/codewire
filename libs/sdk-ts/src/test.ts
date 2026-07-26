import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { create } from "@bufbuild/protobuf";
import { DurationSchema } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createConnectRouter } from "@connectrpc/connect";
import { BadRequestSchema, ErrorInfoSchema } from "@codewire/proto-ts";
import { ApiKeySchema, ApiKeyService } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import {
  DesiredState,
  EnvironmentSchema,
  EnvironmentService,
  EnvironmentState,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { ExecResponseSchema, ExecService } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import { FileEntrySchema, FileService } from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import { PortAccess, PortSchema, PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { PresetSchema, PresetService } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import {
  SecretMetadataSchema,
  SecretProjectSchema,
  SecretService,
} from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { Codewire } from "./index.js";
import { Environment } from "./environment.js";
import { CodewireError } from "./types.js";
import {
  assertAPIKeyConverterCoverage,
  assertRuntimeConverterCoverage,
  fromProtoAPIKey,
  fromProtoEnvironment,
  fromProtoEnvironmentPort,
  fromProtoExecResult,
  fromProtoFileEntry,
  fromProtoPreset,
  fromProtoSecretMetadata,
  fromProtoSecretProject,
  numberFromInt64,
  pollIntervalMs,
} from "./convert.js";

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (!condition) {
    failed++;
    console.error(`  FAIL: ${msg}`);
  } else {
    passed++;
  }
}

function requestHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return headers;
}

async function runTests() {
  let waitReadyCounter = 0;
  let createWaitCounter = 0;
  let uploadHeaders = 0;
  let uploadedBytes = 0;

  const router = createConnectRouter({
    connect: true,
    grpc: false,
    grpcWeb: false,
  });
  router.service(ApiKeyService, {
    listApiKeys: (_request, context) => {
      if (context.requestHeader.get("authorization") !== "Bearer test-key") {
        throw new ConnectError("unauthorized", Code.Unauthenticated);
      }
      return {
        apiKeys: [
          {
            id: "key_1",
            userId: "user_1",
            orgId: "org_test",
            name: "test",
            keyPrefix: "cw_abc",
            scopes: [],
            createdAt: { seconds: 1_767_225_600n, nanos: 987_654_321 },
            createdByName: "Test User",
            createdByEmail: "test@example.com",
          },
        ],
      };
    },
    createApiKey: (request, context) => {
      if (context.requestHeader.get("authorization") !== "Bearer test-key") {
        throw new ConnectError("unauthorized", Code.Unauthenticated);
      }
      if (request.name === "invalid") {
        throw new ConnectError("invalid API key", Code.InvalidArgument, undefined, [
          {
            desc: BadRequestSchema,
            value: create(BadRequestSchema, {
              fieldViolations: [{ field: "name", description: "must not be blank" }],
            }),
          },
          {
            desc: ErrorInfoSchema,
            value: create(ErrorInfoSchema, { metadata: { request_id: "req_api_key" } }),
          },
        ]);
      }
      return {
        apiKey: {
          id: "key_1",
          userId: "user_1",
          orgId: request.orgId,
          name: request.name,
          keyPrefix: "cw_abc",
          scopes: request.scopes,
          createdAt: { seconds: 1_767_225_600n, nanos: 987_654_321 },
          createdByName: "Test User",
          createdByEmail: "test@example.com",
        },
        key: "cw_abc123",
      };
    },
    updateApiKey: (request, context) => {
      if (context.requestHeader.get("authorization") !== "Bearer test-key") {
        throw new ConnectError("unauthorized", Code.Unauthenticated);
      }
      return {
        apiKey: {
          id: request.keyId,
          userId: "user_1",
          orgId: request.orgId,
          name: "test",
          keyPrefix: "cw_abc",
          scopes: [],
          disabledAt: request.disabled ? { seconds: 1_767_225_600n } : undefined,
          createdAt: { seconds: 1_767_225_600n, nanos: 987_654_321 },
          createdByName: "Test User",
          createdByEmail: "test@example.com",
        },
      };
    },
    deleteApiKey: (request, context) => {
      if (context.requestHeader.get("authorization") !== "Bearer test-key") {
        throw new ConnectError("unauthorized", Code.Unauthenticated);
      }
      if (request.keyId === "missing") {
        throw new ConnectError("not found", Code.NotFound);
      }
      return {};
    },
  });

  const timestamp = { seconds: 1_767_225_600n, nanos: 987_654_321 };
  const environment = (id: string, state: EnvironmentState) => ({
    id,
    orgId: "org_test",
    createdBy: "user_1",
    presetId: "tmpl_1",
    type: "sandbox",
    state,
    desiredState: DesiredState.STARTED,
    protected: false,
    recoverable: true,
    setupComplete: false,
    setupPhase: 0,
    stateChangedAt: timestamp,
    cpuMillicores: 2000,
    memoryMb: 4096,
    diskGb: 20,
    totalRunningSeconds: 0,
    createdAt: timestamp,
    retryCount: 0,
  });
  const preset = (name = "Go", cpu = 2000) => ({
    id: "tmpl_1",
    orgId: "org_test",
    name,
    buildStatus: "ready",
    defaultCpuMillicores: cpu,
    defaultMemoryMb: 4096,
    defaultDiskGb: 20,
    official: false,
    createdAt: timestamp,
  });
  const requireTestKey = (context: { requestHeader: Headers }) => {
    if (context.requestHeader.get("authorization") !== "Bearer test-key") {
      throw new ConnectError("unauthorized", Code.Unauthenticated);
    }
  };

  router.service(EnvironmentService, {
    listEnvironments: (_request, context) => {
      requireTestKey(context);
      return {
        environments: [environment("env_123", EnvironmentState.RUNNING)],
        pollInterval: { seconds: 0n, nanos: 100_000_000 },
      };
    },
    createEnvironment: (request, context) => {
      requireTestKey(context);
      if (request.presetSlug === "wait-test") {
        return { environment: environment("env_cwait", EnvironmentState.PENDING) };
      }
      return { environment: environment("env_123", EnvironmentState.RUNNING) };
    },
    getEnvironment: (request, context) => {
      requireTestKey(context);
      if (request.environmentId === "env_nonexistent") {
        throw new ConnectError("not found", Code.NotFound);
      }
      if (request.environmentId === "env_wait") {
        waitReadyCounter++;
        return {
          environment: environment(
            "env_wait",
            waitReadyCounter >= 2 ? EnvironmentState.RUNNING : EnvironmentState.PENDING,
          ),
          pollInterval: { seconds: 0n, nanos: 100_000_000 },
        };
      }
      if (request.environmentId === "env_cwait") {
        createWaitCounter++;
        return {
          environment: environment(
            "env_cwait",
            createWaitCounter >= 2 ? EnvironmentState.RUNNING : EnvironmentState.PENDING,
          ),
          pollInterval: { seconds: 0n, nanos: 100_000_000 },
        };
      }
      return {
        environment: environment("env_123", EnvironmentState.RUNNING),
        pollInterval: { seconds: 0n, nanos: 100_000_000 },
      };
    },
    deleteEnvironment: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    stopEnvironment: (_request, context) => {
      requireTestKey(context);
      return { status: "ok" };
    },
    startEnvironment: (_request, context) => {
      requireTestKey(context);
      return { status: "ok" };
    },
  });

  router.service(ExecService, {
    exec: (_request, context) => {
      requireTestKey(context);
      return {
        exitCode: 0,
        stdout: new TextEncoder().encode("hello\n"),
        stderr: new Uint8Array(),
      };
    },
  });

  router.service(FileService, {
    listFiles: (_request, context) => {
      requireTestKey(context);
      return {
        entries: [
          {
            name: "main.go",
            size: 128n,
            isDir: false,
            mode: 0o644,
            modTime: timestamp,
          },
        ],
      };
    },
    async *downloadFile(_request, context) {
      requireTestKey(context);
      yield {
        payload: {
          case: "info" as const,
          value: {
            name: "main.go",
            size: 12n,
            isDir: false,
            mode: 0o644,
            modTime: timestamp,
          },
        },
      };
      yield {
        payload: {
          case: "chunk" as const,
          value: new TextEncoder().encode("file-content"),
        },
      };
    },
    async uploadFile(request, context) {
      requireTestKey(context);
      for await (const message of request) {
        if (message.payload.case === "header") {
          if (
            message.payload.value.orgId === "org_test" &&
            message.payload.value.environmentId === "env_123"
          ) {
            uploadHeaders++;
          }
        } else if (message.payload.case === "chunk") {
          uploadedBytes += message.payload.value.byteLength;
        }
      }
      return { path: "/workspace/uploaded", size: 3n };
    },
  });

  router.service(PortService, {
    listPorts: (_request, context) => {
      requireTestKey(context);
      return {
        ports: [
          {
            id: "port_1",
            environmentId: "env_123",
            port: 8080,
            label: "web",
            access: PortAccess.PUBLIC,
            createdAt: timestamp,
          },
        ],
      };
    },
    createPort: (request, context) => {
      requireTestKey(context);
      return {
        port: {
          id: "port_2",
          environmentId: request.environmentId,
          port: request.port,
          label: request.label,
          access: request.access,
          createdAt: timestamp,
        },
      };
    },
    deletePort: (_request, context) => {
      requireTestKey(context);
      return {};
    },
  });

  router.service(PresetService, {
    createPreset: (request, context) => {
      requireTestKey(context);
      return { preset: preset(request.name) };
    },
    listPresets: (_request, context) => {
      requireTestKey(context);
      return { presets: [preset()] };
    },
    getPreset: (_request, context) => {
      requireTestKey(context);
      return { preset: preset() };
    },
    updatePreset: (request, context) => {
      requireTestKey(context);
      return { preset: preset(request.name || "Go Updated", request.defaultCpuMillicores || 4000) };
    },
    deletePreset: (_request, context) => {
      requireTestKey(context);
      return {};
    },
  });

  router.service(SecretService, {
    listSecrets: (_request, context) => {
      requireTestKey(context);
      return { secrets: [{ key: "DB_URL" }] };
    },
    setSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    deleteSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    renameSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    listUserSecrets: (_request, context) => {
      requireTestKey(context);
      return { secrets: [{ key: "USER_TOKEN" }] };
    },
    setUserSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    deleteUserSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    renameUserSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    listSecretProjects: (_request, context) => {
      requireTestKey(context);
      return {
        secretProjects: [
          {
            id: "sp_1",
            orgId: "org_test",
            name: "my-project",
            secretCount: 1n,
            createdAt: timestamp,
          },
        ],
      };
    },
    createSecretProject: (request, context) => {
      requireTestKey(context);
      return {
        secretProject: {
          id: "sp_1",
          orgId: request.orgId,
          name: request.name,
          secretCount: 0n,
          createdAt: timestamp,
        },
      };
    },
    deleteSecretProject: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    listProjectSecrets: (_request, context) => {
      requireTestKey(context);
      return { secrets: [{ key: "PROJECT_KEY" }] };
    },
    setProjectSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    deleteProjectSecret: (_request, context) => {
      requireTestKey(context);
      return {};
    },
    renameProjectSecret: (_request, context) => {
      requireTestKey(context);
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

  assertAPIKeyConverterCoverage();
  assertRuntimeConverterCoverage();
  const convertedKey = fromProtoAPIKey(
    create(ApiKeySchema, {
      id: "key_1",
      userId: "user_1",
      orgId: "org_test",
      name: "test",
      keyPrefix: "cw_abc",
      scopes: ["read"],
      lastUsedAt: { seconds: 1_767_229_323n, nanos: 987_654_321 },
      expiresAt: { seconds: 1_798_765_323n, nanos: 123_456_789 },
      disabledAt: { seconds: 1_767_315_723n, nanos: 999_999_999 },
      createdAt: { seconds: 1_767_225_600n, nanos: 987_654_321 },
      createdByName: "Test User",
      createdByEmail: "test@example.com",
    }),
  );
  assert(convertedKey.created_at === "2026-01-01T00:00:00Z", "API key timestamps keep REST second precision");
  assert(convertedKey.last_used_at === "2026-01-01T01:02:03Z", "API key optional timestamps keep REST strings");
  assert(convertedKey.expires_at === "2027-01-01T01:02:03Z", "API key expiry timestamp keeps REST strings");
  assert(convertedKey.disabled_at === "2026-01-02T01:02:03Z", "API key disabled timestamp keeps REST strings");
  assert(numberFromInt64(2_000n) === 2000, "protobuf int64 conversion keeps SDK number values");

  const convertedEnvironment = fromProtoEnvironment(create(EnvironmentSchema, {
    ...environment("env_full", EnvironmentState.RUNNING),
    name: "full environment",
    network: "network_1",
    errorReason: "",
    setupError: "",
    ttlSeconds: 300,
    deletionGraceUntil: timestamp,
    deletionRequestedAt: timestamp,
    shutdownAt: timestamp,
    startedAt: timestamp,
    stoppedAt: timestamp,
    destroyedAt: timestamp,
    presetName: "Go",
    ports: [{
      id: "port_1",
      environmentId: "env_full",
      port: 8080,
      label: "web",
      access: PortAccess.ORG_MEMBERS,
      previewUrl: "https://preview.example.test",
      createdAt: timestamp,
    }],
  }));
  assert(convertedEnvironment.created_at === "2026-01-01T00:00:00Z", "environment timestamps keep REST second precision");
  assert(convertedEnvironment.cpu_millicores === 2000, "environment numbers keep SDK number values");
  assert(convertedEnvironment.desired_state === "started", "environment desired state preserves REST value");
  assert(convertedEnvironment.ports?.[0]?.access === "org_members", "environment ports preserve access values");
  assert(convertedEnvironment.ports?.[0]?.preview_url === "https://preview.example.test", "environment ports preserve optional URLs");
  assert(convertedEnvironment.ttl_seconds === 300, "environment optional numbers are retained");

  const convertedPort = fromProtoEnvironmentPort(create(PortSchema, {
    id: "port_2",
    environmentId: "env_full",
    port: 3000,
    label: "app",
    access: PortAccess.CREATOR,
    createdAt: timestamp,
  }));
  assert(convertedPort.access === "creator", "port access preserves creator visibility");
  assert(convertedPort.environment_id === "env_full", "port environment IDs preserve snake-case shape");

  const convertedExec = fromProtoExecResult(create(ExecResponseSchema, {
    exitCode: 7,
    stdout: new TextEncoder().encode("stdout"),
    stderr: new TextEncoder().encode("stderr"),
  }));
  assert(convertedExec.exit_code === 7, "exec exit codes retain number values");
  assert(convertedExec.stderr === "stderr", "exec bytes decode to REST strings");

  const convertedFile = fromProtoFileEntry(create(FileEntrySchema, {
    name: "main.go",
    size: 128n,
    isDir: false,
    mode: 0o100644,
    modTime: timestamp,
  }));
  assert(convertedFile.mode === "0644", "file modes keep REST octal strings");
  assert(convertedFile.size === 128, "file sizes convert int64 to numbers");
  assert(convertedFile.mod_time === "2026-01-01T00:00:00Z", "file times keep REST timestamps");

  const convertedPreset = fromProtoPreset(create(PresetSchema, {
    ...preset("Go", 4000),
    slug: "go",
    language: "go",
    description: "Go template",
    defaultTtlSeconds: 600,
    image: "golang:1.25",
    secretProjectId: "sp_1",
    defaultSetupConfig: {
      agent: "claude",
      agentEnv: { MODE: "test" },
      agents: [{ type: "claude" }],
      appPorts: [{ access: "public", label: "web", port: 8080 }],
      branch: "main",
      envVars: { GOFLAGS: "-mod=readonly" },
      includeOrgSecrets: true,
      includeUserSecrets: false,
      installAgents: true,
      installCommand: "go install",
      repoUrl: "https://git.example.test/org/repo",
      repos: [{ branch: "main", url: "https://git.example.test/org/repo" }],
      startupScript: "go test ./...",
    },
  }));
  assert(convertedPreset.default_cpu_millicores === 4000, "preset numbers keep SDK values");
  assert(convertedPreset.default_setup_config?.app_ports?.[0]?.access === "public", "preset nested ports preserve values");
  assert(convertedPreset.default_setup_config?.agent_env?.MODE === "test", "preset nested maps preserve values");
  assert(convertedPreset.secret_project_id === "sp_1", "preset optional IDs are retained");

  const convertedSecretMetadata = fromProtoSecretMetadata(create(SecretMetadataSchema, {
    key: "DB_URL",
    createdAt: timestamp,
    updatedAt: timestamp,
  }));
  const convertedSecretProject = fromProtoSecretProject(create(SecretProjectSchema, {
    id: "sp_1",
    orgId: "org_test",
    name: "project",
    secretCount: 2n,
    createdAt: timestamp,
  }));
  assert(convertedSecretMetadata.created_at === "2026-01-01T00:00:00Z", "secret metadata timestamps keep REST values");
  assert(convertedSecretProject.secret_count === 2, "secret project counts convert int64 to numbers");
  assert(pollIntervalMs(create(DurationSchema, { seconds: 0n, nanos: 250_000_000 })) === 250, "poll intervals use the service response");
  assert(pollIntervalMs(undefined) === 2000, "missing poll intervals keep the two-second fallback");

  // Mock server
  const server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      const url = new URL(req.url!, `http://${req.headers.host}`);
      if (await handleConnectRequest(req, res, url)) return;
      res.writeHead(404);
      res.end(JSON.stringify({ detail: "not found" }));
    },
  );

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const addr = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    let defaultRequestUrl = "";
    const defaultOrigin = new Codewire({
      apiKey: "test-key",
      orgId: "org_test",
      fetch: async (input, init) => {
        defaultRequestUrl = input instanceof Request ? input.url : input.toString();
        const url = new URL(defaultRequestUrl);
        return fetch(`${baseUrl}${url.pathname}${url.search}`, init);
      },
    });
    await defaultOrigin.apiKeys.list();
    const parsedDefaultRequestUrl = new URL(defaultRequestUrl);
    assert(
      parsedDefaultRequestUrl.origin === "https://codewire.sh",
      "default Connect origin is the root control-plane origin",
    );
    assert(
      !parsedDefaultRequestUrl.pathname.startsWith("/api/"),
      "default Connect origin does not retain a REST path prefix",
    );

    const cw = new Codewire({
      apiKey: "test-key",
      orgId: "org_test",
      baseUrl,
    });

    // Test: Create environment returns Environment wrapper
    console.log("Test: Environment CRUD");
    const env = await cw.environments.create({ preset_slug: "python" });
    assert(env instanceof Environment, "create returns Environment instance");
    assert(env.id === "env_123", "env.id matches");
    assert(env.state === "running", "env.state matches");

    // Test: Get environment
    const env2 = await cw.environments.get("env_123");
    assert(env2.id === "env_123", "get returns correct env");

    // Test: List environments
    const envs = await cw.environments.list();
    assert(envs.length === 1, "list returns 1 env");
    assert(envs[0] instanceof Environment, "list items are Environment instances");

    // Test: Direct environment service methods
    console.log("Test: Direct environment service methods");
    const directExec = await cw.environments.exec("env_123", {
      command: ["echo", "hello"],
    });
    assert(directExec.exit_code === 0, "direct exec exit code 0");
    await cw.environments.start("env_123");
    await cw.environments.stop("env_123");

    const directFiles = await cw.environments.listFiles(
      "env_123",
      "/workspace",
    );
    assert(directFiles[0].name === "main.go", "direct listFiles works");
    await cw.environments.uploadFile(
      "env_123",
      new Uint8Array([1, 2, 3]),
      "/workspace/direct.bin",
    );
    assert(uploadHeaders === 1, "typed upload stream sends its header");
    assert(uploadedBytes === 3, "typed upload stream sends its file bytes");
    const directDownload = await cw.environments.downloadFile(
      "env_123",
      "/workspace/direct.bin",
    );
    assert(
      directDownload instanceof ArrayBuffer,
      "direct downloadFile returns ArrayBuffer",
    );

    const directPorts = await cw.environments.listPorts("env_123");
    assert(directPorts[0].port === 8080, "direct listPorts works");
    const directPort = await cw.environments.createPort("env_123", {
      port: 3000,
      label: "web",
    });
    assert(directPort.id === "port_2", "direct createPort works");
    await cw.environments.deletePort("env_123", "port_2");
    await cw.environments.delete("env_123");

    // Test: Exec via wrapper
    console.log("Test: Environment exec");
    const result = await env.exec({ command: ["echo", "hello"] });
    assert(result.exit_code === 0, "exec exit code 0");
    assert(result.stdout === "hello\n", "exec stdout matches");

    // Test: Stop via wrapper
    console.log("Test: Environment start/stop/remove");
    await env.start();
    await env.stop();
    await env.remove();

    // Test: Templates
    console.log("Test: Templates");
    const tmpl = await cw.templates.create({
      name: "Go",
    });
    assert(tmpl.id === "tmpl_1", "template created");

    const tmpl2 = await cw.templates.get("tmpl_1");
    assert(tmpl2.name === "Go", "template get works");

    const templates = await cw.templates.list();
    assert(templates.length === 1, "templates list works");

    // Test: API Keys
    console.log("Test: API Keys");
    const key = await cw.apiKeys.create({ name: "test" });
    assert(key.key === "cw_abc123", "api key created");

    const keys = await cw.apiKeys.list();
    assert(keys.length === 1, "api keys listed");

    // Test: API Key Connect errors
    console.log("Test: API Key Connect errors");
    try {
      await cw.apiKeys.create({ name: "invalid" });
      assert(false, "invalid API key should have thrown");
    } catch (e) {
      assert(e instanceof CodewireError, "Connect validation throws CodewireError");
      assert((e as CodewireError).status === 400, "Connect validation status is 400");
      assert((e as CodewireError).violations?.[0]?.field === "name", "Connect validation exposes field violations");
      assert((e as CodewireError).requestId === "req_api_key", "Connect ErrorInfo request ID is retained");
    }

    try {
      const unauthorized = new Codewire({ apiKey: "wrong-key", orgId: "org_test", baseUrl });
      await unauthorized.apiKeys.list();
      assert(false, "unauthorized Connect API key request should have thrown");
    } catch (e) {
      assert((e as CodewireError).status === 401, "Connect unauthenticated status is 401");
    }

    try {
      await cw.apiKeys.delete("missing");
      assert(false, "missing Connect API key should have thrown");
    } catch (e) {
      assert((e as CodewireError).status === 404, "Connect not-found status is 404");
    }

    let customFetchCalls = 0;
    const withCustomFetch = new Codewire({
      apiKey: "test-key",
      orgId: "org_test",
      baseUrl,
      fetch: async (input, init) => {
        customFetchCalls++;
        return fetch(input, init);
      },
    });
    await withCustomFetch.apiKeys.list();
    assert(customFetchCalls === 1, "API key Connect client uses ClientOptions.fetch");
    await withCustomFetch.environments.list();
    assert(
      customFetchCalls === 2,
      "environment Connect client keeps ClientOptions.fetch",
    );

    // Test: Secrets
    console.log("Test: Secrets");
    const secrets = await cw.secrets.list();
    assert(secrets.length === 1, "secrets listed");
    assert(secrets[0].key === "DB_URL", "secret key matches");

    await cw.secrets.set("DB_URL", "postgres://...");
    await cw.secrets.rename("DB_URL", "DATABASE_URL");
    await cw.secrets.delete("DB_URL");

    // Test: Error handling
    console.log("Test: Error handling");
    try {
      const cw2 = new Codewire({
        apiKey: "wrong-key",
        orgId: "org_test",
        baseUrl,
      });
      await cw2.environments.list();
      assert(false, "should have thrown");
    } catch (e) {
      assert(e instanceof CodewireError, "throws CodewireError");
      assert((e as CodewireError).status === 401, "status is 401");
    }

    // Test: Missing orgId
    console.log("Test: Missing orgId");
    try {
      const cw3 = new Codewire({ apiKey: "test-key", baseUrl });
      await cw3.environments.list();
      assert(false, "should have thrown for missing orgId");
    } catch (e) {
      assert(
        (e as Error).message.includes("orgId is required"),
        "error mentions orgId",
      );
    }

    // Test: Secret Projects
    console.log("Test: Secret Projects");
    const sp = await cw.secretProjects.create({ name: "my-project" });
    assert(sp.id === "sp_1", "secret project created with id");
    assert(sp.name === "my-project", "secret project has name");

    const sps = await cw.secretProjects.list();
    assert(Array.isArray(sps), "secret projects list is array");
    assert(sps.length === 1, "secret projects list has 1 item");

    await cw.secretProjects.delete("sp_1");

    const spSecrets = await cw.secretProjects.listSecrets("sp_1");
    assert(Array.isArray(spSecrets), "project secrets is array");
    assert(spSecrets[0].key === "PROJECT_KEY", "project secret key matches");

    await cw.secretProjects.setSecret("sp_1", { key: "PROJECT_KEY", value: "val" });

    await cw.secretProjects.renameSecret(
      "sp_1",
      "PROJECT_KEY",
      "PROJECT_TOKEN",
    );

    await cw.secretProjects.deleteSecret("sp_1", "PROJECT_KEY");

    // Test: User Secrets
    console.log("Test: User Secrets");
    const userSecrets = await cw.secrets.listUser();
    assert(Array.isArray(userSecrets), "user secrets list returned");
    assert(userSecrets[0].key === "USER_TOKEN", "user secret key matches");

    await cw.secrets.setUser("USER_TOKEN", "tok_abc");

    await cw.secrets.renameUser("USER_TOKEN", "USER_ACCESS_TOKEN");

    await cw.secrets.deleteUser("USER_TOKEN");

    // Test: File Operations
    console.log("Test: File Operations");
    await env2.upload(new Uint8Array([1, 2, 3]), "/workspace/test.bin");

    const downloaded = await env2.download("/workspace/test.bin");
    assert(downloaded instanceof ArrayBuffer, "download returns ArrayBuffer");

    const files = await env2.listFiles();
    assert(Array.isArray(files), "listFiles returns array");
    assert(files[0].name === "main.go", "file entry name matches");

    await env2.files.upload(
      new Uint8Array([4, 5, 6]),
      "/workspace/files.bin",
    );
    const filesDownload = await env2.files.download("/workspace/files.bin");
    assert(
      filesDownload instanceof ArrayBuffer,
      "files.download returns ArrayBuffer",
    );
    const listedFiles = await env2.files.list("/workspace");
    assert(listedFiles[0].name === "main.go", "files.list returns entries");

    // Test: Ports
    console.log("Test: Ports");
    const ports = await env2.listPorts();
    assert(Array.isArray(ports), "listPorts returns array");
    assert(ports[0].port === 8080, "port number matches");

    const newPort = await env2.createPort({ port: 3000, label: "web" });
    assert(newPort.id === "port_2", "created port has id");
    assert(newPort.port === 3000, "created port number matches");

    await env2.deletePort("port_2");

    // Test: Template CRUD (extended)
    console.log("Test: Template CRUD (extended)");
    const updatedTmpl = await cw.templates.update("tmpl_1", {
      name: "Go Updated",
      default_cpu_millicores: 4000,
    });
    assert(updatedTmpl.name === "Go Updated", "template name updated");
    assert(updatedTmpl.default_cpu_millicores === 4000, "template cpu updated");

    await cw.templates.delete("tmpl_1");

    // Test: Error 404
    console.log("Test: Error 404");
    try {
      await cw.environments.get("env_nonexistent");
      assert(false, "should have thrown for 404");
    } catch (e) {
      assert(e instanceof CodewireError, "404 throws CodewireError");
      assert((e as CodewireError).status === 404, "404 status matches");
    }

    // Test: waitReady
    console.log("Test: waitReady");
    waitReadyCounter = 0;
    const envWait = await cw.environments.get("env_wait");
    await envWait.waitReady({ interval: 100, timeout: 5000 });
    assert(waitReadyCounter >= 2, "waitReady polled multiple times");

    // Test: API Key Update
    console.log("Test: API Key Update");
    const updatedKey = await cw.apiKeys.update("key_1", { disabled: true });
    assert(updatedKey.id === "key_1", "updated key id matches");
    assert((updatedKey as any).disabled === true, "key disabled field set");
    await cw.apiKeys.delete("key_1");

    // Test: create(wait=true)
    console.log("Test: create(wait=true)");
    createWaitCounter = 0;
    const envWaited = await cw.environments.create(
      { preset_slug: "wait-test" },
      { wait: true, waitTimeout: 10_000 },
    );
    assert(envWaited.id === "env_cwait", "create(wait) returns correct env id");
    assert(envWaited.state === "running", "create(wait) env state is running");
  } finally {
    server.close();
  }

  const expectedAssertions = 87;
  if (passed !== expectedAssertions) {
    failed++;
    console.error(
      `  FAIL: expected ${expectedAssertions} assertions, executed ${passed}`,
    );
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

runTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
