import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import nodeAssert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import { DurationSchema } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createConnectRouter } from "@connectrpc/connect";
import { BadRequestSchema, ErrorInfoSchema } from "@codewire/proto-ts";
import { ApiKeySchema, ApiKeyService } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import {
  ProjectSkillSource,
  ProjectStoragePlacement,
} from "@codewire/proto-ts/gen/codewire/v1/common_pb";
import {
  DesiredState,
  EnvironmentResizeExecutionMode,
  EnvironmentResizeOperationState,
  EnvironmentSchema,
  EnvironmentService,
  EnvironmentSourcesUpdateOutcome,
  EnvironmentState,
  IsolationTier,
  NetworkAttachmentFailure,
  NetworkAttachmentState,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { ExecResponseSchema, ExecService } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import { FileEntrySchema, FileService } from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import { PortAccess, PortSchema, PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { PresetSchema, PresetService } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import {
  SecretMetadataSchema,
  SecretProjectSchema,
  SecretService,
  WorkloadSecretSource as ProtoWorkloadSecretSource,
} from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { Codewire } from "./index.js";
import { Environment } from "./environment.js";
import { CodewireError } from "./types.js";
import { runAccessProfileTests } from "./access-profiles.test.js";
import { runCredentialTests } from "./credentials.test.js";
import {
  assertAPIKeyConverterCoverage,
  assertRuntimeConverterCoverage,
  environmentSourceSelectionAcknowledges,
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
  toProtoCreateEnvironmentRequest,
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
  let sourceUpdateCalls = 0;

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
    presetId: "preset_1",
    type: "sandbox",
    state,
    desiredState: DesiredState.STARTED,
    isolationTier: IsolationTier.STANDARD,
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
    operationGeneration: 9_007_199_254_741_007n,
    sourceSelection: {},
  });
  const resizeOperation = (requestId: string) => ({
    id: "resize_123",
    environmentId: "env_123",
    requestId,
    previousResources: { cpuMillicores: 2000, memoryMb: 4096, diskGb: 20 },
    desiredResources: { cpuMillicores: 3000, memoryMb: 6144, diskGb: 30 },
    lastAppliedResources: { cpuMillicores: 3000, memoryMb: 6144, diskGb: 30 },
    state: EnvironmentResizeOperationState.COMPLETED,
    createdAt: timestamp,
    updatedAt: timestamp,
    completedAt: timestamp,
  });
  const preset = (name = "Go", cpu = 2000) => ({
    id: "preset_1",
    orgId: "org_test",
    name,
    buildStatus: "ready",
    official: false,
    createdAt: timestamp,
    projectSpec: {
      schemaVersion: 1,
      workingDirectory: "/workspace",
      resources: { cpuMillicores: cpu, memoryMib: 4096n, diskGib: 20n },
    },
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
      const requestedSecrets = request.projectSpec?.secrets;
      const requestedCredentials = request.projectSpec?.credentials;
      const created = {
        ...environment("env_123", EnvironmentState.RUNNING),
        orgId: request.orgId,
        sourceSelection: {
          secrets: requestedSecrets && (
            requestedSecrets.project || requestedSecrets.organization ||
            requestedSecrets.user !== undefined
          )
            ? {
                ...requestedSecrets,
                project: requestedSecrets.project
                  ? "platform:id:33333333-3333-4333-8333-333333333333"
                  : "",
              }
            : undefined,
          credentials: requestedCredentials
            ? {
                profile: "platform:id:44444444-4444-4444-8444-444444444444",
              }
            : undefined,
          profileRevision: request.expectedProfileRevision,
        },
      };
      if (request.projectSpec?.preset === "wait-test") {
        return {
          environment: {
            ...created,
            id: "env_cwait",
            state: EnvironmentState.PENDING,
          },
        };
      }
      if (request.projectSpec?.preset === "missing-sources") {
        return {
          environment: { ...created, sourceSelection: undefined },
        };
      }
      return { environment: created };
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
    resizeEnvironment: (request, context) => {
      requireTestKey(context);
      return {
        operation: resizeOperation(request.requestId),
        environment: environment(request.environmentId, EnvironmentState.RUNNING),
      };
    },
    planEnvironmentResize: (request, context) => {
      requireTestKey(context);
      return {
        plan: {
          previousResources: { cpuMillicores: 2000, memoryMb: 4096, diskGb: 20 },
          desiredResources: {
            cpuMillicores: request.cpuMillicores,
            memoryMb: request.memoryMb,
            diskGb: request.diskGb,
          },
          executionMode: EnvironmentResizeExecutionMode.IN_PLACE,
          activeSessionCount: 0,
          activeSessionsWillBeTerminated: false,
          reason: "runtime supports live resize",
          warnings: [],
        },
        environment: environment(request.environmentId, EnvironmentState.RUNNING),
      };
    },
    getEnvironmentResizeOperation: (_request, context) => {
      requireTestKey(context);
      return {
        operation: resizeOperation("stable-request"),
        environment: environment("env_123", EnvironmentState.RUNNING),
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
    updateEnvironmentSources: (request, context) => {
      requireTestKey(context);
      sourceUpdateCalls++;
      if (request.environmentId === "missing-selection") {
        return {
          environmentId: request.environmentId,
          operationGeneration: request.expectedOperationGeneration + 1n,
          outcome: EnvironmentSourcesUpdateOutcome.STORED,
        };
      }
      if (request.environmentId === "stale-selection") {
        throw new ConnectError("stale source selection", Code.Aborted);
      }
      if (request.environmentId === "changed-environment") {
        return {
          environmentId: "different-environment",
          operationGeneration: request.expectedOperationGeneration,
          selection: request.replacement,
          outcome: EnvironmentSourcesUpdateOutcome.STORED,
        };
      }
      if (request.environmentId === "unknown-outcome") {
        return {
          environmentId: request.environmentId,
          operationGeneration: request.expectedOperationGeneration,
          selection: request.replacement,
          outcome: EnvironmentSourcesUpdateOutcome.UNSPECIFIED,
        };
      }
      if (request.expectedOperationGeneration === 12n) {
        return {
          environmentId: request.environmentId,
          operationGeneration: 0n,
          selection: request.replacement,
          outcome: EnvironmentSourcesUpdateOutcome.STORED,
        };
      }
      if (request.expectedOperationGeneration === 10n) {
        assert(request.expected !== undefined, "empty expected selection remains present");
        assert(request.replacement !== undefined, "empty replacement selection remains present");
        assert(
          !request.allowRestart &&
            !request.confirmPersonalCredentials &&
            !request.confirmPersonalSecrets,
          "omitted source-update consent flags remain false",
        );
        return {
          environmentId: request.environmentId,
          operationGeneration: 10n,
          // Rust omits structurally empty ProjectSecretBindings on the wire.
          selection: { ...request.replacement, secrets: undefined },
          outcome: EnvironmentSourcesUpdateOutcome.UNCHANGED,
        };
      }
      assert(request.orgId === "org_test", "source update carries organization identity");
      assert(request.environmentId === "env_123", "source update carries environment identity");
      assert(
        request.expectedOperationGeneration === 9_007_199_254_741_007n,
        "source update preserves the operation generation losslessly",
      );
      assert(
        request.expected?.secrets?.user === ProjectStoragePlacement.PLATFORM &&
          request.expected.credentials?.profile === "platform:id:22222222-2222-4222-8222-222222222222" &&
          request.expected.profileRevision === 9_007_199_254_741_009n,
        "source update preserves the exact expected selection",
      );
      assert(
        request.replacement?.secrets?.project === "platform:project-two" &&
          request.replacement.secrets.organization &&
          request.replacement.secrets.user === ProjectStoragePlacement.PLATFORM &&
          request.replacement.credentials?.profile === "platform:user/profile-two" &&
          request.replacement.profileRevision === 0xffff_ffff_ffff_ffffn,
        "source update preserves every replacement source",
      );
      assert(request.allowRestart, "source update preserves explicit restart consent");
      assert(
        request.confirmPersonalCredentials && request.confirmPersonalSecrets,
        "source update preserves explicit personal-source confirmations",
      );
      return {
        environmentId: request.environmentId,
        operationGeneration: request.expectedOperationGeneration,
        selection: {
          secrets: {
            project: "platform:id:33333333-3333-4333-8333-333333333333",
            organization: request.replacement?.secrets?.organization,
            user: request.replacement?.secrets?.user,
          },
          credentials: {
            profile: "platform:id:44444444-4444-4444-8444-444444444444",
          },
          profileRevision: request.replacement?.profileRevision,
        },
        outcome: EnvironmentSourcesUpdateOutcome.RESTART_REQUIRED,
      };
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
      assert(request.projectSpec?.workingDirectory === "/workspace", "create preset carries canonical project intent");
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
      assert(request.projectSpec?.resources?.cpuMillicores === 4000, "update preset replaces canonical project intent");
      return { preset: preset(request.name || "Go Updated", request.projectSpec?.resources?.cpuMillicores ?? 4000) };
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
    previewWorkloadSecretResolution: (request, context) => {
      requireTestKey(context);
      assert(
        request.orgId === "org_test" &&
          request.organization &&
          request.secretProjectId === "sp_1" &&
          request.user &&
          request.explicitEnvironmentKeys.length === 1 &&
          request.explicitEnvironmentKeys[0] === "EXPLICIT",
        "workload-secret preview request keeps every source selector",
      );
      return {
        secrets: [{
          key: "TOKEN",
          source: ProtoWorkloadSecretSource.USER,
          overriddenSources: [ProtoWorkloadSecretSource.ORGANIZATION],
        }],
      };
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
    isolationTier: IsolationTier.CONFIDENTIAL,
    presetName: "Go",
    sourceSelection: {
      secrets: {
        project: "platform:id:11111111-1111-4111-8111-111111111111",
        organization: false,
        user: ProjectStoragePlacement.PLATFORM,
      },
      credentials: { profile: "platform:id:22222222-2222-4222-8222-222222222222" },
      profileRevision: 9_007_199_254_741_009n,
    },
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
  assert(convertedEnvironment.isolation_tier === "confidential", "environment isolation tier preserves the public value");
  assert(convertedEnvironment.ports?.[0]?.access === "org_members", "environment ports preserve access values");
  assert(convertedEnvironment.ports?.[0]?.preview_url === "https://preview.example.test", "environment ports preserve optional URLs");
  assert(convertedEnvironment.ttl_seconds === 300, "environment optional numbers are retained");
  assert(convertedEnvironment.operation_generation === 9_007_199_254_741_007n, "environment operation generations remain lossless");
  assert(convertedEnvironment.source_selection?.secrets?.user === "platform", "environment personal-secret origins remain typed");
  assert(convertedEnvironment.source_selection?.credentials?.profile === "platform:id:22222222-2222-4222-8222-222222222222", "environment credential profiles are retained");
  assert(convertedEnvironment.source_selection?.profile_revision === 9_007_199_254_741_009n, "environment profile revisions remain lossless");
  assert(convertedEnvironment.network_state === undefined && convertedEnvironment.network_failure === undefined,
    "an unspecified network attachment is absent");
  const refusedEnvironment = fromProtoEnvironment(create(EnvironmentSchema, {
    ...environment("env_refused", EnvironmentState.DESTROYED),
    errorCode: "no_capacity",
  }));
  assert(refusedEnvironment.error_code === "no_capacity", "environment error codes are retained");
  assert(convertedEnvironment.error_code === undefined, "an environment without a failure has no error code");

  const attachedEnvironment = fromProtoEnvironment(create(EnvironmentSchema, {
    ...environment("env_attached", EnvironmentState.RUNNING),
    network: "work",
    networkState: NetworkAttachmentState.FAILED,
    networkFailure: NetworkAttachmentFailure.NOT_A_MEMBER,
  }));
  assert(attachedEnvironment.network === "work" && attachedEnvironment.network_state === "failed"
    && attachedEnvironment.network_failure === "not_a_member", "environment network attachments keep public values");

  const createEnvironment = toProtoCreateEnvironmentRequest("org_test", {
    isolation_tier: "confidential",
    expected_profile_revision: 9_007_199_254_741_009n,
    confirm_personal_credentials: true,
    confirm_personal_secrets: true,
    project_spec: {
      schema_version: 1,
      preset: "python",
      image: "ghcr.io/example/workspace@sha256:abc",
      repositories: [{
        revision: "deadbeef",
        destination: "/workspace/platform",
        source: "https://git.example.test/org/platform",
        known_hosts: ["git.example.test ssh-ed25519 AAAASynthetic"],
      }],
      working_directory: "/workspace/platform",
      skills: [{ source: "repository", reference: ".agents/skills/rust", agents: ["codex"] }],
      resources: { cpu_millicores: 2000, memory_mib: 16384n, disk_gib: 40n },
      secrets: { project: "platform:id:project-one", organization: false, user: "platform" },
      credentials: { profile: "platform:id:profile-one" },
    },
  });
  assert(createEnvironment.isolationTier === IsolationTier.CONFIDENTIAL, "create environment preserves confidential isolation");
  assert(createEnvironment.projectSpec?.repositories[0]?.destination === "/workspace/platform", "create environment preserves repository destinations");
  assert(createEnvironment.projectSpec?.repositories[0]?.revision === "deadbeef", "create environment preserves repository revisions");
  assert(createEnvironment.projectSpec?.resources?.memoryMib === 16384n, "create environment preserves project resource units");
  assert(createEnvironment.projectSpec?.repositories[0]?.knownHosts[0]?.includes("AAAASynthetic") === true, "create environment preserves direct repository host trust");
  assert(createEnvironment.projectSpec?.credentials?.profile === "platform:id:profile-one", "create environment preserves credential profile references");
  assert(createEnvironment.projectSpec?.secrets?.user === 2, "create environment preserves the personal-secret platform origin");
  assert(createEnvironment.expectedProfileRevision === 9_007_199_254_741_009n, "create environment preserves profile revision losslessly");
  assert(createEnvironment.confirmPersonalCredentials && createEnvironment.confirmPersonalSecrets, "create environment preserves explicit personal-source confirmations");
  assert(createEnvironment.omitApplicationPreviews === false, "create preview omission defaults false");
  assert(createEnvironment.network === "", "create joins no network unless asked");
  assert(createEnvironment.orgId === "org_test" && !("organization" in createEnvironment),
    "the SDK names its organization by org_id only");
  assert(createEnvironment.sourceSnapshotId === "", "create starts empty unless given a snapshot");
  assert(toProtoCreateEnvironmentRequest("org_test", { project_spec: { schema_version: 1, working_directory: "/workspace" }, source_snapshot_id: "snapshot_1" }).sourceSnapshotId === "snapshot_1",
    "create preserves the source snapshot");
  assert(toProtoCreateEnvironmentRequest("org_test", { project_spec: { schema_version: 1, working_directory: "/workspace" }, network: "work" }).network === "work",
    "create preserves the requested network");
  for (const invalid of ["", 1]) {
    let rejected = false;
    try {
      toProtoCreateEnvironmentRequest("org_test", { project_spec: { schema_version: 1, working_directory: "/workspace" }, network: invalid as never });
    } catch (error) {
      rejected = error instanceof Error && error.message.includes("Mesh network name");
    }
    assert(rejected, "create rejects an empty or non-string network");
  }
  for (const omit of [true, false]) {
    assert(toProtoCreateEnvironmentRequest("org_test", { project_spec: { schema_version: 1, working_directory: "/workspace" }, omit_application_previews: omit }).omitApplicationPreviews === omit,
      "create preserves explicit preview omission");
  }
  for (const invalid of [1, "true", null]) {
    let rejected = false;
    try {
      toProtoCreateEnvironmentRequest("org_test", { project_spec: { schema_version: 1, working_directory: "/workspace" }, omit_application_previews: invalid as never });
    } catch (error) {
      rejected = error instanceof Error && error.message.includes("explicit boolean");
    }
    assert(rejected, "create preview omission rejects nonbooleans");
  }
  let rejectedMissingProjectSpec = false;
  try {
    toProtoCreateEnvironmentRequest("org_test", {} as never);
  } catch {
    rejectedMissingProjectSpec = true;
  }
  assert(rejectedMissingProjectSpec, "create environment requires project_spec at runtime");
  let rejectedUnknownIsolation = false;
  try {
    toProtoCreateEnvironmentRequest("org_test", {
      isolation_tier: "container" as never,
      confirm_personal_credentials: false,
      confirm_personal_secrets: false,
      project_spec: { schema_version: 1, working_directory: "/workspace" },
    });
  } catch {
    rejectedUnknownIsolation = true;
  }
  assert(rejectedUnknownIsolation, "create environment rejects unknown isolation tiers");
  let rejectedUnknownSkillSource = false;
  try {
    toProtoCreateEnvironmentRequest("org_test", {
      confirm_personal_credentials: false,
      confirm_personal_secrets: false,
      project_spec: {
        schema_version: 1,
        working_directory: "/workspace",
        skills: [{ source: "ambient" as never, reference: "personal" }],
      },
    });
  } catch {
    rejectedUnknownSkillSource = true;
  }
  assert(rejectedUnknownSkillSource, "create environment rejects unknown project skill sources");
  for (const invalid of [
    {
      project_spec: {
        schema_version: 1,
        working_directory: "/workspace",
        credentials: { profile: "platform:id:profile-one" },
      },
      confirm_personal_credentials: true,
      confirm_personal_secrets: false,
    },
    {
      project_spec: { schema_version: 1, working_directory: "/workspace" },
      expected_profile_revision: 1n,
      confirm_personal_credentials: true,
      confirm_personal_secrets: false,
    },
    {
      project_spec: { schema_version: 1, working_directory: "/workspace" },
      confirm_personal_credentials: "yes" as never,
      confirm_personal_secrets: false,
    },
  ]) {
    nodeAssert.throws(
      () => toProtoCreateEnvironmentRequest("org_test", invalid),
      /codewire:/,
    );
  }

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
    projectSpec: {
      schemaVersion: 1,
      image: "golang:1.25",
      workingDirectory: "/workspace/repo",
      applicationPorts: [{ access: "public", label: "web", port: 8080 }],
      environment: { GOFLAGS: "-mod=readonly" },
      agents: { install: true, tools: ["claude"] },
      installCommand: "go install",
      repositories: [{
        branch: "main",
        destination: "/workspace/repo",
        source: "https://git.example.test/org/repo",
        knownHosts: ["git.example.test ssh-ed25519 AAAASyntheticPreset"],
      }],
      startupScript: "go test ./...",
      skills: [{ source: ProjectSkillSource.USER, reference: "personal", agents: ["codex"] }],
      resources: {
        cpuMillicores: 4000,
        memoryMib: 0xffff_ffff_ffff_ffffn,
        diskGib: 9_007_199_254_741_011n,
      },
      secrets: {
        project: "development",
        organization: true,
        user: ProjectStoragePlacement.PLATFORM,
      },
      credentials: { profile: "platform:id:profile-preset" },
    },
  }));
  assert(convertedPreset.project_spec.resources?.cpu_millicores === 4000, "preset project resources keep SDK values");
  assert(convertedPreset.project_spec.application_ports?.[0]?.access === "public", "preset project ports preserve values");
  assert(convertedPreset.project_spec.repositories?.[0]?.destination === "/workspace/repo", "preset repository destinations are retained");
  assert(convertedPreset.project_spec.skills?.[0]?.source === "user", "preset project skill sources use ergonomic values");
  assert(convertedPreset.project_spec.secrets?.project === "development", "preset secret bindings remain opaque names");
  assert(convertedPreset.project_spec.repositories?.[0]?.known_hosts?.[0]?.includes("AAAASyntheticPreset") === true, "preset repository host trust is retained");
  assert(convertedPreset.project_spec.resources?.memory_mib === 0xffff_ffff_ffff_ffffn, "preset project memory remains a lossless uint64");
  assert(convertedPreset.project_spec.resources?.disk_gib === 9_007_199_254_741_011n, "preset project disk remains lossless above the safe integer range");
  assert(convertedPreset.project_spec.secrets?.user === "platform", "preset personal-secret origin remains typed");
  assert(convertedPreset.project_spec.credentials?.profile === "platform:id:profile-preset", "preset credential profiles are retained");

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
    const env = await cw.environments.create({
      project_spec: { schema_version: 1, preset: "python", working_directory: "/workspace" },
      confirm_personal_credentials: false,
      confirm_personal_secrets: false,
    });
    assert(env instanceof Environment, "create returns Environment instance");
    assert(env.id === "env_123", "env.id matches");
    assert(env.state === "running", "env.state matches");
    assert(env.isolation_tier === "standard", "env.isolation_tier matches");
    assert(env.operation_generation === 9_007_199_254_741_007n, "environment wrapper exposes the operation generation");
    assert(env.source_selection !== undefined && env.source_selection.credentials === undefined, "environment wrapper preserves an explicitly empty source selection");
    const canonicalizedCreate = await cw.environments.create({
      project_spec: {
        schema_version: 1,
        working_directory: "/workspace",
        secrets: {
          project: "platform:project-two",
          organization: true,
          user: "platform",
        },
        credentials: { profile: "platform:user/profile-two" },
      },
      expected_profile_revision: 17n,
      confirm_personal_credentials: true,
      confirm_personal_secrets: true,
    });
    assert(canonicalizedCreate.source_selection?.secrets?.project === "platform:id:33333333-3333-4333-8333-333333333333", "create accepts the canonical secret-project acknowledgement for a name");
    assert(canonicalizedCreate.source_selection?.credentials?.profile === "platform:id:44444444-4444-4444-8444-444444444444", "create accepts the canonical profile acknowledgement for a name");
    for (const secrets of [{}, { project: "", organization: false }]) {
      const emptyCreate = await cw.environments.create({
        project_spec: { schema_version: 1, working_directory: "/workspace", secrets },
      });
      assert(emptyCreate.source_selection?.secrets === undefined, "create accepts omitted empty secret bindings");
    }
    await nodeAssert.rejects(
      cw.environments.create({
        project_spec: {
          schema_version: 1,
          preset: "missing-sources",
          working_directory: "/workspace",
        },
        confirm_personal_credentials: false,
        confirm_personal_secrets: false,
      }),
      /different organization or source selection/,
    );

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
    const directPlan = await cw.environments.planResize("env_123", {
      cpu_millicores: 3000,
      memory_mb: 6144,
      disk_gb: 30,
    });
    assert(directPlan.execution_mode === "in_place", "direct resize plan maps mode");
    const directResize = await cw.environments.resize("env_123", {
      cpu_millicores: 3000,
      memory_mb: 6144,
      disk_gb: 30,
      request_id: "stable-request",
    });
    assert(directResize.state === "completed", "direct resize returns typed terminal state");
    assert(directResize.desired_resources?.disk_gb === 30, "direct resize maps resources");
    const fetchedResize = await cw.environments.getResizeOperation(
      "env_123",
      directResize.id,
    );
    assert(fetchedResize.request_id === "stable-request", "resize operation identity is stable");

    const sourceUpdate = await cw.environments.updateSources("env_123", {
      expected_operation_generation: 9_007_199_254_741_007n,
      expected: {
        secrets: {
          project: "platform:id:11111111-1111-4111-8111-111111111111",
          organization: false,
          user: "platform",
        },
        credentials: {
          profile: "platform:id:22222222-2222-4222-8222-222222222222",
        },
        profile_revision: 9_007_199_254_741_009n,
      },
      replacement: {
        secrets: {
          project: "platform:project-two",
          organization: true,
          user: "platform",
        },
        credentials: { profile: "platform:user/profile-two" },
        profile_revision: 0xffff_ffff_ffff_ffffn,
      },
      allow_restart: true,
      confirm_personal_credentials: true,
      confirm_personal_secrets: true,
    });
    assert(sourceUpdate.environment_id === "env_123", "source update returns the environment identity");
    assert(sourceUpdate.operation_generation === 9_007_199_254_741_007n, "source update acknowledges the exact operation generation losslessly");
    assert(sourceUpdate.outcome === "restart_required", "source update returns explicit restart semantics");
    assert(sourceUpdate.selection.secrets?.project === "platform:id:33333333-3333-4333-8333-333333333333", "source update returns the canonical replacement project");
    assert(sourceUpdate.selection.secrets?.user === "platform", "source update returns replacement origin");
    assert(sourceUpdate.selection.credentials?.profile === "platform:id:44444444-4444-4444-8444-444444444444", "source update returns the canonical replacement profile");
    assert(sourceUpdate.selection.profile_revision === 0xffff_ffff_ffff_ffffn, "source update returns the exact profile revision");

    const unchangedSources = await env.updateSources({
      expected_operation_generation: 10n,
      expected: {},
      replacement: {},
    });
    assert(unchangedSources.outcome === "unchanged", "wrapper preserves unchanged source semantics");
    assert(unchangedSources.selection.secrets === undefined, "an explicitly empty source selection is not synthesized");
    for (const secrets of [{}, { project: "", organization: false }]) {
      const emptyUpdate = await env.updateSources({
        expected_operation_generation: 10n,
        expected: { secrets },
        replacement: { secrets },
      });
      assert(emptyUpdate.selection.secrets === undefined, "update accepts omitted empty secret bindings");
    }
    for (const secrets of [
      { organization: true },
      { user: "platform" as const },
      { project: "platform:id:33333333-3333-4333-8333-333333333333" },
    ]) {
      assert(!environmentSourceSelectionAcknowledges({}, { secrets }), "omitted bindings cannot acknowledge a nonempty secret source");
      assert(!environmentSourceSelectionAcknowledges({ secrets }, {}), "unexpected nonempty bindings cannot acknowledge empty sources");
    }

    const sourceCallsBeforeValidation = sourceUpdateCalls;
    const validEmptySourceUpdate = {
      expected_operation_generation: 1n,
      expected: {},
      replacement: {},
      allow_restart: false,
      confirm_personal_credentials: false,
      confirm_personal_secrets: false,
    };
    for (const invalid of [
      { ...validEmptySourceUpdate, expected_operation_generation: 0n },
      { ...validEmptySourceUpdate, allow_restart: "yes" as never },
      {
        ...validEmptySourceUpdate,
        replacement: { credentials: { profile: "platform:id:profile-one" } },
      },
      {
        ...validEmptySourceUpdate,
        replacement: { profile_revision: 1n },
      },
      {
        ...validEmptySourceUpdate,
        replacement: { secrets: { user: "ambient" as never } },
      },
    ]) {
      await nodeAssert.rejects(
        cw.environments.updateSources("env_123", invalid),
        /codewire:/,
      );
    }
    assert(sourceUpdateCalls === sourceCallsBeforeValidation, "invalid source updates fail before transport");
    await nodeAssert.rejects(
      cw.environments.updateSources("missing-selection", validEmptySourceUpdate),
      /omitted selection/,
    );
    const beforeStaleSourceUpdate = sourceUpdateCalls;
    await nodeAssert.rejects(
      cw.environments.updateSources("stale-selection", validEmptySourceUpdate),
      (error: unknown) => error instanceof CodewireError && error.status === 409,
    );
    assert(sourceUpdateCalls === beforeStaleSourceUpdate + 1, "stale source updates are not fetched or retried");
    await nodeAssert.rejects(
      cw.environments.updateSources("changed-environment", validEmptySourceUpdate),
      /did not acknowledge the exact environment operation and replacement/,
    );
    await nodeAssert.rejects(
      cw.environments.updateSources("unknown-outcome", validEmptySourceUpdate),
      /unknown environment sources outcome/,
    );
    await nodeAssert.rejects(
      env.updateSources({
        ...validEmptySourceUpdate,
        expected_operation_generation: 12n,
      }),
      /did not acknowledge the exact environment operation and replacement/,
    );

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
    assert(
      (await env.planResize({ cpu_millicores: 3000, memory_mb: 6144, disk_gb: 30 }))
        .execution_mode === "in_place",
      "wrapper exposes resize plan",
    );
    const wrapperResize = await env.resize({
      cpu_millicores: 3000,
      memory_mb: 6144,
      disk_gb: 30,
      request_id: "wrapper-request",
      force: true,
    });
    assert(wrapperResize.last_applied_resources?.cpu_millicores === 3000, "wrapper resize maps applied CPU");
    assert((await env.getResizeOperation(wrapperResize.id)).state === "completed", "wrapper reads resize operation");
    await env.remove();

    // Test: Presets
    console.log("Test: Presets");
    const presetValue = await cw.presets.create({
      name: "Go",
      project_spec: { schema_version: 1, working_directory: "/workspace" },
    });
    assert(presetValue.id === "preset_1", "preset created");

    const fetchedPreset = await cw.presets.get("preset_1");
    assert(fetchedPreset.name === "Go", "preset get works");

    const presets = await cw.presets.list();
    assert(presets.length === 1, "presets list works");

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

    const preview = await cw.secrets.preview({
      organization: true,
      secret_project_id: "sp_1",
      user: true,
      explicit_environment_keys: ["EXPLICIT"],
    });
    assert(preview.length === 1, "workload-secret preview returns metadata");
    assert(
      preview[0].key === "TOKEN" && preview[0].source === "user",
      "workload-secret preview converts the winning source",
    );
    assert(
      preview[0].overridden_sources[0] === "organization",
      "workload-secret preview converts overridden sources",
    );

    // Test: File Operations
    console.log("Test: File Operations");
    await env2.files.upload(
      new Uint8Array([1, 2, 3]),
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

    // Test: Preset CRUD (extended)
    console.log("Test: Preset CRUD (extended)");
    const updatedPreset = await cw.presets.update("preset_1", {
      name: "Go Updated",
      project_spec: {
        schema_version: 1,
        working_directory: "/workspace",
        resources: { cpu_millicores: 4000 },
      },
    });
    assert(updatedPreset.name === "Go Updated", "preset name updated");
    assert(updatedPreset.project_spec.resources?.cpu_millicores === 4000, "preset project CPU updated");

    await cw.presets.delete("preset_1");

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
      {
        project_spec: {
          schema_version: 1,
          preset: "wait-test",
          working_directory: "/workspace",
        },
        confirm_personal_credentials: false,
        confirm_personal_secrets: false,
      },
      { wait: true, waitTimeout: 10_000 },
    );
    assert(envWaited.id === "env_cwait", "create(wait) returns correct env id");
    assert(envWaited.state === "running", "create(wait) env state is running");
  } finally {
    server.close();
  }

  const expectedAssertions = 179;
  if (passed !== expectedAssertions) {
    failed++;
    console.error(
      `  FAIL: expected ${expectedAssertions} assertions, executed ${passed}`,
    );
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
  await runAccessProfileTests();
  await runCredentialTests();
}

runTests().catch((e) => {
  console.error(e);
  process.exit(1);
});
