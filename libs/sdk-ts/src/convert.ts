import type { Duration, Timestamp } from "@bufbuild/protobuf/wkt";
import {
  ApiKeySchema,
  type ApiKey,
  type CreateApiKeyResponse as ProtoCreateApiKeyResponse,
} from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import {
  type AppPort as ProtoAppPort,
  type RepoEntry as ProtoRepoEntry,
  type SetupAgent as ProtoSetupAgent,
  type SetupConfig as ProtoSetupConfig,
} from "@codewire/proto-ts/gen/codewire/v1/common_pb";
import {
  DesiredState,
  EnvironmentSchema,
  EnvironmentState,
  type Environment as ProtoEnvironment,
} from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import type { ExecResponse } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import {
  FileEntrySchema,
  type FileEntry as ProtoFileEntry,
} from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import {
  PortAccess,
  PortSchema,
  type Port as ProtoPort,
} from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import {
  PresetSchema,
  type Preset as ProtoPreset,
} from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import {
  SecretMetadataSchema,
  SecretProjectSchema,
  type SecretMetadata as ProtoSecretMetadata,
  type SecretProject as ProtoSecretProject,
} from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import type {
  APIKeyData,
  CreateAPIKeyResponse,
  CreateEnvironmentRequest,
  CreatePortRequest,
  CreateTemplateRequest,
  EnvironmentData,
  EnvironmentPort,
  ExecRequest,
  ExecResult,
  FileEntry,
  ListEnvironmentsParams,
  SecretMetadata,
  SecretProject,
  TemplateData,
  UpdateTemplateRequest,
} from "./types.js";

const apiKeyDescriptorFields = new Map([
  [1, "id"],
  [2, "user_id"],
  [3, "org_id"],
  [4, "name"],
  [5, "key_prefix"],
  [6, "scopes"],
  [7, "last_used_at"],
  [8, "expires_at"],
  [9, "disabled_at"],
  [10, "created_at"],
  [11, "created_by_name"],
  [12, "created_by_email"],
]);

function timestampString(value: Timestamp | undefined): string | undefined {
  if (!value) return undefined;
  return new Date(Number(value.seconds) * 1_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}

function optionalString(value: string | undefined): string | undefined {
  return value === "" ? undefined : value;
}

function copyStringMap(
  value: Record<string, string>,
): Record<string, string> | undefined {
  return Object.keys(value).length === 0 ? undefined : { ...value };
}

function int32(
  name: string,
  value: number | null | undefined,
): number | undefined {
  if (value === null || value === undefined) return undefined;
  if (!Number.isInteger(value) || value < -2_147_483_648 || value > 2_147_483_647) {
    throw new Error(`codewire: ${name} is outside the API integer range`);
  }
  return value;
}

function mapEnvironmentState(state: EnvironmentState): string {
  switch (state) {
    case EnvironmentState.UNSPECIFIED:
      return "";
    case EnvironmentState.PENDING:
      return "pending";
    case EnvironmentState.PENDING_BUILD:
      return "pending_build";
    case EnvironmentState.BUILDING:
      return "building";
    case EnvironmentState.BUILD_FAILED:
      return "build_failed";
    case EnvironmentState.PULLING_SNAPSHOT:
      return "pulling_snapshot";
    case EnvironmentState.CREATING:
      return "creating";
    case EnvironmentState.STARTING:
      return "starting";
    case EnvironmentState.RUNNING:
      return "running";
    case EnvironmentState.STOPPING:
      return "stopping";
    case EnvironmentState.STOPPED:
      return "stopped";
    case EnvironmentState.ARCHIVING:
      return "archiving";
    case EnvironmentState.ARCHIVED:
      return "archived";
    case EnvironmentState.RESTORING:
      return "restoring";
    case EnvironmentState.RESIZING:
      return "resizing";
    case EnvironmentState.DESTROYING:
      return "destroying";
    case EnvironmentState.DESTROYED:
      return "destroyed";
    case EnvironmentState.ERROR:
      return "error";
    case EnvironmentState.UNKNOWN:
    default:
      return "unknown";
  }
}

function mapDesiredState(state: DesiredState): string {
  switch (state) {
    case DesiredState.UNSPECIFIED:
      return "";
    case DesiredState.STARTED:
      return "started";
    case DesiredState.STOPPED:
      return "stopped";
    case DesiredState.DESTROYED:
      return "destroyed";
    case DesiredState.ARCHIVED:
      return "archived";
    case DesiredState.RESIZED:
      return "resized";
    default:
      return "unknown";
  }
}

function toProtoEnvironmentState(value: string | undefined): EnvironmentState {
  switch (value) {
    case undefined:
    case "":
      return EnvironmentState.UNSPECIFIED;
    case "pending":
      return EnvironmentState.PENDING;
    case "pending_build":
      return EnvironmentState.PENDING_BUILD;
    case "building":
      return EnvironmentState.BUILDING;
    case "build_failed":
      return EnvironmentState.BUILD_FAILED;
    case "pulling_snapshot":
      return EnvironmentState.PULLING_SNAPSHOT;
    case "creating":
      return EnvironmentState.CREATING;
    case "starting":
      return EnvironmentState.STARTING;
    case "running":
      return EnvironmentState.RUNNING;
    case "stopping":
      return EnvironmentState.STOPPING;
    case "stopped":
      return EnvironmentState.STOPPED;
    case "archiving":
      return EnvironmentState.ARCHIVING;
    case "archived":
      return EnvironmentState.ARCHIVED;
    case "restoring":
      return EnvironmentState.RESTORING;
    case "resizing":
      return EnvironmentState.RESIZING;
    case "destroying":
      return EnvironmentState.DESTROYING;
    case "destroyed":
      return EnvironmentState.DESTROYED;
    case "error":
      return EnvironmentState.ERROR;
    case "unknown":
      return EnvironmentState.UNKNOWN;
    default:
      return -1 as EnvironmentState;
  }
}

function mapPortAccess(access: PortAccess): string {
  switch (access) {
    case PortAccess.UNSPECIFIED:
      return "";
    case PortAccess.PUBLIC:
      return "public";
    case PortAccess.ORG_MEMBERS:
      return "org_members";
    case PortAccess.CREATOR:
      return "creator";
    default:
      return "unknown";
  }
}

function toProtoPortAccess(access: string | undefined): PortAccess {
  switch (access) {
    case undefined:
    case "":
      return PortAccess.UNSPECIFIED;
    case "public":
      return PortAccess.PUBLIC;
    case "org_members":
      return PortAccess.ORG_MEMBERS;
    case "creator":
      return PortAccess.CREATOR;
    default:
      return -1 as PortAccess;
  }
}

function fromProtoSetupAgents(
  value: ProtoSetupAgent[],
): Array<{ type: string }> | undefined {
  return value.length === 0 ? undefined : value.map((agent) => ({ type: agent.type }));
}

function fromProtoAppPorts(
  value: ProtoAppPort[],
): Array<{ access?: string; label: string; port: number }> | undefined {
  return value.length === 0
    ? undefined
    : value.map((port) => ({
        access: optionalString(port.access),
        label: port.label,
        port: port.port,
      }));
}

function fromProtoRepos(
  value: ProtoRepoEntry[],
): Array<{ branch?: string; url: string }> | undefined {
  return value.length === 0
    ? undefined
    : value.map((repo) => ({ branch: optionalString(repo.branch), url: repo.url }));
}

function fromProtoSetupConfig(
  value: ProtoSetupConfig | undefined,
): TemplateData["default_setup_config"] {
  if (!value) return undefined;
  return {
    agent: optionalString(value.agent),
    agent_env: copyStringMap(value.agentEnv),
    agents: fromProtoSetupAgents(value.agents),
    app_ports: fromProtoAppPorts(value.appPorts),
    branch: optionalString(value.branch),
    env_vars: copyStringMap(value.envVars),
    include_org_secrets: value.includeOrgSecrets,
    include_user_secrets: value.includeUserSecrets,
    install_agents: value.installAgents,
    install_command: optionalString(value.installCommand),
    repo_url: optionalString(value.repoUrl),
    repos: fromProtoRepos(value.repos),
    startup_script: optionalString(value.startupScript),
  };
}

function toProtoAgents(value: Array<{ type?: string }> | null | undefined) {
  return (value ?? []).map((agent) => ({ type: agent.type ?? "" }));
}

function toProtoAppPorts(
  value: Array<{ access?: string; label?: string; port?: number }> | null | undefined,
) {
  return (value ?? []).map((port) => ({
    access: port.access ?? "",
    label: port.label ?? "",
    port: int32("app port", port.port) ?? 0,
  }));
}

function toProtoRepos(value: Array<{ branch?: string; url?: string }> | undefined) {
  return (value ?? []).map((repo) => ({
    branch: repo.branch ?? "",
    url: repo.url ?? "",
  }));
}

function optionalUpdateString(value: string | null | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value ?? "";
}

/** Protobuf-es represents int64 as bigint; public SDK numbers stay numbers. */
export function numberFromInt64(value: bigint): number {
  return Number(value);
}

export function fromProtoAPIKey(value: ApiKey): APIKeyData {
  const apiKey: APIKeyData & { disabled?: boolean } = {
    id: value.id,
    user_id: value.userId,
    org_id: value.orgId,
    name: value.name,
    key_prefix: value.keyPrefix,
    scopes: [...value.scopes],
    last_used_at: timestampString(value.lastUsedAt),
    expires_at: timestampString(value.expiresAt),
    disabled_at: timestampString(value.disabledAt),
    created_at: timestampString(value.createdAt) ?? "",
    created_by_name: optionalString(value.createdByName),
    created_by_email: optionalString(value.createdByEmail),
  };
  if (value.disabledAt) apiKey.disabled = true;
  return apiKey;
}

export function fromProtoCreateAPIKeyResponse(
  value: ProtoCreateApiKeyResponse,
): CreateAPIKeyResponse {
  if (!value.apiKey) throw new Error("API key response omitted api_key");
  return { ...fromProtoAPIKey(value.apiKey), key: value.key };
}

export function fromProtoEnvironment(value: ProtoEnvironment): EnvironmentData {
  return {
    cpu_millicores: value.cpuMillicores,
    created_at: timestampString(value.createdAt) ?? "",
    created_by: value.createdBy,
    deletion_grace_until: timestampString(value.deletionGraceUntil),
    deletion_requested_at: timestampString(value.deletionRequestedAt),
    desired_state: mapDesiredState(value.desiredState),
    destroyed_at: timestampString(value.destroyedAt),
    disk_gb: value.diskGb,
    error_reason: optionalString(value.errorReason),
    id: value.id,
    memory_mb: value.memoryMb,
    name: optionalString(value.name),
    network: optionalString(value.network),
    org_id: value.orgId,
    ports: value.ports.length === 0 ? undefined : value.ports.map(fromProtoEnvironmentPort),
    preset_id: optionalString(value.presetId),
    preset_name: optionalString(value.presetName),
    protected: value.protected,
    recoverable: value.recoverable,
    retry_count: value.retryCount,
    setup_complete: value.setupComplete,
    setup_error: optionalString(value.setupError),
    setup_phase: value.setupPhase,
    shutdown_at: timestampString(value.shutdownAt),
    started_at: timestampString(value.startedAt),
    state: mapEnvironmentState(value.state),
    state_changed_at: timestampString(value.stateChangedAt) ?? "",
    stopped_at: timestampString(value.stoppedAt),
    total_running_seconds: value.totalRunningSeconds,
    ttl_seconds: value.ttlSeconds,
    type: value.type,
  };
}

export function fromProtoEnvironmentPort(value: ProtoPort): EnvironmentPort {
  return {
    access: mapPortAccess(value.access),
    created_at: timestampString(value.createdAt) ?? "",
    environment_id: value.environmentId,
    id: value.id,
    label: value.label,
    port: value.port,
    preview_url: optionalString(value.previewUrl),
  };
}

export function fromProtoExecResult(value: ExecResponse): ExecResult {
  return {
    exit_code: value.exitCode,
    stdout: new TextDecoder().decode(value.stdout),
    stderr: new TextDecoder().decode(value.stderr),
  };
}

export function fromProtoFileEntry(value: ProtoFileEntry): FileEntry {
  return {
    is_dir: value.isDir,
    mod_time: timestampString(value.modTime) ?? "",
    mode: (value.mode & 0o777).toString(8).padStart(4, "0"),
    name: value.name,
    size: numberFromInt64(value.size),
  };
}

export function fromProtoPreset(value: ProtoPreset): TemplateData {
  return {
    build_error: optionalString(value.buildError),
    build_status: value.buildStatus,
    created_at: timestampString(value.createdAt) ?? "",
    default_cpu_millicores: value.defaultCpuMillicores,
    default_disk_gb: value.defaultDiskGb,
    default_memory_mb: value.defaultMemoryMb,
    default_setup_config: fromProtoSetupConfig(value.defaultSetupConfig),
    default_ttl_seconds: value.defaultTtlSeconds,
    description: optionalString(value.description),
    id: value.id,
    image: optionalString(value.image),
    language: optionalString(value.language),
    name: value.name,
    official: value.official,
    org_id: optionalString(value.orgId),
    secret_project_id: optionalString(value.secretProjectId),
    slug: optionalString(value.slug),
  };
}

export function fromProtoSecretMetadata(value: ProtoSecretMetadata): SecretMetadata {
  return {
    key: value.key,
    created_at: timestampString(value.createdAt),
    updated_at: timestampString(value.updatedAt),
  };
}

export function fromProtoSecretProject(value: ProtoSecretProject): SecretProject {
  return {
    created_at: timestampString(value.createdAt) ?? "",
    id: value.id,
    name: value.name,
    org_id: value.orgId,
    secret_count: value.secretCount === 0n ? undefined : numberFromInt64(value.secretCount),
  };
}

export function toProtoCreateEnvironmentRequest(
  orgId: string,
  body: CreateEnvironmentRequest,
) {
  return {
    orgId,
    presetId: body.preset_id ?? undefined,
    name: body.name ?? undefined,
    cpuMillicores: int32("cpu_millicores", body.cpu_millicores),
    memoryMb: int32("memory_mb", body.memory_mb),
    diskGb: int32("disk_gb", body.disk_gb),
    ttlSeconds: int32("ttl_seconds", body.ttl_seconds),
    presetSlug: body.preset_slug ?? "",
    repoUrl: body.repo_url ?? "",
    branch: body.branch ?? "",
    repos: toProtoRepos(body.repos),
    image: body.image ?? "",
    installCommand: body.install_command ?? "",
    startupScript: body.startup_script ?? "",
    envVars: body.env_vars ? { ...body.env_vars } : {},
    agents: toProtoAgents(body.agents),
    installAgents: body.install_agents ?? undefined,
    agent: body.agent ?? "",
    agentEnv: body.agent_env ? { ...body.agent_env } : {},
    secretProject: body.secret_project ?? "",
    appPorts: toProtoAppPorts(body.app_ports),
    includeOrgSecrets: body.include_org_secrets ?? undefined,
    includeUserSecrets: body.include_user_secrets ?? undefined,
  };
}

export function toProtoExecRequest(orgId: string, environmentId: string, body: ExecRequest) {
  const timeout = body.timeout === undefined
    ? undefined
    : { seconds: BigInt(body.timeout), nanos: 0 };
  return {
    orgId,
    environmentId,
    command: body.command ? [...body.command] : [],
    workingDir: body.working_dir ?? "",
    env: body.env ? { ...body.env } : {},
    timeout,
  };
}

export function toProtoCreatePortRequest(
  orgId: string,
  environmentId: string,
  body: CreatePortRequest,
) {
  return {
    orgId,
    environmentId,
    port: int32("port", body.port) ?? 0,
    label: body.label,
    access: toProtoPortAccess(body.access),
  };
}

export function toProtoListEnvironmentsRequest(
  orgId: string,
  params: ListEnvironmentsParams | undefined,
) {
  return {
    orgId,
    type: params?.type ?? "",
    state: toProtoEnvironmentState(params?.state),
  };
}

export function toProtoCreatePresetRequest(
  orgId: string,
  body: CreateTemplateRequest,
  secretProjectId: string | undefined,
) {
  return {
    orgId,
    name: body.name,
    slug: body.slug ?? "",
    description: body.description ?? undefined,
    defaultCpuMillicores: int32("default_cpu_millicores", body.default_cpu_millicores),
    defaultMemoryMb: int32("default_memory_mb", body.default_memory_mb),
    defaultDiskGb: int32("default_disk_gb", body.default_disk_gb),
    defaultTtlSeconds: int32("default_ttl_seconds", body.default_ttl_seconds),
    image: body.image ?? "",
    installCommand: body.install_command ?? "",
    startupScript: body.startup_script ?? "",
    envVars: body.env_vars ? { ...body.env_vars } : {},
    agents: toProtoAgents(body.agents),
    installAgents: body.install_agents ?? undefined,
    agent: body.agent ?? "",
    agentEnv: body.agent_env ? { ...body.agent_env } : {},
    appPorts: toProtoAppPorts(body.app_ports),
    includeOrgSecrets: body.include_org_secrets ?? undefined,
    includeUserSecrets: body.include_user_secrets ?? undefined,
    secretProjectId,
  };
}

export function toProtoUpdatePresetRequest(
  orgId: string,
  presetId: string,
  body: UpdateTemplateRequest,
  secretProjectId: string | undefined,
) {
  return {
    orgId,
    presetId,
    name: optionalUpdateString(body.name),
    description: optionalUpdateString(body.description),
    slug: optionalUpdateString(body.slug),
    defaultCpuMillicores: int32("default_cpu_millicores", body.default_cpu_millicores),
    defaultMemoryMb: int32("default_memory_mb", body.default_memory_mb),
    defaultDiskGb: int32("default_disk_gb", body.default_disk_gb),
    defaultTtlSeconds: int32("default_ttl_seconds", body.default_ttl_seconds),
    image: optionalUpdateString(body.image),
    installCommand: optionalUpdateString(body.install_command),
    startupScript: optionalUpdateString(body.startup_script),
    envVars: body.env_vars === undefined ? undefined : { values: body.env_vars ?? {} },
    agents: body.agents === undefined ? undefined : { values: toProtoAgents(body.agents) },
    installAgents: body.install_agents ?? undefined,
    agent: optionalUpdateString(body.agent),
    agentEnv: body.agent_env === undefined ? undefined : { values: body.agent_env ?? {} },
    appPorts: body.app_ports === undefined ? undefined : { values: toProtoAppPorts(body.app_ports) },
    includeOrgSecrets: body.include_org_secrets ?? undefined,
    includeUserSecrets: body.include_user_secrets ?? undefined,
    secretProjectId,
  };
}

export function pollIntervalMs(value: Duration | undefined): number {
  if (!value) return 2_000;
  const milliseconds = Number(value.seconds) * 1_000 + Math.trunc(value.nanos / 1_000_000);
  return Number.isFinite(milliseconds) && milliseconds > 0 ? milliseconds : 2_000;
}

function assertDescriptorCoverage(
  name: string,
  fields: ReadonlyArray<{ number: number; name: string }>,
  expected: Map<number, string>,
): void {
  if (fields.length !== expected.size) {
    throw new Error(`${name} converter covers ${expected.size} descriptor fields, expected ${fields.length}`);
  }
  for (const field of fields) {
    if (expected.get(field.number) !== field.name) {
      throw new Error(`${name} converter does not cover descriptor field ${field.name}`);
    }
  }
}

/** Throws when a future proto field is not deliberately mapped. */
export function assertAPIKeyConverterCoverage(): void {
  assertDescriptorCoverage("API key", ApiKeySchema.fields, apiKeyDescriptorFields);
}

/** Throws when a future runtime proto field has no owned SDK conversion. */
export function assertRuntimeConverterCoverage(): void {
  assertDescriptorCoverage("environment", EnvironmentSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "created_by"], [4, "preset_id"], [5, "type"], [6, "name"], [7, "state"], [8, "desired_state"], [9, "error_reason"], [10, "recoverable"], [11, "state_changed_at"], [12, "retry_count"], [13, "setup_phase"], [14, "setup_complete"], [15, "setup_error"], [16, "ttl_seconds"], [17, "shutdown_at"], [18, "cpu_millicores"], [19, "memory_mb"], [20, "disk_gb"], [21, "total_running_seconds"], [22, "created_at"], [23, "started_at"], [24, "stopped_at"], [25, "destroyed_at"], [26, "protected"], [27, "deletion_requested_at"], [28, "deletion_grace_until"], [29, "preset_name"], [30, "network"], [31, "ports"],
  ]));
  assertDescriptorCoverage("environment port", PortSchema.fields, new Map([
    [1, "id"], [2, "environment_id"], [3, "port"], [4, "label"], [5, "access"], [6, "preview_url"], [7, "created_at"],
  ]));
  assertDescriptorCoverage("file entry", FileEntrySchema.fields, new Map([
    [1, "name"], [2, "size"], [3, "is_dir"], [4, "mode"], [5, "mod_time"],
  ]));
  assertDescriptorCoverage("preset", PresetSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "name"], [4, "slug"], [5, "language"], [6, "official"], [7, "description"], [8, "build_status"], [9, "build_error"], [10, "default_cpu_millicores"], [11, "default_memory_mb"], [12, "default_disk_gb"], [13, "default_ttl_seconds"], [14, "image"], [15, "default_setup_config"], [16, "secret_project_id"], [17, "created_at"],
  ]));
  assertDescriptorCoverage("secret metadata", SecretMetadataSchema.fields, new Map([
    [1, "key"], [2, "created_at"], [3, "updated_at"],
  ]));
  assertDescriptorCoverage("secret project", SecretProjectSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "name"], [4, "secret_count"], [5, "created_at"],
  ]));
}
