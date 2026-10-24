import type { Duration, Timestamp } from "@bufbuild/protobuf/wkt";
import {
  ApiKeySchema,
  type ApiKey,
  type CreateApiKeyResponse as ProtoCreateApiKeyResponse,
} from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import {
  ApplicationPortSchema,
  ProjectAgentsSchema,
  ProjectCredentialBindingSchema,
  ProjectResourcesSchema,
  ProjectSecretBindingsSchema,
  ProjectSkillSelectionSchema,
  ProjectSkillSource,
  ProjectStoragePlacement,
  ProjectSpecSchema,
  RepositorySpecSchema,
  type ApplicationPort as ProtoApplicationPort,
  type ProjectSpec as ProtoProjectSpec,
  type RepositorySpec as ProtoRepositorySpec,
} from "@codewire/proto-ts/gen/codewire/v1/common_pb";
import {
  CreateEnvironmentRequestSchema,
  DesiredState,
  EnvironmentSourceSelectionSchema,
  EnvironmentSourcesUpdateOutcome,
  EnvironmentResizeDisruptionPolicy,
  EnvironmentResizeExecutionMode,
  EnvironmentResizeOperationState,
  EnvironmentSchema,
  EnvironmentState,
  IsolationTier as ProtoIsolationTier,
  NetworkAttachmentFailure as ProtoNetworkAttachmentFailure,
  NetworkAttachmentState as ProtoNetworkAttachmentState,
  UpdateEnvironmentSourcesRequestSchema,
  UpdateEnvironmentSourcesResponseSchema,
  type Environment as ProtoEnvironment,
  type EnvironmentSourceSelection as ProtoEnvironmentSourceSelection,
  type EnvironmentResizeOperation as ProtoEnvironmentResizeOperation,
  type EnvironmentResizePlan as ProtoEnvironmentResizePlan,
  type UpdateEnvironmentSourcesResponse as ProtoUpdateEnvironmentSourcesResponse,
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
  CreatePresetRequestSchema,
  PresetSchema,
  UpdatePresetRequestSchema,
  type Preset as ProtoPreset,
} from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import {
  WorkloadSecretSource as ProtoWorkloadSecretSource,
  SecretMetadataSchema,
  SecretProjectSchema,
  type ResolvedWorkloadSecretMetadata as ProtoResolvedWorkloadSecretMetadata,
  type SecretMetadata as ProtoSecretMetadata,
  type SecretProject as ProtoSecretProject,
} from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import type {
  APIKeyData,
  CreateAPIKeyResponse,
  CreateEnvironmentRequest,
  CreatePortRequest,
  CreatePresetRequest,
  EnvironmentData,
  EnvironmentSourceSelection,
  EnvironmentSourcesUpdate,
  EnvironmentResizeOperation,
  EnvironmentPort,
  ExecRequest,
  ExecResult,
  FileEntry,
  IsolationTier,
  NetworkAttachmentFailure,
  NetworkAttachmentState,
  ListEnvironmentsParams,
  ProjectSkillSelection,
  ProjectStoragePlacement as SdkProjectStoragePlacement,
  ProjectSpec,
  ResolvedWorkloadSecretMetadata,
  SecretMetadata,
  SecretProject,
  PresetData,
  UpdatePresetRequest,
  UpdateEnvironmentSourcesRequest,
  WorkloadSecretSource,
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

function uint32(name: string, value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 0 || value > 4_294_967_295) {
    throw new Error(`codewire: ${name} is outside the API unsigned integer range`);
  }
  return value;
}

function uint64(
  name: string,
  value: bigint | undefined,
  positive = false,
): bigint | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "bigint" ||
    value < (positive ? 1n : 0n) ||
    value > 0xffff_ffff_ffff_ffffn
  ) {
    throw new Error(
      `codewire: ${name} must be ${positive ? "a positive " : "a "}uint64 bigint`,
    );
  }
  return value;
}

function explicitBoolean(name: string, value: boolean | undefined): boolean {
  if (value === undefined) return false;
  if (typeof value !== "boolean") {
    throw new Error(`codewire: ${name} must be an explicit boolean`);
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

function mapNetworkAttachmentState(
  value: ProtoNetworkAttachmentState,
): NetworkAttachmentState | undefined {
  switch (value) {
    case ProtoNetworkAttachmentState.UNSPECIFIED:
      return undefined;
    case ProtoNetworkAttachmentState.PENDING:
      return "pending";
    case ProtoNetworkAttachmentState.ATTACHED:
      return "attached";
    case ProtoNetworkAttachmentState.FAILED:
      return "failed";
    case ProtoNetworkAttachmentState.REVOKED:
      return "revoked";
    default:
      return "unknown";
  }
}

function mapNetworkAttachmentFailure(
  value: ProtoNetworkAttachmentFailure,
): NetworkAttachmentFailure | undefined {
  switch (value) {
    case ProtoNetworkAttachmentFailure.UNSPECIFIED:
      return undefined;
    case ProtoNetworkAttachmentFailure.MESH_UNREACHABLE:
      return "mesh_unreachable";
    case ProtoNetworkAttachmentFailure.NETWORK_NOT_FOUND:
      return "network_not_found";
    case ProtoNetworkAttachmentFailure.NOT_A_MEMBER:
      return "not_a_member";
    case ProtoNetworkAttachmentFailure.NODE_NAME_TAKEN:
      return "node_name_taken";
    case ProtoNetworkAttachmentFailure.REFUSED:
      return "refused";
    default:
      return "unknown";
  }
}

function mapIsolationTier(value: ProtoIsolationTier): IsolationTier {
  switch (value) {
    case ProtoIsolationTier.UNSPECIFIED:
    case ProtoIsolationTier.STANDARD:
      return "standard";
    case ProtoIsolationTier.CONFIDENTIAL:
      return "confidential";
    default:
      throw new Error(`codewire: unknown isolation tier ${value}`);
  }
}

function toProtoIsolationTier(value: IsolationTier | undefined): ProtoIsolationTier {
  switch (value) {
    case undefined:
    case "standard":
      return ProtoIsolationTier.STANDARD;
    case "confidential":
      return ProtoIsolationTier.CONFIDENTIAL;
    default:
      throw new Error("codewire: isolation_tier must be standard or confidential");
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

function fromProtoApplicationPorts(
  value: ProtoApplicationPort[],
): Array<{ access?: string; label: string; port: number }> | undefined {
  return value.length === 0
    ? undefined
    : value.map((port) => ({
        access: optionalString(port.access),
        label: port.label,
        port: port.port,
      }));
}

function fromProtoRepositorySpecs(
  value: ProtoRepositorySpec[],
): Array<{
  branch?: string;
  destination?: string;
  known_hosts?: string[];
  revision?: string;
  source: string;
}> | undefined {
  return value.length === 0
    ? undefined
    : value.map((repo) => ({
        branch: optionalString(repo.branch),
        destination: optionalString(repo.destination),
        known_hosts: repo.knownHosts.length ? [...repo.knownHosts] : undefined,
        revision: optionalString(repo.revision),
        source: repo.source,
      }));
}

function toProtoApplicationPorts(
  value: ProjectSpec["application_ports"],
) {
  return (value ?? []).map((port) => ({
    access: port.access ?? "",
    label: port.label,
    port: int32("app port", port.port)!,
  }));
}

function toProtoRepositorySpecs(
  value: ProjectSpec["repositories"],
) {
  return (value ?? []).map((repo) => ({
    branch: repo.branch ?? "",
    destination: repo.destination ?? "",
    knownHosts: [...(repo.known_hosts ?? [])],
    revision: repo.revision ?? "",
    source: repo.source,
  }));
}

function fromProtoProjectSpec(value: ProtoProjectSpec | undefined): ProjectSpec | undefined {
  if (!value) return undefined;
  return {
    schema_version: value.schemaVersion,
    preset: optionalString(value.preset),
    image: optionalString(value.image),
    repositories: fromProtoRepositorySpecs(value.repositories),
    working_directory: value.workingDirectory,
    install_command: optionalString(value.installCommand),
    startup_script: optionalString(value.startupScript),
    environment: copyStringMap(value.environment),
    agents: value.agents
      ? { install: value.agents.install, tools: value.agents.tools.length ? [...value.agents.tools] : undefined }
      : undefined,
    skills: value.skills.length
      ? value.skills.map((skill) => ({
          source: skill.source === ProjectSkillSource.REPOSITORY
            ? "repository" as const
            : skill.source === ProjectSkillSource.USER
            ? "user" as const
            : (() => { throw new Error("codewire: project skill source is unspecified"); })(),
          reference: skill.reference,
          agents: skill.agents.length ? [...skill.agents] : undefined,
        }))
      : undefined,
    application_ports: fromProtoApplicationPorts(value.applicationPorts),
    resources: value.resources
      ? {
          cpu_millicores: value.resources.cpuMillicores,
          memory_mib: value.resources.memoryMib,
          disk_gib: value.resources.diskGib,
        }
      : undefined,
    secrets: value.secrets
      ? {
          project: optionalString(value.secrets.project),
          organization: value.secrets.organization,
          user: value.secrets.user === undefined
            ? undefined
            : fromProtoStoragePlacement(value.secrets.user),
        }
      : undefined,
    credentials: value.credentials ? { profile: value.credentials.profile } : undefined,
  };
}

function toProtoProjectSkillSource(value: ProjectSkillSelection["source"]): ProjectSkillSource {
  switch (value) {
    case "repository": return ProjectSkillSource.REPOSITORY;
    case "user": return ProjectSkillSource.USER;
    default: throw new Error("codewire: project skill source must be repository or user");
  }
}

function toProtoProjectSpec(value: ProjectSpec | undefined) {
  if (!value) return undefined;
  return {
    schemaVersion: uint32("project schema_version", value.schema_version) ?? 0,
    preset: value.preset ?? "",
    image: value.image ?? "",
    repositories: toProtoRepositorySpecs(value.repositories),
    workingDirectory: value.working_directory,
    installCommand: value.install_command ?? "",
    startupScript: value.startup_script ?? "",
    environment: value.environment ? { ...value.environment } : {},
    agents: value.agents ? { install: value.agents.install, tools: [...(value.agents.tools ?? [])] } : undefined,
    skills: (value.skills ?? []).map((skill) => ({
      source: toProtoProjectSkillSource(skill.source),
      reference: skill.reference,
      agents: [...(skill.agents ?? [])],
    })),
    applicationPorts: toProtoApplicationPorts(value.application_ports),
    resources: value.resources
      ? {
          cpuMillicores: uint32("project cpu_millicores", value.resources.cpu_millicores),
          memoryMib: uint64("project memory_mib", value.resources.memory_mib),
          diskGib: uint64("project disk_gib", value.resources.disk_gib),
        }
      : undefined,
    secrets: value.secrets
      ? {
          project: value.secrets.project ?? "",
          organization: value.secrets.organization === undefined
            ? false
            : explicitBoolean(
                "project secrets.organization",
                value.secrets.organization,
              ),
          user: value.secrets.user === undefined
            ? undefined
            : toProtoStoragePlacement(value.secrets.user),
        }
      : undefined,
    credentials: value.credentials ? { profile: value.credentials.profile } : undefined,
  };
}

function fromProtoStoragePlacement(
  value: ProjectStoragePlacement,
): SdkProjectStoragePlacement {
  switch (value) {
    case ProjectStoragePlacement.LOCAL:
      return "local";
    case ProjectStoragePlacement.PLATFORM:
      return "platform";
    case ProjectStoragePlacement.UNSPECIFIED:
    default:
      throw new Error("codewire: personal secret storage placement is unspecified");
  }
}

function toProtoStoragePlacement(
  value: SdkProjectStoragePlacement,
): ProjectStoragePlacement {
  switch (value) {
    case "local":
      return ProjectStoragePlacement.LOCAL;
    case "platform":
      return ProjectStoragePlacement.PLATFORM;
    default:
      throw new Error("codewire: personal secret storage placement must be local or platform");
  }
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

export function fromProtoEnvironmentSourceSelection(
  value: ProtoEnvironmentSourceSelection,
): EnvironmentSourceSelection {
  const secrets = value.secrets
    ? {
        project: optionalString(value.secrets.project),
        organization: value.secrets.organization,
        user: value.secrets.user === undefined
          ? undefined
          : fromProtoStoragePlacement(value.secrets.user),
      }
    : undefined;
  const credentials = value.credentials
    ? { profile: value.credentials.profile }
    : undefined;
  const profileRevision = uint64(
    "source selection profile_revision",
    value.profileRevision,
    true,
  );
  if ((credentials === undefined) !== (profileRevision === undefined)) {
    throw new Error(
      "codewire: source selection requires credentials and profile_revision together",
    );
  }
  if (
    (secrets?.project && !canonicalPlatformId(secrets.project)) ||
    (credentials && !canonicalPlatformId(credentials.profile))
  ) {
    throw new Error(
      "codewire: environment source selection contains a non-canonical platform reference",
    );
  }
  return {
    secrets,
    credentials,
    profile_revision: profileRevision,
  };
}

export function toProtoEnvironmentSourceSelection(
  value: EnvironmentSourceSelection,
) {
  const profileRevision = uint64(
    "source selection profile_revision",
    value.profile_revision,
    true,
  );
  if ((value.credentials === undefined) !== (profileRevision === undefined)) {
    throw new Error(
      "codewire: source selection requires credentials and profile_revision together",
    );
  }
  return {
    secrets: value.secrets
      ? {
          project: value.secrets.project ?? "",
          organization: value.secrets.organization === undefined
            ? false
            : explicitBoolean(
                "source selection secrets.organization",
                value.secrets.organization,
              ),
          user: value.secrets.user === undefined
            ? undefined
            : toProtoStoragePlacement(value.secrets.user),
        }
      : undefined,
    credentials: value.credentials
      ? { profile: value.credentials.profile }
      : undefined,
    profileRevision,
  };
}

function canonicalPlatformId(value: string | undefined): boolean {
  if (!value?.startsWith("platform:id:")) return false;
  const id = value.slice("platform:id:".length);
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id) &&
    id !== "00000000-0000-0000-0000-000000000000"
  );
}

function resolvedReferenceAcknowledges(
  actual: string | undefined,
  requested: string | undefined,
): boolean {
  if (!requested) return actual === undefined;
  if (!canonicalPlatformId(actual)) return false;
  return requested.startsWith("platform:id:") ? actual === requested : true;
}

export function environmentSourceSelectionAcknowledges(
  actual: EnvironmentSourceSelection,
  requested: EnvironmentSourceSelection,
): boolean {
  // The server omits structurally empty secret bindings when encoding a selection.
  const actualSecrets = actual.secrets ?? {};
  const requestedSecrets = requested.secrets ?? {};
  if (
    !resolvedReferenceAcknowledges(
      optionalString(actualSecrets.project),
      optionalString(requestedSecrets.project),
    ) ||
    (actualSecrets.organization ?? false) !== (requestedSecrets.organization ?? false) ||
    actualSecrets.user !== requestedSecrets.user
  ) {
    return false;
  }
  return (
    (actual.credentials === undefined) === (requested.credentials === undefined) &&
    (actual.credentials === undefined ||
      resolvedReferenceAcknowledges(
        actual.credentials.profile,
        requested.credentials?.profile,
      )) &&
    actual.profile_revision === requested.profile_revision
  );
}

export function createEnvironmentSourceSelection(
  body: CreateEnvironmentRequest,
): EnvironmentSourceSelection {
  return {
    secrets: body.project_spec.secrets,
    credentials: body.project_spec.credentials,
    profile_revision: body.expected_profile_revision,
  };
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
    isolation_tier: mapIsolationTier(value.isolationTier),
    memory_mb: value.memoryMb,
    name: optionalString(value.name),
    network: optionalString(value.network),
    network_state: mapNetworkAttachmentState(value.networkState),
    network_failure: mapNetworkAttachmentFailure(value.networkFailure),
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
    operation_generation: value.operationGeneration,
    source_selection: value.sourceSelection
      ? fromProtoEnvironmentSourceSelection(value.sourceSelection)
      : undefined,
  };
}

export function fromProtoEnvironmentSourcesUpdate(
  value: ProtoUpdateEnvironmentSourcesResponse,
  expectedEnvironmentId: string,
  expectedOperationGeneration: bigint,
  expectedSelection: EnvironmentSourceSelection,
): EnvironmentSourcesUpdate {
  if (!value.selection) {
    throw new Error("environment sources response omitted selection");
  }
  const selection = fromProtoEnvironmentSourceSelection(value.selection);
  if (
    value.environmentId !== expectedEnvironmentId ||
    value.operationGeneration !== expectedOperationGeneration ||
    value.operationGeneration === 0n ||
    !environmentSourceSelectionAcknowledges(selection, expectedSelection)
  ) {
    throw new Error(
      "environment sources response did not acknowledge the exact environment operation and replacement",
    );
  }
  const outcome = (() => {
    switch (value.outcome) {
      case EnvironmentSourcesUpdateOutcome.UNCHANGED:
        return "unchanged" as const;
      case EnvironmentSourcesUpdateOutcome.STORED:
        return "stored" as const;
      case EnvironmentSourcesUpdateOutcome.RESTART_REQUIRED:
        return "restart_required" as const;
      case EnvironmentSourcesUpdateOutcome.UNSPECIFIED:
      default:
        throw new Error(
          `codewire: unknown environment sources outcome ${value.outcome}`,
        );
    }
  })();
  return {
    environment_id: value.environmentId,
    operation_generation: value.operationGeneration,
    selection,
    outcome,
  };
}

export function fromProtoEnvironmentResizeOperation(
  value: ProtoEnvironmentResizeOperation,
): EnvironmentResizeOperation {
  const state = {
    [EnvironmentResizeOperationState.UNSPECIFIED]: "unspecified",
    [EnvironmentResizeOperationState.PENDING]: "pending",
    [EnvironmentResizeOperationState.APPLYING]: "applying",
    [EnvironmentResizeOperationState.RESTARTING]: "restarting",
    [EnvironmentResizeOperationState.COMPLETED]: "completed",
    [EnvironmentResizeOperationState.FAILED]: "failed",
  }[value.state] ?? "unknown";
  const disruptionPolicy = {
    [EnvironmentResizeDisruptionPolicy.UNSPECIFIED]: "unspecified",
    [EnvironmentResizeDisruptionPolicy.LIVE_ONLY]: "live_only",
    [EnvironmentResizeDisruptionPolicy.ALLOW_RESTART]: "allow_restart",
  }[value.disruptionPolicy] ?? "unknown";
  const resources = (resource: typeof value.previousResources) =>
    resource
      ? {
          cpu_millicores: resource.cpuMillicores,
          memory_mb: resource.memoryMb,
          disk_gb: resource.diskGb,
        }
      : undefined;
  return {
    id: value.id,
    environment_id: value.environmentId,
    request_id: value.requestId,
    previous_resources: resources(value.previousResources),
    desired_resources: resources(value.desiredResources),
    last_applied_resources: resources(value.lastAppliedResources),
    state,
    disruption_policy: disruptionPolicy,
    planned_mode: resizeExecutionMode(value.plannedMode),
    applied_mode: resizeExecutionMode(value.appliedMode),
    pod_replaced: value.podReplaced,
    failure: value.failure
      ? { code: value.failure.code, message: value.failure.message }
      : undefined,
    created_at: timestampString(value.createdAt),
    updated_at: timestampString(value.updatedAt),
    completed_at: timestampString(value.completedAt),
  };
}

function resizeExecutionMode(value: EnvironmentResizeExecutionMode): string {
  return {
    [EnvironmentResizeExecutionMode.UNSPECIFIED]: "unspecified",
    [EnvironmentResizeExecutionMode.NOOP]: "noop",
    [EnvironmentResizeExecutionMode.APPLY_ON_START]: "apply_on_start",
    [EnvironmentResizeExecutionMode.IN_PLACE]: "in_place",
    [EnvironmentResizeExecutionMode.RESTART]: "restart",
  }[value] ?? "unknown";
}

export function fromProtoEnvironmentResizePlan(value: ProtoEnvironmentResizePlan) {
  const resources = (resource: typeof value.previousResources) =>
    resource
      ? {
          cpu_millicores: resource.cpuMillicores,
          memory_mb: resource.memoryMb,
          disk_gb: resource.diskGb,
        }
      : undefined;
  return {
    previous_resources: resources(value.previousResources),
    desired_resources: resources(value.desiredResources),
    execution_mode: resizeExecutionMode(value.executionMode),
    active_session_count: value.activeSessionCount,
    active_sessions_will_be_terminated: value.activeSessionsWillBeTerminated,
    reason: value.reason,
    warnings: value.warnings,
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

export function fromProtoPreset(value: ProtoPreset): PresetData {
  if (!value.projectSpec) throw new Error("preset response omitted project_spec");
  return {
    build_error: optionalString(value.buildError),
    build_status: value.buildStatus,
    created_at: timestampString(value.createdAt) ?? "",
    default_ttl_seconds: value.defaultTtlSeconds,
    description: optionalString(value.description),
    id: value.id,
    language: optionalString(value.language),
    name: value.name,
    official: value.official,
    org_id: optionalString(value.orgId),
    slug: optionalString(value.slug),
    project_spec: fromProtoProjectSpec(value.projectSpec)!,
  };
}

export function fromProtoSecretMetadata(value: ProtoSecretMetadata): SecretMetadata {
  return {
    key: value.key,
    created_at: timestampString(value.createdAt),
    updated_at: timestampString(value.updatedAt),
  };
}

function workloadSecretSource(value: ProtoWorkloadSecretSource): WorkloadSecretSource {
  switch (value) {
    case ProtoWorkloadSecretSource.ORGANIZATION:
      return "organization";
    case ProtoWorkloadSecretSource.PROJECT:
      return "project";
    case ProtoWorkloadSecretSource.USER:
      return "user";
    case ProtoWorkloadSecretSource.EXPLICIT_ENVIRONMENT:
      return "explicit_environment";
    default:
      throw new Error(`codewire: invalid workload-secret source ${value}`);
  }
}

export function fromProtoResolvedWorkloadSecretMetadata(
  value: ProtoResolvedWorkloadSecretMetadata,
): ResolvedWorkloadSecretMetadata {
  return {
    key: value.key,
    source: workloadSecretSource(value.source),
    overridden_sources: value.overriddenSources.map(workloadSecretSource),
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
  const projectSpec = toProtoProjectSpec(body.project_spec);
  if (!projectSpec) throw new Error("codewire: project_spec is required");
  // Validate the profile/revision pair and source origins before transport.
  toProtoEnvironmentSourceSelection(createEnvironmentSourceSelection(body));
  return {
    orgId,
    presetId: body.preset_id ?? undefined,
    name: body.name ?? undefined,
    ttlSeconds: int32("ttl_seconds", body.ttl_seconds),
    isolationTier: toProtoIsolationTier(body.isolation_tier),
    projectSpec,
    expectedProfileRevision: uint64(
      "expected_profile_revision",
      body.expected_profile_revision,
      true,
    ),
    confirmPersonalCredentials: explicitBoolean(
      "confirm_personal_credentials",
      body.confirm_personal_credentials,
    ),
    confirmPersonalSecrets: explicitBoolean(
      "confirm_personal_secrets",
      body.confirm_personal_secrets,
    ),
    omitApplicationPreviews: explicitBoolean(
      "omit_application_previews",
      body.omit_application_previews,
    ),
    network: optionalNetwork(body.network),
  };
}

function optionalNetwork(value: string | null | undefined): string {
  if (value === undefined || value === null) {
    return "";
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("codewire: network must be a nonempty Mesh network name");
  }
  return value;
}

export function toProtoUpdateEnvironmentSourcesRequest(
  orgId: string,
  environmentId: string,
  body: UpdateEnvironmentSourcesRequest,
) {
  if (!body.expected || !body.replacement) {
    throw new Error(
      "codewire: expected and replacement source selections are required",
    );
  }
  return {
    orgId,
    environmentId,
    expectedOperationGeneration: uint64(
      "expected_operation_generation",
      body.expected_operation_generation,
      true,
    )!,
    expected: toProtoEnvironmentSourceSelection(body.expected),
    replacement: toProtoEnvironmentSourceSelection(body.replacement),
    allowRestart: explicitBoolean("allow_restart", body.allow_restart),
    confirmPersonalCredentials: explicitBoolean(
      "confirm_personal_credentials",
      body.confirm_personal_credentials,
    ),
    confirmPersonalSecrets: explicitBoolean(
      "confirm_personal_secrets",
      body.confirm_personal_secrets,
    ),
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
  body: CreatePresetRequest,
) {
  const projectSpec = toProtoProjectSpec(body.project_spec);
  if (!projectSpec) throw new Error("codewire: project_spec is required");
  return {
    orgId,
    name: body.name,
    slug: body.slug ?? "",
    description: body.description ?? undefined,
    defaultTtlSeconds: int32("default_ttl_seconds", body.default_ttl_seconds),
    projectSpec,
  };
}

export function toProtoUpdatePresetRequest(
  orgId: string,
  presetId: string,
  body: UpdatePresetRequest,
) {
  return {
    orgId,
    presetId,
    name: optionalUpdateString(body.name),
    description: optionalUpdateString(body.description),
    slug: optionalUpdateString(body.slug),
    defaultTtlSeconds: int32("default_ttl_seconds", body.default_ttl_seconds),
    projectSpec: toProtoProjectSpec(body.project_spec),
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
  assertDescriptorCoverage("repository spec", RepositorySpecSchema.fields, new Map([
    [1, "source"], [2, "branch"], [3, "destination"], [4, "revision"], [5, "known_hosts"],
  ]));
  assertDescriptorCoverage("application port", ApplicationPortSchema.fields, new Map([
    [1, "port"], [2, "label"], [3, "access"],
  ]));
  assertDescriptorCoverage("project agents", ProjectAgentsSchema.fields, new Map([
    [1, "install"], [2, "tools"],
  ]));
  assertDescriptorCoverage("project skill", ProjectSkillSelectionSchema.fields, new Map([
    [1, "source"], [2, "reference"], [3, "agents"],
  ]));
  assertDescriptorCoverage("project resources", ProjectResourcesSchema.fields, new Map([
    [1, "cpu_millicores"], [2, "memory_mib"], [3, "disk_gib"],
  ]));
  assertDescriptorCoverage("project secrets", ProjectSecretBindingsSchema.fields, new Map([
    [1, "project"], [4, "organization"], [6, "user"],
  ]));
  assertDescriptorCoverage("project credentials", ProjectCredentialBindingSchema.fields, new Map([
    [1, "profile"],
  ]));
  assertDescriptorCoverage("project spec", ProjectSpecSchema.fields, new Map([
    [1, "schema_version"], [2, "preset"], [3, "image"], [4, "repositories"], [5, "working_directory"], [6, "install_command"], [7, "startup_script"], [8, "environment"], [9, "agents"], [11, "skills"], [12, "application_ports"], [13, "resources"], [14, "secrets"], [18, "credentials"],
  ]));
  assertDescriptorCoverage("environment", EnvironmentSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "created_by"], [4, "preset_id"], [5, "type"], [6, "name"], [7, "state"], [8, "desired_state"], [9, "error_reason"], [10, "recoverable"], [11, "state_changed_at"], [12, "retry_count"], [13, "setup_phase"], [14, "setup_complete"], [15, "setup_error"], [16, "ttl_seconds"], [17, "shutdown_at"], [18, "cpu_millicores"], [19, "memory_mb"], [20, "disk_gb"], [21, "total_running_seconds"], [22, "created_at"], [23, "started_at"], [24, "stopped_at"], [25, "destroyed_at"], [26, "protected"], [27, "deletion_requested_at"], [28, "deletion_grace_until"], [29, "preset_name"], [30, "network"], [31, "ports"], [32, "isolation_tier"], [33, "operation_generation"], [34, "source_selection"], [35, "network_state"], [36, "network_failure"],
  ]));
  assertDescriptorCoverage("create environment request", CreateEnvironmentRequestSchema.fields, new Map([
    [1, "org_id"], [2, "preset_id"], [3, "name"], [7, "ttl_seconds"], [24, "isolation_tier"], [25, "project_spec"], [26, "expected_profile_revision"], [27, "confirm_personal_credentials"], [28, "confirm_personal_secrets"], [29, "omit_application_previews"], [30, "network"],
  ]));
  assertDescriptorCoverage("environment source selection", EnvironmentSourceSelectionSchema.fields, new Map([
    [1, "secrets"], [2, "credentials"], [3, "profile_revision"],
  ]));
  assertDescriptorCoverage("update environment sources request", UpdateEnvironmentSourcesRequestSchema.fields, new Map([
    [1, "org_id"], [2, "environment_id"], [3, "expected_operation_generation"], [4, "expected"], [5, "replacement"], [6, "allow_restart"], [7, "confirm_personal_credentials"], [8, "confirm_personal_secrets"],
  ]));
  assertDescriptorCoverage("update environment sources response", UpdateEnvironmentSourcesResponseSchema.fields, new Map([
    [1, "environment_id"], [2, "operation_generation"], [3, "selection"], [4, "outcome"],
  ]));
  assertDescriptorCoverage("environment port", PortSchema.fields, new Map([
    [1, "id"], [2, "environment_id"], [3, "port"], [4, "label"], [5, "access"], [6, "preview_url"], [7, "created_at"],
  ]));
  assertDescriptorCoverage("file entry", FileEntrySchema.fields, new Map([
    [1, "name"], [2, "size"], [3, "is_dir"], [4, "mode"], [5, "mod_time"],
  ]));
  assertDescriptorCoverage("preset", PresetSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "name"], [4, "slug"], [5, "language"], [6, "official"], [7, "description"], [8, "build_status"], [9, "build_error"], [13, "default_ttl_seconds"], [17, "created_at"], [18, "project_spec"],
  ]));
  assertDescriptorCoverage("create preset request", CreatePresetRequestSchema.fields, new Map([
    [1, "org_id"], [2, "name"], [3, "slug"], [4, "description"], [8, "default_ttl_seconds"], [21, "project_spec"],
  ]));
  assertDescriptorCoverage("update preset request", UpdatePresetRequestSchema.fields, new Map([
    [1, "org_id"], [2, "preset_id"], [3, "name"], [4, "description"], [5, "slug"], [9, "default_ttl_seconds"], [22, "project_spec"],
  ]));
  assertDescriptorCoverage("secret metadata", SecretMetadataSchema.fields, new Map([
    [1, "key"], [2, "created_at"], [3, "updated_at"],
  ]));
  assertDescriptorCoverage("secret project", SecretProjectSchema.fields, new Map([
    [1, "id"], [2, "org_id"], [3, "name"], [4, "secret_count"], [5, "created_at"],
  ]));
}
