import { Environments } from "./environments.js";
import { Presets } from "./presets.js";
import { APIKeys } from "./api-keys.js";
import { Secrets } from "./secrets.js";
import { SecretProjects } from "./secret-projects.js";
import { createCodewireClients } from "./transport.js";
import type { ClientOptions } from "./types.js";

export class Codewire {
  readonly environments: Environments;
  readonly presets: Presets;
  readonly apiKeys: APIKeys;
  readonly secrets: Secrets;
  readonly secretProjects: SecretProjects;

  constructor(opts: ClientOptions = {}) {
    // Missing credentials fail only when a generated Connect service sends a
    // request, so constructing the client does not access the platform.
    const apiKey = opts.apiKey ?? process.env.CODEWIRE_API_KEY ?? "";
    const baseUrl = opts.baseUrl ?? "https://codewire.sh";
    const orgId = opts.orgId ?? process.env.CODEWIRE_ORG_ID ?? "";
    const clients = createCodewireClients({
      apiKey,
      baseUrl,
      fetch: opts.fetch,
      timeout: opts.timeout,
    });
    this.environments = new Environments(clients, orgId);
    this.presets = new Presets(clients.presets, orgId);
    this.apiKeys = new APIKeys(clients.apiKeys, orgId);
    this.secrets = new Secrets(clients.secrets, orgId);
    this.secretProjects = new SecretProjects(clients.secrets, orgId);
  }
}

export { Codewire as default };
export { CodewireError } from "./types.js";
export { Environment } from "./environment.js";
export { Files } from "./files.js";
export {
  MeshClient,
  MeshGroupsService,
  MeshKVService,
  MeshNetworksService,
  MeshNodesService,
} from "./mesh.js";
export type {
  MeshClientOptions,
  MeshEnrollment,
  MeshGroup,
  MeshGroupMember,
  MeshGroupDebugPolicy,
  MeshGroupMessagesPolicy,
  MeshGroupPolicy,
  MeshKVEntry,
  MeshNetwork,
  MeshNode,
  MeshNodeRegistration,
  MeshTTL,
} from "./mesh.js";
export type {
  ClientOptions,
  FieldViolation,
  CreateEnvironmentRequest,
  ApplicationPort,
  RepositorySpec,
  ProjectAgents,
  ProjectSkillSelection,
  ProjectResources,
  ProjectSecretBindings,
  ProjectAccessBinding,
  ProjectSpec,
  EnvironmentData,
  IsolationTier,
  EnvironmentResources,
  EnvironmentResizeFailure,
  EnvironmentResizeOperation,
  EnvironmentResizePlan,
  ResizeEnvironmentRequest,
  PresetData,
  CreatePresetRequest,
  UpdatePresetRequest,
  APIKeyData,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
  ExecRequest,
  ExecResult,
  FileEntry,
  EnvironmentPort,
  CreatePortRequest,
  SecretMetadata,
  WorkloadSecretSource,
  WorkloadSecretPreviewInput,
  ResolvedWorkloadSecretMetadata,
  SecretProject,
  CreateSecretProjectRequest,
  SetSecretRequest,
  SetUserSecretRequest,
  SetProjectSecretRequest,
  ListEnvironmentsParams,
  StatusResponse,
} from "./types.js";
