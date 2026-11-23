import { Environments } from "./environments.js";
import { Presets } from "./presets.js";
import { APIKeys } from "./api-keys.js";
import { Secrets } from "./secrets.js";
import { SecretProjects } from "./secret-projects.js";
import { AccessProfiles } from "./access-profiles.js";
import { NetworkPolicies } from "./network-policies.js";
import { SandboxIdentity } from "./sandbox-identity.js";
import { Credentials } from "./credentials.js";
import { createCodewireClients } from "./transport.js";
import { reportOnce, resolveSettings } from "./settings.js";
import type { ClientOptions } from "./types.js";

export class Codewire {
  readonly environments: Environments;
  readonly presets: Presets;
  readonly apiKeys: APIKeys;
  readonly secrets: Secrets;
  readonly secretProjects: SecretProjects;
  readonly accessProfiles: AccessProfiles;
  readonly networkPolicies: NetworkPolicies;
  readonly sandboxIdentity: SandboxIdentity;
  readonly credentials: Credentials;

  /**
   * Each setting comes from `opts`, then the process environment, then
   * `.env.local` and `.env` in the working directory, then its default; the
   * server is never read from a `.env` file. Throws before any request when
   * there is neither `CODEWIRE_API_KEY` nor `CODEWIRE_JWT_TOKEN`, or a user
   * token has no organization.
   */
  constructor(opts: ClientOptions = {}) {
    const settings = resolveSettings(opts, { env: process.env, cwd: process.cwd() });
    reportOnce(settings.warnings);
    const orgId = settings.organizationId;
    const clients = createCodewireClients({
      bearer: settings.bearer,
      baseUrl: settings.apiUrl,
      fetch: opts.fetch,
      timeout: opts.timeout,
    });
    this.environments = new Environments(clients, orgId);
    this.presets = new Presets(clients.presets, orgId);
    this.apiKeys = new APIKeys(clients.apiKeys, orgId);
    this.secrets = new Secrets(clients.secrets, orgId);
    this.secretProjects = new SecretProjects(clients.secrets, orgId);
    this.accessProfiles = new AccessProfiles(clients.accessProfiles);
    this.networkPolicies = new NetworkPolicies(clients.networkPolicies, orgId);
    this.sandboxIdentity = new SandboxIdentity(clients.sandboxIdentity, orgId);
    this.credentials = new Credentials(clients.credentials, clients.credentialMutations, clients.githubRepositories);
  }
}

export { Codewire as default };
export { CodewireError } from "./types.js";
export { Environment } from "./environment.js";
export { Files } from "./files.js";
export { CwRuntime, CwRuntimeOutcomeUnknownError } from "./cw-runtime.js";
export { Desktop } from "./desktop.js";
export type {
  EnvironmentDesktop, EnvironmentDesktopRunning, EnvironmentDesktopState,
} from "./desktop.js";
export { PlatformAgents, PlatformAgentOutcomeUnknownError } from "./platform-agents.js";
export type {
  EnvironmentAgentScope, EnvironmentAgentSupport, EnvironmentAgentOperation,
  EnvironmentAgentLaunch, EnvironmentAgentControl, MutateEnvironmentAgentRequest,
  ListEnvironmentAgentsRequest, ReadEnvironmentAgentRequest,
} from "./platform-agents.js";
export type {
  EnvironmentCwRuntimeIdentity, EnvironmentCwRuntimeIncarnation, EnvironmentCwRuntimeExpectation,
  EnvironmentCwRuntimeOperation, EnvironmentCwRuntimeSelection,
  UpdateEnvironmentCwRuntimeHeader, RollbackEnvironmentCwRuntimeRequest,
} from "./cw-runtime.js";
export { AccessProfiles } from "./access-profiles.js";
export { NetworkPolicies } from "./network-policies.js";
export type {
  EnvironmentNetworkPolicy,
  NetworkPolicy,
  NetworkPolicyEnforcementState,
  NetworkPolicyRule,
  NetworkPolicySelector,
} from "./network-policies.js";
export { SandboxIdentity } from "./sandbox-identity.js";
export type {
  EnvironmentIdentityGroups,
  IdentityAudience,
  IdentityGroupUser,
  IdentityGroupUserReasonName,
  RegisterIdentityAudienceOptions,
  SetEnvironmentIdentityGroupsResult,
} from "./sandbox-identity.js";
export { Credentials, EnrollmentOutcomeUnknownError } from "./credentials.js";
export type {
  Credential,
  CredentialProvider,
  SshPublicKey,
  GithubRepository,
  GithubRepositoryPage,
  CodexDeviceChallenge,
  CodexEnrollmentEvent,
  CodexEnrollmentOptions,
} from "./credentials.js";
export type {
  AccessProfile,
  AccessProfileEntry,
  EnvironmentAccessProfile,
  EnvironmentAccessProfileBinding,
} from "./access-profiles.js";
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
  ProjectStoragePlacement,
  ProjectSecretBindings,
  ProjectCredentialBinding,
  ProjectNetworkBinding,
  ProjectSpec,
  EnvironmentData,
  EnvironmentSourceSelection,
  EnvironmentSourcesUpdate,
  EnvironmentSourcesUpdateOutcome,
  StartupScriptUpdate,
  UpdateEnvironmentSourcesRequest,
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
