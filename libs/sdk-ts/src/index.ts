import { Environments } from "./environments.js";
import { Templates } from "./templates.js";
import { APIKeys } from "./api-keys.js";
import { Secrets } from "./secrets.js";
import { SecretProjects } from "./secret-projects.js";
import { LocalService } from "./local.js";
import { createCodewireClients } from "./transport.js";
import type { ClientOptions } from "./types.js";

export class Codewire {
  readonly environments: Environments;
  readonly templates: Templates;
  readonly apiKeys: APIKeys;
  readonly secrets: Secrets;
  readonly secretProjects: SecretProjects;
  readonly local: LocalService;

  constructor(opts: ClientOptions = {}) {
    // API key is resolved lazily so callers that only use `client.local`
    // (which shells out to the `cw` CLI) can construct a Codewire() with no
    // environment variables set. Missing credentials only fail at
    // request-time for generated Connect services.
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
    this.templates = new Templates(clients.presets, clients.secrets, orgId);
    this.apiKeys = new APIKeys(clients.apiKeys, orgId);
    this.secrets = new Secrets(clients.secrets, orgId);
    this.secretProjects = new SecretProjects(clients.secrets, orgId);
    this.local = new LocalService();
  }
}

export { Codewire as default };
export { CodewireError } from "./types.js";
export { Environment } from "./environment.js";
export { Files } from "./files.js";
export {
  LocalError,
  LocalInstance,
  LocalService,
} from "./local.js";
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
  MeshNodeCredentials,
  MeshTTL,
} from "./mesh.js";
export type {
  LocalSpec,
  LocalSpecPort,
  LocalSpecMount,
  LocalPort,
  LocalMount,
  LocalLimaInfo,
  LocalInstanceData,
  LocalExecRequest,
  LocalExecResult,
  LocalCreateOptions,
} from "./local.js";
export type {
  ClientOptions,
  FieldViolation,
  CreateEnvironmentRequest,
  EnvironmentData,
  TemplateData,
  CreateTemplateRequest,
  UpdateTemplateRequest,
  APIKeyData,
  CreateAPIKeyRequest,
  CreateAPIKeyResponse,
  ExecRequest,
  ExecResult,
  FileEntry,
  EnvironmentPort,
  CreatePortRequest,
  SecretMetadata,
  SecretProject,
  CreateSecretProjectRequest,
  SetSecretRequest,
  SetUserSecretRequest,
  SetProjectSecretRequest,
  ListEnvironmentsParams,
  StatusResponse,
} from "./types.js";
