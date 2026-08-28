import { Code, ConnectError } from "@connectrpc/connect";
import { BadRequestSchema, ErrorInfoSchema } from "@codewire/proto-ts";

/**
 * The SDK's public REST-era shapes are owned here. Keep these interfaces
 * structurally identical to the public surface they replace.
 */

interface AppPortInput {
  access?: string;
  label?: string;
  port?: number;
}

interface AppPort {
  access?: string;
  label: string;
  port: number;
}

interface RepoEntryInput {
  branch?: string;
  mount_path?: string;
  url?: string;
}

interface RepoEntry {
  branch?: string;
  mount_path?: string;
  url: string;
}

interface SetupAgentInput {
  type?: string;
}

interface SetupAgent {
  type: string;
}

interface SetupConfig {
  agent?: string;
  agent_env?: { [key: string]: string };
  agents?: SetupAgent[];
  app_ports?: AppPort[];
  branch?: string;
  env_vars?: { [key: string]: string };
  include_org_secrets?: boolean | null;
  include_user_secrets?: boolean | null;
  install_agents?: boolean | null;
  install_command?: string;
  repo_url?: string;
  repos?: RepoEntry[];
  startup_script?: string;
}

export interface EnvironmentPort {
  access: string;
  created_at: string;
  environment_id: string;
  id: string;
  label: string;
  port: number;
  preview_url?: string;
}

export type IsolationTier = "standard" | "confidential";

export interface EnvironmentData {
  cpu_millicores: number;
  created_at: string;
  created_by: string;
  deletion_grace_until?: string | null;
  deletion_requested_at?: string | null;
  desired_state: string;
  destroyed_at?: string | null;
  disk_gb: number;
  error_reason?: string | null;
  id: string;
  isolation_tier: IsolationTier;
  memory_mb: number;
  name?: string | null;
  network?: string | null;
  org_id: string;
  ports?: EnvironmentPort[];
  preset_id?: string;
  preset_name?: string | null;
  protected: boolean;
  recoverable: boolean;
  retry_count: number;
  setup_complete: boolean;
  setup_error?: string | null;
  setup_phase: number;
  shutdown_at?: string | null;
  started_at?: string | null;
  state: string;
  state_changed_at: string;
  stopped_at?: string | null;
  total_running_seconds: number;
  ttl_seconds?: number | null;
  type: string;
}

export interface EnvironmentResources {
  cpu_millicores: number;
  memory_mb: number;
  disk_gb: number;
}

export interface ResizeEnvironmentRequest extends EnvironmentResources {
  request_id: string;
  force?: boolean;
  allow_restart?: boolean;
}

export interface EnvironmentResizePlan {
  previous_resources?: EnvironmentResources;
  desired_resources?: EnvironmentResources;
  execution_mode: string;
  active_session_count: number;
  active_sessions_will_be_terminated: boolean;
  reason: string;
  warnings: string[];
}

export interface EnvironmentResizeFailure {
  code: string;
  message: string;
}

export interface EnvironmentResizeOperation {
  id: string;
  environment_id: string;
  request_id: string;
  previous_resources?: EnvironmentResources;
  desired_resources?: EnvironmentResources;
  last_applied_resources?: EnvironmentResources;
  state: string;
  disruption_policy: string;
  planned_mode: string;
  applied_mode: string;
  pod_replaced: boolean;
  failure?: EnvironmentResizeFailure;
  created_at?: string;
  updated_at?: string;
  completed_at?: string;
}

export interface TemplateData {
  build_error?: string | null;
  build_status: string;
  created_at: string;
  default_cpu_millicores: number;
  default_disk_gb: number;
  default_memory_mb: number;
  default_setup_config?: SetupConfig | null;
  default_ttl_seconds?: number | null;
  description?: string | null;
  id: string;
  image?: string | null;
  language?: string | null;
  name: string;
  official: boolean;
  org_id?: string | null;
  secret_project_id?: string | null;
  slug?: string | null;
}

export interface APIKeyData {
  created_at: string;
  created_by_email?: string;
  created_by_name?: string;
  disabled_at?: string | null;
  expires_at?: string | null;
  id: string;
  key_prefix: string;
  last_used_at?: string | null;
  name: string;
  org_id: string;
  scopes: string[];
  user_id: string;
}

export interface CreateEnvironmentRequest {
  agent?: string;
  agent_env?: { [key: string]: string };
  agents?: SetupAgentInput[];
  app_ports?: AppPortInput[];
  branch?: string;
  cpu_millicores?: number | null;
  disk_gb?: number | null;
  env_vars?: { [key: string]: string };
  image?: string;
  include_org_secrets?: boolean | null;
  include_user_secrets?: boolean | null;
  install_agents?: boolean | null;
  install_command?: string;
  isolation_tier?: IsolationTier;
  memory_mb?: number | null;
  name?: string | null;
  preset_id?: string | null;
  preset_slug?: string;
  repo_url?: string;
  repos?: RepoEntryInput[];
  secret_project?: string;
  startup_script?: string;
  ttl_seconds?: number | null;
}

export interface CreateTemplateRequest {
  agent?: string;
  agent_env?: { [key: string]: string };
  agents?: SetupAgentInput[];
  app_ports?: AppPortInput[];
  default_cpu_millicores?: number | null;
  default_disk_gb?: number | null;
  default_memory_mb?: number | null;
  default_ttl_seconds?: number | null;
  description?: string | null;
  env_vars?: { [key: string]: string };
  image?: string;
  include_org_secrets?: boolean | null;
  include_user_secrets?: boolean | null;
  install_agents?: boolean | null;
  install_command?: string;
  name: string;
  secret_project?: string;
  slug?: string;
  startup_script?: string;
}

export interface UpdateTemplateRequest {
  agent?: string | null;
  agent_env?: { [key: string]: string } | null;
  agents?: SetupAgentInput[] | null;
  app_ports?: AppPortInput[] | null;
  default_cpu_millicores?: number | null;
  default_disk_gb?: number | null;
  default_memory_mb?: number | null;
  default_ttl_seconds?: number | null;
  description?: string | null;
  env_vars?: { [key: string]: string } | null;
  image?: string | null;
  include_org_secrets?: boolean | null;
  include_user_secrets?: boolean | null;
  install_agents?: boolean | null;
  install_command?: string | null;
  name?: string | null;
  secret_project?: string | null;
  slug?: string | null;
  startup_script?: string | null;
}

export interface CreateAPIKeyRequest {
  expires_in_days?: number | null;
  name?: string;
  scopes?: string[] | null;
}

export interface CreateAPIKeyResponse {
  created_at: string;
  created_by_email?: string;
  created_by_name?: string;
  disabled_at?: string | null;
  expires_at?: string | null;
  id: string;
  key: string;
  key_prefix: string;
  last_used_at?: string | null;
  name: string;
  org_id: string;
  scopes: string[];
  user_id: string;
}

export interface ExecRequest {
  command?: string[];
  env?: { [key: string]: string };
  timeout?: number;
  working_dir?: string;
}

export interface ExecResult {
  exit_code: number;
  stderr: string;
  stdout: string;
}

export interface FileEntry {
  is_dir: boolean;
  mod_time: string;
  mode: string;
  name: string;
  size: number;
}

export interface CreatePortRequest {
  access?: string;
  label: string;
  port: number;
}

export interface SecretMetadata {
  created_at?: string;
  key: string;
  updated_at?: string;
}

export interface SecretProject {
  created_at: string;
  id: string;
  name: string;
  org_id: string;
  secret_count?: number;
}

export interface CreateSecretProjectRequest {
  name: string;
}

export interface SetSecretRequest {
  key: string;
  org_id: string;
  value: string;
}

export interface SetUserSecretRequest {
  key: string;
  value: string;
}

export interface SetProjectSecretRequest {
  key: string;
  value: string;
}

export interface StatusResponse {
  status: string;
}

export interface ClientOptions {
  apiKey?: string;
  baseUrl?: string;
  orgId?: string;
  timeout?: number;
  /** Override the fetch implementation. Defaults to the global `fetch`.
   * Mirrors Go's `WithHTTPClient`; useful for custom proxies, tracing, or
   * test doubles. */
  fetch?: typeof fetch;
}

export interface ListEnvironmentsParams {
  type?: string;
  state?: string;
}

export interface FieldViolation {
  field: string;
  description: string;
}

export class CodewireError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public requestId?: string,
    public violations?: FieldViolation[],
  ) {
    let msg = `Codewire API error ${status}: ${detail}`;
    if (requestId) msg += ` (request_id: ${requestId})`;
    super(msg);
    this.name = "CodewireError";
  }
}

function connectStatus(code: Code): number {
  switch (code) {
    case Code.Canceled:
      return 499;
    case Code.InvalidArgument:
    case Code.FailedPrecondition:
    case Code.OutOfRange:
      return 400;
    case Code.DeadlineExceeded:
      return 504;
    case Code.NotFound:
      return 404;
    case Code.AlreadyExists:
    case Code.Aborted:
      return 409;
    case Code.PermissionDenied:
      return 403;
    case Code.ResourceExhausted:
      return 429;
    case Code.Unimplemented:
      return 501;
    case Code.Unavailable:
      return 503;
    case Code.Unauthenticated:
      return 401;
    case Code.Unknown:
    case Code.Internal:
    case Code.DataLoss:
      return 500;
  }
}

export function mapConnectError(error: unknown): unknown {
  if (!(error instanceof ConnectError)) return error;

  const violations = error.findDetails(BadRequestSchema).flatMap((detail) =>
    detail.fieldViolations.map(({ field, description }) => ({
      field,
      description,
    })),
  );
  const requestId =
    error.findDetails(ErrorInfoSchema)[0]?.metadata.request_id ??
    error.metadata.get("x-request-id") ??
    undefined;

  return new CodewireError(
    connectStatus(error.code),
    error.rawMessage,
    requestId,
    violations.length === 0 ? undefined : violations,
  );
}
