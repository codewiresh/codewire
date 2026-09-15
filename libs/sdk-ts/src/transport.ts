import {
  createClient,
  type Client,
  type Interceptor,
} from "@connectrpc/connect";
import { createConnectTransport as createNodeConnectTransport } from "@connectrpc/connect-node";
import { createConnectTransport as createWebConnectTransport } from "@connectrpc/connect-web";
import { ApiKeyService } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import { EnvironmentService } from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { ExecService } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import { FileService } from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import { PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { PresetService } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { AccessProfileService } from "@codewire/proto-ts/gen/codewire/v1/access_profile_pb";
import { CredentialService, CredentialMutationService, GithubRepositoryService } from "@codewire/proto-ts/gen/codewire/v1/credential_pb";

export type ApiKeyClient = Client<typeof ApiKeyService>;
export type EnvironmentClient = Client<typeof EnvironmentService>;
export type ExecClient = Client<typeof ExecService>;
export type FileClient = Client<typeof FileService>;
export type PortClient = Client<typeof PortService>;
export type PresetClient = Client<typeof PresetService>;
export type SecretClient = Client<typeof SecretService>;
export type AccessProfileClient = Client<typeof AccessProfileService>;
export type CredentialClient = Client<typeof CredentialService>;
export type CredentialMutationClient = Client<typeof CredentialMutationService>;
export type GithubRepositoryClient = Client<typeof GithubRepositoryService>;

export interface CodewireClients {
  credentials: CredentialClient;
  credentialMutations: CredentialMutationClient;
  githubRepositories: GithubRepositoryClient;
  accessProfiles: AccessProfileClient;
  apiKeys: ApiKeyClient;
  environments: EnvironmentClient;
  exec: ExecClient;
  files: FileClient;
  fileUploads: FileClient;
  ports: PortClient;
  presets: PresetClient;
  secrets: SecretClient;
}

interface ConnectClientOptions {
  apiKey: string;
  baseUrl: string;
  fetch?: typeof globalThis.fetch;
  timeout?: number;
}

export function createCodewireClients(
  options: ConnectClientOptions,
): CodewireClients {
  const bearerInterceptor: Interceptor = (next) => async (request) => {
    request.header.set("Authorization", `Bearer ${options.apiKey}`);
    return next(request);
  };

  const fetchTransport = createWebConnectTransport({
    baseUrl: options.baseUrl,
    defaultTimeoutMs: options.timeout ?? 30_000,
    fetch: options.fetch,
    interceptors: [bearerInterceptor],
    useBinaryFormat: false,
  });

  // Fetch cannot express Connect client-streaming requests. Keep the public
  // fetch override on every fetch-capable call and use the official Node
  // transport solely for FileService.UploadFile's typed stream.
  const uploadTransport = createNodeConnectTransport({
    baseUrl: options.baseUrl,
    httpVersion: "1.1",
    defaultTimeoutMs: options.timeout ?? 30_000,
    interceptors: [bearerInterceptor],
    useBinaryFormat: false,
  });

  return {
    credentials: createClient(CredentialService, fetchTransport),
    credentialMutations: createClient(CredentialMutationService, fetchTransport),
    githubRepositories: createClient(GithubRepositoryService, fetchTransport),
    accessProfiles: createClient(AccessProfileService, fetchTransport),
    apiKeys: createClient(ApiKeyService, fetchTransport),
    environments: createClient(EnvironmentService, fetchTransport),
    exec: createClient(ExecService, fetchTransport),
    files: createClient(FileService, fetchTransport),
    fileUploads: createClient(FileService, uploadTransport),
    ports: createClient(PortService, fetchTransport),
    presets: createClient(PresetService, fetchTransport),
    secrets: createClient(SecretService, fetchTransport),
  };
}

export function createApiKeyClient(options: ConnectClientOptions): ApiKeyClient {
  return createCodewireClients(options).apiKeys;
}
