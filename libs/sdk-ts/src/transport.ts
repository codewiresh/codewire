import {
  createClient,
  type Client,
  type Interceptor,
} from "@connectrpc/connect";
import { createConnectTransport as createNodeConnectTransport } from "@connectrpc/connect-node";
import { createConnectTransport as createWebConnectTransport } from "@connectrpc/connect-web";
import { ApiKeyService } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import { EnvironmentService } from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { EnvironmentCwRuntimeService } from "@codewire/proto-ts/gen/codewire/v1/environment_cw_runtime_pb";
import { EnvironmentAgentService } from "@codewire/proto-ts/gen/codewire/v1/environment_agent_pb";
import { ExecService } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import { FileService } from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import { PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { PresetService } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";
import { AccessProfileService } from "@codewire/proto-ts/gen/codewire/v1/access_profile_pb";
import { NetworkPolicyService } from "@codewire/proto-ts/gen/codewire/v1/network_policy_pb";
import { CredentialService, CredentialMutationService, GithubRepositoryService } from "@codewire/proto-ts/gen/codewire/v1/credential_pb";

export type ApiKeyClient = Client<typeof ApiKeyService>;
export type EnvironmentClient = Client<typeof EnvironmentService>;
export type CwRuntimeClient = Client<typeof EnvironmentCwRuntimeService>;
export type EnvironmentAgentClient = Client<typeof EnvironmentAgentService>;
export type ExecClient = Client<typeof ExecService>;
export type FileClient = Client<typeof FileService>;
export type PortClient = Client<typeof PortService>;
export type PresetClient = Client<typeof PresetService>;
export type SecretClient = Client<typeof SecretService>;
export type AccessProfileClient = Client<typeof AccessProfileService>;
export type NetworkPolicyClient = Client<typeof NetworkPolicyService>;
export type CredentialClient = Client<typeof CredentialService>;
export type CredentialMutationClient = Client<typeof CredentialMutationService>;
export type GithubRepositoryClient = Client<typeof GithubRepositoryService>;

export interface CodewireClients {
  credentials: CredentialClient;
  credentialMutations: CredentialMutationClient;
  githubRepositories: GithubRepositoryClient;
  accessProfiles: AccessProfileClient;
  networkPolicies: NetworkPolicyClient;
  apiKeys: ApiKeyClient;
  environments: EnvironmentClient;
  cwRuntime: CwRuntimeClient;
  cwRuntimeUpdates: CwRuntimeClient;
  environmentAgents: EnvironmentAgentClient;
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

/** Bound unary runtime responses before Connect's buffering decoder reads them. */
export function boundedRuntimeFetch(fetcher: typeof globalThis.fetch): typeof globalThis.fetch {
  return boundedResponseFetch(fetcher, 32 * 1024, "cw runtime");
}

function boundedResponseFetch(fetcher: typeof globalThis.fetch, maximum: number, operation: string): typeof globalThis.fetch {
  return async (input, init) => {
    const response = await fetcher(input, init);
    if (!response.body) return response;
    const reader = response.body.getReader();
    let bytes = 0;
    const body = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const next = await reader.read();
          if (next.done) { controller.close(); return; }
          bytes += next.value.byteLength;
          if (bytes > maximum) {
            await reader.cancel();
            controller.error(new Error(`${operation} response exceeds its bound`));
            return;
          }
          controller.enqueue(next.value);
        } catch (error) { controller.error(error); }
      },
      async cancel(reason) { await reader.cancel(reason); },
    }, { highWaterMark: 0 });
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
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

  const runtimeUnaryTransport = createWebConnectTransport({
    baseUrl: options.baseUrl,
    defaultTimeoutMs: options.timeout ?? 30_000,
    fetch: boundedRuntimeFetch(options.fetch ?? globalThis.fetch),
    interceptors: [bearerInterceptor],
    useBinaryFormat: true,
  });
  const runtimeUpdateTransport = createNodeConnectTransport({
    baseUrl: options.baseUrl,
    httpVersion: "1.1",
    defaultTimeoutMs: options.timeout ?? 30_000,
    interceptors: [bearerInterceptor],
    useBinaryFormat: true,
    readMaxBytes: 32 * 1024,
    writeMaxBytes: 64 * 1024 + 1024,
  });
  const agentTransport = createWebConnectTransport({
    baseUrl: options.baseUrl,
    defaultTimeoutMs: options.timeout ?? 30_000,
    fetch: boundedResponseFetch(options.fetch ?? globalThis.fetch, 5 * 1024 * 1024 + 32 * 1024, "agent"),
    interceptors: [bearerInterceptor],
    useBinaryFormat: true,
  });

  return {
    credentials: createClient(CredentialService, fetchTransport),
    credentialMutations: createClient(CredentialMutationService, fetchTransport),
    githubRepositories: createClient(GithubRepositoryService, fetchTransport),
    accessProfiles: createClient(AccessProfileService, fetchTransport),
    networkPolicies: createClient(NetworkPolicyService, fetchTransport),
    apiKeys: createClient(ApiKeyService, fetchTransport),
    environments: createClient(EnvironmentService, fetchTransport),
    cwRuntime: createClient(EnvironmentCwRuntimeService, runtimeUnaryTransport),
    cwRuntimeUpdates: createClient(EnvironmentCwRuntimeService, runtimeUpdateTransport),
    environmentAgents: createClient(EnvironmentAgentService, agentTransport),
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
