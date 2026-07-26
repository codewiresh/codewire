import { createClient } from "@connectrpc/connect";
import { createConnectQueryKey } from "@connectrpc/connect-query";
import { createConnectTransport } from "@connectrpc/connect-web";
import { AdminService } from "@codewire/proto-ts/gen/codewire/admin/v1/admin_pb";
import { BillingCatalogService } from "@codewire/proto-ts/gen/codewire/admin/v1/billing_catalog_pb";
import { AccountService } from "@codewire/proto-ts/gen/codewire/console/v1/account_pb";
import { BillingService } from "@codewire/proto-ts/gen/codewire/console/v1/billing_pb";
import { EnvironmentSetupService } from "@codewire/proto-ts/gen/codewire/console/v1/environment_setup_pb";
import { GitHubService } from "@codewire/proto-ts/gen/codewire/console/v1/github_pb";
import { ApiKeyService } from "@codewire/proto-ts/gen/codewire/v1/api_key_pb";
import { EnvironmentService } from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import { ExecService } from "@codewire/proto-ts/gen/codewire/v1/exec_pb";
import { FileService } from "@codewire/proto-ts/gen/codewire/v1/file_pb";
import { OrganizationService } from "@codewire/proto-ts/gen/codewire/v1/organization_pb";
import { PortService } from "@codewire/proto-ts/gen/codewire/v1/port_pb";
import { PresetService } from "@codewire/proto-ts/gen/codewire/v1/preset_pb";
import { SecretService } from "@codewire/proto-ts/gen/codewire/v1/secret_pb";

const credentialedFetch: typeof globalThis.fetch = (input, init) =>
  globalThis.fetch(input, { ...init, credentials: "include" });

export const connectTransport = createConnectTransport({
  baseUrl: "/",
  fetch: credentialedFetch,
  useBinaryFormat: false,
  useHttpGet: true,
});

export const apiKeyClient = createClient(ApiKeyService, connectTransport);
export const environmentClient = createClient(EnvironmentService, connectTransport);
export const execClient = createClient(ExecService, connectTransport);
export const fileClient = createClient(FileService, connectTransport);
export const organizationClient = createClient(OrganizationService, connectTransport);
export const portClient = createClient(PortService, connectTransport);
export const presetClient = createClient(PresetService, connectTransport);
export const secretClient = createClient(SecretService, connectTransport);

export const portServiceQueryKey = createConnectQueryKey({
  schema: PortService,
  transport: connectTransport,
  cardinality: undefined,
});

export const presetServiceQueryKey = createConnectQueryKey({
  schema: PresetService,
  transport: connectTransport,
  cardinality: undefined,
});

export const secretServiceQueryKey = createConnectQueryKey({
  schema: SecretService,
  transport: connectTransport,
  cardinality: undefined,
});

export const accountClient = createClient(AccountService, connectTransport);
export const billingClient = createClient(BillingService, connectTransport);
export const environmentSetupClient = createClient(EnvironmentSetupService, connectTransport);
export const githubClient = createClient(GitHubService, connectTransport);

export const accountServiceQueryKey = createConnectQueryKey({
  schema: AccountService,
  transport: connectTransport,
  cardinality: undefined,
});

export const githubServiceQueryKey = createConnectQueryKey({
  schema: GitHubService,
  transport: connectTransport,
  cardinality: undefined,
});

export const adminClient = createClient(AdminService, connectTransport);
export const billingCatalogClient = createClient(BillingCatalogService, connectTransport);
