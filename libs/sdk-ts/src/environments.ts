import { Environment } from "./environment.js";
import { Files } from "./files.js";
import {
  fromProtoEnvironment,
  fromProtoEnvironmentPort,
  fromProtoExecResult,
  pollIntervalMs,
  toProtoCreateEnvironmentRequest,
  toProtoCreatePortRequest,
  toProtoExecRequest,
  toProtoListEnvironmentsRequest,
} from "./convert.js";
import type { CodewireClients } from "./transport.js";
import { mapConnectError } from "./types.js";
import type {
  CreateEnvironmentRequest,
  CreatePortRequest,
  EnvironmentPort,
  ExecRequest,
  ExecResult,
  FileEntry,
  ListEnvironmentsParams,
} from "./types.js";

function resolveOrgId(orgId: string): string {
  if (!orgId) {
    throw new Error(
      "orgId is required — pass orgId in ClientOptions or set CODEWIRE_ORG_ID",
    );
  }
  return orgId;
}

export class Environments {
  constructor(
    private clients: CodewireClients,
    private orgId: string,
  ) {}

  /** Create a new environment. */
  async create(
    body: CreateEnvironmentRequest,
    opts?: { wait?: boolean; waitTimeout?: number },
  ): Promise<Environment> {
    try {
      const response = await this.clients.environments.createEnvironment(
        toProtoCreateEnvironmentRequest(resolveOrgId(this.orgId), body),
      );
      if (!response.environment) {
        throw new Error("environment response omitted environment");
      }
      const environment = this.wrap(fromProtoEnvironment(response.environment));
      if (opts?.wait) await environment.waitReady({ timeout: opts.waitTimeout });
      return environment;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List environments, optionally filtered by type or state. */
  async list(params?: ListEnvironmentsParams): Promise<Environment[]> {
    try {
      const request = toProtoListEnvironmentsRequest(
        resolveOrgId(this.orgId),
        params,
      );
      const environments: Environment[] = [];
      let pageToken = "";
      do {
        const response = await this.clients.environments.listEnvironments({
          ...request,
          pageToken,
        });
        const pollInterval = pollIntervalMs(response.pollInterval);
        environments.push(
          ...response.environments.map((environment) =>
            this.wrap(fromProtoEnvironment(environment), pollInterval),
          ),
        );
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return environments;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Get an environment by ID. */
  async get(envId: string): Promise<Environment> {
    try {
      const response = await this.clients.environments.getEnvironment({
        orgId: resolveOrgId(this.orgId),
        environmentId: envId,
      });
      if (!response.environment) {
        throw new Error("environment response omitted environment");
      }
      return this.wrap(
        fromProtoEnvironment(response.environment),
        pollIntervalMs(response.pollInterval),
      );
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete an environment. */
  async delete(envId: string): Promise<void> {
    try {
      await this.clients.environments.deleteEnvironment({
        orgId: resolveOrgId(this.orgId),
        environmentId: envId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Stop a running environment. */
  async stop(envId: string): Promise<void> {
    try {
      await this.clients.environments.stopEnvironment({
        orgId: resolveOrgId(this.orgId),
        environmentId: envId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Start a stopped environment. */
  async start(envId: string): Promise<void> {
    try {
      await this.clients.environments.startEnvironment({
        orgId: resolveOrgId(this.orgId),
        environmentId: envId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Execute a command in the environment. */
  async exec(envId: string, request: ExecRequest): Promise<ExecResult> {
    try {
      return fromProtoExecResult(
        await this.clients.exec.exec(
          toProtoExecRequest(resolveOrgId(this.orgId), envId, request),
        ),
      );
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** List files in the environment at the given path. */
  listFiles(envId: string, path?: string): Promise<FileEntry[]> {
    return this.files(envId).list(path);
  }

  /** Upload a file to the environment. */
  uploadFile(
    envId: string,
    src: Uint8Array,
    remotePath: string,
  ): Promise<void> {
    return this.files(envId).upload(src, remotePath);
  }

  /** Download a file from the environment. */
  downloadFile(envId: string, remotePath: string): Promise<ArrayBuffer> {
    return this.files(envId).download(remotePath);
  }

  /** List exposed ports for the environment. */
  async listPorts(envId: string): Promise<EnvironmentPort[]> {
    try {
      const ports: EnvironmentPort[] = [];
      let pageToken = "";
      do {
        const response = await this.clients.ports.listPorts({
          orgId: resolveOrgId(this.orgId),
          environmentId: envId,
          pageToken,
        });
        ports.push(...response.ports.map(fromProtoEnvironmentPort));
        pageToken = response.nextPageToken;
      } while (pageToken !== "");
      return ports;
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Expose a port on the environment. */
  async createPort(
    envId: string,
    request: CreatePortRequest,
  ): Promise<EnvironmentPort> {
    try {
      const response = await this.clients.ports.createPort(
        toProtoCreatePortRequest(resolveOrgId(this.orgId), envId, request),
      );
      if (!response.port) throw new Error("port response omitted port");
      return fromProtoEnvironmentPort(response.port);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Remove an exposed port from the environment. */
  async deletePort(envId: string, portId: string): Promise<void> {
    try {
      await this.clients.ports.deletePort({
        orgId: resolveOrgId(this.orgId),
        environmentId: envId,
        portId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  private files(envId: string): Files {
    return new Files(
      this.clients.files,
      this.clients.fileUploads,
      resolveOrgId(this.orgId),
      envId,
    );
  }

  private wrap(data: import("./types.js").EnvironmentData, pollInterval = 2_000): Environment {
    return new Environment(
      data,
      this.clients,
      resolveOrgId(this.orgId),
      pollInterval,
    );
  }
}
