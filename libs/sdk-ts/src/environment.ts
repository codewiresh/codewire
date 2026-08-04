import { Files } from "./files.js";
import { EnvironmentResizeDisruptionPolicy } from "@codewire/proto-ts/gen/codewire/v1/environment_pb";
import {
  fromProtoEnvironment,
  fromProtoEnvironmentResizeOperation,
  fromProtoEnvironmentResizePlan,
  fromProtoEnvironmentPort,
  fromProtoExecResult,
  pollIntervalMs,
  toProtoCreatePortRequest,
  toProtoExecRequest,
} from "./convert.js";
import type { CodewireClients } from "./transport.js";
import {
  CodewireError,
  mapConnectError,
  type CreatePortRequest,
  type EnvironmentData,
  type EnvironmentPort,
  type EnvironmentResizeOperation,
  type EnvironmentResizePlan,
  type EnvironmentResources,
  type ExecRequest,
  type ExecResult,
  type FileEntry,
  type IsolationTier,
  type ResizeEnvironmentRequest,
} from "./types.js";

export class Environment implements EnvironmentData {
  readonly id: string;
  readonly org_id: string;
  readonly created_by: string;
  readonly preset_id: string | undefined;
  readonly type: string;
  readonly name: string | undefined;
  readonly network: string | undefined;
  readonly state: string;
  readonly desired_state: string;
  readonly error_reason: string | undefined;
  readonly isolation_tier: IsolationTier;
  readonly protected: boolean;
  readonly recoverable: boolean;
  readonly state_changed_at: string;
  readonly retry_count: number;
  readonly setup_complete: boolean;
  readonly setup_error: string | undefined;
  readonly setup_phase: number;
  readonly ttl_seconds: number | undefined;
  readonly deletion_grace_until: string | undefined;
  readonly deletion_requested_at: string | undefined;
  readonly shutdown_at: string | undefined;
  readonly cpu_millicores: number;
  readonly memory_mb: number;
  readonly disk_gb: number;
  readonly total_running_seconds: number;
  readonly created_at: string;
  readonly started_at: string | undefined;
  readonly stopped_at: string | undefined;
  readonly destroyed_at: string | undefined;
  readonly ports: EnvironmentPort[] | undefined;
  readonly preset_name: string | undefined;
  readonly files: Files;

  constructor(
    data: EnvironmentData,
    private clients: CodewireClients,
    private orgId: string,
    private pollInterval = 2_000,
  ) {
    Object.assign(this, data);
    this.id = data.id;
    this.org_id = data.org_id;
    this.created_by = data.created_by;
    this.preset_id = data.preset_id;
    this.type = data.type;
    this.name = data.name ?? undefined;
    this.network = data.network ?? undefined;
    this.state = data.state;
    this.desired_state = data.desired_state;
    this.error_reason = data.error_reason ?? undefined;
    this.isolation_tier = data.isolation_tier;
    this.protected = data.protected;
    this.recoverable = data.recoverable;
    this.state_changed_at = data.state_changed_at;
    this.retry_count = data.retry_count;
    this.setup_complete = data.setup_complete;
    this.setup_error = data.setup_error ?? undefined;
    this.setup_phase = data.setup_phase;
    this.ttl_seconds = data.ttl_seconds ?? undefined;
    this.deletion_grace_until = data.deletion_grace_until ?? undefined;
    this.deletion_requested_at = data.deletion_requested_at ?? undefined;
    this.shutdown_at = data.shutdown_at ?? undefined;
    this.cpu_millicores = data.cpu_millicores;
    this.memory_mb = data.memory_mb;
    this.disk_gb = data.disk_gb;
    this.total_running_seconds = data.total_running_seconds;
    this.created_at = data.created_at;
    this.started_at = data.started_at ?? undefined;
    this.stopped_at = data.stopped_at ?? undefined;
    this.destroyed_at = data.destroyed_at ?? undefined;
    this.ports = data.ports;
    this.preset_name = data.preset_name ?? undefined;
    this.files = new Files(
      clients.files,
      clients.fileUploads,
      orgId,
      this.id,
    );
  }

  /** Execute a command in the environment. */
  async exec(request: ExecRequest): Promise<ExecResult> {
    try {
      return fromProtoExecResult(
        await this.clients.exec.exec(
          toProtoExecRequest(this.orgId, this.id, request),
        ),
      );
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Start the environment. */
  async start(): Promise<void> {
    try {
      await this.clients.environments.startEnvironment({
        orgId: this.orgId,
        environmentId: this.id,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Stop the environment. */
  async stop(): Promise<void> {
    try {
      await this.clients.environments.stopEnvironment({
        orgId: this.orgId,
        environmentId: this.id,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Start an idempotent platform resize for this environment. */
  async resize(request: ResizeEnvironmentRequest): Promise<EnvironmentResizeOperation> {
    try {
      const response = await this.clients.environments.resizeEnvironment({
        orgId: this.orgId,
        environmentId: this.id,
        cpuMillicores: request.cpu_millicores,
        memoryMb: request.memory_mb,
        diskGb: request.disk_gb,
        requestId: request.request_id,
        force: request.force ?? false,
        disruptionPolicy: request.allow_restart
          ? EnvironmentResizeDisruptionPolicy.ALLOW_RESTART
          : EnvironmentResizeDisruptionPolicy.LIVE_ONLY,
      });
      if (!response.operation) throw new Error("resize response omitted operation");
      return fromProtoEnvironmentResizeOperation(response.operation);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Ask the platform whether a resize is live, deferred, or disruptive. */
  async planResize(desired: EnvironmentResources): Promise<EnvironmentResizePlan> {
    try {
      const response = await this.clients.environments.planEnvironmentResize({
        orgId: this.orgId,
        environmentId: this.id,
        cpuMillicores: desired.cpu_millicores,
        memoryMb: desired.memory_mb,
        diskGb: desired.disk_gb,
      });
      if (!response.plan) throw new Error("resize plan response omitted plan");
      return fromProtoEnvironmentResizePlan(response.plan);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Read a durable platform resize operation for this environment. */
  async getResizeOperation(operationId: string): Promise<EnvironmentResizeOperation> {
    try {
      const response =
        await this.clients.environments.getEnvironmentResizeOperation({
          orgId: this.orgId,
          environmentId: this.id,
          operationId,
        });
      if (!response.operation) throw new Error("resize response omitted operation");
      return fromProtoEnvironmentResizeOperation(response.operation);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Delete the environment. */
  async remove(): Promise<void> {
    try {
      await this.clients.environments.deleteEnvironment({
        orgId: this.orgId,
        environmentId: this.id,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** @deprecated Use env.files.upload() instead. */
  upload(src: Uint8Array, remotePath: string): Promise<void> {
    return this.files.upload(src, remotePath);
  }

  /** @deprecated Use env.files.download() instead. */
  download(remotePath: string): Promise<ArrayBuffer> {
    return this.files.download(remotePath);
  }

  /** @deprecated Use env.files.list() instead. */
  listFiles(dirPath?: string): Promise<FileEntry[]> {
    return this.files.list(dirPath);
  }

  /** List exposed ports for the environment. */
  async listPorts(): Promise<EnvironmentPort[]> {
    try {
      const ports: EnvironmentPort[] = [];
      let pageToken = "";
      do {
        const response = await this.clients.ports.listPorts({
          orgId: this.orgId,
          environmentId: this.id,
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
  async createPort(request: CreatePortRequest): Promise<EnvironmentPort> {
    try {
      const response = await this.clients.ports.createPort(
        toProtoCreatePortRequest(this.orgId, this.id, request),
      );
      if (!response.port) throw new Error("port response omitted port");
      return fromProtoEnvironmentPort(response.port);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Remove an exposed port from the environment. */
  async deletePort(portId: string): Promise<void> {
    try {
      await this.clients.ports.deletePort({
        orgId: this.orgId,
        environmentId: this.id,
        portId,
      });
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Poll until environment state is "running". */
  async waitReady(opts?: { timeout?: number; interval?: number }): Promise<void> {
    const timeout = opts?.timeout ?? 300_000;
    let interval = opts?.interval ?? this.pollInterval;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      try {
        const response = await this.clients.environments.getEnvironment({
          orgId: this.orgId,
          environmentId: this.id,
        });
        if (!response.environment) {
          throw new Error("environment response omitted environment");
        }
        const data = fromProtoEnvironment(response.environment);
        Object.assign(this, data);
        this.pollInterval = pollIntervalMs(response.pollInterval);
        if (!opts?.interval) interval = this.pollInterval;
        if (data.state === "running") return;
        if (data.state === "error" || data.state === "destroyed") {
          throw new CodewireError(
            0,
            `environment entered state ${data.state}: ${data.error_reason ?? ""}`,
          );
        }
      } catch (error) {
        throw mapConnectError(error);
      }
      await new Promise((resolve) => setTimeout(resolve, interval));
    }
    throw new CodewireError(0, `environment not ready after ${timeout}ms`);
  }
}
