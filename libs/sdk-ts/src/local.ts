// Local VM support for the Codewire TypeScript SDK.
//
// Shells out to the `cw` CLI's `--output json` interface. Mirrors the remote
// `environments` surface so callers can swap `client.environments` for
// `client.local` with minimal changes. Requires the `cw` binary on PATH
// (or `$CW_BIN` pointing at it).

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { env as processEnv } from "node:process";
import { Readable } from "node:stream";

export class LocalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalError";
  }
}

export interface LocalSpecPort {
  host_port?: number;
  guest_port?: number;
  port?: number;
  label?: string;
}

export interface LocalSpecMount {
  source: string;
  target?: string;
  readonly?: boolean;
}

/** Input document for `cw env --local create --spec`. Mirrors codewire.yaml. */
export interface LocalSpec {
  preset?: string;
  image?: string;
  install?: string;
  startup?: string;
  env?: Record<string, string>;
  ports?: LocalSpecPort[];
  mounts?: LocalSpecMount[];
  cpu?: number;
  memory?: number;
  disk?: number;
  agent?: string;
  secret_project?: string;
  include_org_secrets?: boolean;
  include_user_secrets?: boolean;
}

export interface LocalPort {
  host_port: number;
  guest_port: number;
  label?: string;
}

export interface LocalMount {
  source: string;
  target: string;
  readonly?: boolean;
}

export interface LocalLimaInfo {
  instance_name?: string;
  mount_type?: string;
  vm_type?: string;
}

/** Persisted local VM instance, matching `cw env --local info --output json`. */
export interface LocalInstanceData {
  name: string;
  backend: string;
  status: string;
  runtime_name: string;
  repo_path: string;
  workdir: string;
  image?: string;
  preset?: string;
  install?: string;
  startup?: string;
  secrets?: string;
  agent?: string;
  env?: Record<string, string>;
  ports?: LocalPort[];
  mounts?: LocalMount[];
  cpu?: number;
  memory?: number;
  disk?: number;
  created_at?: string;
  last_used_at?: string;
  lima?: LocalLimaInfo;
}

export interface LocalExecResult {
  exit_code: number;
  stdout: string;
  stderr: string;
}

export interface LocalExecRequest {
  command: string[];
  working_dir?: string;
}

export interface LocalCreateOptions {
  /** Backend to use: "docker", "lima", etc. Required. */
  backend: string;
  /** Override the auto-derived instance name. */
  name?: string;
  /** Project directory associated with the instance. Defaults to cwd. */
  path?: string;
  /** Block until the instance reports status "running". */
  wait?: boolean;
  /** Timeout in milliseconds when wait=true. Default 300_000. */
  waitTimeout?: number;
}

/** Wrapper around a local VM — mirrors the `Environment` surface. */
export class LocalInstance {
  constructor(
    private readonly service: LocalService,
    private data: LocalInstanceData,
  ) {}

  get name(): string {
    return this.data.name;
  }
  get backend(): string {
    return this.data.backend;
  }
  get status(): string {
    return this.data.status;
  }
  get runtimeName(): string {
    return this.data.runtime_name;
  }
  get repoPath(): string {
    return this.data.repo_path;
  }
  get workdir(): string {
    return this.data.workdir;
  }
  get ports(): LocalPort[] {
    return this.data.ports ?? [];
  }

  toJSON(): LocalInstanceData {
    return { ...this.data };
  }

  async start(): Promise<void> {
    await this.service.start(this.name);
  }

  async stop(): Promise<void> {
    await this.service.stop(this.name);
  }

  async remove(): Promise<void> {
    await this.service.remove(this.name);
  }

  async exec(req: LocalExecRequest): Promise<LocalExecResult> {
    return this.service.exec(this.name, req);
  }

  /** Poll `cw env --local info` until status == "running" or terminal. */
  async waitReady(opts?: {
    timeout?: number;
    interval?: number;
  }): Promise<void> {
    const timeout = opts?.timeout ?? 300_000;
    const interval = opts?.interval ?? 1_000;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const fresh = await this.service.get(this.name);
      this.data = fresh.toJSON();
      const status = (this.data.status || "").toLowerCase();
      if (status === "running") return;
      if (status === "error" || status === "missing") {
        throw new LocalError(
          `local instance ${this.name} entered state ${status}`,
        );
      }
      await new Promise((r) => setTimeout(r, interval));
    }
    throw new LocalError(
      `local instance ${this.name} not ready after ${timeout}ms`,
    );
  }
}

type RunOpts = {
  stdin?: Uint8Array;
};

/** Local VM surface. Constructed once and attached to `Codewire`. */
export class LocalService {
  private resolvedBin: string | null = null;

  constructor(private readonly cwBinOverride?: string) {}

  /** Resolve the `cw` binary via override, `CW_BIN`, then PATH. */
  bin(): string {
    if (this.resolvedBin) return this.resolvedBin;
    if (this.cwBinOverride) {
      this.resolvedBin = this.cwBinOverride;
      return this.resolvedBin;
    }
    const override = (processEnv.CW_BIN ?? "").trim();
    if (override) {
      this.resolvedBin = override;
      return override;
    }
    // Node will resolve PATH at spawn time; returning "cw" is enough to let
    // spawn() look it up and produce a sensible ENOENT if missing.
    this.resolvedBin = "cw";
    return "cw";
  }

  async create(
    spec: LocalSpec,
    opts: LocalCreateOptions,
  ): Promise<LocalInstance> {
    if (!opts.backend) throw new Error("opts.backend is required");
    const args = [
      "env",
      "--local",
      "create",
      "--output",
      "json",
      "--backend",
      opts.backend,
      "--spec",
      "-",
    ];
    if (opts.name) args.push("--name", opts.name);
    if (opts.path) args.push("--path", opts.path);
    const body = Buffer.from(JSON.stringify(spec), "utf-8");
    const out = (await this.run(args, { stdin: body })) as string;
    const data = JSON.parse(out) as LocalInstanceData;
    const instance = new LocalInstance(this, data);
    if (opts.wait && instance.status.toLowerCase() !== "running") {
      await instance.waitReady({ timeout: opts.waitTimeout });
    }
    return instance;
  }

  async list(): Promise<LocalInstance[]> {
    const out = (await this.run([
      "env",
      "--local",
      "list",
      "--output",
      "json",
    ])) as string;
    const rows = JSON.parse(out) as LocalInstanceData[];
    return rows.map((row) => new LocalInstance(this, row));
  }

  async get(name: string): Promise<LocalInstance> {
    const out = (await this.run([
      "env",
      "--local",
      "info",
      "--output",
      "json",
      name,
    ])) as string;
    return new LocalInstance(this, JSON.parse(out) as LocalInstanceData);
  }

  async start(name: string): Promise<void> {
    await this.run(["env", "--local", "start", "--output", "json", name]);
  }

  async stop(name: string): Promise<void> {
    await this.run(["env", "--local", "stop", "--output", "json", name]);
  }

  async remove(name: string): Promise<void> {
    await this.run(["env", "--local", "rm", "--output", "json", name]);
  }

  async exec(
    name: string,
    req: LocalExecRequest,
  ): Promise<LocalExecResult> {
    if (!req.command?.length) throw new Error("exec command is required");
    const args = ["run", "--no-tty", name];
    if (req.working_dir) args.push("--workdir", req.working_dir);
    args.push("--");
    args.push(...req.command);
    const out = (await this.run(args)) as string;
    return { exit_code: 0, stdout: out, stderr: "" };
  }

  /** Spawn `cw <args...>` and collect UTF-8 stdout. Rejects with LocalError
   * when the subprocess exits non-zero. */
  async run(
    args: string[],
    opts: RunOpts = {},
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const bin = this.bin();
      const child: ChildProcessWithoutNullStreams = spawn(bin, args, {
        stdio: ["pipe", "pipe", "pipe"],
      });
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      child.stdout.on("data", (c: Buffer) => stdoutChunks.push(c));
      child.stderr.on("data", (c: Buffer) => stderrChunks.push(c));
      child.on("error", (err) => reject(err));
      child.on("close", (code) => {
        if (code !== 0) {
          const stderr = Buffer.concat(stderrChunks).toString("utf-8").trim();
          reject(
            new LocalError(
              `${bin} ${args.join(" ")} exited ${code}: ${stderr}`,
            ),
          );
          return;
        }
        const out = Buffer.concat(stdoutChunks);
        resolve(out.toString("utf-8"));
      });
      if (opts.stdin && opts.stdin.length > 0) {
        Readable.from([Buffer.from(opts.stdin)]).pipe(child.stdin);
      } else {
        child.stdin.end();
      }
    });
  }
}
