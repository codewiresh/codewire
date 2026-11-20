import type { Timestamp } from "@bufbuild/protobuf/wkt";
import {
  EnvironmentDesktopState as ProtoState,
  type EnvironmentDesktop as ProtoDesktop,
} from "@codewire/proto-ts/gen/codewire/v1/environment_desktop_pb";
import type { DesktopClient } from "./transport.js";
import { mapConnectError } from "./types.js";

/**
 * A start answers only once the desktop accepts a viewer. The server allows
 * it 40 seconds; this waits a little longer, so its own answer arrives
 * instead of a local timeout.
 */
const START_TIMEOUT_MS = 45_000;

export type EnvironmentDesktopState =
  | "unavailable"
  | "stopped"
  | "starting"
  | "running"
  | "unknown";

export interface EnvironmentDesktopRunning {
  /** The X display programs in the environment draw on, such as ":1". */
  display: string;
  /** The VNC listener's port on the environment's loopback. */
  port: number;
  started_at?: string;
  /**
   * The password the VNC server asks a viewer for, made at each start. It is
   * not an access control; do not log it.
   */
  viewer_password: string;
}

export interface EnvironmentDesktop {
  state: EnvironmentDesktopState;
  /** What the image lacks, when the state is "unavailable". */
  unavailable_reason?: string;
  /** Set while the state is "running". */
  running?: EnvironmentDesktopRunning;
}

/** The graphical desktop of one environment. */
export class Desktop {
  constructor(
    private readonly client: DesktopClient,
    private readonly orgId: string,
    private readonly environmentId: string,
  ) {}

  /** Starts the desktop, or returns the one that runs. */
  async start(): Promise<EnvironmentDesktop> {
    try {
      const response = await this.client.startDesktop(this.scope(), {
        timeoutMs: START_TIMEOUT_MS,
      });
      return fromProtoDesktop(response.desktop);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  async get(): Promise<EnvironmentDesktop> {
    try {
      const response = await this.client.getDesktop(this.scope());
      return fromProtoDesktop(response.desktop);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  /** Stops the desktop. Stopping one that does not run succeeds. */
  async stop(): Promise<EnvironmentDesktop> {
    try {
      const response = await this.client.stopDesktop(this.scope());
      return fromProtoDesktop(response.desktop);
    } catch (error) {
      throw mapConnectError(error);
    }
  }

  private scope(): { orgId: string; environmentId: string } {
    return { orgId: this.orgId, environmentId: this.environmentId };
  }
}

export function fromProtoDesktop(value: ProtoDesktop | undefined): EnvironmentDesktop {
  if (!value) throw new Error("desktop response omitted desktop");
  return {
    state: mapState(value.state),
    unavailable_reason: value.unavailableReason === "" ? undefined : value.unavailableReason,
    running: value.running
      ? {
          display: value.running.display,
          port: value.running.port,
          started_at: timestampString(value.running.startedAt),
          viewer_password: value.running.viewerPassword,
        }
      : undefined,
  };
}

function mapState(state: ProtoState): EnvironmentDesktopState {
  switch (state) {
    case ProtoState.UNAVAILABLE:
      return "unavailable";
    case ProtoState.STOPPED:
      return "stopped";
    case ProtoState.STARTING:
      return "starting";
    case ProtoState.RUNNING:
      return "running";
    default:
      return "unknown";
  }
}

function timestampString(value: Timestamp | undefined): string | undefined {
  if (!value) return undefined;
  return new Date(Number(value.seconds) * 1_000)
    .toISOString()
    .replace(/\.\d{3}Z$/, "Z");
}
