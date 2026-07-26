export type OrganizationDeletionState = "active" | "deleting" | "delete_failed";

export type OrganizationDeletionStart =
  | { status: 204 }
  | {
      status: 202;
      operation: { operation_id: string; state: OrganizationDeletionState };
    };

export type OrganizationDeletionRead =
  | { status: 404 }
  | {
      status: 200;
      organization: {
        deletion_state?: OrganizationDeletionState | null;
        deletion_operation_id?: string | null;
        deletion_failure_code?: string | null;
      };
    };

export type OrganizationDeletionResult =
  | { state: "deleted"; operationId?: string }
  | { state: "delete_failed"; operationId: string; failureCode: string }
  | {
      state: "deleting";
      operationId: string;
      pollingStopped: boolean;
      serverContinues: true;
    };

export type OrganizationDeletionBridgeOptions = {
  pollIntervalMs?: number;
  pollWindowMs?: number;
  onProgress?: (result: OrganizationDeletionResult) => void;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
};

const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_POLL_WINDOW_MS = 300_000;

const defaultSleep = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));

export async function runOrganizationDeletionBridge(
  start: OrganizationDeletionStart,
  read: () => Promise<OrganizationDeletionRead>,
  options: OrganizationDeletionBridgeOptions = {},
): Promise<OrganizationDeletionResult> {
  if (start.status === 204) {
    const completed: OrganizationDeletionResult = { state: "deleted" };
    options.onProgress?.(completed);
    return completed;
  }

  const operationId = start.operation.operation_id.trim();
  if (!operationId) {
    throw new Error("Organization deletion response is missing operation_id");
  }
  if (start.operation.state !== "deleting") {
    throw new Error(
      `Organization deletion response has unexpected state ${start.operation.state}`,
    );
  }

  const accepted: OrganizationDeletionResult = {
    state: "deleting",
    operationId,
    pollingStopped: false,
    serverContinues: true,
  };
  options.onProgress?.(accepted);

  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? defaultSleep;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const deadline = now() + (options.pollWindowMs ?? DEFAULT_POLL_WINDOW_MS);

  while (true) {
    const observed = await read();
    if (observed.status === 404) {
      const completed: OrganizationDeletionResult = {
        state: "deleted",
        operationId,
      };
      options.onProgress?.(completed);
      return completed;
    }

    const observedOperationId = observed.organization.deletion_operation_id;
    if (observedOperationId && observedOperationId !== operationId) {
      throw new Error(
        `Organization deletion operation changed from ${operationId} to ${observedOperationId}`,
      );
    }
    if (observed.organization.deletion_state === "delete_failed") {
      const failed: OrganizationDeletionResult = {
        state: "delete_failed",
        operationId,
        failureCode:
          observed.organization.deletion_failure_code?.trim() ||
          "organization_deletion_failed",
      };
      options.onProgress?.(failed);
      return failed;
    }
    if (observed.organization.deletion_state === "active") {
      throw new Error(`Organization deletion ${operationId} unexpectedly returned to active`);
    }

    const remainingMs = deadline - now();
    if (remainingMs <= 0) {
      return {
        state: "deleting",
        operationId,
        pollingStopped: true,
        serverContinues: true,
      };
    }
    await sleep(Math.min(pollIntervalMs, remainingMs));
  }
}
