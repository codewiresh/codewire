import { describe, expect, test } from "bun:test";

import {
  type OrganizationDeletionResult,
  runOrganizationDeletionBridge,
} from "../src/lib/organization-deletion";

describe("organization deletion bridge", () => {
  test("legacy 204 is immediate completion", async () => {
    let reads = 0;
    const result = await runOrganizationDeletionBridge(
      { status: 204 },
      async () => {
        reads += 1;
        return { status: 404 };
      },
    );

    expect(result).toEqual({ state: "deleted" });
    expect(reads).toBe(0);
  });

  test("initial 202 reports progress before terminal deletion", async () => {
    const progress: OrganizationDeletionResult[] = [];
    const result = await runOrganizationDeletionBridge(
      {
        status: 202,
        operation: { operation_id: "op_test", state: "deleting" },
      },
      async () => ({ status: 404 }),
      { onProgress: (state) => progress.push(state) },
    );

    expect(progress[0]).toEqual({
      state: "deleting",
      operationId: "op_test",
      pollingStopped: false,
      serverContinues: true,
    });
    expect(progress[0]?.state).not.toBe("deleted");
    expect(result).toEqual({ state: "deleted", operationId: "op_test" });
  });

  test("stopping polling preserves the server-running outcome", async () => {
    let reads = 0;
    const result = await runOrganizationDeletionBridge(
      {
        status: 202,
        operation: { operation_id: "op_test", state: "deleting" },
      },
      async () => {
        reads += 1;
        return {
          status: 200,
          organization: {
            deletion_state: "deleting",
            deletion_operation_id: "op_test",
          },
        };
      },
      { pollWindowMs: 0 },
    );

    expect(reads).toBe(1);
    expect(result).toEqual({
      state: "deleting",
      operationId: "op_test",
      pollingStopped: true,
      serverContinues: true,
    });
  });

  test("retained failures include only the safe failure code", async () => {
    const result = await runOrganizationDeletionBridge(
      {
        status: 202,
        operation: { operation_id: "op_test", state: "deleting" },
      },
      async () => ({
        status: 200,
        organization: {
          deletion_state: "delete_failed",
          deletion_operation_id: "op_test",
          deletion_failure_code: "billing_unavailable",
        },
      }),
    );

    expect(result).toEqual({
      state: "delete_failed",
      operationId: "op_test",
      failureCode: "billing_unavailable",
    });
  });
});
