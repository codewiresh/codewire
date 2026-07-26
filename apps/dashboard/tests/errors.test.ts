import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import {
  BadRequestSchema,
  RetryInfoSchema,
} from "@codewire/proto-ts";
import { describe, expect, test } from "bun:test";
import { errorMessage, fieldViolations, retryDelay } from "../src/lib/errors";

describe("Connect error helpers", () => {
  test("keeps the user-facing Connect message free of the code prefix", () => {
    const error = new ConnectError("name is required", Code.InvalidArgument);
    expect(error.message).toBe("[invalid_argument] name is required");
    expect(errorMessage(error)).toBe("name is required");
    expect(errorMessage(new Error("plain error"))).toBe("plain error");
    expect(errorMessage({})).toBe("Request failed");
  });

  test("extracts every BadRequest field violation", () => {
    const error = new ConnectError("invalid request", Code.InvalidArgument, undefined, [
      {
        desc: BadRequestSchema,
        value: create(BadRequestSchema, {
          fieldViolations: [
            { field: "name", description: "is required" },
            { field: "repos[0].url", description: "is invalid" },
          ],
        }),
      },
    ]);

    expect(fieldViolations(error)).toEqual([
      { field: "name", description: "is required" },
      { field: "repos[0].url", description: "is invalid" },
    ]);
    expect(fieldViolations(new Error("plain error"))).toEqual([]);
  });

  test("returns RetryInfo delays in milliseconds", () => {
    const error = new ConnectError("try later", Code.Unavailable, undefined, [
      {
        desc: RetryInfoSchema,
        value: create(RetryInfoSchema, {
          retryDelay: { seconds: 2n, nanos: 250_000_000 },
        }),
      },
    ]);

    expect(retryDelay(error)).toBe(2_250);
    expect(retryDelay(new ConnectError("no hint"))).toBeUndefined();
  });
});
