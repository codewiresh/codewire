import { describe, expect, test } from "bun:test";
import { safeAuthContinuation } from "../src/lib/auth-continuation";

describe("auth continuation", () => {
  test("preserves a normalized application-relative device target", () => {
    expect(
      safeAuthContinuation("/device?user_code=ABCD-1234#approval"),
    ).toBe("/device?user_code=ABCD-1234#approval");
  });

  test("rejects external, protocol-relative, and ambiguous targets", () => {
    for (const target of [
      "https://evil.example/device",
      "//evil.example/device",
      "/\\evil.example/device",
      "javascript:alert(1)",
      "device",
      "",
      undefined,
    ]) {
      expect(safeAuthContinuation(target)).toBeUndefined();
    }
  });
});
