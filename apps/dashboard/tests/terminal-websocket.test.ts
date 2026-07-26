import { describe, expect, test } from "bun:test";
import { terminalWebSocketUrl } from "../e2e/helpers/terminal-websocket";

describe("dashboard terminal E2E endpoint", () => {
  test("uses the configured HTTP edge and preserves its port", () => {
    expect(
      terminalWebSocketUrl({
        serverUrl: "http://127.0.0.1:8080",
        pageHostname: "127.0.0.1",
        orgId: "org/one",
        envId: "env two",
      }),
    ).toBe(
      "ws://127.0.0.1:8080/api/v1/organizations/org%2Fone/environments/env%20two/terminal",
    );
  });

  test("maps an HTTPS edge to WSS", () => {
    expect(
      terminalWebSocketUrl({
        serverUrl: "https://codewire.test",
        pageHostname: "codewire.test",
        orgId: "org",
        envId: "env",
      }),
    ).toBe("wss://codewire.test/api/v1/organizations/org/environments/env/terminal");
  });

  test("rejects an edge whose host cannot receive the browser cookie", () => {
    expect(() =>
      terminalWebSocketUrl({
        serverUrl: "http://127.0.0.1:8080",
        pageHostname: "localhost",
        orgId: "org",
        envId: "env",
      }),
    ).toThrow("does not match browser hostname");
  });

  test("rejects non-HTTP edge configuration", () => {
    expect(() =>
      terminalWebSocketUrl({
        serverUrl: "ftp://codewire.test",
        pageHostname: "codewire.test",
        orgId: "org",
        envId: "env",
      }),
    ).toThrow("must use http or https");
  });
});
