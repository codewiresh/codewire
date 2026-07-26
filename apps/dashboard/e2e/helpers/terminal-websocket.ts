export interface TerminalWebSocketTarget {
  serverUrl: string;
  pageHostname: string;
  orgId: string;
  envId: string;
}

/**
 * Builds the raw terminal endpoint that the browser E2E probe exercises.
 * Browser cookies are host-scoped (not port-scoped), so the direct edge must
 * share the page hostname even when a local Vite server uses another port.
 */
export function terminalWebSocketUrl({
  serverUrl,
  pageHostname,
  orgId,
  envId,
}: TerminalWebSocketTarget): string {
  let edge: URL;
  try {
    edge = new URL(serverUrl);
  } catch {
    throw new Error(`Terminal E2E SERVER_URL is invalid: ${serverUrl}`);
  }

  if (edge.protocol !== "http:" && edge.protocol !== "https:") {
    throw new Error(
      `Terminal E2E SERVER_URL must use http or https, got ${edge.protocol}`,
    );
  }

  if (edge.hostname !== pageHostname) {
    throw new Error(
      `Terminal E2E edge hostname ${edge.hostname} does not match browser hostname ${pageHostname}; the session cookie cannot be sent to a different host`,
    );
  }

  edge.protocol = edge.protocol === "https:" ? "wss:" : "ws:";
  edge.pathname = `/api/v1/organizations/${encodeURIComponent(orgId)}/environments/${encodeURIComponent(envId)}/terminal`;
  edge.search = "";
  edge.hash = "";
  return edge.toString();
}
