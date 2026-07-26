// Generated TypeScript client for the Codewire API.
//
// `schema.gen.ts` is generated from openapi.json (`bun run generate`);
// this file is the only hand-written code in the package.
import createClient, { type ClientOptions } from "openapi-fetch";
import type { paths } from "./schema.gen.js";

export type { paths, components } from "./schema.gen.js";

export interface CodewireClientOptions extends ClientOptions {
  /** Codewire API key (cw_-prefixed) sent as a Bearer token. */
  apiKey?: string;
}

/**
 * createCodewireClient returns a fully typed fetch client for the Codewire
 * API. Every path, parameter, and response derives from openapi.json.
 */
export function createCodewireClient(options: CodewireClientOptions = {}) {
  const { apiKey, headers, ...rest } = options;
  return createClient<paths>({
    baseUrl: "https://codewire.sh",
    ...rest,
    headers: {
      ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      ...headers,
    },
  });
}

export default createCodewireClient;
