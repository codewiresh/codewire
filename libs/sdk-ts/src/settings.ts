import { readFileSync } from "node:fs";
import path from "node:path";

// The resolution order and the variables are specified in
// docs/dev/AUTH-POLICY.md, "Signing in from the environment".

export const DEFAULT_API_URL = "https://codewire.sh";

const API_KEY = "CODEWIRE_API_KEY";
const JWT_TOKEN = "CODEWIRE_JWT_TOKEN";
const ORGANIZATION = ["CODEWIRE_ORGANIZATION_ID", "CODEWIRE_ORG_ID"];
const SERVER = ["CODEWIRE_API_URL", "CODEWIRE_SERVER_URL"];
const DOTENV_FILES = [".env.local", ".env"];
const DOTENV_VARIABLES: ReadonlySet<string> = new Set([API_KEY, JWT_TOKEN, ...ORGANIZATION, ...SERVER]);

export interface SettingsOptions {
  apiKey?: string;
  jwtToken?: string;
  organizationId?: string;
  apiUrl?: string;
  /** Older name of `organizationId`. */
  orgId?: string;
  /** Older name of `apiUrl`. */
  baseUrl?: string;
}

export interface SettingsSources {
  env: Readonly<Record<string, string | undefined>>;
  /** The directory whose `.env.local` and `.env` are read. */
  cwd: string;
}

export interface Settings {
  /** The API key or user token sent as the bearer. Never log it. */
  bearer: string;
  credential: "api key" | "user token";
  organizationId: string;
  apiUrl: string;
  /** Things to report once, such as a server variable ignored in a `.env` file. */
  warnings: string[];
}

/**
 * Resolves the settings. The credential comes as a unit from the highest
 * source that sets a key or a token (code, the process environment, then
 * `.env.local` and `.env` in `sources.cwd`); a key or token in a lower source
 * is ignored and reported. The organization comes from the highest source
 * at or above the credential's that sets one; failing that, from the highest
 * source below it, which is reported. The server comes from
 * code or the environment, never a file. Throws before any request when
 * there is no credential, or a user token has no organization. Messages
 * never contain a key or a token.
 */
export function resolveSettings(options: SettingsOptions, sources: SettingsSources): Settings {
  const warnings: string[] = [];
  const files = DOTENV_FILES.map((name) => readDotenv(path.join(sources.cwd, name)));
  for (const file of files) {
    for (const variable of SERVER) {
      if (file.values.has(variable)) {
        warnings.push(
          `ignored ${variable} in ${file.path}: the server is never read from a .env file; ` +
          `set ${variable} in the environment or pass apiUrl`,
        );
      }
    }
  }
  const lookup = (name: string, read: (variable: string) => string | undefined): Source => ({
    name,
    apiKey: first([read(API_KEY)]),
    jwtToken: first([read(JWT_TOKEN)]),
    organizationId: first(ORGANIZATION.map(read)),
    organizationVariable: ORGANIZATION.find((variable) => first([read(variable)])),
  });
  const ordered: Source[] = [
    {
      name: "code",
      apiKey: first([options.apiKey]),
      jwtToken: first([options.jwtToken]),
      organizationId: first([options.organizationId, options.orgId]),
    },
    lookup("the environment", (variable) => sources.env[variable]),
    ...files.map((file) => lookup(file.path, (variable) => file.values.get(variable))),
  ];
  const apiUrl = (first([options.apiUrl, options.baseUrl, ...SERVER.map((variable) => sources.env[variable])]) ??
    DEFAULT_API_URL).replace(/\/+$/, "");

  const chosen = ordered.findIndex((source) => source.apiKey || source.jwtToken);
  if (chosen < 0) {
    throw new Error(
      `no credentials: set ${API_KEY} or ${JWT_TOKEN}, or pass apiKey or jwtToken in ClientOptions`,
    );
  }
  const credential = ordered[chosen];
  for (const lower of ordered.slice(chosen + 1)) {
    for (const [variable, value] of [[API_KEY, lower.apiKey], [JWT_TOKEN, lower.jwtToken]] as const) {
      if (value) {
        warnings.push(
          `ignored ${variable} in ${lower.name}: the credential comes from ${credential.name}`,
        );
      }
    }
  }
  let organizationId = first(ordered.slice(0, chosen + 1).map((source) => source.organizationId)) ?? "";
  if (!organizationId) {
    const below = ordered.slice(chosen + 1).find((source) => source.organizationId);
    if (below) {
      organizationId = below.organizationId!;
      warnings.push(
        `used ${below.organizationVariable} in ${below.name}: the credential in ${credential.name} sets no organization`,
      );
    }
  }
  if (credential.apiKey) {
    return { bearer: credential.apiKey, credential: "api key", organizationId, apiUrl, warnings };
  }
  if (!organizationId) {
    throw new Error(
      `a user token needs an organization: set ${ORGANIZATION[0]} or pass organizationId in ClientOptions`,
    );
  }
  return { bearer: credential.jwtToken!, credential: "user token", organizationId, apiUrl, warnings };
}

/** What one source sets; empty values count as unset. */
interface Source {
  name: string;
  apiKey?: string;
  jwtToken?: string;
  organizationId?: string;
  /** The variable that set `organizationId`, for a source other than code. */
  organizationVariable?: string;
}

function first(values: (string | undefined)[]): string | undefined {
  return values.find((value) => value !== undefined && value !== "");
}

interface Dotenv {
  path: string;
  values: Map<string, string>;
}

function readDotenv(file: string): Dotenv {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { path: file, values: new Map() };
    throw new Error(`cannot read ${file}: ${(error as NodeJS.ErrnoException).code ?? "read failed"}`);
  }
  return { path: file, values: parseDotenv(text, file) };
}

/**
 * Reads `KEY=VALUE` lines, `#` comments, an optional `export ` and single or
 * double quotes, keeping only the Codewire settings variables. Other lines
 * are skipped unread, since the file usually belongs to other tools too.
 */
export function parseDotenv(text: string, file: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    let line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (/^export\s/.test(line)) line = line.slice("export".length).trimStart();
    const equals = line.indexOf("=");
    if (equals <= 0) continue;
    const name = line.slice(0, equals).trim();
    if (!DOTENV_VARIABLES.has(name)) continue;
    let value = line.slice(equals + 1).trim();
    const quote = value[0];
    if (quote === '"' || quote === "'") {
      const end = value.indexOf(quote, 1);
      if (end < 0) throw new Error(`${file}:${index + 1}: ${name} has no closing quote`);
      value = value.slice(1, end);
    } else {
      const comment = value.search(/\s#/);
      if (comment >= 0) value = value.slice(0, comment).trimEnd();
    }
    values.set(name, value);
  }
  return values;
}

const reported = new Set<string>();

/** Reports each warning once per process, through Node's warning channel. */
export function reportOnce(warnings: string[]): void {
  for (const warning of warnings) {
    if (reported.has(warning)) continue;
    reported.add(warning);
    process.emitWarning(warning, { code: "CODEWIRE_SETTINGS" });
  }
}
