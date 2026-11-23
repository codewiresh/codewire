import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { inspect } from "node:util";
import { Codewire } from "./index.js";
import { parseDotenv, reportOnce, resolveSettings, type SettingsOptions } from "./settings.js";

const KEY = "cw_synthetic_key";
const TOKEN = "synthetic-user-token";

const VARIABLES = [
  "CODEWIRE_API_KEY", "CODEWIRE_JWT_TOKEN", "CODEWIRE_ORGANIZATION_ID", "CODEWIRE_ORG_ID",
  "CODEWIRE_API_URL", "CODEWIRE_SERVER_URL",
];

/** Builds with none of the settings variables set and `cwd` as the working directory, so nothing of the developer's is read. */
function isolated<T>(cwd: string, build: () => T): T {
  const saved = VARIABLES.map((name) => [name, process.env[name]] as const);
  const previous = process.cwd();
  for (const name of VARIABLES) delete process.env[name];
  process.chdir(cwd);
  try {
    return build();
  } finally {
    process.chdir(previous);
    for (const [name, value] of saved) if (value !== undefined) process.env[name] = value;
  }
}

/** Every state of the journey's `sdk-config` step, from an explicit environment and a scratch directory. */
export async function runSettingsTests(): Promise<void> {
  const root = mkdtempSync(path.join(tmpdir(), "codewire-settings-"));
  let scratch = 0;
  const directory = (files: Record<string, string> = {}): string => {
    const cwd = path.join(root, String(scratch++));
    mkdirSync(cwd);
    for (const [name, text] of Object.entries(files)) writeFileSync(path.join(cwd, name), text);
    return cwd;
  };
  const resolve = (env: Record<string, string>, files: Record<string, string> = {}, options: SettingsOptions = {}) =>
    resolveSettings(options, { env, cwd: directory(files) });
  const refusal = (env: Record<string, string>, files: Record<string, string> = {}): string => {
    try {
      resolve(env, files);
    } catch (error) {
      return (error as Error).message;
    }
    assert.fail("settings were not refused");
  };

  try {
    const keyOnly = resolve({ CODEWIRE_API_KEY: KEY });
    assert.equal(keyOnly.bearer, KEY);
    assert.equal(keyOnly.credential, "api key");
    assert.equal(keyOnly.organizationId, "");
    assert.equal(keyOnly.apiUrl, "https://codewire.sh");
    assert.deepEqual(keyOnly.warnings, []);

    const token = resolve({ CODEWIRE_JWT_TOKEN: TOKEN, CODEWIRE_ORGANIZATION_ID: "org-one" });
    assert.equal(token.bearer, TOKEN);
    assert.equal(token.credential, "user token");
    assert.equal(token.organizationId, "org-one");

    const alias = resolve({ CODEWIRE_JWT_TOKEN: TOKEN, CODEWIRE_ORG_ID: "org-alias" });
    assert.equal(alias.bearer, TOKEN);
    assert.equal(alias.organizationId, "org-alias");
    assert.equal(
      resolve({ CODEWIRE_API_KEY: KEY, CODEWIRE_ORGANIZATION_ID: "org-new", CODEWIRE_ORG_ID: "org-old" }).organizationId,
      "org-new",
    );

    const both = resolve({ CODEWIRE_API_KEY: KEY, CODEWIRE_JWT_TOKEN: TOKEN });
    assert.equal(both.bearer, KEY);
    assert.equal(both.credential, "api key");
    assert.deepEqual(both.warnings, [], "a token beside the key in the same source is not reported");

    const neither = refusal({ CODEWIRE_ORGANIZATION_ID: "org-one" });
    assert.match(neither, /CODEWIRE_API_KEY/);
    assert.match(neither, /CODEWIRE_JWT_TOKEN/);
    assert.match(refusal({ CODEWIRE_API_KEY: "", CODEWIRE_JWT_TOKEN: "" }), /CODEWIRE_API_KEY/);

    const noOrganization = refusal({ CODEWIRE_JWT_TOKEN: TOKEN });
    assert.match(noOrganization, /CODEWIRE_ORGANIZATION_ID/);
    assert.ok(!noOrganization.includes(TOKEN), "the refusal never holds the token");

    const dotenv = resolve({}, { ".env": `CODEWIRE_API_KEY=${KEY}\n` });
    assert.equal(dotenv.bearer, KEY);
    const dotenvToken = resolve({}, { ".env": `CODEWIRE_JWT_TOKEN=${TOKEN}\nCODEWIRE_ORG_ID=org-file\n` });
    assert.equal(dotenvToken.bearer, TOKEN);
    assert.equal(dotenvToken.organizationId, "org-file");

    const local = resolve({}, {
      ".env": "CODEWIRE_API_KEY=cw_from_env_file\nCODEWIRE_ORGANIZATION_ID=org-env-file\n",
      ".env.local": `CODEWIRE_JWT_TOKEN=${TOKEN}\n`,
    });
    assert.equal(local.bearer, TOKEN, ".env.local's token beats .env's key");
    assert.equal(local.credential, "user token");
    assert.equal(local.organizationId, "org-env-file", "with none at or above the credential, a lower source's is used");
    assert.equal(local.warnings.length, 2);
    assert.match(local.warnings[0], /^ignored CODEWIRE_API_KEY in .*\.env: the credential comes from .*\.env\.local$/);
    assert.match(local.warnings[1],
      /^used CODEWIRE_ORGANIZATION_ID in .*\.env: the credential in .*\.env\.local sets no organization$/);
    assert.ok(!local.warnings.join().match(/cw_from_env_file|org-env-file/), "the reports never hold a value");

    const environmentWins = resolve({ CODEWIRE_API_KEY: "cw_from_environment" }, {
      ".env": "CODEWIRE_API_KEY=cw_from_env_file\n",
      ".env.local": "CODEWIRE_API_KEY=cw_from_local_file\n",
    });
    assert.equal(environmentWins.bearer, "cw_from_environment");
    assert.equal(
      resolve({ CODEWIRE_API_KEY: KEY, CODEWIRE_ORG_ID: "org-environment" }, {
        ".env.local": "CODEWIRE_ORGANIZATION_ID=org-file\n",
      }).organizationId,
      "org-environment",
      "an environment alias beats the preferred name in a file",
    );

    const serverInFile = resolve({ CODEWIRE_API_KEY: KEY }, {
      ".env": "CODEWIRE_API_URL=https://elsewhere.example.test\n",
      ".env.local": "CODEWIRE_SERVER_URL=https://other.example.test\n",
    });
    assert.equal(serverInFile.apiUrl, "https://codewire.sh");
    assert.equal(serverInFile.warnings.length, 2);
    assert.match(serverInFile.warnings[0], /CODEWIRE_SERVER_URL in .*\.env\.local/);
    assert.match(serverInFile.warnings[1], /CODEWIRE_API_URL in .*\.env:/);
    assert.ok(!serverInFile.warnings.join().includes("example.test"), "the warning never repeats the value");

    const emitted: string[] = [];
    const emitWarning = process.emitWarning;
    process.emitWarning = ((warning: string) => { emitted.push(warning); }) as typeof process.emitWarning;
    try {
      reportOnce(serverInFile.warnings);
      reportOnce(serverInFile.warnings);
    } finally {
      process.emitWarning = emitWarning;
    }
    assert.deepEqual(emitted, serverInFile.warnings, "each warning is reported once");

    assert.equal(resolve({ CODEWIRE_API_KEY: KEY, CODEWIRE_SERVER_URL: "https://server.example.test/" }).apiUrl,
      "https://server.example.test");
    assert.equal(resolve({
      CODEWIRE_API_KEY: KEY, CODEWIRE_API_URL: "https://api.example.test", CODEWIRE_SERVER_URL: "https://server.example.test",
    }).apiUrl, "https://api.example.test");

    const files = {
      ".env": "CODEWIRE_API_KEY=cw_from_env_file\nCODEWIRE_ORGANIZATION_ID=org-env-file\n",
      ".env.local": "CODEWIRE_JWT_TOKEN=token-from-local-file\n",
    };
    const environment = {
      CODEWIRE_API_KEY: "cw_from_environment", CODEWIRE_ORGANIZATION_ID: "org-environment",
      CODEWIRE_API_URL: "https://environment.example.test",
    };
    const keyInCode = resolve(environment, files, { apiKey: "cw_from_code", apiUrl: "https://code.example.test" });
    assert.equal(keyInCode.bearer, "cw_from_code");
    assert.equal(keyInCode.organizationId, "org-environment", "code sets no organization, so the environment's is used");
    assert.equal(keyInCode.apiUrl, "https://code.example.test");
    assert.equal(keyInCode.warnings.length, 4, "each lower key or token, and the organization from below, is reported");
    assert.equal(keyInCode.warnings[3], "used CODEWIRE_ORGANIZATION_ID in the environment: the credential in code sets no organization");
    assert.ok(!keyInCode.warnings.join().match(/cw_from_environment|cw_from_env_file|token-from-local-file|org-environment/));

    const tokenInCode = resolve(environment, {}, { jwtToken: TOKEN, organizationId: "org-code" });
    assert.equal(tokenInCode.bearer, TOKEN, "a token in code beats a key in the environment");
    assert.equal(tokenInCode.credential, "user token");
    assert.equal(tokenInCode.organizationId, "org-code");
    assert.equal(tokenInCode.apiUrl, "https://environment.example.test");
    assert.deepEqual(tokenInCode.warnings, ["ignored CODEWIRE_API_KEY in the environment: the credential comes from code"]);

    const tokenInEnvironment = resolve({ CODEWIRE_JWT_TOKEN: TOKEN, CODEWIRE_ORG_ID: "org-environment" }, {
      ".env": `CODEWIRE_API_KEY=${KEY}\n`,
    });
    assert.equal(tokenInEnvironment.bearer, TOKEN, "a token in the environment beats a key in .env");
    assert.equal(tokenInEnvironment.warnings.length, 1);
    assert.match(tokenInEnvironment.warnings[0], /^ignored CODEWIRE_API_KEY in .*\.env: the credential comes from the environment$/);
    assert.ok(!tokenInEnvironment.warnings[0].includes(KEY));

    const organizationInCode = resolve({ CODEWIRE_ORGANIZATION_ID: "org-environment" }, {
      ".env": `CODEWIRE_JWT_TOKEN=${TOKEN}\nCODEWIRE_ORGANIZATION_ID=org-env-file\n`,
    }, { organizationId: "org-code" });
    assert.equal(organizationInCode.organizationId, "org-code", "an organization in code always wins");
    assert.deepEqual(organizationInCode.warnings, []);
    const environmentOverFile = resolve({ CODEWIRE_ORGANIZATION_ID: "org-environment" }, {
      ".env": `CODEWIRE_JWT_TOKEN=${TOKEN}\nCODEWIRE_ORGANIZATION_ID=org-env-file\n`,
    });
    assert.equal(environmentOverFile.organizationId, "org-environment",
      "the environment's organization beats .env's when the credential is in .env");
    assert.deepEqual(environmentOverFile.warnings, [], "no report for an organization at or above the credential");
    const inCredentialSource = resolve({}, { ".env.local": `CODEWIRE_API_KEY=${KEY}\nCODEWIRE_ORG_ID=org-alias-file\n` });
    assert.equal(inCredentialSource.organizationId, "org-alias-file", "either alias counts in the credential's source");
    assert.deepEqual(inCredentialSource.warnings, []);

    const olderNames = resolve({}, {}, { apiKey: KEY, orgId: "org-old-name", baseUrl: "https://old.example.test" });
    assert.equal(olderNames.organizationId, "org-old-name");
    assert.equal(olderNames.apiUrl, "https://old.example.test");
    assert.equal(resolve({}, {}, { apiKey: KEY, organizationId: "org-new", orgId: "org-old" }).organizationId, "org-new");

    const parsed = parseDotenv([
      "# a comment",
      "OTHER_TOOL=ignored",
      "export CODEWIRE_API_KEY='cw single # kept'",
      "CODEWIRE_JWT_TOKEN = \"double quoted\" # comment",
      "CODEWIRE_ORGANIZATION_ID=org-plain # comment\r",
      "not a setting",
      "",
    ].join("\n"), ".env");
    assert.deepEqual([...parsed.entries()], [
      ["CODEWIRE_API_KEY", "cw single # kept"],
      ["CODEWIRE_JWT_TOKEN", "double quoted"],
      ["CODEWIRE_ORGANIZATION_ID", "org-plain"],
    ]);
    assert.throws(() => parseDotenv(`CODEWIRE_API_KEY="${KEY}\n`, "/scratch/.env"), (error: Error) =>
      error.message.includes("/scratch/.env:1") && !error.message.includes(KEY));

    const unreadable = directory();
    mkdirSync(path.join(unreadable, ".env"));
    assert.throws(() => resolveSettings({ apiKey: KEY }, { env: {}, cwd: unreadable }), (error: Error) =>
      error.message.includes(path.join(unreadable, ".env")));

    const calls: { authorization: string | null; body: Record<string, unknown>; url: string }[] = [];
    const cw = isolated(directory(), () => new Codewire({
      jwtToken: TOKEN, organizationId: "org-code", apiUrl: "https://code.example.test/", timeout: 5_000,
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        const body = request.method === "GET" ? JSON.parse(url.searchParams.get("message") ?? "{}") : await request.json();
        calls.push({ authorization: request.headers.get("authorization"), body, url: request.url });
        return new Response(JSON.stringify({ apiKeys: [] }), { headers: { "Content-Type": "application/json" } });
      },
    }));
    await cw.apiKeys.list();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].authorization, `Bearer ${TOKEN}`);
    assert.equal(calls[0].body.orgId, "org-code", "the organization goes in the request fields");
    assert.ok(calls[0].url.startsWith("https://code.example.test/codewire.v1.ApiKeyService/"));
    const shown = inspect(cw, { depth: null, showHidden: true }) + String(cw) + JSON.stringify(cw);
    assert.ok(!shown.includes(TOKEN), "the client never shows its token");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  console.log("settings tests passed");
}
