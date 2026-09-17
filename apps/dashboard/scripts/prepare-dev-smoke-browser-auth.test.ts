import { afterAll, beforeAll, expect, mock, test } from "bun:test";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as fsPromises from "node:fs/promises";

const realFsPromises = { ...fsPromises };
let rejectedRemovalPath = "";
mock.module("node:fs/promises", () => ({
  ...realFsPromises,
  rm: async (...args: Parameters<typeof rm>) => {
    if (args[0] === rejectedRemovalPath) throw new Error("hostile-owned-remove-error-canary");
    return realFsPromises.rm(...args);
  },
}));

let activeContext: FakeContext;
let launchEnvironment: Record<string, string> = {};
let persistentProfile = "";
let browserOrigin = "https://codewire-dev.sh";
let redirectMode = "";
let rejectAction = false;
let cleanupSignalEmitted = false;
let credentialFills = 0;
const settingsSignOutButtons = ["Sign out", "Sign out", "Sign out of this browser"];
let matchedSignOutButtons: string[] = [];

class FakeResponse {
  constructor(private readonly path: string, private readonly code: number) {}
  url() { return `https://codewire-dev.sh${this.path}`; }
  status() { return this.code; }
  request() { return { method: () => "POST" }; }
}

class FakeContext {
  page = new FakePage(this);
  session = false;
  signOuts = 0;
  async newPage() { return this.page as never; }
  async cookies() {
    return this.session ? [{ name: "codewire.session_token" }] : [];
  }
  async close() {
    this.page.abortPending();
    if (redirectMode === "cleanup-signal" && !cleanupSignalEmitted) {
      cleanupSignalEmitted = true;
      process.emit("SIGTERM", "SIGTERM");
    }
  }
}

class FakePage {
  private current = "about:blank";
  private challenge = "";
  private pending?: {
    predicate: (response: FakeResponse) => boolean;
    resolve: (response: FakeResponse) => void;
    reject: (error: Error) => void;
  };
  constructor(private readonly owner: FakeContext) {}
  async goto(url: string) {
    const parsed = new URL(url);
    if (parsed.pathname === "/device") {
      this.challenge = parsed.searchParams.get("user_code") ?? "";
      this.current = `${browserOrigin}/login?return_to=${encodeURIComponent(parsed.pathname + parsed.search)}`;
    } else if (parsed.pathname === "/settings/") {
      this.current = url;
    } else {
      this.current = url;
    }
  }
  url() { return this.current; }
  context() { return this.owner as never; }
  setDefaultTimeout(_timeout: number) {}
  setDefaultNavigationTimeout(_timeout: number) {}
  locator(selector: string) {
    return {
      waitFor: async () => {},
      fill: async (_value: string) => {
        if (selector !== "#email" && selector !== "#password" && selector !== "#code") {
          throw new Error("unexpected selector");
        }
        credentialFills += 1;
      },
    };
  }
  getByRole(role: string, options?: { name?: RegExp | string }) {
    if (role === "group" && options?.name === "Device code") {
      return {
        getByRole: (nestedRole: string) => {
          if (nestedRole !== "textbox") throw new Error("unexpected nested role");
          return {
            count: async () => 8,
            evaluateAll: async () => this.challenge.replace("-", "").split(""),
          };
        },
      };
    }
    if (role === "status") return { textContent: async () => "Device approved" };
    if (role !== "button") throw new Error("unexpected role");
    const name = options?.name?.source ?? "";
    return { click: async () => {
      if (name.includes("sign in")) {
        if (rejectAction) throw new Error("synthetic click rejection");
        this.owner.session = true;
        const origin = redirectMode === "external-two-factor" ? "https://evil.invalid" : "https://codewire-dev.sh";
        this.current = `${origin}/two-factor?return_to=device`;
        this.respond("/login/_actions/sign-in", 303);
      } else if (name.includes("verify")) {
        const origin = redirectMode === "external-device" ? "https://evil.invalid" : "https://codewire-dev.sh";
        this.current = `${origin}/device?user_code=${this.challenge}`;
        this.respond("/two-factor/_actions/validate", 303);
      } else if (name.includes("approve device")) {
        this.respond("/device/_actions/approve", 200);
      } else if (name.includes("sign out")) {
        matchedSignOutButtons = settingsSignOutButtons.filter((label) => options!.name instanceof RegExp
          && options.name.test(label));
        if (matchedSignOutButtons.length !== 1) throw new Error("synthetic strict locator ambiguity");
        if (redirectMode === "hostile-sign-out") throw new Error("hostile-password-token-body-canary");
        if (redirectMode === "sign-out-failure") {
          this.respond("/settings/_actions/sign-out", 500);
          return;
        }
        this.owner.session = false;
        this.owner.signOuts += 1;
        this.current = "https://codewire-dev.sh/login";
        this.respond("/settings/_actions/sign-out", 303);
      } else throw new Error("unexpected button");
    } };
  }
  waitForResponse(predicate: (response: FakeResponse) => boolean) {
    return new Promise<FakeResponse>((resolve, reject) => {
      this.pending = { predicate, resolve, reject };
    }) as never;
  }
  abortPending() {
    this.pending?.reject(new Error("synthetic page closed"));
    this.pending = undefined;
  }
  async waitForURL(expected: RegExp) {
    if (!expected.test(this.current)) throw new Error("unexpected URL");
  }
  private respond(path: string, status: number) {
    const response = new FakeResponse(path, status);
    if (!this.pending?.predicate(response)) throw new Error("unexpected response");
    this.pending.resolve(response);
    this.pending = undefined;
  }
}

mock.module("@playwright/test", () => ({
  chromium: {
    launchPersistentContext: async (profile: string, options: { env?: Record<string, string> }) => {
      persistentProfile = profile;
      launchEnvironment = options.env ?? {};
      activeContext = new FakeContext();
      return activeContext;
    },
  },
}));

const helper = await import("./prepare-dev-smoke-browser-auth");

const USER = "11111111111111111111111111111111";
const ORG = "22222222222222222222222222222222";
const EMAIL = "dedicated-smoke@example.test";
const SECRET = "JBSWY3DPEHPK3PXP";
let root = "";
let binRoot = "";

beforeAll(async () => { root = await mkdtemp("/dev/shm/cw-browser-auth-test."); });
beforeAll(async () => { binRoot = await mkdtemp(join(process.cwd(), ".cw-browser-auth-bin-test.")); });
afterAll(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(binRoot, { recursive: true, force: true });
});

function document() {
  return {
    version: "codewire-dev-smoke-browser-auth-v1",
    userId: USER,
    email: EMAIL,
    organizationId: ORG,
    password: "DedicatedSmoke9#pass",
    totpSecret: SECRET,
  } as const;
}

async function fixture(mode = "success") {
  browserOrigin = mode === "external-login" ? "https://evil.invalid" : "https://codewire-dev.sh";
  redirectMode = mode;
  rejectAction = mode === "action-rejection" || mode === "cleanup-signal";
  cleanupSignalEmitted = false;
  credentialFills = 0;
  matchedSignOutButtons = [];
  const directory = await mkdtemp(`${root}/case.`);
  const config = join(directory, "login");
  const credential = join(directory, "dedicated.json");
  const cwDirectory = await mkdtemp(`${binRoot}/case.`);
  const cw = join(cwDirectory, "cw");
  await mkdir(config, { mode: 0o700 });
  await writeFile(credential, `${JSON.stringify(document())}\n`, { mode: 0o600 });
  const whoami = mode === "wrong-identity"
    ? JSON.stringify({ id: "3".repeat(32), email: EMAIL })
    : JSON.stringify({ id: USER, email: EMAIL });
  const login = mode === "drift"
    ? "printf 'changed challenge output\\n'; exit 1"
    : mode === "timeout"
      ? "exec sleep 30"
      : `printf '%s\\n' 'Opening browser to authorize...' "If browser doesn't open, visit: https://codewire-dev.sh/device" 'Your code: ABCD-1234'
         cat >"$CW_CONFIG_DIR/config.json" <<'JSON'
{"server_url":"https://codewire-dev.sh","default_org":"${ORG}"}
JSON
         cat >"$CW_CONFIG_DIR/credentials.json" <<'JSON'
{"issuer":"https://codewire-dev.sh","client_id":"codewire-cli","access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_at_unix":4102444800,"scope":"openid profile email offline_access codewire.api"}
JSON
         chmod 600 "$CW_CONFIG_DIR/config.json" "$CW_CONFIG_DIR/credentials.json"
         ${mode === "signal" ? "exec sleep 30" : "exit 0"}`;
  await writeFile(cw, `#!/bin/sh
set -eu
test -z "\${OPENAI_API_KEY+x}\${CODEWIRE_API_KEY+x}\${BAO_TOKEN+x}\${DISPLAY+x}\${BROWSER+x}" || exit 91
case " $* " in
  *" login --org "*) ${login} ;;
  *" whoami --output json "*) printf '%s\\n' '${whoami}' ;;
  *" org list --output json "*) printf '%s\\n' '[{"id":"${ORG}","role":"owner"}]' ;;
  *" org current "*) printf 'ID: ${ORG}\\nRole: owner\\n' ;;
  *" logout "*) rm -f -- "$CW_CONFIG_DIR/config.json" "$CW_CONFIG_DIR/credentials.json" ;;
  *) exit 92 ;;
esac
`, { mode: 0o700 });
  await chmod(cw, 0o700);
  return {
    directory, config, credential, cw,
    args: [
      "--cw-bin", cw, "--config-dir", config, "--credential-file", credential,
      "--expected-user-id", USER, "--expected-email", EMAIL, "--expected-org-id", ORG,
      "--chromium-executable", "/usr/bin/true",
    ],
  };
}

test("credential and challenge contracts are exact and value-blind", () => {
  expect(helper.validateCredentialDocument(document(), {
    expectedUserId: USER, expectedEmail: EMAIL, expectedOrgId: ORG,
  })).toEqual(document());
  expect(() => helper.validateCredentialDocument({ ...document(), extra: "secret" }, {
    expectedUserId: USER, expectedEmail: EMAIL, expectedOrgId: ORG,
  })).toThrow("invalid-credential-document");
  expect(helper.parseDeviceChallenge([
    "Opening browser to authorize...",
    "If browser doesn't open, visit: https://codewire-dev.sh/device",
    "Your code: ABCD-1234",
  ])).toEqual({ verificationUrl: "https://codewire-dev.sh/device", userCode: "ABCD-1234" });
  for (const changed of [
    ["Visit https://codewire-dev.sh/device", "Your code: ABCD-1234"],
    ["If browser doesn't open, visit: https://evil.invalid/device", "Your code: ABCD-1234"],
    ["If browser doesn't open, visit: https://codewire-dev.sh/device", "Code: ABCD-1234"],
  ]) expect(() => helper.parseDeviceChallenge(changed)).toThrow("device-challenge-invalid");
});

test("child environments contain only the fixed non-secret allowlist", () => {
  process.env.OPENAI_API_KEY = "ambient-canary";
  process.env.BAO_TOKEN = "ambient-canary";
  const env = helper.childEnvironment("/config", "/home", "/runtime");
  expect(Object.keys(env).sort()).toEqual([
    "CW_CONFIG_DIR", "DBUS_SESSION_BUS_ADDRESS", "HOME", "LC_ALL", "LOGNAME", "PATH",
    "SHELL", "TERM", "USER", "XDG_RUNTIME_DIR",
  ]);
  expect(JSON.stringify(env)).not.toContain("ambient-canary");
  delete process.env.OPENAI_API_KEY;
  delete process.env.BAO_TOKEN;
});

test("identity checks bind user, email, exact owner organization and current organization", () => {
  const expected = { expectedUserId: USER, expectedEmail: EMAIL, expectedOrgId: ORG };
  expect(() => helper.assertIdentityResponses(
    { id: USER, email: EMAIL }, [{ id: ORG, role: "owner" }, { id: "other", role: "member" }],
    `ID: ${ORG}\nRole: owner\n`, expected,
  )).not.toThrow();
  expect(() => helper.assertIdentityResponses(
    { id: "3".repeat(32), email: EMAIL }, [{ id: ORG, role: "owner" }],
    `ID: ${ORG}\nRole: owner\n`, expected,
  )).toThrow("identity-mismatch");
  expect(() => helper.assertIdentityResponses(
    { id: USER, email: EMAIL }, [{ id: ORG, role: "owner" }, { id: ORG, role: "member" }],
    `ID: ${ORG}\nRole: owner\n`, expected,
  )).toThrow("organization-mismatch");
});

test("ordinary browser selectors prepare a fresh CLI login and sign out without artifacts", async () => {
  const value = await fixture();
  await helper.main(value.args, 5_000);
  expect((await readdir(value.config)).sort()).toEqual(["config.json", "credentials.json"]);
  expect(activeContext.signOuts).toBe(1);
  expect(persistentProfile).toBe(join(value.config, ".browser-profile"));
  expect(Object.keys(launchEnvironment).sort()).toEqual([
    "HOME", "LC_ALL", "PATH", "TMPDIR", "TZ", "XDG_RUNTIME_DIR",
  ]);
  expect(launchEnvironment.TMPDIR).toBe(join(value.config, ".browser-temp"));
  expect(JSON.stringify(launchEnvironment)).not.toContain(document().password);
  const source = await readFile(new URL("./prepare-dev-smoke-browser-auth.ts", import.meta.url), "utf8");
  expect(source.startsWith("#!")).toBe(false);
  expect(source).toContain("`--no-env-file`, `--config=/dev/null`");
  for (const forbidden of ["global-setup", "helpers/seed", "storageState", "recordVideo", "trace:", "screenshot:", "console.log"] ) {
    expect(source).not.toContain(forbidden);
  }
});

test("external redirects are rejected before each credential or device action", async () => {
  for (const [mode, stage, fills] of [
    ["external-login", "browser-login-route", 0],
    ["external-two-factor", "browser-two-factor-route", 2],
    ["external-device", "browser-device-route", 3],
  ] as const) {
    const value = await fixture(mode);
    await expect(helper.main(value.args, 5_000)).rejects.toThrow(stage);
    expect(credentialFills).toBe(fills);
    expect(await readdir(value.config)).toEqual([]);
  }
});

test("a rejected browser action is reduced to a fixed stage without an unhandled response", async () => {
  const value = await fixture("action-rejection");
  await expect(helper.main(value.args, 5_000)).rejects.toThrow("browser-flow");
  expect(await readdir(value.config)).toEqual([]);
});

test("signal handling remains active and idempotent through browser cleanup", async () => {
  const listeners = process.listenerCount("SIGTERM");
  const value = await fixture("cleanup-signal");
  await expect(helper.main(value.args, 5_000)).rejects.toThrow("signal-sigterm");
  expect(cleanupSignalEmitted).toBe(true);
  expect(process.listenerCount("SIGTERM")).toBe(listeners);
  expect(await readdir(value.config)).toEqual([]);
});

test("multiple session revoke controls select only sign out of this browser", async () => {
  expect(settingsSignOutButtons.filter((label) => /sign out/i.test(label))).toHaveLength(3);
  const value = await fixture();
  await helper.main(value.args, 5_000);
  expect(matchedSignOutButtons).toEqual(["Sign out of this browser"]);
  expect(activeContext.signOuts).toBe(1);
  expect(activeContext.session).toBe(false);
});

test("browser sign-out failure is reported after remaining local cleanup", async () => {
  const value = await fixture("sign-out-failure");
  const failure = await helper.main(value.args, 5_000).catch((error) => error);
  expect(failure.stage).toBe("browser-sign-out");
  expect(failure.cleanupFailures).toEqual(["browser-sign-out:failed"]);
  expect(activeContext.session).toBe(true);
  expect(await readdir(value.config)).toEqual([]);
  expect(JSON.parse(await readFile(value.credential, "utf8"))).toEqual(document());
});

test("opaque browser errors never enter original or cleanup diagnostics", async () => {
  const value = await fixture("hostile-sign-out");
  const failure = await helper.main(value.args, 5_000).catch((error) => error);
  expect(failure.stage).toBe("browser-sign-out");
  expect(failure.cleanupFailures).toEqual(["browser-sign-out:failed"]);
  expect(JSON.stringify(failure)).not.toContain("hostile-password-token-body-canary");
  expect(await readdir(value.config)).toEqual([]);
});

test("successful body with failed owned-directory cleanup is still nonzero", async () => {
  const value = await fixture();
  rejectedRemovalPath = join(value.config, ".browser-profile");
  try {
    const failure = await helper.main(value.args, 5_000).catch((error) => error);
    expect(failure.stage).toBe("cleanup-incomplete");
    expect(failure.cleanupFailures).toContain("browser-profile-remove:failed");
    expect(JSON.stringify(failure)).not.toContain("hostile-owned-remove-error-canary");
  } finally {
    rejectedRemovalPath = "";
  }
});

test("wrong identity and challenge drift revoke the owned login and clear only config contents", async () => {
  for (const mode of ["wrong-identity", "drift"]) {
    const value = await fixture(mode);
    await expect(helper.main(value.args, 5_000)).rejects.toBeInstanceOf(helper.FixedStageError);
    expect(await readdir(value.config)).toEqual([]);
    expect(JSON.parse(await readFile(value.credential, "utf8"))).toEqual(document());
  }
});

test("timeout and signal are bounded and clear the owned login", async () => {
  const timed = await fixture("timeout");
  await expect(helper.main(timed.args, 30)).rejects.toThrow("total-timeout");
  expect(await readdir(timed.config)).toEqual([]);

  const signaled = await fixture("signal");
  const run = helper.main(signaled.args, 5_000);
  setTimeout(() => process.emit("SIGTERM", "SIGTERM"), 25);
  await expect(run).rejects.toThrow("signal-sigterm");
  expect(await readdir(signaled.config)).toEqual([]);
});
