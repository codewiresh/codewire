// Invoke through the checked-in smoke harness with a fixed Bun executable,
// `--no-env-file`, `--config=/dev/null`, and an empty private working directory.
import { chromium, type BrowserContext, type Page } from "@playwright/test";
import * as OTPAuth from "otpauth";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { accessSync } from "node:fs";
import { basename, join } from "node:path";
import { userInfo } from "node:os";
import { DevUxError, OwnedUxSandbox, uxOrganizationSlug } from "./dev-ux-ownership";

const DEV_ORIGIN = "https://codewire-dev.sh";
const TOTAL_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_PRIVATE_OUTPUT_BYTES = 64 * 1024;
const REQUIRED_SCOPE = "openid profile email offline_access codewire.api";

export const BROWSER_CONTRACT = Object.freeze({
  email: "#email",
  password: "#password",
  signIn: /sign in/i,
  totp: "#code",
  verify: /verify/i,
  deviceCodeGroup: "Device code",
  approve: /approve device/i,
  approvedStatus: /device approved/i,
  signOut: /^sign out of this browser$/i,
});

type Options = {
  cwBin: string;
  configDir: string;
  credentialFile: string;
  expectedUserId: string;
  expectedEmail: string;
  expectedOrgId: string;
  chromiumExecutable: string;
  uxWalkthrough: boolean;
};

export type CredentialDocument = {
  version: "codewire-dev-smoke-browser-auth-v1";
  userId: string;
  email: string;
  organizationId: string;
  password: string;
  totpSecret: string;
};

export type DeviceChallenge = { verificationUrl: string; userCode: string };

type CleanupOperation = "browser-sign-out" | "browser-context-close" | "browser-profile-remove"
  | "browser-temp-remove" | "runtime-remove" | "home-remove" | "config-clear" | "ux-sandbox-remove";

export class FixedStageError extends Error {
  cleanupFailures: string[] = [];
  constructor(readonly stage: string) {
    super(stage);
    this.name = "FixedStageError";
  }
}

function fail(stage: string): never {
  throw new FixedStageError(stage);
}

function fixedBrowserFailure(stage: string): (error: unknown) => never {
  return (error) => {
    if (error instanceof FixedStageError) throw error;
    fail(stage);
  };
}

export function parseOptions(argv: string[]): Options {
  const values = new Map<string, string>();
  const accepted = new Set([
    "--cw-bin", "--config-dir", "--credential-file", "--expected-user-id",
    "--expected-email", "--expected-org-id", "--chromium-executable",
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if ((!accepted.has(name) && name !== "--ux-walkthrough") || !value || values.has(name)) fail("invalid-arguments");
    values.set(name, value);
  }
  if ([...accepted].some((key) => !values.has(key))
    || (values.has("--ux-walkthrough") && values.get("--ux-walkthrough") !== "enabled")) fail("invalid-arguments");
  return {
    cwBin: values.get("--cw-bin")!,
    configDir: values.get("--config-dir")!,
    credentialFile: values.get("--credential-file")!,
    expectedUserId: values.get("--expected-user-id")!,
    expectedEmail: values.get("--expected-email")!,
    expectedOrgId: values.get("--expected-org-id")!,
    chromiumExecutable: values.get("--chromium-executable")!,
    uxWalkthrough: values.has("--ux-walkthrough"),
  };
}

function exactKeys(value: object, expected: string[]): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

export function validateCredentialDocument(value: unknown, options: Pick<Options,
  "expectedUserId" | "expectedEmail" | "expectedOrgId">): CredentialDocument {
  if (!value || typeof value !== "object" || Array.isArray(value) || !exactKeys(value, [
    "version", "userId", "email", "organizationId", "password", "totpSecret",
  ])) fail("invalid-credential-document");
  const document = value as Record<string, unknown>;
  if (document.version !== "codewire-dev-smoke-browser-auth-v1"
    || typeof document.userId !== "string"
    || typeof document.email !== "string"
    || typeof document.organizationId !== "string"
    || typeof document.password !== "string"
    || typeof document.totpSecret !== "string"
    || document.userId !== options.expectedUserId
    || document.email !== options.expectedEmail
    || document.organizationId !== options.expectedOrgId
    || !/^[0-9a-f]{32}$/.test(document.userId)
    || document.userId === "0".repeat(32)
    || !/^[0-9a-f]{32}$/.test(document.organizationId)
    || document.organizationId === "0".repeat(32)
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(document.email)
    || document.password.length < 12 || document.password.length > 128
    || !/^[A-Z2-7]+=*$/.test(document.totpSecret)
    || document.totpSecret.length < 16 || document.totpSecret.length > 256) {
    fail("invalid-credential-document");
  }
  return document as CredentialDocument;
}

export function parseDeviceChallenge(lines: readonly string[]): DeviceChallenge {
  let verificationUrl = "";
  let userCode = "";
  for (const line of lines) {
    const url = /^If browser doesn't open, visit: (\S+)$/.exec(line);
    if (url) {
      if (verificationUrl) fail("device-challenge-invalid");
      verificationUrl = url[1];
    }
    const code = /^Your code: ([A-Z0-9]+(?:-[A-Z0-9]+)*)$/.exec(line);
    if (code) {
      if (userCode) fail("device-challenge-invalid");
      userCode = code[1];
    }
  }
  let parsed: URL;
  try { parsed = new URL(verificationUrl); } catch { fail("device-challenge-invalid"); }
  if (parsed.origin !== DEV_ORIGIN || parsed.pathname !== "/device"
    || parsed.search || parsed.hash || userCode.length < 4 || userCode.length > 64) {
    fail("device-challenge-invalid");
  }
  return { verificationUrl, userCode };
}

async function requirePrivateFile(path: string, label: string): Promise<void> {
  let canonical: string;
  try { canonical = await realpath(path); } catch { fail(label); }
  const metadata = await lstat(path).catch(() => fail(label));
  if (!path.startsWith("/") || canonical !== path || !metadata.isFile()
    || metadata.isSymbolicLink() || metadata.uid !== process.getuid?.()
    || (metadata.mode & 0o777) !== 0o600) fail(label);
}

async function requireExecutable(path: string, label: string): Promise<void> {
  let canonical: string;
  try { canonical = await realpath(path); } catch { fail(label); }
  const metadata = await lstat(path).catch(() => fail(label));
  if (!path.startsWith("/") || canonical !== path || !metadata.isFile()
    || metadata.isSymbolicLink()) fail(label);
  try { accessSync(path, fsConstants.X_OK); } catch { fail(label); }
}

async function requireEmptyPrivateTmpfs(path: string): Promise<void> {
  let canonical: string;
  try { canonical = await realpath(path); } catch { fail("invalid-config-directory"); }
  const metadata = await lstat(path).catch(() => fail("invalid-config-directory"));
  if (!path.startsWith("/") || canonical !== path || !metadata.isDirectory()
    || metadata.isSymbolicLink() || metadata.uid !== process.getuid?.()
    || (metadata.mode & 0o777) !== 0o700
    || (await readdir(path)).length !== 0) fail("invalid-config-directory");
  const probe = spawn("/usr/bin/findmnt", ["-nro", "FSTYPE", "-T", path], {
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C" }, stdio: ["ignore", "pipe", "ignore"],
  });
  let output = "";
  probe.stdout.setEncoding("utf8");
  probe.stdout.on("data", (chunk: string) => { output += chunk; });
  if ((await new Promise<number>((resolve) => probe.on("close", (code) => resolve(code ?? 1)))) !== 0
    || output.trim() !== "tmpfs") fail("invalid-config-directory");
}

export function childEnvironment(configDir: string, home: string, runtime: string): NodeJS.ProcessEnv {
  const user = userInfo().username;
  return {
    PATH: "/usr/bin:/bin", HOME: home, USER: user, LOGNAME: user, SHELL: "/bin/sh",
    TERM: "xterm-256color", LC_ALL: "C", CW_CONFIG_DIR: configDir,
    XDG_RUNTIME_DIR: runtime, DBUS_SESSION_BUS_ADDRESS: `unix:path=${runtime}/no-owner-bus`,
  };
}

function remaining(deadline: number): number {
  const value = deadline - Date.now();
  if (value <= 0) fail("total-timeout");
  return value;
}

async function childExit(child: ChildProcess, deadline: number): Promise<number> {
  if (child.exitCode !== null) return child.exitCode;
  if (child.signalCode !== null) return 1;
  return await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new FixedStageError("total-timeout")), remaining(deadline));
    child.once("close", (code) => { clearTimeout(timer); resolve(code ?? 1); });
    child.once("error", () => { clearTimeout(timer); reject(new FixedStageError("child-process")); });
  });
}

async function withinDeadline<T>(operation: () => Promise<T>, deadline: number): Promise<T> {
  return await new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new FixedStageError("total-timeout")), remaining(deadline));
    operation().then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

function disableCoreDumps(): void {
  const result = spawnSync("/usr/bin/prlimit", ["--core=0", `--pid=${process.pid}`], {
    env: { PATH: "/usr/bin:/bin", LC_ALL: "C" }, stdio: "ignore",
  });
  if (result.status !== 0) fail("core-dump-confinement");
}

async function challengeFrom(child: ChildProcess, deadline: number): Promise<DeviceChallenge> {
  if (!child.stdout) fail("child-process");
  const lines: string[] = [];
  let bytes = 0;
  const reader = createInterface({ input: child.stdout });
  return await new Promise<DeviceChallenge>((resolve, reject) => {
      const timer = setTimeout(() => reject(new FixedStageError("total-timeout")), remaining(deadline));
      const finish = (value: DeviceChallenge) => { clearTimeout(timer); resolve(value); };
      const stop = (error: FixedStageError) => { clearTimeout(timer); reject(error); };
      reader.on("line", (line) => {
        bytes += Buffer.byteLength(line) + 1;
        if (bytes > MAX_PRIVATE_OUTPUT_BYTES) return stop(new FixedStageError("device-challenge-invalid"));
        lines.push(line);
        try {
          const challenge = parseDeviceChallenge(lines);
          finish(challenge);
        } catch (error) {
          if (error instanceof FixedStageError && lines.length < 6) return;
          stop(new FixedStageError("device-challenge-invalid"));
        }
      });
      child.once("close", () => stop(new FixedStageError("device-challenge-missing")));
      child.once("error", () => stop(new FixedStageError("child-process")));
  });
}

function drain(stream: NodeJS.ReadableStream, child: ChildProcess): void {
  let bytes = 0;
  stream.on("data", (chunk: Buffer | string) => {
    bytes += Buffer.byteLength(chunk);
    if (bytes > MAX_PRIVATE_OUTPUT_BYTES) signalProcessGroup(child, "SIGTERM");
  });
}

function signalProcessGroup(child: ChildProcess, signal: NodeJS.Signals): void {
  if (child.pid === undefined) return;
  try { process.kill(-child.pid, signal); } catch { child.kill(signal); }
}

async function stopProcessGroup(child: ChildProcess): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  let stopped = childExit(child, Date.now() + 1000).then(() => true).catch(() => false);
  signalProcessGroup(child, "SIGTERM");
  if (await stopped) return true;
  stopped = childExit(child, Date.now() + 1000).then(() => true).catch(() => false);
  signalProcessGroup(child, "SIGKILL");
  return await stopped;
}

async function fill(page: Page, selector: string, value: string): Promise<void> {
  const field = page.locator(selector);
  await field.waitFor({ state: "attached" });
  await field.fill(value);
}

async function responseFor(page: Page, pathname: string, action: () => Promise<void>): Promise<number> {
  const response = page.waitForResponse((candidate) => {
    try { return new URL(candidate.url()).pathname === pathname && candidate.request().method() === "POST"; }
    catch { return false; }
  });
  const [result] = await Promise.all([response, action()]);
  return result.status();
}

function requireDevPage(page: Page, pathname: string, stage: string): void {
  let location: URL;
  try { location = new URL(page.url()); } catch { fail(stage); }
  if (location.origin !== DEV_ORIGIN || location.pathname !== pathname) fail(stage);
}

export async function approveInOrdinaryBrowser(
  page: Page, challenge: DeviceChallenge, credentials: CredentialDocument,
): Promise<void> {
  try {
    const target = `${challenge.verificationUrl}?user_code=${encodeURIComponent(challenge.userCode)}`;
    await page.goto(target, { waitUntil: "domcontentloaded" });
    requireDevPage(page, "/login", "browser-login-route");
    await fill(page, BROWSER_CONTRACT.email, credentials.email);
    await fill(page, BROWSER_CONTRACT.password, credentials.password);
    const signIn = await responseFor(page, "/login/_actions/sign-in", async () => {
      await page.getByRole("button", { name: BROWSER_CONTRACT.signIn }).click();
    });
    if (signIn !== 303) fail("browser-sign-in");
    await page.waitForURL(/\/two-factor(?:\?|$)/);
    requireDevPage(page, "/two-factor", "browser-two-factor-route");
    const totp = new OTPAuth.TOTP({ secret: credentials.totpSecret }).generate();
    await fill(page, BROWSER_CONTRACT.totp, totp);
    const secondFactor = await responseFor(page, "/two-factor/_actions/validate", async () => {
      await page.getByRole("button", { name: BROWSER_CONTRACT.verify }).click();
    });
    if (secondFactor !== 303) fail("browser-two-factor");
    await page.waitForURL(/\/device\?user_code=/);
    requireDevPage(page, "/device", "browser-device-route");
    const deviceCodeSlots = page
      .getByRole("group", { name: BROWSER_CONTRACT.deviceCodeGroup })
      .getByRole("textbox");
    if (await deviceCodeSlots.count() !== 8) fail("browser-device-code");
    const actualCode = await deviceCodeSlots.evaluateAll((inputs) => inputs.map((input) => (
      input instanceof HTMLInputElement ? input.value : ""
    )));
    if (actualCode.join("") !== challenge.userCode.replace("-", "")) fail("browser-device-code");
    const approval = await responseFor(page, "/device/_actions/approve", async () => {
      await page.getByRole("button", { name: BROWSER_CONTRACT.approve }).click();
    });
    if (approval !== 200) fail("browser-device-approval");
    const status = (await page.getByRole("status").textContent()) ?? "";
    if (!BROWSER_CONTRACT.approvedStatus.test(status)) fail("browser-device-approval");
  } catch (error) {
    if (error instanceof FixedStageError) throw error;
    fail("browser-flow");
  }
}

async function signOut(page: Page): Promise<void> {
  try {
    const session = (await page.context().cookies()).some((cookie) => cookie.name === "codewire.session_token");
    if (!session) return;
    await page.goto(`${DEV_ORIGIN}/settings/`, { waitUntil: "domcontentloaded" });
    const status = await responseFor(page, "/settings/_actions/sign-out", async () => {
      await page.getByRole("button", { name: BROWSER_CONTRACT.signOut }).click();
    });
    if (status !== 303) fail("browser-sign-out");
    if ((await page.context().cookies()).some((cookie) => cookie.name === "codewire.session_token")) {
      fail("browser-sign-out");
    }
  } catch (error) {
    if (error instanceof FixedStageError) throw error;
    fail("browser-sign-out");
  }
}

async function runJson(cwBin: string, env: NodeJS.ProcessEnv, args: string[], deadline: number): Promise<unknown> {
  const child = spawn(cwBin, ["--server", DEV_ORIGIN, ...args], {
    env, stdio: ["ignore", "pipe", "pipe"], detached: true,
  });
  if (!child.stdout || !child.stderr) fail("child-process");
  let stdout = "";
  let bytes = 0;
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    bytes += Buffer.byteLength(chunk);
    if (bytes <= MAX_PRIVATE_OUTPUT_BYTES) stdout += chunk;
    else child.kill("SIGTERM");
  });
  drain(child.stderr, child);
  let exit: number;
  try { exit = await childExit(child, deadline); }
  catch (error) {
    if (!await stopProcessGroup(child)) fail("cleanup-incomplete");
    throw error;
  }
  if (exit !== 0 || bytes > MAX_PRIVATE_OUTPUT_BYTES) fail("identity-command");
  try { return JSON.parse(stdout); } catch { fail("identity-response"); }
}

export function assertIdentityResponses(
  whoami: unknown, organizations: unknown, current: string,
  expected: Pick<Options, "expectedUserId" | "expectedEmail" | "expectedOrgId">,
): void {
  if (!whoami || typeof whoami !== "object" || Array.isArray(whoami)
    || (whoami as Record<string, unknown>).id !== expected.expectedUserId
    || (whoami as Record<string, unknown>).email !== expected.expectedEmail) fail("identity-mismatch");
  if (!Array.isArray(organizations)) fail("organization-mismatch");
  const targetOrganizations = organizations.filter((entry) => entry && typeof entry === "object"
    && (entry as Record<string, unknown>).id === expected.expectedOrgId);
  if (targetOrganizations.length !== 1
    || (targetOrganizations[0] as Record<string, unknown>).role !== "owner") fail("organization-mismatch");
  const ids = [...current.matchAll(/^ID:\s+(\S+)\s*$/gm)].map((match) => match[1]);
  const roles = [...current.matchAll(/^Role:\s+(\S+)\s*$/gm)].map((match) => match[1]);
  if (ids.length !== 1 || ids[0] !== expected.expectedOrgId
    || roles.length !== 1 || roles[0] !== "owner") fail("organization-mismatch");
}

async function runText(cwBin: string, env: NodeJS.ProcessEnv, args: string[], deadline: number): Promise<string> {
  const child = spawn(cwBin, ["--server", DEV_ORIGIN, ...args], {
    env, stdio: ["ignore", "pipe", "pipe"], detached: true,
  });
  if (!child.stdout || !child.stderr) fail("child-process");
  let stdout = "";
  let bytes = 0;
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    bytes += Buffer.byteLength(chunk);
    if (bytes <= MAX_PRIVATE_OUTPUT_BYTES) stdout += chunk;
    else child.kill("SIGTERM");
  });
  drain(child.stderr, child);
  let exit: number;
  try { exit = await childExit(child, deadline); }
  catch (error) {
    if (!await stopProcessGroup(child)) fail("cleanup-incomplete");
    throw error;
  }
  if (exit !== 0 || bytes > MAX_PRIVATE_OUTPUT_BYTES) fail("identity-command");
  return stdout;
}

async function clearDirectory(path: string): Promise<void> {
  for (const entry of await readdir(path).catch(() => [])) {
    await rm(join(path, entry), { recursive: true, force: true });
  }
}

export async function main(argv: string[], totalTimeoutMs = TOTAL_TIMEOUT_MS): Promise<void> {
  disableCoreDumps();
  const options = parseOptions(argv);
  // Do not expand the enclosing protected container's 25-minute budget. UX
  // including login gets five minutes plus two-minute resource cleanup, leaving
  // over seventeen minutes for the original all-scope journey. Slow cold starts
  // fail closed; cleanup never borrows an expired action deadline.
  const deadline = Date.now() + Math.min(totalTimeoutMs, options.uxWalkthrough ? 300_000 : TOTAL_TIMEOUT_MS);
  if (basename(options.cwBin) !== "cw") fail("invalid-cw-binary");
  await requireExecutable(options.cwBin, "invalid-cw-binary");
  await requireExecutable(options.chromiumExecutable, "invalid-browser-binary");
  await requirePrivateFile(options.credentialFile, "invalid-credential-file");
  await requireEmptyPrivateTmpfs(options.configDir);
  const credentialPath = await realpath(options.credentialFile);
  if (credentialPath.startsWith(`${options.configDir}/`)) fail("invalid-credential-file");
  const raw = await readFile(options.credentialFile, { encoding: "utf8" });
  if (Buffer.byteLength(raw) > 16 * 1024) fail("invalid-credential-document");
  let decoded: unknown;
  try { decoded = JSON.parse(raw); } catch { fail("invalid-credential-document"); }
  const credentials = validateCredentialDocument(decoded, options);
  const home = join(options.configDir, ".browser-auth-home");
  const runtime = join(options.configDir, ".browser-auth-runtime");
  const browserProfile = join(options.configDir, ".browser-profile");
  const browserTemp = join(options.configDir, ".browser-temp");
  await mkdir(home, { mode: 0o700 });
  await mkdir(runtime, { mode: 0o700 });
  await mkdir(browserProfile, { mode: 0o700 });
  await mkdir(browserTemp, { mode: 0o700 });
  await chmod(home, 0o700); await chmod(runtime, 0o700);
  await chmod(browserProfile, 0o700); await chmod(browserTemp, 0o700);
  const env = childEnvironment(options.configDir, home, runtime);
  let login: ChildProcess | undefined;
  let context: BrowserContext | undefined;
  let page: Page | undefined;
  let success = false;
  let originalFailure: FixedStageError | undefined;
  let uxSandbox: OwnedUxSandbox | undefined;
  let signalStage = "";
  const signals = ["SIGHUP", "SIGINT", "SIGTERM"] as NodeJS.Signals[];
  const signalHandlers = new Map<NodeJS.Signals, () => void>();
  for (const signal of signals) {
    const handler = () => {
      if (signalStage) return;
      signalStage = `signal-${signal.toLowerCase()}`;
      if (login) signalProcessGroup(login, signal);
      if (context) void context.close().catch(() => undefined);
    };
    signalHandlers.set(signal, handler);
    process.on(signal, handler);
  }
  try {
    login = spawn(options.cwBin, ["--server", DEV_ORIGIN, "login", "--org", options.expectedOrgId], {
      env, stdio: ["ignore", "pipe", "pipe"], detached: true,
    });
    if (!login.stdout || !login.stderr) fail("child-process");
    drain(login.stderr, login);
    const challenge = await challengeFrom(login, deadline);
    context = await chromium.launchPersistentContext(browserProfile, {
      executablePath: options.chromiumExecutable,
      headless: true,
      env: {
        PATH: "/usr/bin:/bin", HOME: browserProfile, XDG_RUNTIME_DIR: runtime,
        TMPDIR: browserTemp, LC_ALL: "C", TZ: "UTC",
      },
      acceptDownloads: false,
      timeout: remaining(deadline),
    }).catch(fixedBrowserFailure("browser-launch"));
    page = await withinDeadline(() => context!.newPage(), deadline)
      .catch(fixedBrowserFailure("browser-page"));
    page.setDefaultTimeout(remaining(deadline));
    page.setDefaultNavigationTimeout(remaining(deadline));
    await withinDeadline(() => approveInOrdinaryBrowser(page!, challenge, credentials), deadline);
    const loginExit = await childExit(login, deadline);
    if (signalStage) fail(signalStage);
    if (loginExit !== 0) fail("cli-device-login");
    login = undefined;
    const savedRaw = await readFile(join(options.configDir, "credentials.json"), "utf8")
      .catch(() => fail("saved-oauth-invalid"));
    let saved: unknown;
    try { saved = JSON.parse(savedRaw); } catch { fail("saved-oauth-invalid"); }
    if (!saved || typeof saved !== "object" || Array.isArray(saved)) fail("saved-oauth-invalid");
    const record = saved as Record<string, unknown>;
    const savedKeys = ["issuer", "client_id", "access_token", "refresh_token", "expires_at_unix", "scope"];
    const scopes = typeof record.scope === "string" ? record.scope.trim().split(/\s+/) : [];
    if (!exactKeys(record, savedKeys)
      || record.issuer !== DEV_ORIGIN || record.client_id !== "codewire-cli"
      || typeof record.access_token !== "string" || !record.access_token
      || typeof record.refresh_token !== "string" || !record.refresh_token
      || typeof record.expires_at_unix !== "number"
      || scopes.length !== REQUIRED_SCOPE.split(" ").length
      || new Set(scopes).size !== scopes.length
      || !REQUIRED_SCOPE.split(" ").every((scope) => scopes.includes(scope))) {
      fail("saved-oauth-invalid");
    }
    const whoami = await runJson(options.cwBin, env, ["whoami", "--output", "json"], deadline);
    const organizations = await runJson(options.cwBin, env, ["org", "list", "--output", "json"], deadline);
    const current = await runText(options.cwBin, env, ["org", "current"], deadline);
    assertIdentityResponses(whoami, organizations, current, options);
    if (options.uxWalkthrough) {
      const slug = uxOrganizationSlug(organizations, options.expectedOrgId);
      uxSandbox = new OwnedUxSandbox(options.expectedUserId, options.expectedOrgId, async (args, limit) => {
        const bounded = Math.min(limit, Date.now() + 30_000);
        return args.includes("rm")
          ? runText(options.cwBin, env, args, bounded)
          : runJson(options.cwBin, env, args, bounded);
      });
      const { runDevUxWalkthrough } = await import("./dev-ux-walkthrough");
      await withinDeadline(() => runDevUxWalkthrough(page!, {
        slug, userId: options.expectedUserId, orgId: options.expectedOrgId,
        owned: uxSandbox!, deadline,
      }), deadline);
    }
    await withinDeadline(() => signOut(page!), deadline);
    await withinDeadline(() => context!.close(), deadline)
      .catch(fixedBrowserFailure("browser-close"));
    context = undefined; page = undefined;
    success = true;
  } catch (error) {
    originalFailure = error instanceof FixedStageError ? error
      : new FixedStageError(error instanceof DevUxError ? error.stage : "unexpected-failure");
    throw originalFailure;
  } finally {
    const cleanupFailures: string[] = [];
    const cleanupAttempt = async (label: CleanupOperation, operation: () => Promise<void>) => {
      try { await operation(); } catch { cleanupFailures.push(`${label}:failed`); }
    };
    try {
      if (login && !await stopProcessGroup(login)) cleanupFailures.push("login-process:unreaped");
      const cleanupDeadline = Date.now() + 30_000;
      if (page) await cleanupAttempt("browser-sign-out", () => withinDeadline(
        () => signOut(page!), Math.min(cleanupDeadline, Date.now() + 5000),
      ));
      if (context) await cleanupAttempt("browser-context-close", () => withinDeadline(
        () => context!.close(), Math.min(cleanupDeadline, Date.now() + 5000),
      ));
      // Quiesce browser actions before resource reconciliation, including a
      // walkthrough whose outer deadline fired during an in-flight request.
      if (uxSandbox) {
        await cleanupAttempt("ux-sandbox-remove", () => uxSandbox!.cleanup(Date.now() + 120_000));
        if (cleanupFailures.length) success = false;
        else console.error("[dev-ux] owned-sandbox-cleanup:passed");
      }
      if (!success) {
        const logout = spawn(options.cwBin, ["--server", DEV_ORIGIN, "logout"], {
          env, stdio: ["ignore", "ignore", "ignore"], detached: true,
        });
        let logoutExit = 1;
        try { logoutExit = await childExit(logout, Date.now() + 30_000); }
        catch { if (!await stopProcessGroup(logout)) cleanupFailures.push("logout-process:unreaped"); }
        if (logoutExit !== 0) cleanupFailures.push("cli-logout:nonzero-or-timeout");
      }
      await cleanupAttempt("browser-profile-remove", () => rm(browserProfile, { recursive: true, force: true }));
      await cleanupAttempt("browser-temp-remove", () => rm(browserTemp, { recursive: true, force: true }));
      await cleanupAttempt("runtime-remove", () => rm(runtime, { recursive: true, force: true }));
      await cleanupAttempt("home-remove", () => rm(home, { recursive: true, force: true }));
      if (!success) await cleanupAttempt("config-clear", () => clearDirectory(options.configDir));
    } finally {
      for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
      const failure = signalStage ? new FixedStageError(signalStage) : originalFailure
        ?? (cleanupFailures.length ? new FixedStageError("cleanup-incomplete") : undefined);
      if (failure) { failure.cleanupFailures = cleanupFailures; throw failure; }
    }
  }
  console.error("[dev-smoke-browser-auth] fresh dedicated CLI OAuth login prepared");
}

if ((import.meta as ImportMeta & { main?: boolean }).main) {
  process.umask(0o077);
  main(process.argv.slice(2)).catch((error) => {
    const stage = error instanceof FixedStageError ? error.stage : "unexpected-failure";
    console.error(`[dev-smoke-browser-auth] ERROR: ${stage}`);
    if (error instanceof FixedStageError && error.cleanupFailures.length) {
      console.error(`[dev-smoke-browser-auth] CLEANUP: ${error.cleanupFailures.join(",")}`);
    }
    process.exitCode = stage === "signal-sigint" ? 130 : stage === "signal-sigterm" ? 143 : stage === "signal-sighup" ? 129 : 1;
  });
}
