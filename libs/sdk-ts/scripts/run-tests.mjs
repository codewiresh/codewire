import { spawn } from "node:child_process";
import { constants } from "node:fs";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const SDK_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SUITES = ["test.js", "mesh.test.js", "cw-runtime.test.js", "platform-agents.test.js"];
const MAX_FILES = 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const SUITE_TIMEOUT_MS = 120_000;

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative !== "" && !relative.startsWith(".." + path.sep) &&
    relative !== ".." && !path.isAbsolute(relative);
}

function checkAbort(signal) {
  if (signal?.aborted) {
    const error = new Error("SDK test run cancelled");
    error.exitCode = 130;
    throw error;
  }
}

async function regular(file) {
  const metadata = await fs.lstat(file);
  requireCondition(metadata.isFile() && !metadata.isSymbolicLink(),
    "SDK test input/output must be a regular file");
  requireCondition(metadata.size <= MAX_FILE_BYTES, "SDK test file exceeds bound");
  const handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const held = await handle.stat();
    requireCondition(held.isFile() && held.dev === metadata.dev &&
      held.ino === metadata.ino && held.size === metadata.size,
    "SDK test file identity changed");
    const contents = await handle.readFile("utf8");
    requireCondition(Buffer.byteLength(contents) <= MAX_FILE_BYTES, "SDK test file exceeds bound");
    const after = await handle.stat();
    requireCondition(after.dev === held.dev && after.ino === held.ino &&
      after.size === held.size && after.mtimeMs === held.mtimeMs && after.ctimeMs === held.ctimeMs,
    "SDK test file changed during read");
    return contents;
  } finally {
    await handle.close();
  }
}

async function filesBelow(root, suffix) {
  const result = [];
  let bytes = 0;
  async function walk(directory) {
    const metadata = await fs.lstat(directory);
    requireCondition(metadata.isDirectory() && !metadata.isSymbolicLink(),
      "SDK source/output directory must not be a symlink");
    const entries = await fs.readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      requireCondition(!entry.isSymbolicLink(), "SDK source/output symlink refused");
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(file);
      } else {
        requireCondition(entry.isFile(), "SDK source/output topology refused");
        if (!entry.name.endsWith(suffix)) continue;
        const info = await fs.lstat(file);
        requireCondition(info.size <= MAX_FILE_BYTES, "SDK source/output exceeds file bound");
        bytes += info.size;
        result.push(file);
        requireCondition(result.length <= MAX_FILES && bytes <= MAX_TOTAL_BYTES,
          "SDK source/output exceeds inventory bound");
      }
    }
  }
  await walk(root);
  return result;
}

// Only generated relative import/export tokens change, in the private emitted tree.
// The public TypeScript and package exports remain untouched.
export async function qualifyGeneratedImports(root) {
  const files = await filesBelow(root, ".js");
  const admitted = new Set(files);
  for (const file of files) {
    const source = await regular(file);
    const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS);
    requireCondition(parsed.parseDiagnostics.length === 0, "Emitted generated JavaScript is malformed");
    const edits = [];
    const targets = new Set();
    function inspect(node) {
      let literal;
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        literal = node.moduleSpecifier;
      } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        requireCondition(node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]),
          "Generated dynamic import must be a fixed string");
        literal = node.arguments[0];
      }
      if (literal) {
        requireCondition(ts.isStringLiteral(literal), "Generated import must be a fixed string");
        const specifier = literal.text;
        if (specifier.startsWith(".")) {
          requireCondition(/^\.{1,2}\/[A-Za-z0-9_./-]+$/.test(specifier),
            "Generated relative import syntax refused");
          const qualified = specifier.endsWith(".js") ? specifier : specifier + ".js";
          const target = path.resolve(path.dirname(file), qualified);
          requireCondition(inside(root, target) && admitted.has(target),
            "Generated import has no admitted emitted target");
          targets.add(target);
          if (qualified !== specifier) {
            edits.push({ start: literal.getStart(parsed), end: literal.end, text: JSON.stringify(qualified) });
          }
        }
      }
      ts.forEachChild(node, inspect);
    }
    inspect(parsed);
    // Reopen each target rather than relying on its name or an exists() check.
    for (const target of targets) await regular(target);
    let rewritten = source;
    for (const edit of edits.sort((left, right) => right.start - left.start)) {
      rewritten = rewritten.slice(0, edit.start) + edit.text + rewritten.slice(edit.end);
    }
    if (rewritten !== source) await fs.writeFile(file, rewritten, { mode: 0o600 });
  }
  for (const file of files) await regular(file);
  return files;
}

function commonDirectory(left, right) {
  let root = left;
  while (root !== right && !inside(root, right)) {
    const parent = path.dirname(root);
    requireCondition(parent !== root, "SDK/proto source roots have no common directory");
    root = parent;
  }
  return root;
}

function diagnosticText(diagnostics) {
  const formatted = ts.formatDiagnostics(diagnostics, {
    getCurrentDirectory: () => process.cwd(),
    getCanonicalFileName: (file) => file,
    getNewLine: () => "\n",
  });
  return formatted.slice(0, 16_384);
}

export async function compileTests({ sdkDir, protoDir, workDir, signal }) {
  checkAbort(signal);
  const sdkSource = path.join(sdkDir, "src");
  const protoSource = path.join(protoDir, "src");
  const sourceFiles = [
    ...await filesBelow(sdkSource, ".ts"),
    ...await filesBelow(protoSource, ".ts"),
  ];
  requireCondition(sourceFiles.length > 0 && sourceFiles.length <= MAX_FILES,
    "SDK/proto source inventory refused");
  const configFile = path.join(sdkDir, "tsconfig.json");
  const config = ts.parseConfigFileTextToJson(configFile, await regular(configFile));
  requireCondition(!config.error, "SDK TypeScript configuration is malformed");
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, sdkDir);
  requireCondition(parsed.errors.length === 0, diagnosticText(parsed.errors));
  const protoPackage = JSON.parse(await regular(path.join(protoDir, "package.json")));
  requireCondition(protoPackage.name === "@codewire/proto-ts" &&
    protoPackage.type === "module" && protoPackage.exports &&
    typeof protoPackage.exports === "object" && !Array.isArray(protoPackage.exports),
  "Generated package identity/exports refused");
  const paths = {};
  const exports = {};
  for (const [key, target] of Object.entries(protoPackage.exports)) {
    requireCondition((key === "." || /^\.\/[A-Za-z0-9_/-]+\*?$/.test(key)) &&
      typeof target === "string" && /^\.\/src\/[A-Za-z0-9_/*.-]+\.ts$/.test(target) &&
      !target.split("/").includes("..") &&
      (key.match(/\*/g) ?? []).length === (target.match(/\*/g) ?? []).length,
    "Generated package export path refused");
    paths[key === "." ? "@codewire/proto-ts" : "@codewire/proto-ts/" + key.slice(2)] =
      [path.resolve(protoDir, target)];
    exports[key] = target.slice(0, -3) + ".js";
  }
  const sourceRoot = commonDirectory(sdkDir, protoDir);
  const emitted = path.join(workDir, "emitted");
  await fs.mkdir(emitted, { mode: 0o700 });
  const options = {
    ...parsed.options,
    rootDir: sourceRoot,
    outDir: emitted,
    paths,
    noEmit: false,
    noEmitOnError: true,
    declaration: false,
    declarationMap: false,
    sourceMap: false,
    inlineSourceMap: false,
    incremental: false,
    composite: false,
    tsBuildInfoFile: undefined,
  };
  const emittedFiles = new Map();
  const host = ts.createCompilerHost(options);
  host.getCurrentDirectory = () => sdkDir;
  const resolutionCache = ts.createModuleResolutionCache(sdkDir, (file) => file, options);
  host.resolveModuleNames = (names, containingFile) => names.map((name) => {
    // The selected generated tree is separate from npm's installed file copy.
    // Its external imports must use the SDK's exact installed dependencies,
    // rather than whichever packages happen to be above the source checkout.
    const issuer = inside(protoSource, containingFile) && !name.startsWith(".")
      ? path.join(sdkSource, "__generated_dependencies__.ts") : containingFile;
    return ts.resolveModuleName(name, issuer, options, host, resolutionCache).resolvedModule;
  });
  host.writeFile = (file, contents, _bom, _onError, sources) => {
    requireCondition(inside(emitted, path.resolve(file)) && file.endsWith(".js") &&
      sources?.every((source) => inside(sdkSource, source.fileName) || inside(protoSource, source.fileName)),
    "Compiler emitted an unexpected file");
    requireCondition(Buffer.byteLength(contents) <= MAX_FILE_BYTES, "Compiler output exceeds file bound");
    emittedFiles.set(file, contents);
    requireCondition(emittedFiles.size <= MAX_FILES, "Compiler output exceeds inventory bound");
  };
  const program = ts.createProgram(sourceFiles, options, host);
  const diagnostics = ts.getPreEmitDiagnostics(program);
  requireCondition(diagnostics.length === 0, "SDK TypeScript compilation failed:\n" + diagnosticText(diagnostics));
  const result = program.emit();
  requireCondition(!result.emitSkipped && result.diagnostics.length === 0,
    "SDK TypeScript emit failed:\n" + diagnosticText(result.diagnostics));
  checkAbort(signal);
  let emittedBytes = 0;
  for (const [file, contents] of emittedFiles) {
    emittedBytes += Buffer.byteLength(contents);
    requireCondition(emittedBytes <= MAX_TOTAL_BYTES, "Compiler output exceeds total bound");
    await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
    await fs.writeFile(file, contents, { flag: "wx", mode: 0o600 });
  }
  const emittedProto = path.join(emitted, path.relative(sourceRoot, protoDir));
  const emittedProtoSource = path.join(emittedProto, "src");
  const admitted = new Set(await qualifyGeneratedImports(emittedProtoSource));
  for (const target of Object.values(exports)) {
    if (target.includes("*")) {
      const [prefix, suffix] = path.resolve(emittedProto, target).split("*");
      requireCondition([...admitted].some((file) => file.startsWith(prefix) && file.endsWith(suffix)),
        "Generated wildcard export has no admitted output");
    } else {
      requireCondition(admitted.has(path.resolve(emittedProto, target)),
        "Generated export has no admitted output");
    }
  }
  await fs.writeFile(path.join(emitted, "package.json"), '{"type":"module"}\n', { flag: "wx", mode: 0o600 });
  await fs.writeFile(path.join(emittedProto, "package.json"),
    JSON.stringify({ name: "@codewire/proto-ts", type: "module", exports }) + "\n",
    { flag: "wx", mode: 0o600 });
  const modules = path.join(emitted, "node_modules");
  await fs.mkdir(path.join(modules, "@codewire"), { recursive: true, mode: 0o700 });
  await fs.symlink(emittedProto, path.join(modules, "@codewire", "proto-ts"), "dir");
  const sdkPackage = JSON.parse(await regular(path.join(sdkDir, "package.json")));
  for (const name of Object.keys(sdkPackage.dependencies ?? {})) {
    if (name === "@codewire/proto-ts") continue;
    requireCondition(/^(?:@[a-z0-9_-]+\/)?[a-z0-9_.-]+$/.test(name), "SDK dependency name refused");
    const destination = path.join(modules, name);
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
    await fs.symlink(await fs.realpath(path.join(sdkDir, "node_modules", name)), destination, "dir");
  }
  const sdkOutput = path.join(emitted, path.relative(sourceRoot, sdkDir), "src");
  const suites = SUITES.map((name) => path.join(sdkOutput, name));
  for (const file of suites) await regular(file);
  checkAbort(signal);
  return { suites, sourceFiles: sourceFiles.length, emittedFiles: emittedFiles.size };
}

export async function runSuite(file, { signal, cwd, environment, stdio = "inherit", timeoutMs = SUITE_TIMEOUT_MS } = {}) {
  checkAbort(signal);
  await regular(file);
  checkAbort(signal);
  let child;
  let closed = false;
  let cancelled = false;
  let expired = false;
  let spawnError;
  let escalation;
  const stop = () => {
    if (closed) return;
    child.kill("SIGTERM");
    escalation ??= setTimeout(() => {
      if (!closed) child.kill("SIGKILL");
    }, 1_000);
  };
  const onAbort = () => { cancelled = true; stop(); };
  try {
    const completion = new Promise((resolve) => {
      child = spawn(process.execPath, [file], { cwd, env: environment, stdio });
      child.once("error", (error) => { spawnError = error; });
      child.once("close", (code, childSignal) => {
        closed = true;
        resolve({ code, signal: childSignal });
      });
    });
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
    const deadline = setTimeout(() => { expired = true; stop(); }, timeoutMs);
    let result;
    try {
      result = await completion;
    } finally {
      clearTimeout(deadline);
    }
    if (spawnError) throw new Error("SDK suite process could not start", { cause: spawnError });
    if (cancelled || expired || result.code !== 0 || result.signal !== null) {
      const error = new Error(cancelled ? "SDK suite cancelled after child closure" :
        expired ? "SDK suite timed out after child closure" :
          "SDK suite failed: " + path.basename(file));
      error.exitCode = cancelled ? 130 : expired ? 124 : result.code || 1;
      throw error;
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    clearTimeout(escalation);
  }
}

export async function runTests({ sdkDir = SDK_DIR,
  protoDir = path.resolve(sdkDir, "../../packages/codewire-proto-ts"),
  temporaryParent = tmpdir(), signal, stdio = "inherit" } = {}) {
  checkAbort(signal);
  const workDir = await fs.mkdtemp(path.join(temporaryParent, "codewire-sdk-tests-"));
  try {
    const compiled = await compileTests({ sdkDir, protoDir, workDir, signal });
    const home = path.join(workDir, "home");
    const temp = path.join(workDir, "temp");
    await fs.mkdir(home, { mode: 0o700 });
    await fs.mkdir(temp, { mode: 0o700 });
    const environment = {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: home, TMPDIR: temp, LC_ALL: "C.UTF-8", TZ: "UTC",
    };
    for (const file of compiled.suites) {
      await new Promise((resolve) => setImmediate(resolve));
      checkAbort(signal);
      await runSuite(file, { signal, cwd: sdkDir, environment, stdio });
    }
    checkAbort(signal);
    return { suites: SUITES.length, sourceFiles: compiled.sourceFiles,
      emittedFiles: compiled.emittedFiles };
  } finally {
    await fs.rm(workDir, { recursive: true });
  }
}

async function main() {
  requireCondition(process.argv.length === 2, "SDK test runner takes no arguments");
  requireCondition(Number(process.versions.node.split(".")[0]) >= 22, "SDK tests require Node >=22");
  const controller = new AbortController();
  let exitCode;
  const handlers = new Map();
  for (const [name, code] of [["SIGINT", 130], ["SIGTERM", 143], ["SIGHUP", 129]]) {
    const handler = () => { exitCode ??= code; controller.abort(); };
    handlers.set(name, handler);
    process.on(name, handler);
  }
  try {
    const result = await runTests({ signal: controller.signal });
    checkAbort(controller.signal);
    console.log("SDK unit suites completed: " + result.suites);
  } catch (error) {
    console.error(String(error.message).slice(0, 16_384));
    process.exitCode = exitCode ?? error.exitCode ?? 1;
  } finally {
    for (const [name, handler] of handlers) process.off(name, handler);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
