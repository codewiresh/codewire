import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { compileTests, qualifyGeneratedImports, runSuite, runTests } from "./run-tests.mjs";

const SUITES = ["test", "mesh.test", "cw-runtime.test", "platform-agents.test"];

async function temporary(run) {
  const root = await fs.mkdtemp(path.join(tmpdir(), "cw-sdk-runner-fixture-"));
  try {
    return await run(root);
  } finally {
    await fs.rm(root, { recursive: true });
  }
}

async function sourceFixture(root, { failure, typeError = false } = {}) {
  const sdkDir = path.join(root, "libs", "sdk-ts");
  const protoDir = path.join(root, "packages", "codewire-proto-ts");
  await fs.mkdir(path.join(sdkDir, "src"), { recursive: true, mode: 0o700 });
  await fs.mkdir(path.join(protoDir, "src"), { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(sdkDir, "package.json"),
    JSON.stringify({ type: "module", dependencies: { "@codewire/proto-ts": "file:../../packages/codewire-proto-ts" } }));
  await fs.writeFile(path.join(sdkDir, "tsconfig.json"), JSON.stringify({
    compilerOptions: { target: "ES2022", module: "ESNext", moduleResolution: "bundler",
      strict: true, skipLibCheck: true, types: [], rootDir: "src", outDir: "dist" },
    include: ["src"],
  }));
  await fs.writeFile(path.join(protoDir, "package.json"), JSON.stringify({
    name: "@codewire/proto-ts", type: "module", exports: { ".": "./src/index.ts" },
  }));
  await fs.writeFile(path.join(protoDir, "src", "index.ts"), 'export { value } from "./value";\n');
  await fs.writeFile(path.join(protoDir, "src", "value.ts"), "export const value = 7;\n");
  await fs.writeFile(path.join(sdkDir, "src", "ambient.d.ts"), [
    'declare module "node:fs" { export function appendFileSync(path: string, value: string): void; }',
    "declare const process: { exit(code: number): never; env: Record<string, string | undefined> };",
    "",
  ].join("\n"));
  const marker = path.join(root, "executed");
  for (const suite of SUITES) {
    await fs.writeFile(path.join(sdkDir, "src", suite + ".ts"), [
      'import { value } from "@codewire/proto-ts";',
      'import { appendFileSync } from "node:fs";',
      "if (value !== 7) throw new Error('wrong generated value');",
      "if (process.env.CW_RUNNER_SYNTHETIC_SECRET) throw new Error('ambient variable inherited');",
      "appendFileSync(" + JSON.stringify(marker) + ", " + JSON.stringify(suite + "\n") + ");",
      typeError && suite === "test" ? 'const wrong: number = "not a number";' : "",
      failure === suite ? "process.exit(7);" : "",
      "",
    ].join("\n"));
  }
  const temporaryParent = path.join(root, "work");
  await fs.mkdir(temporaryParent, { mode: 0o700 });
  return { sdkDir, protoDir, marker, temporaryParent };
}

async function compileFixture(root, fixture) {
  const workDir = path.join(root, "compile");
  await fs.mkdir(workDir, { mode: 0o700 });
  return { result: await compileTests({ ...fixture, workDir }), workDir };
}

test("compiler emits both real source trees and the private generated package view", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root);
    const originalPackage = await fs.readFile(path.join(fixture.protoDir, "package.json"));
    const { result, workDir } = await compileFixture(root, fixture);
    assert.equal(result.suites.length, SUITES.length);
    const generated = await fs.readFile(
      path.join(workDir, "emitted", "packages", "codewire-proto-ts", "src", "index.js"), "utf8");
    assert.match(generated, /from "\.\/value\.js"/);
    assert.deepEqual(await fs.readFile(path.join(fixture.protoDir, "package.json")), originalPackage);
    const packageView = JSON.parse(await fs.readFile(
      path.join(workDir, "emitted", "packages", "codewire-proto-ts", "package.json"), "utf8"));
    assert.deepEqual(packageView.exports, { ".": "./src/index.js" });
    await assert.rejects(fs.stat(fixture.marker), { code: "ENOENT" });
  });
});

test("compiler errors refuse every suite before execution and remove private output", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root, { typeError: true });
    await assert.rejects(runTests({ ...fixture, stdio: "ignore" }), /TypeScript compilation failed/);
    await assert.rejects(fs.stat(fixture.marker), { code: "ENOENT" });
    assert.deepEqual(await fs.readdir(fixture.temporaryParent), []);
  });
});

test("all three fixed suites run in order with an isolated child environment", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root);
    const previous = process.env.CW_RUNNER_SYNTHETIC_SECRET;
    process.env.CW_RUNNER_SYNTHETIC_SECRET = "fixture-only";
    try {
      const result = await runTests({ ...fixture, stdio: "ignore" });
      assert.equal(result.suites, SUITES.length);
      assert.equal(await fs.readFile(fixture.marker, "utf8"), SUITES.join("\n") + "\n");
      assert.deepEqual(await fs.readdir(fixture.temporaryParent), []);
    } finally {
      if (previous === undefined) delete process.env.CW_RUNNER_SYNTHETIC_SECRET;
      else process.env.CW_RUNNER_SYNTHETIC_SECRET = previous;
    }
  });
});

test("generated external imports resolve through the SDK's installed dependency closure", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root);
    const name = "@cw-runner-fixture/dep";
    const dependency = path.join(fixture.sdkDir, "node_modules", name);
    await fs.mkdir(dependency, { recursive: true, mode: 0o700 });
    await fs.writeFile(path.join(dependency, "package.json"), JSON.stringify({
      name, version: "0.0.0-fixture", type: "module",
      exports: { ".": { types: "./index.d.ts", default: "./index.js" } },
    }));
    await fs.writeFile(path.join(dependency, "index.d.ts"), "export declare const external: number;\n");
    await fs.writeFile(path.join(dependency, "index.js"), "export const external = 7;\n");
    const packageFile = path.join(fixture.sdkDir, "package.json");
    const sdkPackage = JSON.parse(await fs.readFile(packageFile, "utf8"));
    sdkPackage.dependencies[name] = "0.0.0-fixture";
    await fs.writeFile(packageFile, JSON.stringify(sdkPackage));
    await fs.writeFile(path.join(fixture.protoDir, "src", "value.ts"),
      'import { external } from "@cw-runner-fixture/dep"; export const value = external;\n');
    await runTests({ ...fixture, stdio: "ignore" });
    assert.equal(await fs.readFile(fixture.marker, "utf8"), SUITES.join("\n") + "\n");
  });
});

for (const [index, suite] of SUITES.entries()) {
  test("failure in " + suite + " preserves exit status and stops later suites", async () => {
    await temporary(async (root) => {
      const fixture = await sourceFixture(root, { failure: suite });
      await assert.rejects(runTests({ ...fixture, stdio: "ignore" }),
        (error) => error.exitCode === 7 && error.message.includes(suite + ".js"));
      assert.equal(await fs.readFile(fixture.marker, "utf8"), SUITES.slice(0, index + 1).join("\n") + "\n");
      assert.deepEqual(await fs.readdir(fixture.temporaryParent), []);
    });
  });
}

test("AST qualification preserves bare imports, comments and ordinary string values", async () => {
  await temporary(async (root) => {
    await fs.writeFile(path.join(root, "dep.js"), "export const value = 1;\n");
    await fs.writeFile(path.join(root, "main.js"), [
      'import assert from "node:assert";',
      'export { value } from "./dep";',
      'const text = "./not-an-import"; // "./another-not-import"',
      "",
    ].join("\n"));
    await qualifyGeneratedImports(root);
    const actual = await fs.readFile(path.join(root, "main.js"), "utf8");
    assert.match(actual, /from "node:assert"/);
    assert.match(actual, /from "\.\/dep\.js"/);
    assert.match(actual, /const text = "\.\/not-an-import"; \/\/ "\.\/another-not-import"/);
  });
});

test("missing generated import target refuses rather than falling back to source", async () => {
  await temporary(async (root) => {
    await fs.writeFile(path.join(root, "main.js"), 'export * from "./missing";\n');
    await assert.rejects(qualifyGeneratedImports(root), /no admitted emitted target/);
  });
});

test("generated import cannot escape its emitted tree even when the outside file exists", async () => {
  await temporary(async (root) => {
    const emitted = path.join(root, "emitted");
    await fs.mkdir(emitted);
    const sentinel = "owned external sentinel\n";
    await fs.writeFile(path.join(root, "outside.js"), sentinel);
    await fs.writeFile(path.join(emitted, "main.js"), 'export * from "../outside";\n');
    await assert.rejects(qualifyGeneratedImports(emitted), /no admitted emitted target/);
    assert.equal(await fs.readFile(path.join(root, "outside.js"), "utf8"), sentinel);
  });
});

test("generated target symlinks are refused without modifying their destination", async () => {
  await temporary(async (root) => {
    const emitted = path.join(root, "emitted");
    await fs.mkdir(emitted);
    const sentinel = "owned external sentinel\n";
    const outside = path.join(root, "outside.js");
    await fs.writeFile(outside, sentinel);
    await fs.symlink(outside, path.join(emitted, "dep.js"));
    await fs.writeFile(path.join(emitted, "main.js"), 'export * from "./dep";\n');
    await assert.rejects(qualifyGeneratedImports(emitted), /symlink refused/);
    assert.equal(await fs.readFile(outside, "utf8"), sentinel);
  });
});

test("computed generated dynamic import is refused", async () => {
  await temporary(async (root) => {
    await fs.writeFile(path.join(root, "main.js"), 'const name = "./dep"; await import(name);\n');
    await assert.rejects(qualifyGeneratedImports(root), /fixed string/);
  });
});

test("missing fixed suite refuses before any suite execution", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root);
    await fs.rm(path.join(fixture.sdkDir, "src", "mesh.test.ts"));
    await assert.rejects(runTests({ ...fixture, stdio: "ignore" }), { code: "ENOENT" });
    await assert.rejects(fs.stat(fixture.marker), { code: "ENOENT" });
    assert.deepEqual(await fs.readdir(fixture.temporaryParent), []);
  });
});

test("a pre-cancelled run allocates no work or child", async () => {
  await temporary(async (root) => {
    const fixture = await sourceFixture(root);
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(runTests({ ...fixture, signal: controller.signal, stdio: "ignore" }), /cancelled/);
    await assert.rejects(fs.stat(fixture.marker), { code: "ENOENT" });
    assert.deepEqual(await fs.readdir(fixture.temporaryParent), []);
  });
});

async function waitForFile(file) {
  const limit = Date.now() + 3_000;
  while (Date.now() < limit) {
    try { return await fs.readFile(file, "utf8"); } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("owned child did not become ready");
}

test("cancellation waits for the retained child to close before rejecting", async () => {
  await temporary(async (root) => {
    const ready = path.join(root, "ready");
    const closed = path.join(root, "closed");
    const file = path.join(root, "suite.mjs");
    await fs.writeFile(file, [
      'import { writeFileSync } from "node:fs";',
      "writeFileSync(" + JSON.stringify(ready) + ", String(process.pid));",
      "const timer = setInterval(() => {}, 100);",
      'process.once("SIGTERM", () => setTimeout(() => {',
      "  writeFileSync(" + JSON.stringify(closed) + ', "closed");',
      "  clearInterval(timer);",
      "}, 25));",
      "",
    ].join("\n"));
    const controller = new AbortController();
    const result = runSuite(file, { signal: controller.signal, stdio: "ignore" });
    const rejection = assert.rejects(result, /cancelled after child closure/);
    try {
      await waitForFile(ready);
    } finally {
      controller.abort();
      await rejection;
    }
    assert.equal(await fs.readFile(closed, "utf8"), "closed");
  });
});

test("timeout closes a TERM-resistant child and remains a failure", async () => {
  await temporary(async (root) => {
    const ready = path.join(root, "ready");
    const file = path.join(root, "suite.mjs");
    await fs.writeFile(file, [
      'import { writeFileSync } from "node:fs";',
      'process.on("SIGTERM", () => {});',
      "writeFileSync(" + JSON.stringify(ready) + ", String(process.pid));",
      "setInterval(() => {}, 100);",
      "",
    ].join("\n"));
    const result = runSuite(file, { stdio: "ignore", timeoutMs: 1_000 });
    const rejection = assert.rejects(result,
      (error) => error.exitCode === 124 && error.message.includes("after child closure"));
    await waitForFile(ready);
    await rejection;
  });
});
