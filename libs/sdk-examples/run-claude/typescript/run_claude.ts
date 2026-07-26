// Runnable proof that the TypeScript SDK can drive a local VM end-to-end.
//
// Creates a Docker-backed local environment, runs
// `claude -p <prompt>` inside, prints the model's response, and tears down.
//
// Usage:
//   cd sdk/examples/run-claude/typescript
//   npm ci --ignore-scripts
//   npm run start
//
// Requires: docker running, `cw` binary on PATH (or $CW_BIN set), and a
// valid CLAUDE_CODE_OAUTH_TOKEN in ~/.claude/.credentials.json (which the
// CLI forwards into the container automatically).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Codewire, type LocalInstance } from "@codewire/sdk";

const DEFAULT_IMAGE = "docker.io/library/alpine:3.20";
const DEFAULT_CMD = "echo hello from codewire";

async function main(): Promise<number> {
  const image = process.env.CW_EXAMPLE_IMAGE ?? DEFAULT_IMAGE;
  const cmdline = process.env.CW_EXAMPLE_CMD ?? DEFAULT_CMD;

  const cw = new Codewire(); // no API key needed for local-only use
  const workdir = mkdtempSync(join(tmpdir(), "cw-example-ts-"));

  let inst: LocalInstance | undefined;
  try {
    console.log("==> Creating docker local instance…");
    inst = await cw.local.create(
      { image },
      { backend: "docker", path: workdir, wait: true },
    );
    console.log(
      `    created ${inst.name} (backend=${inst.backend} status=${inst.status})`,
    );

    console.log(`==> Running: ${cmdline}`);
    const res = await inst.exec({ command: ["sh", "-c", cmdline] });

    console.log(`\n--- exit ${res.exit_code} ---`);
    process.stdout.write(res.stdout.endsWith("\n") ? res.stdout : res.stdout + "\n");
    console.log("--- end ---");

    if (res.exit_code !== 0) {
      console.error("stderr:");
      console.error(res.stderr);
      return res.exit_code;
    }
    return 0;
  } finally {
    if (inst) {
      console.log("==> Removing instance…");
      try {
        await inst.remove();
      } catch (err) {
        console.error("remove error:", err);
      }
    }
    rmSync(workdir, { recursive: true, force: true });
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(err);
    process.exit(1);
  },
);
