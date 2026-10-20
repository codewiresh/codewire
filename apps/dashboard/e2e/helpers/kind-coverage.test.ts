import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

// Every Kind dashboard spec names, in `// covers:` lines, the dashboard crate
// files it exercises; `make kind-test` runs only the specs a change covers
// (scripts/dev/kind/dashboard-specs.py, #2974). A renamed or removed template
// or route module must update those lines.
test("every Kind dashboard spec is mapped to dashboard files that exist", () => {
  const script = fileURLToPath(new URL("../../../../scripts/dev/kind/dashboard-specs.py", import.meta.url));
  const result = spawnSync("python3", ["-B", script, "check"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});
