import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { QUARANTINE_TAG, quarantine } from "./quarantine";

const e2e = new URL("../", import.meta.url);
const today = new Date("2026-10-20T15:00:00Z");

test("an active quarantine tags the test and names its issue and last day", () => {
  assert.deepEqual(quarantine(2990, "2026-11-03", [], today), {
    tag: [QUARANTINE_TAG],
    annotation: [{ type: "quarantine", description: "#2990 until 2026-11-03" }],
  });
  assert.deepEqual(quarantine(2990, "2026-10-20", ["@kind-heavy"], today).tag, ["@kind-heavy", QUARANTINE_TAG]);
});

test("a quarantine past its last day blocks again", () => {
  const ended = quarantine(2990, "2026-10-19", ["@kind-heavy"], today);
  assert.deepEqual(ended.tag, ["@kind-heavy"]);
  assert.equal(ended.annotation[0].description, "#2990 ended 2026-10-19; blocking again");
});

test("a quarantine needs an issue and a real last day at most 30 days ahead", () => {
  for (const [issue, until] of [
    [0, "2026-11-03"], [-1, "2026-11-03"], [29.5, "2026-11-03"],
    [2990, "2026-11-31"], [2990, "next week"], [2990, "2026-11-3"],
    [2990, "2026-11-20"],
  ] as const) {
    assert.throws(() => quarantine(issue, until, [], today), `${issue} ${until}`);
  }
  assert.doesNotThrow(() => quarantine(2990, "2026-11-19", [], today));
  assert.throws(() => quarantine(2990, "2026-11-03", [QUARANTINE_TAG], today));
});

test("specs quarantine only through the helper", () => {
  const sources: string[] = [];
  const walk = (directory: URL) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory()) walk(new URL(`${entry.name}/`, directory));
      else if (entry.name.endsWith(".ts") && !/^quarantine(\.test)?\.ts$/.test(entry.name)) {
        sources.push(new URL(entry.name, directory).pathname);
      }
    }
  };
  walk(e2e);
  assert.ok(sources.length > 10);
  for (const path of sources) {
    assert.ok(!readFileSync(path, "utf8").includes(QUARANTINE_TAG), `${path} names ${QUARANTINE_TAG}; use quarantine()`);
  }
});
