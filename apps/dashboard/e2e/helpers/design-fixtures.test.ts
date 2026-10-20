import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  designFixtureSpecPattern,
  designFixtureSpecs,
  designOriginAwareApplicationSpecs,
} from "./design-fixtures";

const e2e = new URL("../", import.meta.url);
const specs = readdirSync(e2e).filter((name) => name.endsWith(".ssr.ts")).sort();
const source = (name: string) => readFileSync(new URL(name, e2e), "utf8");

test("every spec that reads the design origin is classified exactly once", () => {
  const listed = new Set<string>([...designFixtureSpecs, ...designOriginAwareApplicationSpecs]);
  assert.equal(listed.size, designFixtureSpecs.length + designOriginAwareApplicationSpecs.length);
  for (const name of listed) assert.ok(specs.includes(name), `${name} does not exist`);
  const readers = specs.filter((name) => source(name).includes("CODEWIRE_DESIGN_ORIGIN"));
  assert.deepEqual(readers, [...listed].sort());
});

test("fixture specs never navigate relative to the dashboard application", () => {
  for (const name of designFixtureSpecs) {
    assert.doesNotMatch(source(name), /\.goto\(\s*["'`]\//, `${name} navigates to an application path`);
  }
});

test("the fixture pattern selects exactly the listed specs", () => {
  const selected = specs.filter((name) => designFixtureSpecPattern.test(`/repo/apps/dashboard/e2e/${name}`));
  assert.deepEqual(selected, [...designFixtureSpecs].sort());
  assert.ok(!designFixtureSpecPattern.test("/repo/apps/dashboard/e2e/xssr-dashboard.resize.ssr.ts"));
});

test("every fixture spec fails at once when its page loses a script (#3043)", () => {
  for (const name of designFixtureSpecs) {
    assert.match(source(name), /^import \{[^}]*\btest\b[^}]*\} from "\.\/helpers\/fixture-test";$/m, `${name} takes test from helpers/fixture-test`);
    assert.doesNotMatch(source(name), /from "@playwright\/test"/, `${name} bypasses helpers/fixture-test`);
  }
});

test("the verification selector keeps exactly the fixture specs out of Kind", () => {
  const selector = readFileSync(new URL("../../../../scripts/ci/select/select-verification.sh", import.meta.url), "utf8");
  const named = [...selector.matchAll(/apps\/dashboard\/e2e\/(ssr-dashboard\.[\w.-]+\.ssr\.ts)/g)].map((match) => match[1]);
  assert.deepEqual(named.sort(), [...designFixtureSpecs].sort());
});
