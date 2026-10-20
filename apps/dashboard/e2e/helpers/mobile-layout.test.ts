import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

import { designFixtureSpecs } from "./design-fixtures";
import { mobileLayoutSpecPattern, mobileLayoutSpecs } from "./mobile-layout";

const e2e = new URL("../", import.meta.url);
const fixtures = new Set<string>(designFixtureSpecs);
const dashboardSpecs = readdirSync(e2e)
  .filter((name) => name.startsWith("ssr-dashboard.") && name.endsWith(".ssr.ts") && !fixtures.has(name))
  .sort();
const source = (name: string) => readFileSync(new URL(name, e2e), "utf8");

// A test written for the mobile project: it skips itself on desktop.
const hasMobileOnlyTest = (text: string) => /test\.skip\(\s*!isMobile\b/.test(text);
// Reads `isMobile` beyond declaring it and skipping on mobile: a layout branch.
const branchesOnMobile = (text: string) => text
  .replace(/test\.skip\(\s*!!isMobile\b/g, "")
  .replace(/\(\{[^}]*\}[^)]*\)\s*=>/g, "")
  .includes("isMobile");
// Skips on mobile somewhere: by `isMobile` or by naming the desktop project.
const skipsOnMobile = (text: string) => /test\.skip\(\s*!!isMobile\b|project\.name !== "dashboard-ssr-desktop"/.test(text);

test("every listed spec is an existing dashboard spec, listed once", () => {
  assert.equal(new Set(mobileLayoutSpecs).size, mobileLayoutSpecs.length);
  for (const name of mobileLayoutSpecs) assert.ok(dashboardSpecs.includes(name), `${name} is not a dashboard spec`);
});

test("no mobile check is left out of the mobile project", () => {
  for (const name of dashboardSpecs) {
    const text = source(name);
    if (hasMobileOnlyTest(text) || branchesOnMobile(text)) {
      assert.ok((mobileLayoutSpecs as readonly string[]).includes(name), `${name} checks the mobile layout but is not listed`);
    }
  }
});

test("every listed spec still does something on mobile", () => {
  for (const name of mobileLayoutSpecs) {
    const text = source(name);
    assert.ok(
      hasMobileOnlyTest(text) || branchesOnMobile(text) || !skipsOnMobile(text),
      `${name} no longer checks the mobile layout; remove it from the list`,
    );
  }
});

test("the mobile pattern selects exactly the listed specs", () => {
  const selected = dashboardSpecs.filter((name) => mobileLayoutSpecPattern.test(`/repo/apps/dashboard/e2e/${name}`));
  assert.deepEqual(selected, [...mobileLayoutSpecs].sort());
  assert.ok(!mobileLayoutSpecPattern.test("/repo/apps/dashboard/e2e/xssr-dashboard.read.ssr.ts"));
});

test("the classifier helpers see the cases they are written for", () => {
  assert.ok(hasMobileOnlyTest('test.skip(!isMobile, "mobile visual contract");'));
  assert.ok(!hasMobileOnlyTest('test.skip(!!isMobile, "desktop contract");'));
  assert.ok(!branchesOnMobile('test("a", async ({ page, isMobile }) => {\n  test.skip(!!isMobile, "desktop");\n});'));
  assert.ok(branchesOnMobile('test("a", async ({ page, isMobile }) => {\n  await open(page, isMobile);\n});'));
  assert.ok(skipsOnMobile('test.skip(info.project.name !== "dashboard-ssr-desktop", "one proof");'));
  assert.ok(!skipsOnMobile('test("a", async ({ page }) => {});'));
});
