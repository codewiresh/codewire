import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { designFixtureMobileTag, designFixtureSpecs } from "./design-fixtures";
import { classifyFixtureTests } from "./design-fixtures-mobile";

const e2e = new URL("../", import.meta.url);
const source = (name: string) => readFileSync(new URL(name, e2e), "utf8");
const tag = designFixtureMobileTag;

test("exactly the fixture tests that check the mobile width carry the mobile tag", () => {
  let mobile = 0;
  for (const name of designFixtureSpecs) {
    const tests = classifyFixtureTests(source(name), tag);
    // Every test call is classified: one whose title the classifier cannot
    // read would otherwise run at neither width's judgement.
    const calls = source(name).match(/^\s*test(?:\.only|\.fixme)?\(/gm) ?? [];
    assert.ok(tests.length > 0 && tests.length === calls.length,
      `${name}: classified ${tests.length} of its ${calls.length} tests; give each a one-line title literal`);
    for (const { title, mobile: checks, tagged } of tests) {
      if (checks) mobile += 1;
      assert.ok(!checks || tagged, `${name} › ${title} looks at the mobile width but lacks ${tag}`);
      assert.ok(checks || !tagged, `${name} › ${title} carries ${tag} but never looks at the project's width`);
    }
  }
  assert.ok(mobile > 0, "no fixture test runs at the mobile width");
});

test("the classifier sees the cases it is written for", () => {
  const classify = (body: string, header = "") =>
    classifyFixtureTests(`test("t"${header}, async ({ page }) => {\n${body}\n});\n`, tag)[0];
  // A test that measures at the project's width needs the tag; one that
  // measures only after setting its own viewport, or never measures, does not.
  assert.equal(classify("  expect((await row.boundingBox())!.width).toBeLessThan(10);").mobile, true);
  assert.equal(classify("  if ((page.viewportSize()?.width || 0) < 640) await open();").mobile, true);
  assert.equal(classify("  await page.setViewportSize({ width: 390, height: 844 });\n  await row.boundingBox();").mobile, false);
  assert.equal(classify("  await row.boundingBox();\n  await page.setViewportSize({ width: 1000, height: 700 });").mobile, true);
  assert.equal(classify("  await page.getByRole(\"button\").click();").mobile, false);
  assert.equal(classify("  await row.boundingBox();", `, { tag: "${tag}" }`).tagged, true);
  assert.equal(classify("  await row.boundingBox();").tagged, false);
  // Through a helper of the file, and through a helper that calls one.
  const helpers = `async function measure(page) {\n  return page.viewportSize();\n}\nasync function open(page) {\n  await measure(page);\n}\n`;
  assert.equal(classifyFixtureTests(`${helpers}test("t", async ({ page }) => {\n  await open(page);\n});\n`, tag)[0].mobile, true);
  // A hook that measures measures for every test.
  assert.equal(classifyFixtureTests(`test.beforeEach(async ({ page }) => {\n  await page.viewportSize();\n});\ntest("t", async ({ page }) => {\n  await page.click("a");\n});\n`, tag)[0].mobile, true);
});
