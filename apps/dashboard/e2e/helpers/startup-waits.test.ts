import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Fixture pages finish their own asynchronous start-up after load. These
// guards keep specs from reading a page, or racing it with their own routes,
// before that work settles (#2991).
const source = (name: string) => readFileSync(new URL(`../${name}`, import.meta.url), "utf8");
const testBodies = (text: string) => text.split(/\n(?=(?: {2})?test\()/);
const title = (body: string) => /test\(\s*[`"]([^`"]+)/.exec(body)?.[1] ?? body.slice(0, 60);

test("the durable terminal opens and reloads only through its start-up settle", () => {
  const text = source("ssr-dashboard.durable-terminal.ssr.ts");
  assert.match(text, /async function openFixture\(page: Page\) \{\n {2}await gotoFixture\(page\);\n {2}await settleStartup\(page\);\n\}/);
  assert.match(text, /async function reloadFixture\(page: Page\) \{\n {2}await page\.reload\(\);\n {2}await settleStartup\(page\);\n\}/);
  assert.equal([...text.matchAll(/page\.reload\(/g)].length, 1, "a spec reloads through reloadFixture");
});

test("Create tests that drive a restore let the automatic restore settle first", () => {
  const text = source("ssr-dashboard.creation-disclosure.ssr.ts");
  let checked = 0;
  for (const body of testBodies(text)) {
    const opened = body.indexOf("await page.goto(fixtureUrl());");
    const routed = body.indexOf('page.route("**/fixture/_fragments/create-draft"');
    // A route installed before the page opens meets the automatic restore on purpose.
    if (opened < 0 || routed < opened || !body.includes("sessionStorage.setItem")) continue;
    checked += 1;
    assert.ok(body.slice(opened, routed).includes("await settleAutomaticRestore(page);"), title(body));
  }
  assert.ok(checked >= 5, `only ${checked} restore tests found`);
});
