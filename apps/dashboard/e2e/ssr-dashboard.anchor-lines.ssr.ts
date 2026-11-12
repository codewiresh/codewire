import { expect, test } from "./helpers/fixture-test";
import {
  expectOnAnchorLines,
  sidebarAdminAnchors,
  sidebarLeftAnchors,
  sidebarRightAnchors,
  type AnchorCheck,
} from "./helpers/anchor-lines";

// The sidebar's anchor lines are listed in helpers/anchor-lines.ts; this
// fixture is an administrator's, so it checks the Admin rows too. The phone's
// drawer is the same sidebar. The live sidebar is checked in
// ssr-dashboard.environment-lifecycle.ssr.ts and the Sandbox workspace's left
// line in ssr-dashboard.durable-terminal.ssr.ts. The sign-in page's column
// has one left and one right line, its panel's edges: the provider buttons,
// the "or" rule, the fields and the submit button span it.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

const sidebarChecks = [...sidebarLeftAnchors, ...sidebarAdminAnchors, ...sidebarRightAnchors];

test("the sidebar's marks and plain rows sit on its two anchor lines, in the sidebar and the phone's drawer", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${origin}/reference/fixtures/terminal-tabs.html`);
  const sidebar = ".cw-sidebar-slot .cw-console-sidebar";
  await expect(page.locator(sidebar)).toBeVisible();
  await expectOnAnchorLines(page, "sidebar at 1440", sidebar, "var(--cw-sidebar-anchor)", sidebarChecks);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  const drawer = ".cw-mobile-drawer .cw-console-sidebar";
  await expect(page.locator(drawer)).toBeVisible();
  await expectOnAnchorLines(page, "drawer at 390", drawer, "var(--cw-sidebar-anchor)", sidebarChecks);
});

test("the sign-in column's provider buttons, rule, fields and submit share its two edges", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  const column: AnchorCheck[] = [
    { selector: ".cw-auth-providers li:first-child .cw-button", at: "start" },
    { selector: ".cw-auth-providers li:last-child .cw-button", at: "start" },
    { selector: ".cw-auth-divider", at: "start" },
    { selector: "#email", at: "start" },
    { selector: ".cw-auth-submit", at: "start" },
  ];
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`${origin}/reference/fixtures/login.html`);
    await expect(page.locator(".cw-auth-providers")).toBeVisible();
    await expectOnAnchorLines(page, `sign-in column at ${width}`, ".cw-auth-panel", "0px", column);
    // An anchor check measures a box's left edge; each box's right edge must
    // meet the panel's too.
    const rightGaps = await page.evaluate((selectors) => {
      const panel = document.querySelector(".cw-auth-panel")!.getBoundingClientRect();
      return selectors.map((selector) => panel.right - document.querySelector(selector)!.getBoundingClientRect().right);
    }, column.map((check) => check.selector));
    for (const [index, gap] of rightGaps.entries()) {
      expect.soft(Math.abs(gap), `${column[index].selector} right edge at ${width}`).toBeLessThanOrEqual(1);
    }
  }
});
