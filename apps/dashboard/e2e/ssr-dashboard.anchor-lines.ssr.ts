import { expect, test } from "./helpers/fixture-test";
import { expectOnAnchorLines, type AnchorCheck } from "./helpers/anchor-lines";

// The sidebar's grid (routes/dashboard.css) puts every mark on one of two
// anchor lines: on the left the logo's c, the organization badge, the create
// plus, the sort icon, the rail's dots, the footer icons and the account
// badge, with the Admin label and links starting on it; on the right the
// collapse icon, the chevrons, the view-all icon and the region labels. The
// phone's drawer is the same sidebar. The Sandbox workspace's left line is
// checked in ssr-dashboard.durable-terminal.ssr.ts. The sign-in page's column
// has one left and one right line, its panel's edges: the provider buttons,
// the "or" rule, the fields and the submit button span it.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

const left: AnchorCheck[] = [
  { selector: ".cw-console-brand img", at: "start", plus: "var(--sidebar-logo-anchor)" },
  { selector: ".cw-org-switcher > summary .cw-org-initial", at: "centre" },
  { selector: ".cw-console-create > .cw-icon", at: "centre" },
  { selector: "[data-rail-sort] .cw-icon", at: "centre" },
  { selector: ".cw-rail-dot", at: "centre" },
  { selector: ".cw-console-admin .cw-section-label", at: "text" },
  { selector: ".cw-console-admin .cw-nav-link", at: "text" },
  { selector: ".cw-console-get-started .cw-nav-link > .cw-icon", at: "centre" },
  { selector: ".cw-account-menu > summary .cw-org-initial", at: "centre" },
];
const right: AnchorCheck[] = [
  { selector: "[data-sidebar-close] .cw-icon", at: "centre", side: "right" },
  { selector: ".cw-org-chevron", at: "centre", side: "right" },
  { selector: "[aria-label='View all sandboxes'] .cw-icon", at: "centre", side: "right" },
  { selector: ".cw-rail-state", at: "centre", side: "right" },
  { selector: ".cw-account-chevrons", at: "centre", side: "right" },
];

test("the sidebar's marks and plain rows sit on its two anchor lines, in the sidebar and the phone's drawer", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${origin}/reference/fixtures/terminal-tabs.html`);
  const sidebar = ".cw-sidebar-slot .cw-console-sidebar";
  await expect(page.locator(sidebar)).toBeVisible();
  await expectOnAnchorLines(page, "sidebar at 1440", sidebar, "var(--cw-sidebar-anchor)", [...left, ...right]);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  const drawer = ".cw-mobile-drawer .cw-console-sidebar";
  await expect(page.locator(drawer)).toBeVisible();
  await expectOnAnchorLines(page, "drawer at 390", drawer, "var(--cw-sidebar-anchor)", [...left, ...right]);
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
