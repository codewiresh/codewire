import { expect, test, type Page } from "./helpers/fixture-test";

// The account home's organization cards (#4464): every tile keeps its value on
// one line, one organization's card spans the list, and several share the grid.
test.use({ storageState: { cookies: [], origins: [] } });
const fixture = (name: string) => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/${name}.html`;

const tilesOnOneLine = async (page: Page) => {
  const values = page.locator(".cw-org-overview .cw-stat > dd");
  await expect(values).not.toHaveCount(0);
  for (const value of await values.all()) {
    const box = await value.evaluate((node) => ({
      text: node.textContent,
      height: node.getBoundingClientRect().height,
      line: parseFloat(getComputedStyle(node).lineHeight),
      overflows: node.scrollWidth > node.clientWidth + 1,
    }));
    expect(box.height, `${box.text} wraps`).toBeLessThan(box.line * 1.5);
    expect(box.overflows, `${box.text} overflows its tile`).toBe(false);
  }
};
const widths = (page: Page) => page.locator(".cw-org-overview").evaluate((list) => ({
  list: list.getBoundingClientRect().width,
  cards: [...list.children].map((card) => card.getBoundingClientRect()).map(({ width, top }) => ({ width, top })),
}));

test("organization cards keep tile values on one line, and one organization's card spans the list", async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
  for (const width of [1440, 375]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(fixture("account-overview-unlimited"));
    const balance = page.locator(".cw-stat").filter({ has: page.locator("dt", { hasText: "Balance" }) }).locator("dd");
    await expect(balance.locator('[aria-hidden="true"]')).toHaveText("∞");
    await expect(page.locator(".cw-stat").filter({ has: page.locator("dt", { hasText: "This month" }) }).locator("dd")).toHaveText("< $0.01");
    await tilesOnOneLine(page);
    const single = await widths(page);
    expect(single.cards).toHaveLength(1);
    expect(Math.abs(single.cards[0].width - single.list)).toBeLessThanOrEqual(1);

    await page.goto(fixture("account-overview-active"));
    await tilesOnOneLine(page);
    const two = await widths(page);
    expect(two.cards).toHaveLength(2);
    if (width === 1440) {
      // Side by side, each about half the list.
      expect(two.cards[0].top).toBe(two.cards[1].top);
      for (const card of two.cards) expect(card.width).toBeLessThan(two.list / 2);
    } else {
      // A phone stacks them, each the list's width.
      for (const card of two.cards) expect(Math.abs(card.width - two.list)).toBeLessThanOrEqual(1);
    }
  }
});

// The usage charts' euro scale (#4959): ticks from the top down to $0, the top
// at least the largest hour, each label level with its gridline, hidden from
// screen readers, and the same on the account overview and the Billing page.
const euros = (text: string) => Number((text.match(/\$([0-9.]+)/) ?? ["", "NaN"])[1]);

for (const name of ["account-overview-active", "account-overview-unlimited", "organization-billing"]) {
  test(`the usage chart's euro scale reads off every bar, ${name}`, { tag: "@mobile" }, async ({ page }) => {
    test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
    await page.goto(fixture(name));
    const charts = page.locator(".cw-usage-chart");
    await expect(charts).not.toHaveCount(0);
    for (const chart of await charts.all()) {
      const scale = chart.locator(".cw-chart-scale");
      await expect(scale).toHaveAttribute("aria-hidden", "true");
      const labels = await scale.locator("span").allTextContents();
      const values = labels.map(euros);
      expect(values.at(-1), labels.join(" ")).toBe(0);
      for (let i = 1; i < values.length; i++) expect(values[i - 1], labels.join(" ")).toBeGreaterThan(values[i]);
      const bars = (await chart.locator(".cw-chart-bar title").allTextContents()).map(euros);
      expect(values[0], labels.join(" ")).toBeGreaterThanOrEqual(Math.max(...bars));
      // Each label is level with its line: the top gridline at 8 of 88, the
      // $0 line at 80, in the chart's own height.
      const svg = (await chart.locator("svg").boundingBox())!;
      const centers = await scale.locator("span").evaluateAll((spans) =>
        spans.map((span) => {
          // The text, not its zero-height line: where a reader sees the label.
          const range = document.createRange();
          range.selectNodeContents(span);
          const box = range.getBoundingClientRect();
          return box.top + box.height / 2;
        }));
      expect(Math.abs(centers[0] - (svg.y + svg.height * 8 / 88))).toBeLessThanOrEqual(1.5);
      expect(Math.abs(centers.at(-1)! - (svg.y + svg.height * 80 / 88))).toBeLessThanOrEqual(1.5);
      const box = (await scale.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(svg.x);
    }
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
}

