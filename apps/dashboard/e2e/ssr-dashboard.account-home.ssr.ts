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
    await expect(page.locator(".cw-stat").filter({ has: page.locator("dt", { hasText: "This month" }) }).locator("dd")).toHaveText("< €0.01");
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
