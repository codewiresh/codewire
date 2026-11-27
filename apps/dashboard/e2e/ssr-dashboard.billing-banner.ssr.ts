import { expect, test } from "./helpers/fixture-test";

// The console's credit banner in each state (#4754; private-docs
// designs/billing-compute-credits.md, "What the console says about credit"):
// its tone, its words, an action only where the owner can act, and a banner
// that fits a phone without horizontal scroll.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

const states = [
  {
    fixture: "sandboxes-credit-low",
    tone: "warning",
    text: "$1.40 of compute credit left, about 7 hours at current use.",
    action: "Add credit",
  },
  {
    fixture: "sandboxes-credit-low-top-up",
    tone: "warning",
    text: "$3.20 of compute credit left. Automatic top-up charges $20.00 to Visa •••• 4242 in about 15 hours at current use.",
    action: null,
  },
  {
    fixture: "sandboxes-credit-out",
    tone: "danger",
    text: "Out of compute credit. New Sandboxes and starts are refused, and running Sandboxes stop tomorrow at 09:12 UTC. Their storage is kept.",
    action: "Add a card",
  },
  {
    fixture: "sandboxes-credit-charging",
    tone: "warning",
    text: "Out of compute credit: new Sandboxes and starts are refused until automatic top-up charges $20.00 to Visa •••• 4242.",
    action: null,
  },
];

for (const state of states) {
  test(`the credit banner, ${state.fixture}`, { tag: "@mobile" }, async ({ page }) => {
    const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
    test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
    await page.goto(`${origin}/reference/fixtures/${state.fixture}.html`);
    const banner = page.getByRole("complementary", { name: "Billing", exact: true });
    await expect(banner).toHaveCount(1);
    await expect(banner).toHaveAttribute("data-tone", state.tone);
    await expect(banner.locator("p")).toHaveText(state.text);
    const action = banner.locator(".cw-banner-action");
    if (state.action) await expect(action).toHaveText(state.action);
    else await expect(action).toHaveCount(0);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    const box = (await banner.boundingBox())!;
    expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  });
}
