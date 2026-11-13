import { artifactScreenshot, expect, test } from "./helpers/fixture-test";

test.use({ storageState: { cookies: [], origins: [] }, contextOptions: { reducedMotion: "reduce" } });

// The privacy policy and the terms of service are long text on the public
// sheet: each part's text keeps a readable measure, nothing scrolls sideways
// (the processor table included) and the footer links both pages, as do the
// home and pricing footers and the sign-up form.
const pages = [
  { fixture: "privacy.html", heading: "Privacy policy", current: "Privacy" },
  { fixture: "terms.html", heading: "Terms of service", current: "Terms" },
] as const;

test("the legal pages read at a measure with no sideways scroll", { tag: "@mobile" }, async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const width = page.viewportSize()!.width;
  for (const { fixture, heading, current } of pages) {
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      await page.goto(`${origin}/reference/fixtures/${fixture}`);
      await page.evaluate(() => document.fonts.ready);
      await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();

      const root = await page.evaluate(() => {
        const element = document.scrollingElement ?? document.documentElement;
        return { scroll: element.scrollWidth, client: element.clientWidth };
      });
      expect(root.scroll, `${fixture} ${colorScheme}: the page scrolls sideways`).toBeLessThanOrEqual(root.client);

      // About 75 characters a line at most, and never wider than the screen.
      const bodies = await page.locator(".clause-body").evaluateAll((elements) =>
        elements.map((element) => {
          const box = element.getBoundingClientRect();
          const size = Number.parseFloat(getComputedStyle(element).fontSize);
          return { left: box.left, right: box.right, ems: box.width / size };
        }));
      expect(bodies.length).toBeGreaterThan(3);
      for (const body of bodies) {
        expect(body.ems).toBeLessThanOrEqual(38.5);
        expect(body.left).toBeGreaterThanOrEqual(0);
        expect(body.right).toBeLessThanOrEqual(width);
      }

      const table = page.locator(".clause-body table");
      if (fixture === "privacy.html") {
        const fits = await table.evaluate((element) => ({
          table: element.scrollWidth,
          column: element.parentElement!.clientWidth,
        }));
        expect(fits.table, `${colorScheme}: the processor table is wider than its column`).toBeLessThanOrEqual(fits.column);
        await expect(table.locator("tbody tr")).toHaveCount(6);
      } else {
        await expect(table).toHaveCount(0);
      }

      const legal = page.getByRole("navigation", { name: "Legal" });
      await expect(legal.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "/privacy");
      await expect(legal.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
      await expect(legal.getByRole("link", { name: current })).toHaveAttribute("aria-current", "page");
      await artifactScreenshot(page, `${fixture.replace(".html", "")}-${width}-${colorScheme}.png`, { fullPage: true });
    }
  }
});

test("home, pricing and sign-up link the privacy policy and the terms", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  for (const fixture of ["home.html", "pricing.html"]) {
    await page.goto(`${origin}/reference/fixtures/${fixture}`);
    const legal = page.getByRole("navigation", { name: "Legal" });
    await expect(legal.getByRole("link", { name: "Privacy" })).toHaveAttribute("href", "/privacy");
    await expect(legal.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
    await expect(legal.getByRole("link", { name: "Privacy" })).not.toHaveAttribute("aria-current", /./);
  }
  await page.goto(`${origin}/reference/fixtures/signup.html`);
  const agreement = page.locator(".cw-auth-legal");
  await expect(agreement).toHaveText("By requesting access you agree to the Terms and the Privacy policy.");
  await expect(agreement.getByRole("link", { name: "Terms" })).toHaveAttribute("href", "/terms");
  await expect(agreement.getByRole("link", { name: "Privacy policy" })).toHaveAttribute("href", "/privacy");
});
