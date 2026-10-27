import { expect, test, type Page } from "./helpers/fixture-test";

// The Sandbox rail is rendered in the desktop sidebar and again in the mobile
// drawer. Only the copy on screen refreshes, so one page load makes one rail
// request and each 10-second interval one more (#3395). Each refresh is the
// `sandbox-rail-refresh` event htmx answers with one request.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

async function openRails(page: Page, viewport: { width: number; height: number }, loading: boolean) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.setViewportSize(viewport);
  await page.addInitScript((loading) => {
    const refreshes: string[] = [];
    Object.assign(window, { railRefreshes: refreshes });
    document.addEventListener("sandbox-rail-refresh", (event) => {
      const rail = event.target as Element;
      refreshes.push(rail.closest(".cw-mobile-drawer") ? "drawer" : rail.closest(".cw-sidebar-slot") ? "sidebar" : "other");
    }, true);
    // An organization page renders its rail loading; the fixture renders it
    // filled. This runs before dashboard.js reads the rails.
    if (loading) {
      document.addEventListener("DOMContentLoaded", () => {
        document.querySelectorAll<HTMLElement>("[data-sandbox-rail]").forEach((rail) => {
          rail.dataset.railLoading = "true";
        });
      });
    }
  }, loading);
  await page.clock.install();
  await page.goto(`${origin}/reference/fixtures/sandboxes.html`);
  await expect(page.locator("[data-sandbox-rail]")).toHaveCount(2);
}

const refreshes = (page: Page) =>
  page.evaluate(() => (window as unknown as { railRefreshes: string[] }).railRefreshes.slice());

test("a desktop page load refreshes only the sidebar rail, once per interval", async ({ page }) => {
  await openRails(page, { width: 1440, height: 900 }, true);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar"]);
  await page.clock.runFor(10_000);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar", "sidebar"]);
});

test("a rendered rail waits for its interval before refreshing", async ({ page }) => {
  await openRails(page, { width: 1440, height: 900 }, false);
  await page.clock.runFor(5_000);
  expect(await refreshes(page)).toEqual([]);
  await page.clock.runFor(5_000);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar"]);
});

test("on a phone only the open drawer's rail refreshes", async ({ page }) => {
  await openRails(page, { width: 390, height: 844 }, true);
  await page.clock.runFor(10_000);
  expect(await refreshes(page)).toEqual([]);
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  await expect.poll(() => refreshes(page)).toEqual(["drawer"]);
  await page.clock.runFor(10_000);
  await expect.poll(() => refreshes(page)).toEqual(["drawer", "drawer"]);
  // The overlay shows beside the drawer; click the part the drawer leaves uncovered.
  await page.locator(".cw-mobile-overlay").click({ position: { x: 385, y: 400 } });
  await expect(page.locator(".cw-mobile-drawer")).toBeHidden();
  await page.clock.runFor(20_000);
  expect(await refreshes(page)).toEqual(["drawer", "drawer"]);
});
