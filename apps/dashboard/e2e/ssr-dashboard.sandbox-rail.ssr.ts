import { expect, pauseClock, test, type Page } from "./helpers/fixture-test";

// The Sandbox rail is rendered in the desktop sidebar and again in the mobile
// drawer. Only the copy on screen refreshes (#3395), and only when the live
// stream says a Sandbox changed or asks for a resync, coalesced over a second
// (#4762). Each refresh is the `sandbox-rail-refresh` event htmx answers with
// one request.
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

const live = (page: Page, kind: "sandbox" | "resync") =>
  page.evaluate((kind) => document.body.dispatchEvent(new CustomEvent(`codewire:live:${kind}`, {
    detail: kind === "sandbox" ? { organization: "org_fixture", environment: "00000000-0000-0000-0000-000000000001" } : {},
  })), kind);

test("a loading rail refreshes once, then only when a Sandbox changes", async ({ page }) => {
  await openRails(page, { width: 1440, height: 900 }, true);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar"]);
  // No timer: a minute passes without a request.
  await page.clock.runFor(60_000);
  expect(await refreshes(page)).toEqual(["sidebar"]);
  // A change refreshes at once. Changes within the next second ride on one
  // refresh a second after it, so the rail still ends on the last of them.
  await pauseClock(page);
  await live(page, "sandbox");
  await expect.poll(() => refreshes(page)).toEqual(["sidebar", "sidebar"]);
  await live(page, "sandbox");
  await live(page, "sandbox");
  await page.clock.runFor(900);
  expect(await refreshes(page)).toEqual(["sidebar", "sidebar"]);
  await page.clock.runFor(100);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar", "sidebar", "sidebar"]);
  await page.clock.runFor(60_000);
  expect(await refreshes(page)).toEqual(["sidebar", "sidebar", "sidebar"]);
});

test("through a long change the rail refreshes about once a second and ends after its last change (#4762)", async ({ page }) => {
  await openRails(page, { width: 1440, height: 900 }, false);
  await pauseClock(page);
  // A change every 300 ms for three seconds, as a Sandbox's start sends.
  for (let i = 0; i < 10; i += 1) {
    await live(page, "sandbox");
    if (i === 0) expect(await refreshes(page)).toEqual(["sidebar"]);
    await page.clock.runFor(300);
  }
  // At once, then at 1, 2 and 3 s: the last covers the change at 2.7 s.
  expect(await refreshes(page)).toHaveLength(4);
  await page.clock.runFor(60_000);
  expect(await refreshes(page)).toHaveLength(4);
});

test("a rendered rail makes no request until the stream asks", async ({ page }) => {
  await openRails(page, { width: 1440, height: 900 }, false);
  await page.clock.runFor(60_000);
  expect(await refreshes(page)).toEqual([]);
  await live(page, "resync");
  await page.clock.runFor(1_000);
  await expect.poll(() => refreshes(page)).toEqual(["sidebar"]);
});

test("on a phone only the open drawer's rail refreshes", async ({ page }) => {
  await openRails(page, { width: 390, height: 844 }, true);
  await page.clock.runFor(10_000);
  expect(await refreshes(page)).toEqual([]);
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  await expect.poll(() => refreshes(page)).toEqual(["drawer"]);
  // The overlay shows beside the drawer; click the part the drawer leaves uncovered.
  await page.locator(".cw-mobile-overlay").click({ position: { x: 385, y: 400 } });
  await expect(page.locator(".cw-mobile-drawer")).toBeHidden();
  // A change while the drawer is closed refreshes nothing now, and the
  // drawer catches up when it opens.
  await live(page, "sandbox");
  await page.clock.runFor(1_000);
  expect(await refreshes(page)).toEqual(["drawer"]);
  await page.getByRole("button", { name: "Toggle sidebar" }).click();
  await expect.poll(() => refreshes(page)).toEqual(["drawer", "drawer"]);
});

// The rail's tools (owner, 2026-11-10): sort newest or oldest first and show
// one status, on both rails, again after a refresh replaces the list, and
// remembered by this browser.
test("the rail's sort and status filter hold on both rails and through a refresh", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${origin}/reference/fixtures/sandboxes.html`);
  const sidebar = page.locator(".cw-sidebar-slot");
  const shown = (scope: string) => page.locator(scope).evaluate((root) =>
    Array.from(root.querySelectorAll<HTMLElement>(".cw-rail-list > li"))
      .filter((item) => !item.hidden)
      .map((item) => item.querySelector(".cw-rail-name")?.textContent ?? ""));
  const served = await sidebar.locator(".cw-rail-list").innerHTML();
  const newest = await shown(".cw-sidebar-slot");

  await sidebar.getByRole("button", { name: "Sort: newest first" }).click();
  await expect(sidebar.getByRole("button", { name: "Sort: oldest first" })).toBeVisible();
  expect(await shown(".cw-sidebar-slot")).toEqual([...newest].reverse());
  expect(await shown(".cw-mobile-drawer")).toEqual([...newest].reverse());

  await sidebar.locator(".cw-rail-filter > summary").click();
  await sidebar.getByRole("button", { name: "Running" }).click();
  await expect(sidebar.locator(".cw-rail-filter > summary")).toHaveAttribute("aria-label", "Filter by status: running");
  const running = await shown(".cw-sidebar-slot");
  expect(running.length).toBeGreaterThan(0);
  expect(running.length).toBeLessThan(newest.length);

  // A refresh swaps in the server's list again; the choice applies to it.
  await page.evaluate((html) => {
    const rail = document.querySelector<HTMLElement>(".cw-sidebar-slot [data-sandbox-rail]")!;
    rail.querySelector(".cw-rail-list")!.innerHTML = html;
    rail.dispatchEvent(new CustomEvent("htmx:afterSwap", { bubbles: true }));
  }, served);
  expect(await shown(".cw-sidebar-slot")).toEqual(running);

  await page.reload();
  await expect(sidebar.getByRole("button", { name: "Sort: oldest first" })).toBeVisible();
  expect(await shown(".cw-sidebar-slot")).toEqual(running);
});
