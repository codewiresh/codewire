import { test as base, type Locator, type Page } from "@playwright/test";

export * from "@playwright/test";

// A design-fixture page means nothing without its scripts and stylesheets.
// When one fails to load, the page still fires load but never wires its
// behaviour, so a test waits out its timeout for a reaction that cannot come
// (#2991). On the workstation the usual cause is the host's network churn:
// Chromium cancels in-flight requests when an interface changes, with
// net::ERR_NETWORK_CHANGED (#3043). The page is closed at once with that
// request named, so the test fails as infrastructure, not as a product
// assertion. Every design-fixture spec takes `test` from here.
const pageResources = new Set(["script", "stylesheet"]);

export const test = base.extend({
  context: async ({ context }, use) => {
    context.on("requestfailed", (request) => {
      const error = request.failure()?.errorText ?? "an unknown error";
      // Navigating away cancels what the old page was still loading.
      if (!pageResources.has(request.resourceType()) || error === "net::ERR_ABORTED") return;
      let page;
      try { page = request.frame().page(); } catch { return; }
      void page.close({ reason: `infrastructure: the page's ${request.resourceType()} ${request.url()} failed to load (${error}), so the page never wired its behaviour (#3043)` });
    });
    await use(context);
  },
});

// Screenshots in these specs are artifacts for review, never compared, so they
// are taken in CSS pixels. At a device scale factor above 1 (the mobile
// project's Pixel 5, 2.75) Chromium resizes the view to device pixels for each
// capture and retries the copy at once rather than waiting for a frame at that
// size; on a loaded host every attempt misses and the capture fails with
// "Unable to capture screenshot" (#4452). Returns the file's path.
export async function artifactScreenshot(target: Page | Locator, name: string, options: { fullPage?: boolean } = {}) {
  const path = test.info().outputPath(name);
  if ("goto" in target) await target.screenshot({ path, scale: "css", ...options });
  else await target.screenshot({ path, scale: "css" });
  return path;
}

// Pause a page's installed clock a second ahead of where that clock is now.
// The target is read from the page's own clock, and read again if the page
// has already passed it: a target taken from the runner's clock can be in
// the page's past on a loaded host ("Cannot fast-forward to the past").
export async function pauseClock(page: Page) {
  for (let attempt = 1; ; attempt += 1) {
    const now = await page.evaluate(() => Date.now());
    try {
      await page.clock.pauseAt(new Date(now + 1_000));
      return;
    } catch (error) {
      if (attempt >= 5 || !String(error).includes("Cannot fast-forward to the past")) throw error;
    }
  }
}
