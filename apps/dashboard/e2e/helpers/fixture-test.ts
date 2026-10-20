import { test as base } from "@playwright/test";

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
