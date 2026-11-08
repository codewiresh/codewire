import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";

const moduleSpecifier = process.env.CODEWIRE_PLAYWRIGHT_MODULE || "playwright";
const { chromium } = await import(moduleSpecifier);
const baseUrl = new URL(process.env.CODEWIRE_DOCS_URL || "http://127.0.0.1:5173/docs");
const screenshotDirectory = resolve(process.env.CODEWIRE_DOCS_SCREENSHOT_DIR || "/tmp/codewire-zola-screenshots");

const ensure = (condition, message) => {
  if (!condition) throw new Error(message);
};

// A test browser never reaches the desktop session: no display variable, so
// nothing it loads can open the owner's X or Wayland server (#3019).
const browserEnvironment = Object.fromEntries(Object.entries(process.env)
  .filter(([name, value]) => value !== undefined && name !== "DISPLAY" && name !== "WAYLAND_DISPLAY"));
const browser = await chromium.launch({ headless: true, env: browserEnvironment });
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  colorScheme: "dark",
});
const externalRequests = new Set();
const browserErrors = [];
const failedResources = [];

context.on("request", (request) => {
  const target = new URL(request.url());
  if (["http:", "https:", "ws:", "wss:"].includes(target.protocol) && target.host !== baseUrl.host) {
    externalRequests.add(request.url());
  }
});
context.on("requestfailed", (request) => failedResources.push(`${request.resourceType()} ${request.url()} ${request.failure()?.errorText || "failed"}`));
context.on("response", (response) => {
  const resourceType = response.request().resourceType();
  if (["document", "stylesheet", "script", "image", "fetch"].includes(resourceType) && response.status() >= 400) {
    failedResources.push(`${resourceType} ${response.url()} ${response.status()}`);
  }
});

await mkdir(screenshotDirectory, { recursive: true });

try {
  const desktop = await context.newPage();
  desktop.on("pageerror", (error) => browserErrors.push(error.message));
  await desktop.goto(baseUrl.href, { waitUntil: "networkidle" });
  ensure(await desktop.title() === "What is Codewire? · Codewire", "desktop title mismatch");
  ensure(await desktop.locator(".docs-nav-link").count() === 63, "desktop navigation is not the 63-route manifest");
  ensure(await desktop.locator(".docs-nav-link[aria-current='page']").count() === 1, "desktop navigation has no unique active route");
  ensure(await desktop.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor) === "rgb(10, 10, 10)", "The design-system background token is not active");

  await desktop.keyboard.press("/");
  const search = desktop.locator("[data-docs-search-input]");
  ensure(await search.evaluate((element) => element === document.activeElement), "slash shortcut did not focus search");
  await search.fill("environment statuses");
  const searchOptions = desktop.locator("[data-docs-search-results] [role='option']");
  await searchOptions.first().waitFor({ state: "visible" });
  ensure(await searchOptions.count() > 0, "search returned no local results");
  await search.press("ArrowDown");
  const selected = desktop.locator("[data-docs-search-results] [aria-selected='true'] a");
  const resultUrl = new URL(await selected.getAttribute("href"), baseUrl);
  ensure(!resultUrl.pathname.endsWith("/"), "search result uses a trailing-slash URL");
  await Promise.all([
    desktop.waitForURL((url) => url.pathname === resultUrl.pathname),
    search.press("Enter"),
  ]);
  ensure(await desktop.locator(".docs-nav-link[aria-current='page']").count() === 1, "search navigation lost active-route state");
  await desktop.screenshot({ path: resolve(screenshotDirectory, "docs-desktop-1440x900.png"), fullPage: true });

  await desktop.goto(new URL("docs/reference/openssf", baseUrl.origin + "/").href, { waitUntil: "networkidle" });
  ensure(await desktop.title() === "OpenSSF security posture · Codewire", "OpenSSF page title mismatch");
  ensure(await desktop.locator(".docs-security-posture").count() === 1, "OpenSSF report is missing");
  ensure(await desktop.locator(".docs-security-posture table, .docs-security-unavailable").count() > 0, "OpenSSF report has neither results nor its unavailable state");
  ensure(await desktop.locator("a[href^='https://scorecard.dev/viewer/']").count() > 0, "OpenSSF report has no authoritative viewer link");
  await desktop.screenshot({ path: resolve(screenshotDirectory, "docs-openssf-1440x900.png"), fullPage: true });

  const mobile = await context.newPage();
  await mobile.setViewportSize({ width: 390, height: 844 });
  mobile.on("pageerror", (error) => browserErrors.push(error.message));
  await mobile.goto(baseUrl.href, { waitUntil: "networkidle" });
  const toggle = mobile.locator("[data-docs-nav-toggle]");
  await toggle.click();
  ensure(await toggle.getAttribute("aria-expanded") === "true", "mobile navigation did not expose expanded state");
  const sidebar = mobile.locator("#docs-sidebar");
  await mobile.waitForFunction(() => document.querySelector("#docs-sidebar")?.getBoundingClientRect().x >= -1);
  const sidebarBox = await sidebar.boundingBox();
  ensure(sidebarBox && sidebarBox.width >= 300, "mobile navigation is not fully visible after opening");
  await mobile.screenshot({ path: resolve(screenshotDirectory, "docs-mobile-390x844.png") });
  await mobile.keyboard.press("Escape");
  ensure(await toggle.getAttribute("aria-expanded") === "false", "Escape did not close mobile navigation");

  // A light system turns the docs light: the white wordmark is inverted, and code takes the light syntax theme.
  const light = await browser.newPage({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
  light.on("pageerror", (error) => browserErrors.push(error.message));
  await light.goto(new URL("docs/environments/codewire-yaml", baseUrl.origin + "/").href, { waitUntil: "networkidle" });
  ensure(await light.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor) === "rgb(255, 255, 255)", "light docs background is not white");
  ensure(await light.locator(".docs-brand img").evaluate((img) => getComputedStyle(img).filter) === "invert(1)", "light docs wordmark is not inverted");
  ensure(await light.locator("pre.z-code").first().evaluate((pre) => getComputedStyle(pre).color) === "rgb(36, 41, 46)", "light docs code does not use the light syntax theme");
  await light.screenshot({ path: resolve(screenshotDirectory, "docs-light-1440x900.png") });
  await light.close();

  ensure(externalRequests.size === 0, `external browser requests detected: ${[...externalRequests].join(", ")}`);
  ensure(browserErrors.length === 0, `browser errors detected: ${browserErrors.join("; ")}`);
  ensure(failedResources.length === 0, `browser resources failed: ${failedResources.join("; ")}`);
  console.log(`browser verification passed; screenshots=${screenshotDirectory}`);
} finally {
  await browser.close();
}
