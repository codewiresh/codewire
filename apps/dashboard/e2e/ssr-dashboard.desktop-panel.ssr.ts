import { artifactScreenshot, checkReadinessNow, expect, test, type Page, type WebSocketRoute } from "./helpers/fixture-test";

// The Desktop panel (docs/dev/SANDBOX-DESKTOP.md, "The dashboard viewer") on
// the Sandbox workspace fixture, with the vendored noVNC talking to a small
// synthetic VNC server on a routed WebSocket. The BFF answers and the server
// are synthetic; the real stream, daemon and desktop are walked on Kind.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });
const environment = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const password = "a1b2c3d4";
const refusal = "4 viewers already watch this desktop, the most it takes";
type DesktopState = "unavailable" | "stopped" | "starting" | "running";

// One viewer's stream: what the page sent after the VNC handshake.
type Stream = { route: WebSocketRoute; url: URL; afterInit: Buffer; ready: boolean };

const u32 = (value: number) => { const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes; };

// RFB 3.8 with VNC authentication, up to ServerInit for an 800×600 desktop.
// The page's bytes after its ClientInit are kept for the test to read.
function serveVnc(route: WebSocketRoute, stream: Stream) {
  let received = Buffer.alloc(0);
  const init = Buffer.alloc(24 + 4);
  init.writeUInt16BE(800, 0);
  init.writeUInt16BE(600, 2);
  Buffer.from([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]).copy(init, 4);
  init.writeUInt32BE(4, 20);
  init.write("demo", 24, "latin1");
  // [bytes the page sends at this step, the server's answer]
  const steps: Array<[number, Buffer]> = [
    [12, Buffer.from([1, 2])], // version → VNC authentication only
    [1, Buffer.alloc(16, 7)], // the chosen type → a challenge
    [16, u32(0)], // the response → success
    [1, init], // ClientInit → ServerInit
  ];
  let step = 0;
  let consumed = 0;
  route.onMessage((message) => {
    received = Buffer.concat([received, typeof message === "string" ? Buffer.from(message) : message]);
    while (step < steps.length && received.length - consumed >= steps[step][0]) {
      consumed += steps[step][0];
      route.send(steps[step][1]);
      step += 1;
      stream.ready = step === steps.length;
    }
    if (stream.ready) stream.afterInit = received.subarray(consumed);
  });
  route.send(Buffer.from("RFB 003.008\n"));
}

async function transport(page: Page) {
  const state = {
    accountId: "account-a", desktop: "stopped" as DesktopState, sandboxRunning: true, gets: 0, starts: 0, stops: 0,
    forms: [] as string[][], streams: [] as Stream[],
    // How the next stream ends before its handshake: by a close code and reason.
    refuse: null as { code: number; reason: string } | null,
  };
  const answer = () => ({ accountId: state.accountId, state: state.desktop, ...(state.desktop === "running" ? { password } : {}) });
  // The Sandbox's readiness, which the test can stop and start, and the
  // terminal beside the panel: one quiet session.
  await page.route("**/_fragments/terminal-readiness?fields=terminals", (route) => route.fulfill({ json: {
    environmentId: environment, running: state.sandboxRunning, setupComplete: true, setupRunning: false, setupFailed: false,
    detail: { state: state.sandboxRunning ? "running" : "stopped", desiredState: state.sandboxRunning ? "started" : "stopped",
      tone: state.sandboxRunning ? "success" : "neutral", lastEvent: "just now", resources: "1 vCPU · 2 GiB · 10 GiB",
      cpuMillicores: 1000, memoryMib: 2048, diskGib: 10, startEligible: !state.sandboxRunning, stopEligible: state.sandboxRunning,
      deleteEligible: true, deletionState: "unscheduled", shutdownAt: null, actionsAllowed: true, pending: false },
  } }));
  await page.route("**/_fragments/terminal-sessions", (route) => route.fulfill({ json: {
    accountId: state.accountId, sessions: [{ sessionId: "session-00000000-0000-4000-8000-000000000001", state: "running" }] } }));
  await page.routeWebSocket("**/terminal?**", () => {});
  await page.route("**/_fragments/desktop", (route) => { state.gets += 1; return route.fulfill({ json: answer() }); });
  for (const action of ["start", "stop"] as const) {
    await page.route(`**/_actions/desktop/${action}`, (route) => {
      const form = new URLSearchParams(route.request().postData() || "");
      state.forms.push([...form.keys()].sort());
      expect(form.get("account_id")).toBe(state.accountId);
      if (action === "start") { state.starts += 1; state.desktop = "running"; }
      else { state.stops += 1; state.desktop = "stopped"; }
      return route.fulfill({ json: answer() });
    });
  }
  await page.routeWebSocket("**/desktop-stream?**", (route) => {
    const stream: Stream = { route, url: new URL(route.url()), afterInit: Buffer.alloc(0), ready: false };
    state.streams.push(stream);
    if (state.refuse) {
      const { code, reason } = state.refuse;
      state.refuse = null;
      route.close({ code, reason });
      return;
    }
    serveVnc(route, stream);
  });
  return state;
}

async function openFixture(page: Page) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/terminal-tabs.html`);
}

const panel = (page: Page) => page.locator("[data-desktop-panel]");
const control = (page: Page, name: string) => panel(page).getByRole("button", { name, exact: true });
// noVNC accepts a WebSocket whose members are its own or its class's
// (core/websock.js), as a browser's are. Playwright's routed WebSocket
// defines them on a base class, so they are copied down to WebSocket's own
// prototype before the panel shows and the viewer opens its socket.
async function showDesktop(page: Page) {
  await page.evaluate(() => {
    const own = WebSocket.prototype;
    for (const name of ["send", "close", "binaryType", "onerror", "onmessage", "onopen"]) {
      if (Object.hasOwn(own, name)) continue;
      for (let base = Object.getPrototypeOf(own); base; base = Object.getPrototypeOf(base)) {
        const member = Object.getOwnPropertyDescriptor(base, name);
        if (member) { Object.defineProperty(own, name, member); break; }
      }
    }
  });
  await page.getByRole("group", { name: "Sandbox view" }).getByRole("button", { name: "Desktop", exact: true }).click();
}

async function connected(page: Page, state: Awaited<ReturnType<typeof transport>>) {
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "connected", { timeout: 15_000 });
  await expect.poll(() => state.streams.at(-1)?.ready).toBe(true);
}

test("the Desktop view stays chosen through the terminal's readiness checks", async ({ page }) => {
  await transport(page);
  await openFixture(page);
  const terminal = page.locator("[data-durable-terminal]");
  await expect(terminal).toBeVisible();
  await showDesktop(page);
  await expect(terminal).toBeHidden();
  await expect(panel(page)).toBeVisible();
  // The readiness check owns the terminal's `hidden`; a check must not bring
  // the terminal back over the desktop.
  await checkReadinessNow(page);
  await checkReadinessNow(page);
  await expect(terminal).toBeHidden();
  await page.getByRole("group", { name: "Sandbox view" }).getByRole("button", { name: "Terminal", exact: true }).click();
  await expect(terminal).toBeVisible();
  await expect(panel(page)).toBeHidden();
});

test("Start connects a viewer whose address names only the account, and the screen fills the panel", async ({ page }) => {
  // The fill is measured at a desktop width; the phone test measures its own.
  await page.setViewportSize({ width: 1280, height: 800 });
  const state = await transport(page);
  const violations: string[] = [];
  page.on("console", (message) => { if (/Content Security Policy/i.test(message.text())) violations.push(message.text()); });
  await openFixture(page);
  await showDesktop(page);
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText("The desktop is not running.");
  await control(page, "Start desktop").click();
  await connected(page, state);
  expect(state.starts).toBe(1);
  expect(state.forms).toEqual([["_csrf", "account_id"]]);
  const url = state.streams[0].url;
  expect(url.pathname).toBe(`/api/v1/organizations/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/environments/${environment}/desktop-stream`);
  expect([...url.searchParams.keys()]).toEqual(["account_id"]);
  expect(url.toString()).not.toContain(password);
  // With the note hidden, the screen still takes the panel's remaining height.
  const screen = await panel(page).locator("[data-desktop-screen]").boundingBox();
  expect(screen!.height).toBeGreaterThan(300);
  const canvas = await panel(page).locator("canvas").boundingBox();
  expect(canvas!.height).toBeGreaterThan(300);
  for (const name of ["Paste to desktop", "Copy from desktop", "Release keyboard", "Stop desktop"]) await expect(control(page, name)).toBeVisible();
  await expect(control(page, "Copy from desktop")).toBeDisabled();
  await artifactScreenshot(page, "desktop-connected.png");
  expect(violations).toEqual([]);

  await control(page, "Stop desktop").click();
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText("The desktop is not running.");
  await expect(control(page, "Start desktop")).toBeVisible();
  expect(state.stops).toBe(1);
});

test("the clipboard moves only on its buttons, and Release keyboard stops the keys", async ({ page, context }) => {
  const state = await transport(page);
  state.desktop = "running";
  await openFixture(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(page.url()).origin });
  await showDesktop(page);
  await connected(page, state);
  const stream = state.streams[0];

  // From the desktop: the button enables, and only its click writes the browser's clipboard.
  await page.evaluate(() => navigator.clipboard.writeText("untouched"));
  const text = Buffer.from("from-the-desktop", "latin1");
  stream.route.send(Buffer.concat([Buffer.from([3, 0, 0, 0]), u32(text.length), text]));
  await expect(control(page, "Copy from desktop")).toBeEnabled();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("untouched");
  await control(page, "Copy from desktop").click();
  await expect(panel(page).locator("[data-desktop-note]")).toHaveText("Copied from the desktop.");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("from-the-desktop");

  // To the desktop: nothing is sent until Paste.
  await page.evaluate(() => navigator.clipboard.writeText("to-the-desktop"));
  expect(stream.afterInit.includes("to-the-desktop")).toBe(false);
  await control(page, "Paste to desktop").click();
  await expect(panel(page).locator("[data-desktop-note]")).toHaveText("Pasted to the desktop.");
  await expect.poll(() => stream.afterInit.includes("to-the-desktop")).toBe(true);

  // Keys reach the desktop while the screen has focus, and not after Release.
  await panel(page).locator("canvas").click();
  let before = stream.afterInit.length;
  await page.keyboard.press("q");
  await expect.poll(() => stream.afterInit.length).toBeGreaterThan(before);
  await control(page, "Release keyboard").click();
  await expect(control(page, "Release keyboard")).toBeFocused();
  before = stream.afterInit.length;
  await page.keyboard.press("q");
  await page.waitForTimeout(500);
  expect(stream.afterInit.length).toBe(before);
});

test("a refused viewer shows the stream's reason and can reconnect", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  state.refuse = { code: 1008, reason: refusal };
  await openFixture(page);
  await showDesktop(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "lost");
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText(`${refusal[0].toUpperCase()}${refusal.slice(1)}.`);
  await expect(control(page, "Reconnect")).toBeVisible();
  await expect(panel(page).locator("[data-desktop-screen]")).toBeHidden();
  await control(page, "Reconnect").click();
  await connected(page, state);
  expect(state.streams).toHaveLength(2);
});

test("a draining server's close is retried without a word to the viewer", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  state.refuse = { code: 1012, reason: "" };
  await openFixture(page);
  await showDesktop(page);
  await connected(page, state);
  expect(state.streams).toHaveLength(2);
});

test("a Sandbox that stops pauses the viewer, and one that runs again reconnects", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  await openFixture(page);
  await showDesktop(page);
  await connected(page, state);
  // The Sandbox stops (from this page or elsewhere): readiness says so, the
  // stream ends and the panel asks for the Sandbox, not a reload.
  state.sandboxRunning = false;
  state.desktop = "unavailable";
  await page.route("**/_fragments/desktop", (route) => route.fulfill({ status: 409, json: { error: "desktop-refused" } }));
  await checkReadinessNow(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "sandbox");
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText("Start the Sandbox to use its desktop.");
  await expect(panel(page).locator("[data-desktop-screen]")).toBeHidden();
  await expect.poll(() => page.evaluate(() => document.querySelectorAll("[data-desktop-panel] canvas").length)).toBe(0);
  // It runs again with its desktop still up: the panel reads it and connects.
  await page.unroute("**/_fragments/desktop");
  await page.route("**/_fragments/desktop", (route) => route.fulfill({ json: { accountId: state.accountId, state: "running", password } }));
  state.sandboxRunning = true;
  await checkReadinessNow(page);
  await connected(page, state);
  expect(state.streams).toHaveLength(2);
});

test("a Sandbox that stops while the viewer loads opens no stream", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  // The bundle announces itself through a global and an event; both are held
  // until the test lets the viewer finish loading.
  await page.addInitScript(() => {
    const held = { on: true, value: undefined as unknown };
    Object.defineProperty(globalThis, "CodewireNoVNC", {
      configurable: true,
      get: () => (held.on ? undefined : held.value),
      set: (value) => { held.value = value; },
    });
    globalThis.addEventListener("codewire:novnc-ready", (event) => { if (held.on) event.stopImmediatePropagation(); }, true);
    (globalThis as unknown as { releaseViewer: () => void }).releaseViewer = () => {
      held.on = false;
      globalThis.dispatchEvent(new Event("codewire:novnc-ready"));
    };
  });
  await openFixture(page);
  await showDesktop(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "connecting");
  state.sandboxRunning = false;
  await checkReadinessNow(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "sandbox");
  await page.evaluate(() => (globalThis as unknown as { releaseViewer: () => void }).releaseViewer());
  await page.waitForTimeout(500);
  expect(state.streams).toHaveLength(0);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "sandbox");
  await expect(panel(page).locator("[data-desktop-screen]")).toBeHidden();
});

test("a Sandbox started from the page reads its desktop without a reload", async ({ page }) => {
  const state = await transport(page);
  state.sandboxRunning = false;
  await openFixture(page);
  await showDesktop(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "sandbox", { timeout: 12_000 });
  await expect(control(page, "Start desktop")).toBeHidden();
  state.sandboxRunning = true;
  await checkReadinessNow(page);
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText("The desktop is not running.");
  await expect(control(page, "Start desktop")).toBeVisible();
});

test("a desktop answered while the tab was hidden connects when the tab shows again", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  await openFixture(page);
  const setVisibility = (hidden: boolean) => page.evaluate((value) => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => value });
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => (value ? "hidden" : "visible") });
    document.dispatchEvent(new Event("visibilitychange"));
  }, hidden);
  await setVisibility(true);
  await showDesktop(page);
  await expect(panel(page)).toHaveAttribute("data-desktop-state", "connecting");
  await page.waitForTimeout(500);
  expect(state.streams).toHaveLength(0);
  await setVisibility(false);
  await connected(page, state);
  expect(state.streams).toHaveLength(1);
});

test("an image without the desktop says so and offers no Start", async ({ page }) => {
  const state = await transport(page);
  state.desktop = "unavailable";
  await openFixture(page);
  await showDesktop(page);
  await expect(panel(page).locator("[data-desktop-status]")).toHaveText("This Sandbox's image has no desktop. Create the Sandbox again to use one.");
  await expect(control(page, "Start desktop")).toBeHidden();
  expect(state.streams).toHaveLength(0);
});

test("on a phone the connected panel fits the width", { tag: "@mobile" }, async ({ page }) => {
  const state = await transport(page);
  state.desktop = "running";
  await openFixture(page);
  await showDesktop(page);
  await connected(page, state);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  expect((await panel(page).locator("canvas").boundingBox())!.width).toBeGreaterThan(200);
  await artifactScreenshot(page, "desktop-phone.png", { fullPage: true });
});
