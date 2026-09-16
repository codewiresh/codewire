import { expect, test, type Page, type WebSocketRoute } from "@playwright/test";

// Browser controller proof on the checked-in design server. These explicitly
// synthetic BFF/WS responses do not qualify real daemon or authentication flows.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });
const org = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const environment = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const prefix = "codewire:terminal:v1:";
const sessionId = (index: number) => `session-00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
type Session = { sessionId: string; state: string };
type Connection = { route: WebSocketRoute; url: URL; frames: Array<Record<string, unknown>>; closed: boolean };

async function transport(page: Page) {
  const state = { accountId: "account-a", sessions: [] as Session[], connections: [] as Connection[],
    launches: 0, stops: 0, lists: 0, launchFailure: "", stopFailure: "", listStatus: 200, listGate: Promise.resolve(),
    statusGate: Promise.resolve(), statusAvailable: true, running: true, setupComplete: true };
  await page.route("**/_fragments/terminal-readiness", async (route) => {
    await state.statusGate;
    await route.fulfill({ status: state.statusAvailable ? 200 : 503, json: {
      environmentId: environment, running: state.running, setupComplete: state.setupComplete,
    } });
  });
  await page.route("**/_fragments/terminal-sessions", async (route) => {
    state.lists += 1;
    await state.listGate;
    await route.fulfill({ status: state.listStatus, json: state.listStatus === 200
      ? { accountId: state.accountId, sessions: state.sessions } : { error: "sign-in-required" } });
  });
  await page.route("**/_actions/terminal-sessions/launch", async (route) => {
    state.launches += 1;
    const form = new URLSearchParams(route.request().postData() || "");
    expect([...form.keys()].sort()).toEqual(["_csrf", "account_id"]);
    expect(form.get("account_id")).toBe(state.accountId);
    if (state.launchFailure === "csrf") {
      await route.fulfill({ status: 403, json: { error: "request-rejected" } });
      return;
    }
    const session = { sessionId: sessionId(state.launches), state: "running" };
    state.sessions.push(session);
    if (state.launchFailure === "lost") { await route.abort(); return; }
    await route.fulfill({ json: session });
  });
  await page.route("**/_actions/terminal-sessions/stop", async (route) => {
    state.stops += 1;
    const form = new URLSearchParams(route.request().postData() || "");
    expect([...form.keys()].sort()).toEqual(["_csrf", "account_id", "session_id"]);
    const id = form.get("session_id")!;
    state.sessions = state.sessions.filter((session) => session.sessionId !== id);
    if (state.stopFailure === "lost") { await route.abort(); return; }
    await route.fulfill({ json: { sessionId: id, state: "stopped" } });
  });
  await page.routeWebSocket("**/terminal?**", (route) => {
    const connection: Connection = { route, url: new URL(route.url()), frames: [], closed: false };
    expect(connection.url.searchParams.get("account_id")).toBe(state.accountId);
    state.connections.push(connection);
    route.onMessage((value) => connection.frames.push(JSON.parse(String(value))));
    route.onClose(() => { connection.closed = true; });
  });
  return state;
}

async function openFixture(page: Page) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/terminal-tabs.html`);
  await expect(page.getByRole("button", { name: "Refresh sessions", exact: true })).toBeEnabled();
}

function output(connection: Connection, text: string, offset = 0n) {
  const data = Buffer.from(text);
  connection.route.send(JSON.stringify({ type: "output", offset: String(offset), nextOffset: String(offset + BigInt(data.length)), data: data.toString("base64") }));
  return offset + BigInt(data.length);
}

async function holdRenderCallbacks(page: Page) {
  await page.addInitScript(() => {
    type Presentation = { terminal: { write(data: string | Uint8Array, callback?: () => void): void } };
    type Factory = { open(...args: unknown[]): Presentation };
    const state = { hold: true, throwNext: false, writes: [] as string[], callbacks: [] as Array<() => void>,
      releaseOne() { this.callbacks.shift()?.(); }, release() {
      this.hold = false;
      for (const callback of this.callbacks.splice(0)) callback();
    } };
    (window as unknown as { terminalTestWrites: typeof state }).terminalTestWrites = state;
    Object.defineProperty(window, "CodewireTerminalPresentation", { configurable: true, set(factory: Factory) {
      Object.defineProperty(window, "CodewireTerminalPresentation", { configurable: true, value: {
        ...factory, open(...args: unknown[]) {
          const presentation = factory.open(...args);
          const write = presentation.terminal.write.bind(presentation.terminal);
          presentation.terminal.write = (data, callback) => {
            if (state.throwNext) { state.throwNext = false; throw new Error("Synthetic renderer failure"); }
            state.writes.push(typeof data === "string" ? data : new TextDecoder().decode(data));
            write(data, () => {
              if (!callback) return;
              if (state.hold) state.callbacks.push(callback); else callback();
            });
          };
          return presentation;
        },
      } });
    } });
  });
}

// Control drainage from outside the product. Actual frame delivery still uses
// Playwright's WebSocket route; this models only the browser's pending buffer.
function gap(connection: Connection, requested: bigint, retained: bigint) {
  connection.route.send(JSON.stringify({ type: "historyGap", requestedOffset: String(requested), retainedStartOffset: String(retained) }));
}

async function heldWrites(page: Page) {
  return page.evaluate(() => {
    const state = (window as unknown as { terminalTestWrites: { writes: string[]; callbacks: unknown[] } }).terminalTestWrites;
    return { writes: state.writes, callbacks: state.callbacks.length };
  });
}

async function releaseOneWrite(page: Page) {
  await page.evaluate(() => (window as unknown as { terminalTestWrites: { releaseOne(): void } }).terminalTestWrites.releaseOne());
}

test("old output, history gap and recent output render serially before final settled state", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const oldEnd = output(state.connections[0], "old-output\r\n");
  gap(state.connections[0], oldEnd, 4096n);
  const recentEnd = output(state.connections[0], "recent-output\r\n", 4096n);
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "exited", exitCode: 0 }));
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  expect((await heldWrites(page)).writes).toEqual(["old-output\r\n"]);
  await expect(page.locator("[data-terminal-history-gap]")).toBeHidden();
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "false");
  await releaseOneWrite(page);
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await expect(page.locator("[data-terminal-history-gap]")).toBeVisible();
  expect((await heldWrites(page)).writes[1]).toContain("Older terminal output is unavailable");
  await expect.poll(() => state.connections[0].frames.filter((frame) => frame.type === "ack").map((frame) => frame.offset)).toEqual([String(oldEnd)]);
  await releaseOneWrite(page);
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  expect((await heldWrites(page)).writes[2]).toBe("recent-output\r\n");
  await expect.poll(() => state.connections[0].frames.filter((frame) => frame.type === "ack").map((frame) => frame.offset)).toEqual([String(oldEnd), "4096"]);
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "false");
  await releaseOneWrite(page);
  await expect.poll(() => state.connections[0].frames.filter((frame) => frame.type === "ack").map((frame) => frame.offset)).toEqual([String(oldEnd), "4096", String(recentEnd)]);
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "true");
  await expect(page.locator("[data-terminal-connection]")).toHaveText("exited (0)");
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("reconnect drains queued history gaps without ACKing the replacement socket", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const oldEnd = output(state.connections[0], "old\r\n");
  gap(state.connections[0], oldEnd, 4096n);
  const end = output(state.connections[0], "recent\r\n", 4096n);
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.lists).toBe(2);
  for (let index = 0; index < 3; index += 1) {
    await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
    expect(state.connections.length).toBe(1);
    await releaseOneWrite(page);
  }
  await expect.poll(() => state.connections.length).toBe(2);
  expect(state.connections[1].url.searchParams.get("output_offset")).toBe(String(end));
  expect(state.connections.flatMap((connection) => connection.frames).some((frame) => frame.type === "ack")).toBe(false);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("queued final rendering cannot overwrite a later protocol rejection", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const cursor = output(state.connections[0], "queued-before-final\r\n");
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "exited", exitCode: 0 }));
  output(state.connections[0], "invalid-after-final\r\n", cursor);
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await releaseOneWrite(page);
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "true");
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("clean final socket closure drains output before publishing the exact exit status", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "last-output\r\n");
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "exited", exitCode: 7 }));
  state.connections[0].route.close({ code: 1000, reason: "finished" });
  await expect(page.locator("[data-terminal-connection]")).toHaveText("Rendering terminal output…");
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "false");
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await releaseOneWrite(page);
  await expect(page.locator("[data-terminal-connection]")).toHaveText("exited (7)");
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "true");
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("abnormal final socket closure remains visible after queued output drains", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "output-before-transport-failure\r\n");
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "exited", exitCode: 0 }));
  state.connections[0].route.close({ code: 1008, reason: "invalid upstream" });
  await expect(page.locator("[data-terminal-connection]")).toContainText("could be confirmed");
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await releaseOneWrite(page);
  await expect(page.locator("[data-terminal-root]")).toHaveAttribute("data-terminal-settled", "true");
  await expect(page.locator("[data-terminal-connection]")).toContainText("could be confirmed");
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

for (const retire of ["replay", "account-change"] as const) {
  test(`${retire} cancels queued renders and late callbacks cannot mutate the new presentation`, async ({ page }) => {
    await holdRenderCallbacks(page);
    const state = await transport(page);
    state.sessions = [{ sessionId: sessionId(1), state: "running" }];
    await openFixture(page);
    await expect.poll(() => state.connections.length).toBe(1);
    const oldEnd = output(state.connections[0], "old-epoch\r\n");
    gap(state.connections[0], oldEnd, 4096n);
    output(state.connections[0], "must-not-render\r\n", 4096n);
    await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
    if (retire === "replay") {
      await page.getByRole("button", { name: "Replay recent output", exact: true }).click();
    } else {
      state.accountId = "account-b";
      state.sessions = [{ sessionId: sessionId(2), state: "running" }];
      await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
    }
    await expect.poll(() => state.connections.length).toBe(2);
    expect(state.connections[1].url.searchParams.get("output_offset")).toBe("0");
    await releaseOneWrite(page);
    expect((await heldWrites(page)).writes).toEqual(["old-epoch\r\n"]);
    await expect(page.locator("[data-terminal-history-gap]")).toBeHidden();
    const newEnd = output(state.connections[1], "new-epoch\r\n");
    await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
    await releaseOneWrite(page);
    await expect.poll(() => state.connections[1].frames.filter((frame) => frame.type === "ack").map((frame) => frame.offset)).toEqual([String(newEnd)]);
    expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
    expect(state.stops).toBe(0);
  });
}

test("unrendered history gap frames are bounded without ACK or shell mutation", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  for (let index = 0; index < 65; index += 1) gap(state.connections[0], BigInt(index), BigInt(index + 1));
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

for (const [requested, retained] of [[1n, 4096n], [0n, 0n]] as const) {
  test(`invalid gap ${requested} to ${retained} cannot render or advance the cursor`, async ({ page }) => {
    await holdRenderCallbacks(page);
    const state = await transport(page);
    state.sessions = [{ sessionId: sessionId(1), state: "running" }];
    await openFixture(page);
    await expect.poll(() => state.connections.length).toBe(1);
    gap(state.connections[0], requested, retained);
    await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
    expect((await heldWrites(page)).writes).toEqual([]);
    await expect(page.locator("[data-terminal-history-gap]")).toBeHidden();
    expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  });
}

test("a queued write failing during reconnect cannot admit a replacement transport", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const first = output(state.connections[0], "first\r\n");
  output(state.connections[0], "throws-on-drain\r\n", first);
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.lists).toBe(2);
  await page.evaluate(() => { (window as unknown as { terminalTestWrites: { throwNext: boolean } }).terminalTestWrites.throwNext = true; });
  await releaseOneWrite(page);
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be rendered");
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeDisabled();
  expect(state.connections.length).toBe(1);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("a synchronous renderer failure resolves the old queue and permits explicit replay", async ({ page }) => {
  await holdRenderCallbacks(page);
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(error.message));
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  await page.evaluate(() => { (window as unknown as { terminalTestWrites: { throwNext: boolean } }).terminalTestWrites.throwNext = true; });
  output(state.connections[0], "failed-write");
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be rendered");
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Replay recent output", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  const end = output(state.connections[1], "recovered\r\n");
  await expect.poll(async () => (await heldWrites(page)).callbacks).toBe(1);
  await releaseOneWrite(page);
  await expect.poll(() => state.connections[1].frames.some((frame) => frame.type === "ack" && frame.offset === String(end))).toBe(true);
  expect(failures).toEqual([]);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

async function controlledSendBuffer(page: Page, tail: number | null = null) {
  await page.evaluate((tail) => {
    const Native = WebSocket;
    const state = { buffered: 0, tail, sizes: [] as number[] };
    (window as unknown as { terminalTestBuffer: typeof state }).terminalTestBuffer = state;
    window.WebSocket = class extends Native {
      constructor(url: string | URL, protocols?: string | string[]) {
        super(url, protocols);
        Object.defineProperty(this, "bufferedAmount", { configurable: true, get: () => state.buffered });
        const send = this.send.bind(this);
        this.send = (data) => {
          if (typeof data !== "string") throw new Error("Expected a JSON terminal frame");
          const bytes = new TextEncoder().encode(data).length;
          send(data);
          state.sizes.push(bytes);
          state.buffered = state.tail === null ? state.buffered + bytes : Math.min(state.tail, state.buffered + bytes);
        };
      }
    };
  }, tail);
}

test("continuous partial drainage does not count already transmitted frames toward the limit", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page, 8);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.some((frame) => frame.type === "resize")).toBe(true);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  const input = page.getByRole("textbox", { name: "Terminal input" });
  await input.focus();
  for (let index = 0; index < 80; index += 1) {
    await page.keyboard.insertText("é");
    await page.clock.runFor(20);
  }
  await expect.poll(() => state.connections[0].frames.filter((frame) => frame.type === "input").length).toBe(80);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  expect(state.stops).toBe(0);
});

test("a genuinely full frame queue pauses without replaying input on reconnect", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  const initialFrames = state.connections[0].frames.length;
  for (let index = initialFrames; index < 64; index += 1) {
    await page.keyboard.insertText("x");
    await page.clock.runFor(20);
  }
  await expect.poll(() => state.connections[0].frames.length).toBe(64);
  await page.keyboard.insertText("not-sent");
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  expect(state.connections[0].frames).toHaveLength(64);
  await page.evaluate(() => { (window as unknown as { terminalTestBuffer: { buffered: number } }).terminalTestBuffer.buffered = 0; });
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  expect(state.connections[1].frames.some((frame) => frame.type === "input")).toBe(false);
  expect(state.stops).toBe(0);
});

test("fast multibyte keystrokes batch once in order and continuous typing cannot delay the flush", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  const inputFrames = () => state.connections[0].frames.filter((frame) => frame.type === "input").map((frame) => frame.data);
  for (let index = 0; index < 80; index += 1) await page.keyboard.insertText("é");
  expect(inputFrames()).toEqual([]);
  await page.clock.runFor(8);
  await page.keyboard.insertText("a");
  await page.clock.runFor(8);
  await expect.poll(inputFrames).toEqual(["é".repeat(80) + "a"]);
  await page.keyboard.insertText("b");
  await page.clock.runFor(8);
  await page.keyboard.insertText("c");
  await page.clock.runFor(8);
  await expect.poll(inputFrames).toEqual(["é".repeat(80) + "a", "bc"]);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  expect(state.stops).toBe(0);
});

for (const transition of ["disconnect", "foreground", "stopping", "exited"] as const) {
  test(`staged input is discarded on ${transition} without replay or a spurious deadline`, async ({ page }) => {
    await page.clock.install();
    const state = await transport(page);
    await openFixture(page);
    await page.getByRole("button", { name: "New terminal", exact: true }).click();
    await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
    await page.clock.pauseAt(new Date(Date.now() + 1000));
    await page.getByRole("textbox", { name: "Terminal input" }).focus();
    await page.keyboard.insertText("abandoned");
    if (transition === "disconnect") {
      await page.locator("[data-terminal-toggle]").evaluate((button: HTMLButtonElement) => button.click());
      await page.getByRole("button", { name: "Reconnect", exact: true }).click();
      await expect.poll(() => state.connections.length).toBe(2);
    } else if (transition === "foreground") {
      await page.evaluate(() => window.dispatchEvent(new Event("focus")));
      await expect.poll(() => state.connections.length).toBe(2);
    } else {
      state.connections[0].route.send(JSON.stringify({ type: "status", state: transition }));
      await expect(page.locator("[data-terminal-connection]")).toHaveText(transition);
      if (transition === "stopping") {
        state.connections[0].route.send(JSON.stringify({ type: "status", state: "running" }));
        await expect(page.locator("[data-terminal-connection]")).toHaveText("running");
        await page.keyboard.insertText("new-input");
      }
    }
    await page.clock.runFor(6000);
    await expect.poll(() => state.connections.flatMap((connection) => connection.frames.filter((frame) => frame.type === "input").map((frame) => frame.data)))
      .toEqual(transition === "stopping" ? ["new-input"] : []);
    if (transition === "exited") await expect(page.locator("[data-terminal-connection]")).toHaveText("exited");
    else await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
    expect(state.stops).toBe(0);
  });
}

test("a staged frame reserves capacity against newer output acknowledgements", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  for (let index = state.connections[0].frames.length; index < 63; index += 1) {
    await page.keyboard.insertText("x");
    await page.clock.runFor(20);
  }
  await expect.poll(() => state.connections[0].frames.length).toBe(63);
  await page.keyboard.insertText("reserved");
  output(state.connections[0], "acknowledge");
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  expect(state.connections[0].frames).toHaveLength(63);
  await page.clock.runFor(20);
  await expect(page.getByRole("tabpanel")).toContainText("acknowledge");
  expect(state.connections[0].frames.some((frame) => frame.data === "reserved")).toBe(false);
  expect(state.stops).toBe(0);
});

test("staged encoded bytes reserve capacity against newer output acknowledgements", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  for (let index = 0; index < 15; index += 1) {
    await page.keyboard.insertText("x".repeat(16384));
    await page.clock.runFor(20);
  }
  await expect.poll(() => state.connections[0].frames.filter((frame) => frame.type === "input").length).toBe(15);
  const sentBytes = state.connections[0].frames.reduce((sum, frame) => sum + Buffer.byteLength(JSON.stringify(frame)), 0);
  const remaining = 262144 - sentBytes - Buffer.byteLength(JSON.stringify({ type: "input", data: "" })) - 1;
  expect(remaining).toBeGreaterThan(0);
  expect(remaining).toBeLessThan(16384);
  await page.keyboard.insertText("y".repeat(remaining));
  output(state.connections[0], "acknowledge");
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  await page.clock.runFor(20);
  await expect(page.getByRole("tabpanel")).toContainText("acknowledge");
  expect(state.connections[0].frames.filter((frame) => frame.type === "input")).toHaveLength(15);
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.stops).toBe(0);
});

test("staged input retains its older deadline when an ACK overtakes it on the wire", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  await page.evaluate(() => { (window as unknown as { terminalTestBuffer: { buffered: number } }).terminalTestBuffer.buffered = 0; });
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  await page.keyboard.insertText("older");
  await page.clock.runFor(8);
  output(state.connections[0], "ack");
  await expect.poll(() => state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(true);
  await page.clock.runFor(8);
  await expect.poll(() => state.connections[0].frames.filter((frame) => ["ack", "input"].includes(String(frame.type))).map((frame) => frame.type))
    .toEqual(["ack", "input"]);
  await page.clock.runFor(4983);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  await page.clock.runFor(1);
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  expect(state.stops).toBe(0);
});

test("send deadlines follow the oldest outstanding frame and partial progress cannot renew them", async ({ page }) => {
  await page.clock.install();
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.clock.fastForward(2000);
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  await page.keyboard.insertText("é");
  await expect.poll(() => state.connections[0].frames.some((frame) => frame.type === "input")).toBe(true);
  await page.evaluate(() => {
    const buffer = (window as unknown as { terminalTestBuffer: { buffered: number; sizes: number[] } }).terminalTestBuffer;
    buffer.buffered = buffer.sizes.at(-1)!;
  });
  await page.clock.fastForward(3200);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  await page.evaluate(() => { (window as unknown as { terminalTestBuffer: { buffered: number } }).terminalTestBuffer.buffered -= 1; });
  await page.clock.fastForward(2100);
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  await page.evaluate(() => { (window as unknown as { terminalTestBuffer: { buffered: number } }).terminalTestBuffer.buffered = 0; });
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  await page.evaluate(() => { (window as unknown as { terminalTestBuffer: { buffered: number } }).terminalTestBuffer.buffered = 0; });
  await page.clock.fastForward(6000);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeEnabled();
  expect(state.connections[1].frames.some((frame) => frame.type === "input")).toBe(false);
  expect(state.stops).toBe(0);
});

test("genuine encoded bytes are bounded before the frame cap is reached", async ({ page }) => {
  const state = await transport(page);
  await openFixture(page);
  await controlledSendBuffer(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections[0]?.frames.length || 0).toBeGreaterThan(0);
  await page.getByRole("textbox", { name: "Terminal input" }).focus();
  for (let index = 0; index < 16; index += 1) await page.keyboard.insertText("é".repeat(8192));
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  const encodedBytes = state.connections[0].frames.reduce((total, frame) => total + Buffer.byteLength(JSON.stringify(frame)), 0);
  expect(encodedBytes).toBeLessThanOrEqual(262144);
  expect(encodedBytes).toBeGreaterThan(245760);
  expect(state.connections[0].frames.length).toBeLessThan(64);
  expect(state.connections[0].frames.filter((frame) => frame.type === "input")).toHaveLength(15);
  expect(state.stops).toBe(0);
});

test("terminal tabs launch explicitly, retain separate displays and bound the visible tab set", async ({ page }, testInfo) => {
  const state = await transport(page);
  await openFixture(page);
  expect(state.launches).toBe(0);
  await expect(page.getByRole("tab")).toHaveCount(0);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "first-terminal-output\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("first-terminal-output");
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  output(state.connections[1], "second-terminal-output\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("second-terminal-output");
  await expect(page.getByRole("tabpanel")).not.toContainText("first-terminal-output");
  await page.getByRole("tab", { name: "Terminal 1", exact: true }).click();
  await expect(page.getByRole("tabpanel")).toContainText("first-terminal-output");
  await page.getByRole("tab", { name: "Terminal 1", exact: true }).press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Terminal 2", exact: true })).toBeFocused();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: new URL(page.url()).origin });
  for (const [name, text] of [["Terminal 1", "first-terminal-output"], ["Terminal 2", "second-terminal-output"]]) {
    await page.getByRole("tab", { name, exact: true }).click();
    const panel = page.getByRole("tabpanel");
    const copy = panel.getByRole("button", { name: "Copy selection", exact: true });
    await expect(copy).toBeDisabled();
    const bounds = (await panel.locator(".xterm-rows").getByText(text, { exact: true }).boundingBox())!;
    await page.mouse.move(bounds.x, bounds.y + bounds.height / 2);
    await page.mouse.down();
    await page.mouse.move(bounds.x + bounds.width, bounds.y + bounds.height / 2, { steps: 12 });
    await page.mouse.up();
    await expect(copy).toBeEnabled();
    await copy.click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(text);
    await expect(panel.locator("[data-terminal-copy-status]")).toHaveText("Selection copied.");
  }
  for (let count = 3; count <= 8; count += 1) {
    await page.getByRole("button", { name: "New terminal", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(count);
  }
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(page.viewportSize()!.width);
  const stored = await page.evaluate(() => ({ ...sessionStorage }));
  const references = JSON.parse(stored[`${prefix}account-a:${org}:${environment}`]);
  expect(Object.keys(references).sort()).toEqual(["accountId", "activeSessionId", "environmentId", "organizationId", "sessions", "version"]);
  expect(references.sessions).toEqual(Array.from({ length: 8 }, (_, index) => sessionId(index + 1)));
  expect(JSON.stringify(stored)).not.toContain("terminal-output");
  expect(JSON.stringify(stored)).not.toContain("csrf");
  await page.getByRole("tab", { name: "Terminal 1", exact: true }).click();
  await page.screenshot({ path: testInfo.outputPath("durable-terminal-tabs.png"), fullPage: true });
  expect(state.stops).toBe(0);
});

test("disconnect retains output, reload replays from zero, and Close requires confirmation", async ({ page }) => {
  const state = await transport(page);
  await openFixture(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(1);
  const cursor = output(state.connections[0], "retained-output\r\n");
  await expect.poll(() => state.connections[0].frames.some((frame) => frame.type === "ack" && frame.offset === String(cursor))).toBe(true);
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.getByRole("tabpanel")).toContainText("retained-output");
  expect(state.stops).toBe(0);
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  expect(state.connections[1].url.searchParams.get("output_offset")).toBe(String(cursor));
  expect(state.connections[1].url.searchParams.get("session_id")).toBe(sessionId(1));
  await page.reload();
  await expect.poll(() => state.connections.length).toBe(3);
  expect(state.connections[2].url.searchParams.get("output_offset")).toBe("0");
  expect(state.connections[2].url.searchParams.get("session_id")).toBe(sessionId(1));
  expect(state.launches).toBe(1);
  output(state.connections[2], "replayed-output\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("replayed-output");
  await page.getByRole("button", { name: "Close terminal", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Close terminal?" });
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  expect(state.stops).toBe(0);
  await page.getByRole("button", { name: "Close terminal", exact: true }).click();
  await dialog.getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect(page.getByRole("tab")).toHaveCount(0);
  expect(state.stops).toBe(1);
});

test("reconnect drains old render callbacks and never ACKs them on the replacement socket", async ({ page }) => {
  await holdRenderCallbacks(page);
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const cursor = output(state.connections[0], "delayed-render\r\n");
  await expect.poll(() => page.evaluate(() => (window as unknown as { terminalTestWrites: { callbacks: unknown[] } }).terminalTestWrites.callbacks.length)).toBe(1);
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.lists).toBe(2);
  expect(state.connections.length).toBe(1);
  await page.evaluate(() => (window as unknown as { terminalTestWrites: { release(): void } }).terminalTestWrites.release());
  await expect.poll(() => state.connections.length).toBe(2);
  expect(state.connections[1].url.searchParams.get("output_offset")).toBe(String(cursor));
  expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
  expect(state.connections[1].frames.some((frame) => frame.type === "ack")).toBe(false);
  const next = output(state.connections[1], "next-output\r\n", cursor);
  await expect.poll(() => state.connections[1].frames.some((frame) => frame.type === "ack" && frame.offset === String(next))).toBe(true);
  await page.getByRole("button", { name: "Replay recent output", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(3);
  expect(state.connections[2].url.searchParams.get("output_offset")).toBe("0");
});

test("unknown launch outcomes require inspection and stale CSRF requires reload without retry", async ({ page }) => {
  const state = await transport(page);
  state.launchFailure = "lost";
  await openFixture(page);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect(page.locator("[data-terminal-message]")).toContainText("could not be confirmed");
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  expect(state.launches).toBe(1);
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  expect(state.launches).toBe(1);
  expect(state.connections.length).toBe(0);
  await page.getByLabel("Existing terminal", { exact: true }).selectOption(sessionId(1));
  await page.getByRole("button", { name: "Open terminal", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "keep-on-stale-csrf\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("keep-on-stale-csrf");
  state.launchFailure = "csrf";
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect(page.getByRole("link", { name: "Reload page", exact: true })).toBeVisible();
  await expect(page.getByRole("tabpanel")).toContainText("keep-on-stale-csrf");
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  expect(state.launches).toBe(2);
});

test("fresh identity precedes restored output and account change clears only terminal references", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "previous-account-output\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("previous-account-output");
  await page.evaluate(() => sessionStorage.setItem("unrelated-user-setting", "preserve"));
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
  await expect(page.locator("[data-terminal-panels]")).toBeHidden();
  let release!: () => void;
  state.listGate = new Promise<void>((resolve) => { release = resolve; });
  state.accountId = "account-b";
  state.sessions = [{ sessionId: sessionId(2), state: "running" }];
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
  await expect.poll(() => state.lists).toBe(2);
  await expect(page.locator("[data-terminal-panels]")).toBeHidden();
  release();
  await expect.poll(() => state.connections.length).toBe(2);
  await expect(page.locator("[data-terminal-panels]")).not.toContainText("previous-account-output");
  const stored = await page.evaluate(() => ({ ...sessionStorage }));
  expect(stored[`${prefix}account`]).toBe("account-b");
  expect(stored["unrelated-user-setting"]).toBe("preserve");
  expect(Object.keys(stored).some((key) => key.startsWith(`${prefix}account-a:`))).toBe(false);
  expect(state.stops).toBe(0);

  await page.route("**/settings/_actions/sign-out", (route) => route.fulfill({ contentType: "text/html", body: "<p>Signed out fixture</p>" }));
  await page.evaluate(() => {
    const form = document.createElement("form");
    form.method = "post";
    form.action = "/settings/_actions/sign-out";
    document.body.append(form);
    form.requestSubmit();
  });
  await expect(page).toHaveURL(/\/settings\/_actions\/sign-out$/);
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("codewire:terminal:v1:")))).toEqual([]);
  expect(await page.evaluate(() => sessionStorage.getItem("unrelated-user-setting"))).toBe("preserve");
  expect(state.stops).toBe(0);
});

test("missing stored sessions do not launch replacements", async ({ page }) => {
  await page.addInitScript(({ prefix, org, environment, id }) => {
    sessionStorage.setItem(`${prefix}account`, "account-a");
    sessionStorage.setItem(`${prefix}account-a:${org}:${environment}`, JSON.stringify({ version: 1,
      accountId: "account-a", organizationId: org, environmentId: environment, sessions: [id], activeSessionId: id }));
  }, { prefix, org, environment, id: sessionId(99) });
  const state = await transport(page);
  await openFixture(page);
  await expect(page.locator("[data-terminal-message]")).toContainText("no longer available");
  expect(state.launches).toBe(0);
  expect(state.connections.length).toBe(0);
});

test("ended terminals replay without resize and can be removed locally", async ({ page }) => {
  const state = await transport(page);
  state.sessions = ["exited", "failed", "interrupted"].map((status, index) => ({ sessionId: sessionId(index + 1), state: status }));
  await openFixture(page);
  await expect(page.getByRole("tab")).toHaveCount(0);
  for (let index = 0; index < state.sessions.length; index += 1) {
    await page.getByLabel("Existing terminal", { exact: true }).selectOption(sessionId(index + 1));
    await page.getByRole("button", { name: "Open terminal", exact: true }).click();
    await expect.poll(() => state.connections.length).toBe(index + 1);
    const connection = state.connections[index];
    const cursor = output(connection, `historical-output-${index}\r\n`);
    await expect(page.getByRole("tabpanel")).toContainText(`historical-output-${index}`);
    await expect.poll(() => connection.frames.some((frame) => frame.type === "ack" && frame.offset === String(cursor))).toBe(true);
    expect(connection.frames.some((frame) => ["resize", "input"].includes(String(frame.type)))).toBe(false);
    await expect(page.getByRole("button", { name: "Close terminal", exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Remove tab", exact: true }).click();
    await expect(page.getByRole("tab")).toHaveCount(0);
  }
  expect(state.stops).toBe(0);
  expect(state.launches).toBe(0);
});

test("unknown Stop is not repeated and a missing tab can be removed without another Stop", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  state.stopFailure = "lost";
  await openFixture(page);
  await page.getByRole("button", { name: "Close terminal", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect(page.locator("[data-terminal-message]")).toContainText("could not be confirmed");
  await expect(page.getByRole("button", { name: "Close terminal", exact: true })).toBeDisabled();
  expect(state.stops).toBe(1);
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await page.getByRole("button", { name: "Remove tab", exact: true }).click();
  await expect(page.getByRole("tab")).toHaveCount(0);
  await expect(page.locator("[data-terminal-message]")).toContainText("No terminal stop was requested");
  expect(state.stops).toBe(1);
  expect(state.launches).toBe(0);
});

test("Close confirmation rechecks a terminal that ended while the dialog was open", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  await page.getByRole("button", { name: "Close terminal", exact: true }).click();
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "failed" }));
  await expect(page.locator("[data-terminal-connection]")).toHaveText("failed");
  await page.getByRole("dialog").getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect(page.locator("[data-terminal-message]")).toContainText("Use Remove tab");
  await page.getByRole("button", { name: "Remove tab", exact: true }).click();
  expect(state.stops).toBe(0);
});

test("initial terminal restoration waits for fresh status rather than rendered running state", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  let release!: () => void;
  state.statusGate = new Promise<void>((resolve) => { release = resolve; });
  await openFixture(page);
  await expect(page.locator("[data-terminal-message]")).toContainText("Checking Sandbox status");
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  expect(state.lists).toBe(0);
  expect(state.connections).toHaveLength(0);
  expect(state.launches).toBe(0);
  release();
  await expect.poll(() => state.connections.length).toBe(1);
  expect(state.launches).toBe(0);
});

test("incomplete setup blocks launch and attachment until an explicit action after readiness", async ({ page }) => {
  const state = await transport(page);
  state.setupComplete = false;
  state.sessions = [{ sessionId: sessionId(9), state: "running" }];
  await openFixture(page);
  await expect(page.getByRole("tab")).toHaveCount(1);
  await expect(page.locator("[data-terminal-connection]")).toContainText("setup is not complete");
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Close terminal", exact: true })).toBeEnabled();
  expect(state.launches).toBe(0);
  expect(state.connections).toHaveLength(0);
  state.setupComplete = true;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeEnabled();
  expect(state.connections).toHaveLength(0);
  expect(state.launches).toBe(0);
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.launches).toBe(1);
  await expect.poll(() => state.connections.length).toBe(1);
});

test("starting a stopped Sandbox enables terminals after its first ready status without reload", async ({ page }) => {
  const state = await transport(page);
  state.running = false;
  state.setupComplete = false;
  state.listStatus = 503;
  await openFixture(page);
  await expect(page.locator("[data-terminal-empty]")).toContainText("Start this Sandbox");
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  expect(state.lists).toBe(0);
  state.running = true;
  state.setupComplete = true;
  state.listStatus = 200;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  expect(state.lists).toBe(1);
  expect(state.launches).toBe(0);
  expect(state.connections).toHaveLength(0);
});

test("setup loss pauses input and attachment but still permits explicit Stop", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  state.setupComplete = false;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect.poll(() => state.connections[0].closed).toBe(true);
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Close terminal", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect.poll(() => state.stops).toBe(1);
  expect(state.launches).toBe(0);
});

test("a pending stopped-state list cannot consume initial restoration when setup becomes ready", async ({ page }) => {
  const state = await transport(page);
  state.running = false;
  state.setupComplete = false;
  state.listStatus = 503;
  let release!: () => void;
  state.listGate = new Promise<void>((resolve) => { release = resolve; });
  await openFixture(page);
  await expect(page.locator("[data-terminal-empty]")).toContainText("Start this Sandbox");
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect.poll(() => state.lists).toBe(1);
  state.running = true;
  state.setupComplete = true;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(page.locator("[data-terminal-empty]")).toContainText("Choose New terminal");
  release();
  await expect(page.locator("[data-terminal-message]")).toContainText("Terminal sessions are unavailable");
  state.listStatus = 200;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  expect(state.lists).toBe(2);
  expect(state.launches).toBe(0);
  expect(state.connections).toHaveLength(0);
});

test("Sandbox lifecycle changes pause terminal controls without automatic launch or reconnect", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "retained-on-sandbox-stop\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("retained-on-sandbox-stop");
  const status = async (available: boolean, running: boolean, id = environment) => {
    if (id === environment) { state.statusAvailable = available; state.running = running; }
    await page.evaluate((detail) => {
      document.dispatchEvent(new CustomEvent("codewire:sandbox-status", { detail }));
    }, { environmentId: id, available, running, setupComplete: true });
  };
  await status(false, false, org);
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  await status(true, false);
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeDisabled();
  await expect(page.getByRole("tabpanel")).toContainText("retained-on-sandbox-stop");
  await expect.poll(() => state.connections[0].closed).toBe(true);
  await status(false, true);
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("button", { name: "Refresh sessions", exact: true })).toBeEnabled();
  expect(state.connections.length).toBe(1);
  await status(true, true);
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Reconnect", exact: true })).toBeEnabled();
  expect(state.connections.length).toBe(1);
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
});

test("foreground account revalidation hides old output until fresh identity is known", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  output(state.connections[0], "old-foreground-account\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("old-foreground-account");
  let release!: () => void;
  state.listGate = new Promise<void>((resolve) => { release = resolve; });
  state.accountId = "account-b";
  state.sessions = [];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect.poll(() => state.lists).toBe(2);
  await expect(page.locator("[data-terminal-panels]")).toBeHidden();
  await expect.poll(() => state.connections[0].closed).toBe(true);
  release();
  await expect(page.getByRole("button", { name: "New terminal", exact: true })).toBeEnabled();
  await expect(page.locator(".xterm")).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.getItem("codewire:terminal:v1:account"))).toBe("account-b");
  expect(state.launches).toBe(0);
  expect(state.stops).toBe(0);
});

test("oversized input and a full browser send buffer are never queued for replay", async ({ page }) => {
  const state = await transport(page);
  await openFixture(page);
  await page.evaluate(() => {
    const Native = WebSocket;
    const sockets: WebSocket[] = [];
    (window as unknown as { terminalTestSockets: WebSocket[] }).terminalTestSockets = sockets;
    window.WebSocket = class extends Native {
      constructor(url: string | URL, protocols?: string | string[]) { super(url, protocols); sockets.push(this); }
    };
  });
  await page.getByRole("button", { name: "New terminal", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(1);
  const input = page.getByRole("tabpanel").getByRole("textbox", { name: "Terminal input" });
  await input.focus();
  await page.keyboard.insertText("x".repeat(16385));
  await expect(page.locator("[data-terminal-connection]")).toContainText("Input is too large");
  expect(state.connections[0].frames.some((frame) => frame.type === "input")).toBe(false);
  await page.evaluate(() => Object.defineProperty((window as unknown as { terminalTestSockets: WebSocket[] }).terminalTestSockets[0], "bufferedAmount", { configurable: true, value: 262144 }));
  await page.keyboard.type("x");
  await expect(page.locator("[data-terminal-connection]")).toContainText("will not be resent");
  expect(state.connections[0].frames.some((frame) => frame.type === "input")).toBe(false);
  await page.getByRole("button", { name: "Reconnect", exact: true }).click();
  await expect.poll(() => state.connections.length).toBe(2);
  expect(state.connections[1].frames.some((frame) => frame.type === "input")).toBe(false);
  expect(state.stops).toBe(0);
});

test("output after a final state is rejected and auth failure clears retained display", async ({ page }) => {
  const state = await transport(page);
  state.sessions = [{ sessionId: sessionId(1), state: "running" }];
  await openFixture(page);
  await expect.poll(() => state.connections.length).toBe(1);
  const cursor = output(state.connections[0], "before-exit\r\n");
  await expect(page.getByRole("tabpanel")).toContainText("before-exit");
  state.connections[0].route.send(JSON.stringify({ type: "status", state: "exited", exitCode: 0 }));
  output(state.connections[0], "invalid-after-exit", cursor);
  await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
  await expect(page.getByRole("tabpanel")).not.toContainText("invalid-after-exit");
  state.listStatus = 401;
  await page.getByRole("button", { name: "Refresh sessions", exact: true }).click();
  await expect(page.getByRole("tab")).toHaveCount(0);
  await expect(page.locator(".xterm")).toHaveCount(0);
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("codewire:terminal:v1:")))).toEqual([]);
  expect(state.stops).toBe(0);
});

for (const limit of ["frames", "bytes"] as const) {
  test(`unrendered ${limit} are bounded and rejected without ACK or Stop`, async ({ page }) => {
    await holdRenderCallbacks(page);
    const state = await transport(page);
    state.sessions = [{ sessionId: sessionId(1), state: "running" }];
    await openFixture(page);
    await expect.poll(() => state.connections.length).toBe(1);
    let cursor = 0n;
    const count = limit === "frames" ? 65 : 9;
    for (let index = 0; index < count; index += 1) cursor = output(state.connections[0], "x".repeat(limit === "frames" ? 1 : 32768), cursor);
    await expect(page.locator("[data-terminal-connection]")).toContainText("could not be verified");
    expect(state.connections[0].frames.some((frame) => frame.type === "ack")).toBe(false);
    expect(state.stops).toBe(0);
  });
}
