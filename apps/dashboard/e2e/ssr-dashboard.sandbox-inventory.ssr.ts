import { expect, test, type Page } from "./helpers/fixture-test";

// Inventory controller proof on the checked-in design server. Synthetic list
// refreshes stand in for the Sandboxes fragment; nothing is deleted.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

const oldPier = "00000000-0000-0000-0000-000000000004";
const quietMesa = "00000000-0000-0000-0000-000000000001";
const dryHarbor = "00000000-0000-0000-0000-000000000003";

type Change = { id: string; state: string | null; tone?: string };

async function openInventory(page: Page) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.clock.install();
  await page.goto(`${origin}/reference/fixtures/sandboxes.html`);
  await page.clock.pauseAt(new Date(Date.now() + 1000));
  // Record every message the status shows from here on, so a repeat is visible.
  await page.locator("[data-inventory-status]").evaluate((status) => {
    const shown: string[] = [];
    new MutationObserver(() => { if (status.textContent) shown.push(status.textContent); })
      .observe(status, { childList: true, characterData: true, subtree: true });
    Object.assign(window, { inventoryAnnouncements: shown });
  });
}

const announcements = (page: Page) => page.evaluate(() =>
  (window as unknown as { inventoryAnnouncements: string[] }).inventoryAnnouncements);

// One list refresh as htmx performs it: the fragment replaces the list's
// children, then htmx:afterSwap fires on the list. A removed row has left the
// fragment; a changed row carries its new state.
async function refresh(page: Page, changes: Change[] = [], search?: string) {
  await page.locator("#environment-list").evaluate((list, { changes, search }) => {
    const fragment = list.firstElementChild!.cloneNode(true) as HTMLElement;
    if (search !== undefined) fragment.dataset.listSearch = search;
    for (const change of changes) {
      const row = fragment.querySelector<HTMLElement>(`tr[data-environment-id="${change.id}"]`)!;
      if (change.state === null) {
        row.remove();
        continue;
      }
      row.dataset.environmentState = change.state;
      const pill = row.querySelector<HTMLElement>(".cw-status")!;
      pill.textContent = change.state;
      if (change.tone) pill.dataset.tone = change.tone;
    }
    list.replaceChildren(fragment);
    list.dispatchEvent(new CustomEvent("htmx:afterSwap", { bubbles: true }));
  }, { changes, search });
}

test("a click anywhere on a row opens its Sandbox, except on the row menu", { tag: "@mobile" }, async ({ page }) => {
  await openInventory(page);
  const row = page.locator(`tr[data-environment-id="${quietMesa}"]`);
  const href = await row.locator("a.cw-environment-name").getAttribute("href");
  const list = page.url();
  // The menu opens where it is and the list stays.
  const menu = row.locator("details.cw-row-menu");
  await menu.locator(":scope > summary").click();
  await expect(menu).toHaveJSProperty("open", true);
  expect(page.url()).toBe(list);
  await menu.locator(":scope > summary").click();
  await expect(menu).toHaveJSProperty("open", false);
  // A click on the State cell, away from the name, lands on the row's one link.
  const state = (await row.locator("td").nth(1).boundingBox())!;
  await page.mouse.click(state.x + state.width / 2, state.y + state.height / 2);
  await expect(page).toHaveURL(new URL(href!, list).href);
});

test("the desktop sidebar collapses to a rail and expands again, remembered in a cookie", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openInventory(page);
  const slot = page.locator(".cw-sidebar-slot");
  const main = page.locator("main.cw-main");
  const wide = (await slot.boundingBox())!.width;
  await slot.getByRole("button", { name: "Collapse navigation", exact: true }).click();
  const expand = slot.getByRole("button", { name: "Expand navigation", exact: true });
  await expect(expand).toBeFocused();
  await expect(slot.getByRole("link", { name: "Create Sandbox" })).toBeHidden();
  const rail = (await slot.boundingBox())!.width;
  expect(rail).toBeLessThan(wide / 3);
  expect(Math.abs((await main.boundingBox())!.x - rail)).toBeLessThanOrEqual(1);
  expect(await page.evaluate(() => document.cookie)).toContain("codewire.sidebar=collapsed");
  await expand.click();
  await expect(slot.getByRole("button", { name: "Collapse navigation", exact: true })).toBeFocused();
  expect(Math.abs((await slot.boundingBox())!.width - wide)).toBeLessThanOrEqual(1);
  expect(await page.evaluate(() => document.cookie)).not.toContain("codewire.sidebar");
});

test("a Sandbox being deleted stays listed as Deleting with only its detail page", async ({ page }) => {
  await openInventory(page);
  const row = page.locator(`tr[data-environment-id="${oldPier}"]`);
  await expect(row.locator(".cw-status")).toHaveText("Deleting…");
  await expect(row.locator(".cw-status")).toHaveAttribute("data-tone", "warning");
  await row.getByLabel("Actions for old-pier", { exact: true }).click();
  const menu = row.locator(".cw-menu-panel");
  await expect(menu.getByRole("link")).toHaveText(["Open Sandbox"]);
  await expect(menu.getByRole("button")).toHaveCount(0);
  await expect(menu).toContainText("Deletion in progress. No other actions are available.");
  // The delete that brought the user here is named in the page's one status.
  await expect(page.getByRole("status")).toHaveCount(1);
  await expect(page.getByRole("status")).toHaveText("Deleting old-pier…");
  await expect(page.getByRole("status")).toHaveClass(/cw-toast/);
});

// #2361: a bound capability whose credential needs the owner is named in
// the broker's words, with a link to the page that fixes it.
test("a Sandbox names the bound capability that needs Reconnect and links to Credentials", async ({ page }) => {
  await openInventory(page);
  const row = page.locator(`tr[data-environment-id="${quietMesa}"]`);
  await row.getByLabel("Actions for quiet-mesa", { exact: true }).click();
  await row.getByRole("button", { name: "Secrets and credentials", exact: true }).click();
  const sources = page.getByRole("dialog", { name: "Secrets and credentials of quiet-mesa", exact: true });
  await expect(sources.locator(".cw-credential-attention > li")).toHaveCount(1);
  await expect(sources.getByRole("link", { name: "Codex needs Reconnect", exact: true }))
    .toHaveAttribute("href", "settings-credentials.html");
});

test("a deleted Sandbox is announced once and leaves the list", async ({ page }) => {
  await openInventory(page);
  const status = page.locator("[data-inventory-status]");
  const rows = page.locator("tbody tr");
  await expect(rows).toHaveCount(4);
  // The post-delete message clears itself; an unchanged refresh says nothing.
  await page.clock.runFor(8_000);
  await expect(status).toBeEmpty();
  await refresh(page);
  await expect(status).toBeEmpty();
  await refresh(page, [{ id: oldPier, state: null }]);
  await expect(page.locator(`tr[data-environment-id="${oldPier}"]`)).toHaveCount(0);
  await expect(rows).toHaveCount(3);
  await expect(status).toHaveText("old-pier deleted.");
  await expect(page.getByRole("status")).toHaveCount(1);
  await expect(page.getByRole("status")).toHaveText("old-pier deleted.");
  // Later refreshes never repeat it, before or after the message clears.
  await refresh(page);
  await page.clock.runFor(8_000);
  await expect(status).toBeEmpty();
  await refresh(page);
  await refresh(page);
  await expect(status).toBeEmpty();
  expect(await announcements(page)).toEqual(["old-pier deleted."]);
});

test("a failed deletion is announced once and keeps the Sandbox listed", async ({ page }) => {
  await openInventory(page);
  const status = page.locator("[data-inventory-status]");
  await refresh(page, [{ id: oldPier, state: "error", tone: "danger" }]);
  await expect(status).toHaveText("old-pier could not be deleted.");
  const row = page.locator(`tr[data-environment-id="${oldPier}"]`);
  await expect(row.locator(".cw-status")).toHaveText("error");
  await refresh(page);
  expect(await announcements(page)).toEqual(["old-pier could not be deleted."]);
});

test("Stop and Start outcomes use the same announcement, one message per refresh", async ({ page }) => {
  await openInventory(page);
  const status = page.locator("[data-inventory-status]");
  await refresh(page, [{ id: quietMesa, state: "stopped", tone: "neutral" }, { id: dryHarbor, state: "running", tone: "success" }]);
  await expect(status).toHaveText("quiet-mesa stopped. dry-harbor is running.");
  await refresh(page, [{ id: quietMesa, state: "destroying", tone: "warning" }]);
  await expect(status).toHaveText("Deleting quiet-mesa…");
  expect(await announcements(page)).toEqual(["quiet-mesa stopped. dry-harbor is running.", "Deleting quiet-mesa…"]);
});

test("a failed refresh speaks once through the same status and keeps its note until recovery", async ({ page }) => {
  await openInventory(page);
  await page.clock.runFor(8_000);
  const note = page.locator("[data-environment-list-error]");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page.locator("#environment-list").evaluate((list) => list.dispatchEvent(new CustomEvent("htmx:responseError", { bubbles: true })));
  }
  await expect(note).toBeVisible();
  await expect(page.getByRole("status")).toHaveCount(1);
  await expect(page.getByRole("status")).toHaveText("Sandbox list could not be refreshed. Retrying…");
  await refresh(page);
  await expect(note).toBeHidden();
  expect(await announcements(page)).toEqual(["Sandbox list could not be refreshed. Retrying…"]);
});

test("a refresh under a different search compares nothing and announces nothing", async ({ page }) => {
  await openInventory(page);
  await page.clock.runFor(8_000);
  // Typing a search narrows the next refresh: old-pier is filtered, not deleted.
  await refresh(page, [{ id: oldPier, state: null }], "quiet");
  await refresh(page, [], "quiet");
  await expect(page.locator("[data-inventory-status]")).toBeEmpty();
  expect(await announcements(page)).toEqual([]);
});

// The list's poll as htmx runs it: a cancelable htmx:beforeRequest on the
// list, then, unless a listener cancelled the request, the fragment swap.
async function poll(page: Page): Promise<boolean> {
  const sent = await page.locator("#environment-list").evaluate((list) =>
    list.dispatchEvent(new CustomEvent("htmx:beforeRequest", {
      bubbles: true, cancelable: true, detail: { elt: list, target: list },
    })));
  if (sent) await refresh(page);
  return sent;
}

test("a row menu stays open through the list's refresh until it is closed", async ({ page }) => {
  await openInventory(page);
  const menu = () => page.locator(`tr[data-environment-id="${quietMesa}"] details.cw-row-menu`);
  await menu().locator(":scope > summary").click();
  await expect(menu()).toHaveJSProperty("open", true);
  // While it is open the list waits rather than replace the row under it.
  expect(await poll(page)).toBe(false);
  await expect(menu()).toHaveJSProperty("open", true);
  // A click elsewhere closes it, and the next refresh runs.
  await page.locator("main h1").click();
  await expect(menu()).toHaveJSProperty("open", false);
  expect(await poll(page)).toBe(true);
  await expect(menu()).toHaveJSProperty("open", false);
});

test("an open row menu sits above the other rows' menu buttons", { tag: "@mobile" }, async ({ page }) => {
  await openInventory(page);
  const menu = page.locator(`tr[data-environment-id="${quietMesa}"] details.cw-row-menu`);
  await menu.locator(":scope > summary").click();
  const covered = await menu.locator(".cw-menu-panel").evaluate((panel) => {
    const box = panel.getBoundingClientRect();
    const others = [...document.querySelectorAll<HTMLElement>("details.cw-row-menu > summary")]
      .filter((summary) => !panel.parentElement!.contains(summary));
    return others.flatMap((summary) => {
      const { left, top, width, height } = summary.getBoundingClientRect();
      const [x, y] = [left + width / 2, top + height / 2];
      if (x < box.left || x > box.right || y < box.top || y > box.bottom) return [];
      return [panel.contains(document.elementFromPoint(x, y))];
    });
  });
  // At least one other button lies under the panel, and none shows through it.
  expect(covered.length).toBeGreaterThan(0);
  expect(covered.every(Boolean)).toBe(true);
});

test("a row menu's actions open dialogs, with no caret, and Cancel returns to the action", async ({ page }) => {
  await openInventory(page);
  const row = page.locator(`tr[data-environment-id="${quietMesa}"]`);
  await row.getByLabel("Actions for quiet-mesa", { exact: true }).click();
  const panel = row.locator(".cw-row-menu > .cw-menu-panel");
  const carets = await panel.locator("summary").evaluateAll((summaries) => summaries
    .filter((summary) => summary.checkVisibility() && getComputedStyle(summary, "::before").content !== "none")
    .map((summary) => summary.textContent));
  expect(carets).toEqual([]);
  for (const [action, dialogName] of [
    ["Secrets and credentials", "Secrets and credentials of quiet-mesa"],
    ["Resize", "Resize quiet-mesa"],
    ["Delete", "Delete quiet-mesa?"],
  ]) {
    const item = panel.getByRole("button", { name: action, exact: true });
    await item.focus();
    await page.keyboard.press("Enter");
    const dialog = page.getByRole("dialog", { name: dialogName, exact: true });
    await expect(dialog).toBeVisible();
    await dialog.getByRole("button", { name: /^(Cancel|Close)$/ }).click();
    await expect(dialog).toBeHidden();
    await expect(item).toBeFocused();
  }
});

// Live updates (#4762; private-docs designs/live-updates.md §3a). The list
// makes no request of its own: a live change re-fetches only that row, and an
// open row menu or dialog is never replaced. The row fragment is answered by
// the test; the list refresh is the event htmx would answer.
async function openLiveInventory(page: Page) {
  await openInventory(page);
  const asked: string[] = [];
  const rows = new Map<string, { status: number; body?: string }>();
  await page.route("**/reference/fixtures/sandbox-row/*", (route) => {
    const id = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    asked.push(id);
    const answer = rows.get(id) ?? { status: 204 };
    return route.fulfill({ status: answer.status, contentType: "text/html", body: answer.body ?? "" });
  });
  await page.locator("#environment-list").evaluate((list) => {
    const refreshes: number[] = [];
    list.addEventListener("codewire:sandbox-list-refresh", () => refreshes.push(Date.now()));
    Object.assign(window, { listRefreshes: refreshes });
  });
  return { asked, rows };
}

const listRefreshes = (page: Page) => page.evaluate(() =>
  (window as unknown as { listRefreshes: number[] }).listRefreshes.length);

const live = (page: Page, kind: "sandbox" | "resize" | "resync", environment = "", organization = "org_fixture") =>
  page.evaluate(({ kind, environment, organization }) => document.body.dispatchEvent(
    new CustomEvent(`codewire:live:${kind}`, { detail: { organization, environment } })), { kind, environment, organization });

// The row as the server would render it after the Sandbox stopped.
const stoppedRow = (page: Page, id: string) => page.locator(`tr[data-environment-id="${id}"]`).evaluate((row) =>
  row.outerHTML.replace('data-environment-state="running"', 'data-environment-state="stopped"'));

test("a live change re-fetches only that row, replaces it, and announces it", async ({ page }) => {
  const { asked, rows } = await openLiveInventory(page);
  rows.set(quietMesa, { status: 200, body: await stoppedRow(page, quietMesa) });
  await live(page, "sandbox", quietMesa);
  await live(page, "sandbox", quietMesa);
  await page.clock.runFor(300);
  // Two events within 250 ms are one request, for that row only.
  await expect.poll(() => asked).toEqual([quietMesa]);
  await expect(page.locator(`tr[data-environment-id="${quietMesa}"]`)).toHaveAttribute("data-environment-state", "stopped");
  await expect.poll(() => announcements(page)).toContain("quiet-mesa stopped.");
  expect(await listRefreshes(page)).toBe(0);
  // Without an event, nothing is asked for.
  await page.clock.runFor(60_000);
  expect(asked).toEqual([quietMesa]);
});

test("a replaced row's menu works as the first one did: Stop and its dialogs open and close", async ({ page }) => {
  const { rows } = await openLiveInventory(page);
  // The row as the server sends it: Stop hidden behind its no-script fallback.
  const served = await page.locator(`tr[data-environment-id="${quietMesa}"]`).evaluate((row) => {
    const copy = row.cloneNode(true) as HTMLElement;
    copy.querySelector("[data-inventory-stop]")?.setAttribute("hidden", "");
    copy.querySelector("[data-inventory-stop-fallback]")?.removeAttribute("hidden");
    copy.setAttribute("data-live-replaced", "");
    return copy.outerHTML;
  });
  rows.set(quietMesa, { status: 200, body: served });
  await live(page, "sandbox", quietMesa);
  await page.clock.runFor(300);
  const row = page.locator(`tr[data-environment-id="${quietMesa}"][data-live-replaced]`);
  await expect(row).toHaveCount(1);
  await row.getByLabel("Actions for quiet-mesa", { exact: true }).click();
  await expect(row.locator("[data-inventory-stop-fallback]")).toBeHidden();
  await row.getByRole("button", { name: "Stop", exact: true }).click();
  const stop = page.getByRole("dialog", { name: "Stop quiet-mesa?", exact: true });
  await expect(stop).toBeVisible();
  await stop.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(stop).toBeHidden();
  // Cancel returns to the open menu. The row's own dialog closes from its
  // backdrop, as before the update.
  await expect(row.locator("details.cw-row-menu")).toHaveJSProperty("open", true);
  await row.getByRole("button", { name: "Secrets and credentials", exact: true }).click();
  const sources = page.getByRole("dialog", { name: "Secrets and credentials of quiet-mesa", exact: true });
  await expect(sources).toBeVisible();
  await page.mouse.click(4, 4);
  await expect(sources).toBeHidden();
});

test("an open row menu holds its row's update until it closes, then runs it once", async ({ page }) => {
  const { asked, rows } = await openLiveInventory(page);
  rows.set(quietMesa, { status: 200, body: await stoppedRow(page, quietMesa) });
  const menu = page.locator(`tr[data-environment-id="${quietMesa}"] details.cw-row-menu`);
  await page.getByLabel("Actions for quiet-mesa", { exact: true }).click();
  await expect(menu).toHaveAttribute("open", "");
  await live(page, "sandbox", quietMesa);
  await page.clock.runFor(300);
  expect(asked).toEqual([]);
  await expect(menu).toHaveAttribute("open", "");
  // A whole-list update waits for it too.
  await live(page, "resync");
  expect(await listRefreshes(page)).toBe(0);
  await page.getByLabel("Actions for quiet-mesa", { exact: true }).click();
  // Closing runs what waited: the list, once, which covers the row.
  await expect.poll(() => listRefreshes(page)).toBe(1);
});

test("a Sandbox with no row, a row that left the view, and a resync re-fetch the list", async ({ page }) => {
  const { asked } = await openLiveInventory(page);
  await live(page, "sandbox", "00000000-0000-0000-0000-0000000000aa");
  await page.clock.runFor(300);
  await expect.poll(() => listRefreshes(page)).toBe(1);
  expect(asked).toEqual([]);
  // The row fragment answers 204: the Sandbox left this view.
  await live(page, "sandbox", dryHarbor);
  await page.clock.runFor(300);
  await expect.poll(() => asked).toEqual([dryHarbor]);
  await expect.poll(() => listRefreshes(page)).toBe(2);
  await live(page, "resync");
  await expect.poll(() => listRefreshes(page)).toBe(3);
});

test("another organization's change touches nothing", async ({ page }) => {
  const { asked } = await openLiveInventory(page);
  await live(page, "sandbox", quietMesa, "org_other");
  await page.clock.runFor(300);
  expect(asked).toEqual([]);
  expect(await listRefreshes(page)).toBe(0);
});

test("an active resize card re-reads itself on its Sandbox's resize events and on resync, and on nothing else (#4762)", async ({ page }) => {
  await openLiveInventory(page);
  // An active card as environment-resize-operation.html renders it; its
  // hx-trigger turns codewire:resize-operation-refresh into its request.
  await page.evaluate((id) => {
    const card = document.createElement("section");
    card.id = "environment-resize-operation";
    card.dataset.environmentId = id;
    card.setAttribute("hx-get", `resize-card?resize_environment=${id}`);
    const refreshes: number[] = [];
    card.addEventListener("codewire:resize-operation-refresh", () => refreshes.push(Date.now()));
    Object.assign(window, { cardRefreshes: refreshes });
    document.querySelector("main")?.append(card);
  }, quietMesa);
  const cardRefreshes = () => page.evaluate(() => (window as unknown as { cardRefreshes: number[] }).cardRefreshes.length);
  // Ten seconds with no change, another Sandbox's resize, and a Sandbox
  // change that is not a resize ask for nothing.
  await page.clock.runFor(10_000);
  await live(page, "resize", dryHarbor);
  await live(page, "sandbox", quietMesa);
  expect(await cardRefreshes()).toBe(0);
  await live(page, "resize", quietMesa);
  expect(await cardRefreshes()).toBe(1);
  await live(page, "resync");
  expect(await cardRefreshes()).toBe(2);
  // A card whose resize has finished has no request to make.
  await page.locator("#environment-resize-operation").evaluate((card) => card.removeAttribute("hx-get"));
  await live(page, "resize", quietMesa);
  await live(page, "resync");
  expect(await cardRefreshes()).toBe(2);
});
