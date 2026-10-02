import { expect, test, type Page } from "@playwright/test";

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
  const sources = row.locator("details.cw-disclosure", { hasText: "Secrets and credentials" });
  await sources.locator(":scope > summary").click();
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
