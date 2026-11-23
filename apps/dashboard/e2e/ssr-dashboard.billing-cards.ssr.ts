// covers: templates/organization-billing.html templates/organization-billing-stack.html
import { artifactScreenshot, expect, test, type Page } from "./helpers/fixture-test";

// The Billing page as landed in design v4 (owner, 2026-11-14, #4750):
// payment methods first with Add card as the first action, then the
// automatic top-up line, then Add credit, then invoices. Cards are added in
// the page through Stripe's card form, never on a Stripe page.
test.use({ storageState: { cookies: [], origins: [] }, contextOptions: { reducedMotion: "reduce" } });

const open = async (page: Page) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/organization-billing.html`);
};

test("Billing reads balance, payment methods, top-up, Add credit, invoices", { tag: "@mobile" }, async ({ page }) => {
  await open(page);
  const stack = page.locator("#billing-stack");
  const order = await stack.locator(":scope > header, :scope > section").evaluateAll((parts) =>
    parts.map((part) => part.getAttribute("aria-label") || part.querySelector("h2")?.textContent?.trim()));
  expect(order).toEqual(["Compute credit", "Payment methods", "Automatic top-up", "Add credit", "Invoices", "Sandbox Usage"]);

  // Add card is the first action, at primary weight, as Pay is.
  const addCard = stack.getByRole("button", { name: "Add card" });
  await expect(stack.getByRole("button").first()).toHaveText("Add card");
  await expect(addCard).not.toHaveClass(/cw-button--outline/);
  await expect(stack.getByRole("button", { name: /^Pay/ })).not.toHaveClass(/cw-button--outline/);

  // The top-up line is one row on a desktop: switch, name, i and amount.
  const line = stack.locator("form.cw-top-up-line");
  const centres = await line.locator(".cw-switch, .cw-label, .cw-field-help-trigger, .cw-select").evaluateAll((controls) =>
    controls.map((control) => { const box = control.getBoundingClientRect(); return box.top + box.height / 2; }));
  expect(centres).toHaveLength(4);
  if ((page.viewportSize()?.width || 0) > 672) {
    expect(Math.max(...centres) - Math.min(...centres)).toBeLessThanOrEqual(2);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await artifactScreenshot(page, "billing-v4.png");
});

test("Pay names the amount a chip or Other chooses", async ({ page }) => {
  await open(page);
  const form = page.locator("#billing-stack form[data-add-credit]");
  const pay = form.locator("[data-add-credit-submit]");
  await expect(pay).toHaveText("Pay €100");
  await form.getByRole("radio", { name: "€250", exact: true }).check();
  await expect(pay).toHaveText("Pay €250");
  const other = form.getByLabel("Other amount in euros");
  await other.fill("12.50");
  await expect(pay).toHaveText("Pay €12.50");
  expect(await form.locator('input[name="choice"]:checked').count()).toBe(0);
  await form.getByRole("radio", { name: "€50", exact: true }).check();
  await expect(other).toHaveValue("");
  await expect(pay).toHaveText("Pay €50");
  await other.fill("4");
  await expect(pay).toHaveText("Pay");
});

test("Add card names the charge saving makes, and says when the form can't load", async ({ page }) => {
  await open(page);
  await page.locator("#billing-stack").getByRole("button", { name: "Add card" }).click();
  const dialog = page.getByRole("dialog", { name: "Add card" });
  await expect(dialog).toBeVisible();
  const save = dialog.locator("[data-card-submit]");
  await expect(save).toHaveText("Save card and pay €20");
  await dialog.getByLabel("Top-up amount").selectOption("50");
  await expect(save).toHaveText("Save card and pay €50");
  await expect(dialog.locator("[data-card-top-up-euros]").first()).toHaveText("€50");
  await dialog.getByRole("switch", { name: "Automatic top-up" }).uncheck();
  await expect(save).toHaveText("Save card");
  await expect(dialog.getByLabel("Top-up amount")).toBeDisabled();
  // The fixture has no Stripe: the dialog says so at the field, not silently.
  await expect(dialog.getByRole("alert")).toHaveText("The card form couldn't load. Check your connection and try again.");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).not.toBeVisible();
});

test("a card's menu makes it the default or removes it after saying what changes", async ({ page }) => {
  await open(page);
  const stack = page.locator("#billing-stack");
  // The menu is a <summary>, named by its aria-label; Playwright gives a
  // summary no button role.
  const defaultMenu = stack.getByLabel("Actions for Visa ending in 4242", { exact: true });
  await defaultMenu.click();
  await expect(stack.getByRole("menuitem", { name: "Make default" })).toHaveCount(0);
  await stack.getByRole("menuitem", { name: "Remove card…" }).first().click();
  const remove = page.getByRole("dialog", { name: "Remove Visa •••• 4242?" });
  await expect(remove).toBeVisible();
  await expect(remove).toContainText("It's your default card.");
  await remove.getByRole("button", { name: "Cancel" }).click();
  await expect(remove).not.toBeVisible();

  await stack.getByLabel("Actions for Mastercard ending in 5454", { exact: true }).click();
  await expect(stack.getByRole("menuitem", { name: "Make default" })).toBeVisible();
});

test("with no card, Pay opens Stripe's card form under Add credit first", async ({ page }) => {
  await open(page);
  const empty = page.locator("#billing-stack-empty");
  await expect(empty.getByText("No card yet.")).toBeVisible();
  const form = empty.locator("form[data-add-credit]");
  const region = form.locator("[data-card-form]");
  await expect(region).toBeHidden();
  await form.locator("[data-add-credit-submit]").click();
  await expect(region).toBeVisible();
  await expect(region.getByRole("switch", { name: "Automatic top-up" })).toBeChecked();
  await expect(region.getByRole("alert")).toHaveText("The card form couldn't load. Check your connection and try again.");
  // Nothing navigated: the page stays on Billing.
  await expect(page).toHaveURL(/organization-billing\.html$/);
});

test("a live credit refresh waits while a dialog is open, then runs once", async ({ page }) => {
  await open(page);
  const refreshes: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/_fragments/billing")) refreshes.push(request.url());
  });
  const credit = () => page.evaluate(() => document.body.dispatchEvent(new CustomEvent("codewire:live:credit")));
  // Nothing open: the stack re-fetches itself.
  await credit();
  await expect.poll(() => refreshes.length).toBe(1);
  // A dialog open: the refresh waits, and the dialog and its form stay.
  await page.locator("#billing-stack").getByRole("button", { name: "Add card" }).click();
  const dialog = page.getByRole("dialog", { name: "Add card" });
  await dialog.getByLabel("Top-up amount").selectOption("50");
  await credit();
  await credit();
  await page.waitForTimeout(250);
  expect(refreshes).toHaveLength(1);
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel("Top-up amount")).toHaveValue("50");
  // Closing it runs the refresh it held, once.
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect.poll(() => refreshes.length).toBe(2);
});

// The page's live stream (#4762, #5874): live.js turns /_events/live into
// codewire:live:* events, and the stack re-fetches itself on them. The
// stream is answered by the test; a body that ends is a stream that closed.
const openLive = async (page: Page, stream: { status: number; events: string[] }) => {
  await open(page);
  const refreshes: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/_fragments/billing")) refreshes.push(request.url());
  });
  await page.route("**/_events/live", (route) => route.fulfill({
    status: stream.status,
    contentType: "text/event-stream",
    // A long retry keeps EventSource from reopening within the test.
    body: `retry: 600000\n\n${stream.events.map((event) => `event: ${event}\ndata: {}\n\n`).join("")}`,
  }));
  await page.addScriptTag({ url: `${process.env.CODEWIRE_DESIGN_ORIGIN}/live.js` });
  return refreshes;
};

test("a credit change on the live stream re-fetches the stack", async ({ page }) => {
  const refreshes = await openLive(page, { status: 200, events: ["credit"] });
  await expect.poll(() => refreshes.length).toBe(1);
});

test("resyncs from the live stream wait a moment and re-fetch the stack once", async ({ page }) => {
  const refreshes = await openLive(page, { status: 200, events: ["resync", "resync"] });
  await expect.poll(() => refreshes.length, { timeout: 2_000 }).toBe(1);
  await page.waitForTimeout(1_200);
  expect(refreshes).toHaveLength(1);
});

test("a refused live stream falls back to one resync, not a retry loop", async ({ page }) => {
  const refreshes = await openLive(page, { status: 401, events: [] });
  await expect.poll(() => refreshes.length).toBe(1);
  await page.waitForTimeout(1_200);
  expect(refreshes).toHaveLength(1);
});

test("an opened card form holds the live refresh only while a card is typed in (#4981)", async ({ page }) => {
  // Stripe's Payment Element, reduced to what the hold reads: its change
  // event, which says whether the field is empty.
  await page.addInitScript(() => {
    const element = { handlers: {} as Record<string, (event: { empty: boolean }) => void> };
    Object.assign(window, {
      typeCard: (empty: boolean) => element.handlers.change?.({ empty }),
      Stripe: () => ({
        elements: () => ({
          create: () => ({
            on: (name: string, handler: (event: { empty: boolean }) => void) => { element.handlers[name] = handler; },
            mount: () => {},
          }),
        }),
      }),
    });
  });
  await open(page);
  const refreshes: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/_fragments/billing")) refreshes.push(request.url());
  });
  const credit = () => page.evaluate(() => document.body.dispatchEvent(new CustomEvent("codewire:live:credit")));
  const typeCard = (empty: boolean) => page.evaluate((value) => (window as unknown as { typeCard: (empty: boolean) => void }).typeCard(value), empty);
  // Opened and left empty: the refresh runs.
  const empty = page.locator("#billing-stack-empty");
  await empty.locator("form[data-add-credit] [data-add-credit-submit]").click();
  await expect(empty.locator("[data-card-form]")).toBeVisible();
  await credit();
  await expect.poll(() => refreshes.length).toBe(1);
  // A card typed in: the refresh waits, and the form stays.
  await typeCard(false);
  await credit();
  await credit();
  await page.waitForTimeout(250);
  expect(refreshes).toHaveLength(1);
  await expect(empty.locator("[data-card-form]")).toBeVisible();
  // Cleared again: the held refresh runs, once.
  await typeCard(true);
  await expect.poll(() => refreshes.length).toBe(2);
  await page.waitForTimeout(250);
  expect(refreshes).toHaveLength(2);
});

test("a bank's return cleans the address before any request and finishes with only the SetupIntent", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const fixture = `${origin}/reference/fixtures/organization-billing.html`;
  const requests: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  let finish: { referer: string; body: string } | null = null;
  await page.route(fixture, async (route) => {
    const request = route.request();
    if (request.method() !== "POST") return route.continue();
    finish = { referer: (await request.headerValue("referer")) || "", body: request.postData() || "" };
    return route.fulfill({ json: { location: `${fixture}?message=card-saved` } });
  });
  // As Stripe sends it back: its SetupIntent, the secret and the status,
  // beside the console's card_return.
  await page.goto(
    `${fixture}?card_return=1&setup_intent=seti_return0000000000000000&setup_intent_client_secret=seti_return0000000000000000_secret_x&redirect_status=succeeded`,
  );
  await expect(page).toHaveURL(/\?message=card-saved$/);
  expect(finish).not.toBeNull();
  // The finish went out after the address was cleaned, and carried nothing
  // but the SetupIntent: no amount, no top-up, no attempt key.
  expect(finish!.referer).not.toContain("setup_intent");
  expect([...new URLSearchParams(finish!.body)]).toEqual([
    ["_csrf", "design-fixture-only"],
    ["setup_intent", "seti_return0000000000000000"],
  ]);
  // Nothing left the console's origin: no Stripe.js, no other script.
  const others = requests.filter((url) => !url.startsWith(origin!) && !url.startsWith("data:"));
  expect(others).toEqual([]);
});
