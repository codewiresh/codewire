import { expect, test, type Locator, type Page } from "./helpers/fixture-test";

// Synthetic private-controller proof, not managed auth/daemon qualification.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });
const environment = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const requestId = "0123456789abcdef0123456789abcdef";
const operationId = "fedcba9876543210fedcba9876543210";
const storageKey = `codewire.resize.v1:account-a:fixture-org:${environment}`;
const desired = { cpuMillicores: 2000, memoryMib: 4096, diskGib: 20 };

async function transport(page: Page) {
  const state = { plans: 0, applies: 0, observations: 0, lost: false, restart: false, foreign: false,
    oversized: false, operationState: "applying", observationUnavailable: false,
    // undefined answers like a server from before setupRunning existed.
    setupRunning: false as boolean | undefined,
    planRefusal: null as Record<string, unknown> | null, planGate: Promise.resolve(), applyGate: Promise.resolve() };
  // Only the opted-in readiness request is answered.
  await page.route("**/_fragments/terminal-readiness?fields=setup", (route) => route.fulfill({ json: {
    environmentId: environment, running: true, setupComplete: state.setupRunning !== true,
    ...(state.setupRunning === undefined ? {} : { setupRunning: state.setupRunning }),
    detail: { state: "running", desiredState: "started", tone: "success", lastEvent: "just now",
      resources: "1 vCPU · 2 GiB · 10 GiB", cpuMillicores: 1000, memoryMib: 2048, diskGib: 10,
      startEligible: false, stopEligible: true, deleteEligible: true, deletionState: "unscheduled", shutdownAt: null, actionsAllowed: true, pending: false },
  } }));
  await page.route("**/_actions/resize/plan", async (route) => {
    state.plans += 1;
    const form = new URLSearchParams(route.request().postData() || "");
    expect([...form.keys()].sort()).toEqual(["_csrf", "account_id", "cpu_millicores", "disk_gb", "memory_mb"]);
    expect(form.get("account_id")).toBe("account-a");
    await state.planGate;
    if (state.planRefusal) { await route.fulfill({ status: 409, json: state.planRefusal }); return; }
    await route.fulfill({ json: { accountId: state.foreign ? "account-b" : "account-a", environmentId: environment,
      requestId, previousResources: { cpuMillicores: 1000, memoryMib: 2048, diskGib: 10 }, desiredResources: desired,
      mode: state.restart ? "restart" : "in-place", restartRequired: state.restart,
      sessionsWillTerminate: state.restart, activeSessionCount: state.restart ? 2 : 0,
      ...(state.oversized ? { privateReason: "x".repeat(3000) } : {}),
    } });
  });
  await page.route("**/_actions/resize/apply", async (route) => {
    state.applies += 1;
    const form = new URLSearchParams(route.request().postData() || "");
    expect([...form.keys()].sort()).toEqual(["_csrf", "account_id", "allow_restart", "cpu_millicores", "disk_gb", "force", "memory_mb", "request_id"]);
    expect(form.get("request_id")).toBe(requestId);
    expect(form.get("allow_restart")).toBe(String(state.restart));
    expect(form.get("force")).toBe(String(state.restart));
    expect(await page.evaluate((key) => sessionStorage.getItem(key), storageKey)).not.toBeNull();
    await state.applyGate;
    if (state.lost) { await route.abort(); return; }
    await route.fulfill({ json: { accountId: "account-a", environmentId: environment, operationId, requestId,
      desiredResources: desired, policy: state.restart ? "allow-restart" : "live-only", state: "applying" } });
  });
  await page.route("**/_fragments/resize-operation?**", (route) => {
    state.observations += 1;
    expect(new URL(route.request().url()).searchParams.get("account_id")).toBe("account-a");
    expect(new URL(route.request().url()).searchParams.get("operation_id")).toBe(operationId);
    return route.fulfill({ status: state.observationUnavailable ? 503 : 200, json: {
      accountId: state.foreign ? "account-b" : "account-a", environmentId: environment, operationId, requestId,
      desiredResources: desired, policy: state.restart ? "allow-restart" : "live-only", state: state.operationState,
    } });
  });
  return state;
}

async function open(page: Page) {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
  await page.goto(`${origin}/reference/fixtures/sandbox-resize.html`);
  // Resize enables after the first readiness poll settles; under a loaded
  // machine page start-up alone can exceed the default expect timeout.
  await expect(page.getByRole("button", { name: "Resize", exact: true })).toBeEnabled({ timeout: 15_000 });
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  return page.getByRole("dialog", { name: "Resize Fixture Sandbox" });
}

// The visible footer actions, in order. Hidden buttons are not in the
// accessibility tree, so this is exactly the set a user can reach.
const footer = (dialog: Locator) => dialog.locator("footer").getByRole("button");

// A submitted or unrecoverable change is read-only: its fields are disabled
// and Done is the only action, so no new review can start.
async function expectReadOnly(dialog: Locator) {
  await expect(footer(dialog)).toHaveText(["Done"]);
  await expect(dialog.getByLabel("CPU", { exact: true })).toBeDisabled();
}

async function review(page: Page) {
  const dialog = page.getByRole("dialog", { name: "Resize Fixture Sandbox" });
  await dialog.getByLabel("CPU", { exact: true }).selectOption("2000");
  await dialog.getByLabel("Memory", { exact: true }).selectOption("4096");
  await dialog.getByLabel("Disk (GiB)", { exact: true }).fill("20");
  await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-plan]")).toBeVisible();
  return dialog;
}

test("reviews consequences and resolves only a matching operation observation", async ({ page }) => {
  const state = await transport(page);
  const opened = await open(page);
  // Choosing is an editor: Cancel plus its one primary action, no Back.
  await expect(footer(opened)).toHaveText(["Cancel", "Review resize"]);
  await expect(opened.getByRole("button", { name: "Back", exact: true })).toBeHidden();
  const choosing = (await opened.boundingBox())!;
  const memory = (await opened.getByLabel("Memory", { exact: true }).boundingBox())!;
  expect(memory.x + memory.width).toBeLessThanOrEqual(choosing.x + choosing.width);
  const dialog = await review(page);
  await expect(dialog.locator("[data-resize-summary]")).toContainText("1 vCPU · 2 GiB memory · 10 GiB disk → 2 vCPU · 4 GiB memory");
  await expect(dialog.locator("[data-resize-disk-warning]")).toBeVisible();
  await expect(dialog.locator("[data-resize-restart-consent]")).not.toBeVisible();
  await expect(dialog.locator("[data-resize-session-consent]")).not.toBeVisible();
  // Reviewing is a nested step: Back, then Cancel plus Apply in one footer.
  await expect(dialog.getByRole("button", { name: "Back", exact: true })).toBeFocused();
  await expect(footer(dialog)).toHaveText(["Cancel", "Apply resize"]);
  await expect(dialog.getByLabel("CPU", { exact: true })).toBeHidden();
  const bounds = (await dialog.boundingBox())!;
  expect(bounds.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  await expect(dialog.getByRole("button", { name: "Check resize status" })).not.toBeVisible();
  const apply = (await dialog.getByRole("button", { name: "Apply resize", exact: true }).boundingBox())!;
  expect(apply.y).toBeGreaterThanOrEqual(0);
  expect(apply.y + apply.height).toBeLessThanOrEqual(page.viewportSize()!.height);
  const reviewImage = test.info().outputPath("resize-resource-review.png");
  await dialog.screenshot({ path: reviewImage });
  await test.info().attach("Resize resource review", { path: reviewImage, contentType: "image/png" });
  expect(state.applies).toBe(0);
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Resize applying");
  await expect(page.locator('[data-sandbox-action="stop"]')).toBeDisabled();
  // A submitted change cannot be edited or cancelled here: Done dismisses it.
  await expectReadOnly(dialog);
  await expect(dialog.getByRole("button", { name: "Done", exact: true })).toBeFocused();
  state.observationUnavailable = true;
  await dialog.getByRole("button", { name: "Check resize status" }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("stays locked");
  await expectReadOnly(dialog);
  state.observationUnavailable = false;
  state.foreign = true;
  state.operationState = "completed";
  await dialog.getByRole("button", { name: "Check resize status" }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("stays locked");
  expect(await page.evaluate((key) => sessionStorage.getItem(key), storageKey)).not.toBeNull();
  state.foreign = false;
  await dialog.getByRole("button", { name: "Check resize status" }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Resize completed");
  expect(await page.evaluate((key) => sessionStorage.getItem(key), storageKey)).toBeNull();
  await expect(page.locator('[data-sandbox-action="stop"]')).toBeEnabled();
  // The outcome is read-only: a single Done closes it, and reopening starts over.
  await expect(footer(dialog)).toHaveText(["Done"]);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(dialog).toBeHidden();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(footer(dialog)).toHaveText(["Cancel", "Review resize"]);
  await expect(dialog.locator("[data-resize-status]")).toBeEmpty();
  expect(state.applies).toBe(1);
});

// #2333: the server refuses Resize while setup owns the running Sandbox.
test("Resize waits for setup with a visible reason and returns when setup finishes", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
  const state = await transport(page);
  state.setupRunning = true;
  await page.goto(`${origin}/reference/fixtures/sandbox-resize.html`);
  const opener = page.getByRole("button", { name: "Resize", exact: true });
  const reason = page.getByText("Resize is available when setup finishes.", { exact: true });
  await expect(reason).toBeVisible({ timeout: 15_000 });
  await expect(opener).toBeVisible();
  await expect(opener).toBeDisabled();
  await expect(opener).toHaveAccessibleDescription("Resize is available when setup finishes.");
  const bounds = (await reason.boundingBox())!;
  expect(bounds.x + bounds.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  state.setupRunning = false;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(opener).toBeEnabled();
  await expect(reason).toBeHidden();
  await expect(opener).toHaveAccessibleDescription("");
  // A server from before setupRunning omits it: Resize works as it did.
  state.setupRunning = true;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(opener).toBeDisabled();
  state.setupRunning = undefined;
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(opener).toBeEnabled();
  await expect(reason).toBeHidden();
  await expect(page.locator("[data-sandbox-observation-status]")).toBeHidden();
  expect(state.plans).toBe(0);
});

test("a Review that races setup says setup is still running, never server text", async ({ page }) => {
  const state = await transport(page);
  const dialog = await open(page);
  await dialog.getByLabel("CPU", { exact: true }).selectOption("2000");
  const status = dialog.locator("[data-resize-status]");
  state.planRefusal = { error: "setup-in-progress" };
  await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
  await expect(status).toHaveText("Setup is still running. Nothing was applied. You can resize when it finishes.");
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  await expect(footer(dialog)).toHaveText(["Cancel", "Review resize"]);
  // Only the closed code is trusted: other refusals stay generic.
  for (const [index, refusal] of [{ error: "setup-in-progress", detail: "private server text" }, { error: "account-changed" }].entries()) {
    state.planRefusal = refusal;
    await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
    await expect.poll(() => state.plans).toBe(index + 2);
    await expect(status).toHaveText("The resize could not be reviewed. Nothing was applied. Check current status before reviewing again.");
  }
  await expect(dialog).not.toContainText("private server text");
  expect(state.plans).toBe(3);
  expect(state.applies).toBe(0);
});

test("Back keeps the chosen values and Cancel closes without a request", async ({ page }) => {
  const state = await transport(page);
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Back", exact: true }).click();
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  await expect(footer(dialog)).toHaveText(["Cancel", "Review resize"]);
  await expect(dialog.getByLabel("CPU", { exact: true })).toBeFocused();
  await expect(dialog.getByLabel("CPU", { exact: true })).toHaveValue("2000");
  await expect(dialog.getByLabel("Memory", { exact: true })).toHaveValue("4096");
  await expect(dialog.getByLabel("Disk (GiB)", { exact: true })).toHaveValue("20");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(state.plans).toBe(1);
  expect(state.applies).toBe(0);
});

test("lost Apply acknowledgement remains locked across dismissal, readiness and reload", async ({ page }) => {
  const state = await transport(page);
  state.lost = true;
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("outcome is unknown");
  // Synthetic lifecycle delivery exercises the controller's persisted-page
  // handlers; this does not claim actual browser BFcache admission.
  await page.evaluate(() => {
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
  });
  await expectReadOnly(dialog);
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expectReadOnly(dialog);
  await page.reload();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText(requestId);
  await expectReadOnly(dialog);
  await expect(page.locator('[data-sandbox-action="stop"]')).toBeDisabled();
  await expect(page.locator("details[data-sandbox-resize]")).toBeHidden();
  expect(state.plans).toBe(1);
  expect(state.applies).toBe(1);
  expect(state.observations).toBe(0);
});

test("requires separate restart and session termination consents", async ({ page }) => {
  const state = await transport(page);
  state.restart = true;
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Confirm the required");
  expect(state.applies).toBe(0);
  await dialog.getByLabel("Allow a restart of this Sandbox.", { exact: true }).check();
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  expect(state.applies).toBe(0);
  await dialog.getByLabel("Allow the active terminal sessions shown in this review to end.", { exact: true }).check();
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Resize applying");
  expect(state.applies).toBe(1);
});

test("late or foreign review cannot install a stale plan", async ({ page }) => {
  const state = await transport(page);
  let release = () => {};
  state.planGate = new Promise<void>((resolve) => { release = resolve; });
  const dialog = await open(page);
  await dialog.getByLabel("CPU", { exact: true }).selectOption("2000");
  await dialog.getByLabel("Memory", { exact: true }).selectOption("4096");
  await dialog.getByLabel("Disk (GiB)", { exact: true }).fill("20");
  await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
  await expect.poll(() => state.plans).toBe(1);
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeEnabled();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  release();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  state.foreign = true;
  await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("could not be reviewed");
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  expect(state.applies).toBe(0);
});

test("malformed pending storage fails closed without dispatch", async ({ page }) => {
  const state = await transport(page);
  await page.addInitScript((key) => { sessionStorage.setItem(key, "malformed"); }, storageKey);
  const dialog = await open(page);
  await expect(dialog.locator("[data-resize-status]")).toContainText("cannot be safely recovered");
  await expectReadOnly(dialog);
  expect(state.applies).toBe(0);
  expect(state.plans).toBe(0);
});

test("known operation resumes read-only after reload", async ({ page }) => {
  const state = await transport(page);
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Resize applying");
  await page.reload();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("Resize applying");
  expect(state.applies).toBe(1);
  expect(state.plans).toBe(1);
  expect(state.observations).toBeGreaterThan(0);
});

test("dismissal during Apply keeps uncertainty and rejects its late acknowledgement", async ({ page }) => {
  const state = await transport(page);
  let release = () => {};
  state.applyGate = new Promise<void>((resolve) => { release = resolve; });
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect.poll(() => state.applies).toBe(1);
  await expect(dialog.getByRole("button", { name: "Done", exact: true })).toBeEnabled();
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  release();
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("outcome is unknown");
  await expectReadOnly(dialog);
  expect(state.observations).toBe(0);
  expect(state.applies).toBe(1);
});

test("storage write failure prevents dispatch even after a valid review", async ({ page }) => {
  const state = await transport(page);
  await open(page);
  const dialog = await review(page);
  await page.evaluate(() => { Storage.prototype.setItem = () => { throw new Error("Synthetic storage failure"); }; });
  await dialog.getByRole("button", { name: "Apply resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("cannot be safely recovered");
  expect(state.applies).toBe(0);
  await expectReadOnly(dialog);
});

test("oversized review is rejected without forwarding backend text", async ({ page }) => {
  const state = await transport(page);
  state.oversized = true;
  const dialog = await open(page);
  await dialog.getByLabel("CPU", { exact: true }).selectOption("2000");
  await dialog.getByLabel("Memory", { exact: true }).selectOption("4096");
  await dialog.getByLabel("Disk (GiB)", { exact: true }).fill("20");
  await dialog.getByRole("button", { name: "Review resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-status]")).toContainText("could not be reviewed");
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  expect(state.applies).toBe(0);
});

test("readiness updates while closed invalidate an older reviewed tuple on reopen", async ({ page }) => {
  const state = await transport(page);
  await open(page);
  const dialog = await review(page);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(page.locator('#sandbox-resize [name="cpu_millicores"]')).toHaveValue("1000");
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(dialog.locator("[data-resize-plan]")).toBeHidden();
  await expect(dialog.locator("[data-resize-status]")).toContainText("resources changed");
  expect(state.plans).toBe(1);
  expect(state.applies).toBe(0);
});

test("a current value outside the fixed choices stays selected as its own choice across live polls", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN");
  let release = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  const live = { cpuMillicores: 1500, memoryMib: 3072 };
  await page.route("**/_fragments/terminal-readiness?fields=setup", async (route) => {
    await held;
    await route.fulfill({ json: {
      environmentId: environment, running: true, setupComplete: true, setupRunning: false,
      detail: { state: "running", desiredState: "started", tone: "success", lastEvent: "just now",
        resources: "live", ...live, diskGib: 10, startEligible: false, stopEligible: true, deleteEligible: true,
        deletionState: "unscheduled", shutdownAt: null, actionsAllowed: true, pending: false },
    } });
  });
  await page.goto(`${origin}/reference/fixtures/sandbox-resize.html`);
  // The closed dialog is not in the accessibility tree; its fields still are in the form.
  const dialog = page.locator("#sandbox-resize");
  const cpu = dialog.getByLabel("CPU", { exact: true });
  const memory = dialog.getByLabel("Memory", { exact: true });
  // Rendered before any poll: the Sandbox's own value is the selected choice.
  await expect(cpu).toHaveValue("750");
  await expect(cpu.locator("option")).toHaveText(["750 millicores (current)", "1 vCPU", "2 vCPU", "4 vCPU", "8 vCPU"]);
  await expect(cpu.locator("option:checked")).toHaveText("750 millicores (current)");
  await expect(memory.locator("option:checked")).toHaveText("1536 MiB (current)");
  release();
  // A different off-catalog live value replaces the one current choice
  // instead of blanking the select or keeping a stale "(current)".
  await expect(cpu).toHaveValue("1500");
  await expect(cpu.locator("option:checked")).toHaveText("1500 millicores (current)");
  await expect(cpu.locator("option", { hasText: "(current)" })).toHaveCount(1);
  await expect(memory).toHaveValue("3072");
  await expect(memory.locator("option:checked")).toHaveText("3072 MiB (current)");
  await expect(page.getByRole("button", { name: "Resize", exact: true })).toBeEnabled({ timeout: 15_000 });
  await page.getByRole("button", { name: "Resize", exact: true }).click();
  await expect(cpu).toBeVisible();
  await expect(cpu.locator("option:checked")).toHaveText("1500 millicores (current)");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  // A catalog value selects that choice and drops the extra option.
  Object.assign(live, { cpuMillicores: 2000, memoryMib: 4096 });
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(cpu).toHaveValue("2000");
  await expect(cpu.locator("option")).toHaveText(["1 vCPU", "2 vCPU", "4 vCPU", "8 vCPU"]);
  await expect(memory.locator("option:checked")).toHaveText("4 GiB");
  await expect(memory.locator("option")).toHaveText(["2 GiB", "4 GiB", "8 GiB", "16 GiB"]);
  Object.assign(live, { cpuMillicores: 750, memoryMib: 1536 });
  await page.getByRole("button", { name: "Refresh sandbox status", exact: true }).click();
  await expect(cpu).toHaveValue("750");
  await expect(cpu.locator("option")).toHaveText(["750 millicores (current)", "1 vCPU", "2 vCPU", "4 vCPU", "8 vCPU"]);
  await expect(memory.locator("option:checked")).toHaveText("1536 MiB (current)");
});
