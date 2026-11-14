import { expect, test, type Page, type Route } from "./helpers/fixture-test";

// Setup-progress browser proof on the checked-in design fixture. The event
// stream is synthetic; it does not qualify orchestration or authentication.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

const environment = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const eventsPath = `**/fixture-org/${environment}/_events/setup-progress`;
const id = (n: number) => n.toString(16).padStart(32, "0");

const fixtureUrl = () => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for setup progress fixture checks");
  return `${origin}/reference/fixtures/setup-progress.html`;
};

type Stage = { phase: string; status: string; label: string; repoIndex?: number; repoCount?: number;
  stage?: string; percent?: number; durationMs?: number; createdAt?: string };
const frame = (n: number, stage: Stage) => `id: ${id(n)}\nevent: stage\ndata: ${JSON.stringify(stage)}\n\n`;
const end = (outcome: string) => `event: end\ndata: {"outcome":"${outcome}"}\n\n`;
const fulfill = (route: Route, body: string) => route.fulfill({
  status: 200, headers: { "content-type": "text/event-stream; charset=utf-8", "cache-control": "no-store" }, body,
});

// A Sandbox that is not running yet: the page marks its setup section so.
async function starting(page: Page) {
  await page.addInitScript(() => {
    new MutationObserver((_, observer) => {
      const section = document.querySelector("[data-setup-progress]");
      if (!section) return;
      section.setAttribute("data-setup-starting", "");
      observer.disconnect();
    }).observe(document, { childList: true, subtree: true });
  });
}
const status = (page: Page, detail: Record<string, boolean>) => page.evaluate(([environmentId, value]) =>
  document.dispatchEvent(new CustomEvent("codewire:sandbox-status", { detail: { environmentId, ...value } })), [environment, detail] as const);

async function streams(page: Page, answers: string[]) {
  const resumes: Array<string | null> = [];
  await page.route(eventsPath, async (route) => {
    resumes.push(route.request().headers()["last-event-id"] ?? null);
    const body = answers.shift();
    if (body === undefined) await route.fulfill({ status: 204 });
    else await fulfill(route, body);
  });
  return resumes;
}

test("setup stages and clone progress stream, resume after a reconnect, and end", async ({ page }) => {
  const resumes = await streams(page, [
    // The first connection ends early; the browser resumes after its last id.
    "retry: 50\n\n"
      + frame(1, { phase: "health_check", status: "started", label: "Checking sidecar readiness", createdAt: "2026-10-06T10:00:00Z" })
      + frame(2, { phase: "health_check", status: "completed", label: "Checking sidecar readiness", durationMs: 1200 })
      + frame(3, { phase: "git_clone", status: "started", label: "Cloning repositories" })
      + frame(4, { phase: "git_clone", status: "started", label: "Cloning repository 1 of 2", repoIndex: 1, repoCount: 2 })
      + frame(5, { phase: "git_clone", status: "progress", label: "Cloning repositories", repoIndex: 1, repoCount: 2, stage: "receiving_objects", percent: 45 }),
    frame(6, { phase: "git_clone", status: "completed", label: "Cloned repository 1 of 2", repoIndex: 1, repoCount: 2 })
      + frame(7, { phase: "git_clone", status: "progress", label: "Cloning repositories", repoIndex: 2, repoCount: 2, stage: "resolving_deltas", percent: 100 })
      + frame(8, { phase: "git_clone", status: "completed", label: "Cloning repositories" })
      + frame(9, { phase: "complete", status: "completed", label: "Setup complete" })
      + end("complete"),
  ]);
  await page.goto(fixtureUrl());
  const setup = page.getByRole("region", { name: "Starting your Sandbox" });
  await expect(setup.getByRole("heading", { level: 2, name: "Starting your Sandbox" })).toBeVisible();
  const first = setup.getByRole("progressbar", { name: "Repository 1 of 2" });
  const second = setup.getByRole("progressbar", { name: "Repository 2 of 2" });
  await expect(second).toHaveJSProperty("value", 100);
  await expect(first).toHaveJSProperty("value", 100);
  await expect(setup.locator("[data-setup-announce]")).toHaveText("Setup complete. The terminal opens when the Sandbox reports it is ready.");
  await expect(setup.locator("[data-setup-status]")).toBeHidden();
  const stages = setup.locator("[data-setup-stages] > li");
  // "complete" ends the list; it is not a step of its own.
  await expect(stages).toHaveCount(2);
  await expect(stages.nth(0)).toContainText("Checking sidecar readiness");
  await expect(stages.nth(0)).toContainText("1.2 s");
  await expect(setup.getByRole("progressbar", { name: "Starting your Sandbox" })).toHaveAttribute("aria-valuenow", "100");
  await expect(stages.nth(1).getByRole("listitem")).toHaveCount(2);
  expect(resumes).toEqual([null, id(5)]);
  await expect(setup.getByRole("alert")).toBeHidden();
  // The terminal's readiness, not the stream, decides when setup is over:
  // only a running Sandbox whose setup completed closes the list.
  await status(page, { setupComplete: true });
  await expect(setup).toBeVisible();
  await status(page, { running: true, setupComplete: true });
  await expect(setup).toBeHidden();
});

test("a first start shows one starting row, never a start phase, then setup under the project", async ({ page }) => {
  await starting(page);
  const resumes = await streams(page, [
    frame(1, { phase: "create_claim", status: "started", label: "Claiming workspace" })
      + frame(2, { phase: "pod_scheduled", status: "completed", label: "Workspace pod scheduled", durationMs: 500 })
      + frame(3, { phase: "health_check", status: "started", label: "Checking sidecar readiness" }),
  ]);
  await page.goto(fixtureUrl());
  const setup = page.getByRole("region", { name: "Starting your Sandbox" });
  const stages = setup.locator("[data-setup-stages] > .cw-setup-stage");
  await expect(stages).toHaveCount(1);
  await expect(stages.nth(0)).toContainText("Starting the Sandbox");
  await expect(stages.nth(0)).toHaveAttribute("data-state", "running");
  // The stream opens only once readiness says setup has not finished.
  expect(resumes).toHaveLength(0);
  await status(page, { starting: true, setupComplete: false });
  await expect(stages).toHaveText([/^Starting the Sandbox/, /^Checking sidecar readiness/]);
  await expect(stages.nth(0)).toHaveAttribute("data-state", "completed");
  await expect(stages.nth(1)).toHaveAttribute("data-state", "running");
  await expect(setup.locator(".cw-setup-group")).toHaveText("Setting up your project");
  await expect(setup).not.toContainText("Claiming workspace");
  await expect(setup).not.toContainText("Workspace pod scheduled");
});

test("a restart shows the starting row, replays no earlier run, and closes once running", async ({ page }) => {
  await starting(page);
  const resumes = await streams(page, [frame(1, { phase: "health_check", status: "completed", label: "an earlier run" })]);
  await page.goto(fixtureUrl());
  const setup = page.getByRole("region", { name: "Starting your Sandbox" });
  // Setup finished on an earlier run, so this start follows no stream.
  await status(page, { starting: true, setupComplete: true });
  await expect(setup).toBeVisible();
  const stages = setup.locator("[data-setup-stages] > .cw-setup-stage");
  await expect(stages).toHaveCount(1);
  await expect(stages.nth(0)).toHaveAttribute("data-state", "running");
  await status(page, { running: true, setupComplete: true });
  await expect(setup).toBeHidden();
  expect(resumes).toHaveLength(0);
  await expect(page.getByText("an earlier run")).toHaveCount(0);
});

test("a failed stage is announced and stream text is never markup", async ({ page }) => {
  const hostile = "<img src=x onerror=\"document.body.dataset.injected='yes'\">";
  await streams(page, [
    frame(1, { phase: "git_clone", status: "started", label: "Cloning repositories" })
      + frame(2, { phase: "git_clone", status: "failed", label: `git clone: exited 128 ${hostile}` })
      + end("failed"),
  ]);
  await page.goto(fixtureUrl());
  const setup = page.getByRole("region", { name: "Starting your Sandbox" });
  await expect(setup.getByRole("alert")).toHaveText(`Cloning repositories failed: git clone: exited 128 ${hostile}`);
  await expect(setup.locator("[data-setup-status]")).toHaveText("Setup stopped.");
  await expect(setup.locator("img")).toHaveCount(0);
  expect(await page.evaluate(() => document.body.dataset.injected)).toBeUndefined();
  // A failure stays visible even after readiness reports setup state.
  await status(page, { running: true, setupComplete: true });
  await expect(setup).toBeVisible();
});

test("a refused stream says live progress is unavailable", async ({ page }) => {
  await page.route(eventsPath, (route) => route.fulfill({ status: 401, body: "" }));
  await page.goto(fixtureUrl());
  await expect(page.getByRole("region", { name: "Starting your Sandbox" }).locator("[data-setup-status]"))
    .toHaveText("Live setup progress is unavailable. Sandbox status below still updates.");
});

test("the account follow limit stops retrying and says what to do", async ({ page }) => {
  const resumes = await streams(page, ["retry: 50\n\nevent: busy\ndata: {}\n\n", "event: busy\ndata: {}\n\n"]);
  await page.goto(fixtureUrl());
  await expect(page.getByRole("region", { name: "Starting your Sandbox" }).locator("[data-setup-status]"))
    .toHaveText("Too many live setup views are open for this account. Close one, then reload this page to follow setup here.");
  // A busy answer closes the source: no reconnect follows the short retry.
  await page.waitForTimeout(500);
  expect(resumes).toHaveLength(1);
});
