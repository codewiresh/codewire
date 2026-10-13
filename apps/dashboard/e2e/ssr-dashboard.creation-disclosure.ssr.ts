import { expect, test, type Page } from "@playwright/test";

// Native form/disclosure proof only; not real auth or managed-Sandbox proof.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

test("creation keeps sources visible and closed advanced fields remain native form values", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native creation fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const resources = page.locator("[data-create-resources]");
  const runtime = page.locator("[data-create-runtime]");
  // Resources and lifetime are first-class fields; only runtime commands fold away.
  await expect(resources.getByRole("heading", { name: "Resources and lifetime", exact: true })).toBeVisible();
  await expect(resources.locator("summary")).toHaveCount(0);
  await expect(runtime).not.toHaveAttribute("open", "");
  await expect(page.getByLabel("CPU", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Install command", { exact: true })).toBeHidden();
  await expect(page.getByRole("heading", { name: "Repositories", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Application secrets", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provider credentials", exact: true })).toBeVisible();
  await expect(page.locator(".cw-snapshot-stub, .cw-snapshot-meter")).toHaveCount(0);
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Memory", { exact: true }).selectOption("4096");
  await page.getByLabel("Disk", { exact: true }).selectOption("20");
  await expect(page.getByLabel("CPU", { exact: true }).locator("option:checked")).toHaveText("2 vCPU");
  await expect(page.getByLabel("Memory", { exact: true }).locator("option:checked")).toHaveText("4 GiB");
  const ttl = page.getByLabel("Delete after");
  await expect(ttl).toHaveAccessibleDescription(/automatic deletion.*not an idle timeout.*without one, the Sandbox is not scheduled/);
  // No preset is selected: empty states what it does instead of "infinity".
  await expect(ttl).toHaveValue("");
  await expect(ttl).toHaveAttribute("placeholder", "Not scheduled");
  for (const legacy of ["0", "infinity", "∞"]) {
    await ttl.fill(legacy);
    await ttl.press("Tab");
    await expect(ttl).toHaveValue("");
  }
  await ttl.fill(" 8 H ");
  await ttl.press("Tab");
  await expect(ttl).toHaveValue("8h");
  await ttl.fill("");
  await runtime.locator("summary").click();
  await page.getByLabel("Install command", { exact: true }).fill("bun install");
  await page.getByLabel("Startup script", { exact: true }).fill("bun run dev");
  await runtime.locator("summary").click();
  const fields = await page.locator("[data-environment-form]").evaluate((form: HTMLFormElement) => {
    const data = new FormData(form);
    return Object.fromEntries(["cpu", "memory", "disk", "ttl", "install_command", "startup_script"].map((name) => [name, data.get(name)]));
  });
  expect(fields).toEqual({ cpu: "2000", memory: "4096", disk: "20", ttl: "", install_command: "bun install", startup_script: "bun run dev" });
});

const draftPrefix = "codewire.create-selections.v1:";
const actor = "11111111111140008000000000000001";
// Product organization IDs are opaque 32-hex strings, not UUIDs.
const organization = "6bf8d155e84c4fc5b479b17022fe41dd";
const draftId = "00000000-0000-4000-8000-000000000003";
const projectId = "6bf8d155-e84c-4fc5-b479-b17022fe41dd";
const profile = "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@9007199254740993";
const selectionsDraft = () => ({
  version: 1, actor, organization, draft: draftId, saved_at: Date.now(),
  selections: {
    preset_id: "", cpu: "2000", memory: "4096", disk: "20", ttl: "8h",
    isolation_tier: "standard", agents: [] as string[], ports: [] as { port: string; access: string }[],
    secret_project: projectId, credential_profile: profile,
    include_org_secrets: true, include_user_secrets: false,
  },
});
type Draft = ReturnType<typeof selectionsDraft>;
const keyForDraft = (draft: Draft) => `${draftPrefix}${draft.actor}:${draft.organization}:${draft.draft}`;
const fixtureUrl = () => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native draft checks");
  return `${origin}/reference/fixtures/create-sandbox.html`;
};

function loadingCreateFixture(hydratedHtml: string) {
  const start = hydratedHtml.indexOf('<div class="cw-create-stack" data-create-optional-options>');
  const end = hydratedHtml.indexOf('<details class="cw-create-panel cw-runtime-options', start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return `${hydratedHtml.slice(0, start)}<div class="cw-create-stack" data-create-optional-options><p role="status">Loading provider, secret, agent, and isolation choices…</p><button type="button" data-retry-create-options hidden>Retry loading choices</button><input type="hidden" name="isolation_tier" value="standard"></div>\n${hydratedHtml.slice(end)}`
    .replace('data-create-options-loading="false"', 'data-create-options-loading="true"')
    .replace(/<p class="cw-field-help" data-create-preview-hint>.*?<\/p>/, '<p class="cw-field-help" data-create-preview-hint>Loading preview URL details…</p>');
}

function hydratedCreateCard(hydratedHtml: string) {
  const start = hydratedHtml.indexOf('<section id="environment-create-card"');
  const end = hydratedHtml.indexOf("<template data-repository-template>", start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return hydratedHtml.slice(start, end);
}

test("late Create choices preserve edited core fields, focus, rows, and profile selectors", async ({ page }) => {
  const url = fixtureUrl();
  let hydratedHtml = "";
  let releaseOptions!: () => void;
  const heldOptions = new Promise<void>((resolve) => { releaseOptions = resolve; });
  await page.route(url, async (route) => {
    const original = await route.fetch();
    hydratedHtml = await original.text();
    await route.fulfill({ response: original, body: loadingCreateFixture(hydratedHtml) });
  });
  await page.route("**/fixture/_fragments/create-options", async (route) => {
    await heldOptions;
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: hydratedCreateCard(hydratedHtml) });
  });
  const pending = page.waitForRequest((request) => request.url().endsWith("/fixture/_fragments/create-options"));
  await page.goto(url);
  await pending;
  const form = page.locator("[data-environment-form]");
  const originalForm = await form.elementHandle();
  const draft = await form.getAttribute("data-create-draft-id");
  await page.getByLabel("Workspace image").fill("registry.example.test/custom:stable");
  await page.getByLabel("Repository URL").fill("https://example.test/owner/repo");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Internal port").fill("3000");
  await page.getByLabel("Preview label").fill("web");
  await page.locator("[data-create-runtime] summary").click();
  await page.getByLabel("Startup Script").fill("bun run dev\necho ready");
  await page.getByLabel("Name", { exact: true }).fill("typing-survives-options");
  await expect(page.getByLabel("Name", { exact: true })).toBeFocused();
  releaseOptions();
  await expect(form).toHaveAttribute("data-create-options-loading", "false");
  expect(await originalForm?.evaluate((node) => node.isConnected)).toBe(true);
  await expect(form).toHaveAttribute("data-create-draft-id", draft!);
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("typing-survives-options");
  await expect(page.getByLabel("Name", { exact: true })).toBeFocused();
  await expect(page.getByLabel("Workspace image")).toHaveValue("registry.example.test/custom:stable");
  await expect(page.getByLabel("Repository URL")).toHaveValue("https://example.test/owner/repo");
  await expect(page.getByLabel("Internal port")).toHaveValue("3000");
  await expect(page.getByLabel("Preview label")).toHaveValue("web");
  await expect(page.getByLabel("Startup Script")).toHaveValue("bun run dev\necho ready");
  await expect(page.getByLabel("Credential profile", { exact: true })).toBeVisible();
  // Browsing uses the account's one GitHub connection, which every profile
  // includes: there is no GitHub selector and no per-profile GitHub choice.
  await expect(page.locator("[data-github-connection]")).toHaveCount(0);
  await expect(form.locator("[data-include-github]")).toHaveCount(0);
  await expect(page.locator("[data-github-browser]")).toBeVisible();
});

test("Create rejects choices returned for another organization without losing input", async ({ page }) => {
  const url = fixtureUrl();
  let hydratedHtml = "";
  let releaseOptions!: () => void;
  const heldOptions = new Promise<void>((resolve) => { releaseOptions = resolve; });
  await page.route(url, async (route) => {
    const original = await route.fetch();
    hydratedHtml = await original.text();
    await route.fulfill({ response: original, body: loadingCreateFixture(hydratedHtml) });
  });
  await page.route("**/fixture/_fragments/create-options", async (route) => {
    await heldOptions;
    const foreign = hydratedCreateCard(hydratedHtml).replace(
      `data-create-draft-organization="${organization}"`,
      'data-create-draft-organization="00000000-0000-4000-8000-000000000099"',
    );
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: foreign });
  });
  const pending = page.waitForRequest((request) => request.url().endsWith("/fixture/_fragments/create-options"));
  await page.goto(url);
  await pending;
  await page.getByLabel("Name", { exact: true }).fill("never-apply-foreign-options");
  const originalForm = await page.locator("[data-environment-form]").elementHandle();
  releaseOptions();
  await expect(page.locator("[data-create-optional-options] [role=alert]")).toContainText("Choices could not be loaded");
  await expect(page.getByRole("button", { name: "Retry loading choices" })).toBeVisible();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("never-apply-foreign-options");
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-organization", organization);
  expect(await originalForm?.evaluate((node) => node.isConnected)).toBe(true);
});

test("Create choices resume after a cached-page return and ignore the canceled response", async ({ page }) => {
  const url = fixtureUrl();
  let hydratedHtml = "";
  let releaseFirst!: () => void;
  const firstHeld = new Promise<void>((resolve) => { releaseFirst = resolve; });
  let firstStarted!: () => void;
  const firstRequest = new Promise<void>((resolve) => { firstStarted = resolve; });
  let secondStarted!: () => void;
  const secondRequest = new Promise<void>((resolve) => { secondStarted = resolve; });
  let attempts = 0;
  await page.route(url, async (route) => {
    const original = await route.fetch();
    hydratedHtml = await original.text();
    await route.fulfill({ response: original, body: loadingCreateFixture(hydratedHtml) });
  });
  await page.route("**/fixture/_fragments/create-options", async (route) => {
    attempts += 1;
    if (attempts === 1) {
      firstStarted();
      await firstHeld;
      await route.fulfill({ status: 200, contentType: "text/html", body: "<p>stale response</p>" }).catch(() => {});
      return;
    }
    secondStarted();
    await route.fulfill({ status: 200, contentType: "text/html", body: hydratedCreateCard(hydratedHtml) });
  });
  try {
    await page.goto(url);
    await firstRequest;
    await page.getByLabel("Name", { exact: true }).fill("still-here-after-return");
    await page.evaluate(() => {
      window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true }));
      window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true }));
    });
    await secondRequest;
    await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-options-loading", "false");
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-here-after-return");
    releaseFirst();
    await expect(page.locator("[data-create-optional-options]")).toContainText("Provider credentials");
    expect(attempts).toBe(2);
  } finally {
    releaseFirst();
  }
});

test("inventory load failure becomes unavailable and later recovery preserves rows", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.evaluate(() => {
    const list = document.createElement("div");
    list.id = "environment-list";
    list.dataset.environmentsLoading = "true";
    list.innerHTML = '<p role="status">Loading Sandboxes…</p>';
    const error = document.createElement("p");
    error.dataset.environmentListError = "";
    error.hidden = true;
    error.textContent = "Sandbox list could not be refreshed. Retrying…";
    document.body.append(list, error);
    list.dispatchEvent(new CustomEvent("htmx:responseError", { bubbles: true }));
  });
  await expect(page.locator("#environment-list")).toContainText("unavailable");
  await expect(page.locator("[data-environment-list-error]")).toBeVisible();
  await page.evaluate(() => {
    const list = document.querySelector("#environment-list")!;
    list.innerHTML = "<ul><li>Recovered Sandbox</li></ul>";
    list.dispatchEvent(new CustomEvent("htmx:afterSwap", { bubbles: true }));
    list.dispatchEvent(new CustomEvent("htmx:responseError", { bubbles: true }));
  });
  await expect(page.locator("#environment-list")).toContainText("Recovered Sandbox");
  await expect(page.locator("[data-environment-list-error]")).toBeVisible();
  await page.locator("#environment-list").evaluate((list) => list.dispatchEvent(new CustomEvent("htmx:afterSwap", { bubbles: true })));
  await expect(page.locator("[data-environment-list-error]")).toBeHidden();
});

test("optional-choice failure offers retry without clearing the Create form", async ({ page }) => {
  const url = fixtureUrl();
  let hydratedHtml = "";
  let attempts = 0;
  await page.route(url, async (route) => {
    const original = await route.fetch();
    hydratedHtml = await original.text();
    await route.fulfill({ response: original, body: loadingCreateFixture(hydratedHtml) });
  });
  // A transient failure is retried twice by itself before Retry is offered.
  await page.route("**/fixture/_fragments/create-options", async (route) => {
    attempts += 1;
    if (attempts <= 3) await route.fulfill({ status: 503, contentType: "text/plain", body: "unavailable" });
    else await route.fulfill({ status: 200, contentType: "text/html", body: hydratedCreateCard(hydratedHtml) });
  });
  await page.goto(url);
  const form = page.locator("[data-environment-form]");
  await expect(page.locator("[data-create-optional-options] [role=status]")).toHaveText("Choices did not load. Retrying (1 of 2)…");
  await expect(page.getByRole("button", { name: "Retry loading choices" })).toBeVisible({ timeout: 10_000 });
  expect(attempts).toBe(3);
  await expect(page.locator("[data-github-status]")).toContainText("Repository access unavailable");
  await expect(page.locator("[data-github-spinner]")).toBeHidden();
  const originalForm = await form.elementHandle();
  await page.getByLabel("Name", { exact: true }).fill("retry-keeps-my-name");
  await page.getByRole("button", { name: "Retry loading choices" }).click();
  await expect(form).toHaveAttribute("data-create-options-loading", "false");
  await expect(page.locator("[data-github-status]")).toContainText("Repositories available through this connection");
  expect(await originalForm?.evaluate((node) => node.isConnected)).toBe(true);
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("retry-keeps-my-name");
  expect(attempts).toBe(4);
});

test("a transient optional-choice failure recovers by itself", async ({ page }) => {
  const url = fixtureUrl();
  let hydratedHtml = "";
  let attempts = 0;
  await page.route(url, async (route) => {
    const original = await route.fetch();
    hydratedHtml = await original.text();
    await route.fulfill({ response: original, body: loadingCreateFixture(hydratedHtml) });
  });
  await page.route("**/fixture/_fragments/create-options", async (route) => {
    attempts += 1;
    if (attempts === 1) await route.abort("connectionreset");
    else await route.fulfill({ status: 200, contentType: "text/html", body: hydratedCreateCard(hydratedHtml) });
  });
  await page.goto(url);
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-options-loading", "false");
  await expect(page.getByRole("button", { name: "Retry loading choices" })).toHaveCount(0);
  expect(attempts).toBe(2);
});

test("busy repository loading cannot bypass dirty Create navigation", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("busy-navigation-canary");
  await page.locator("[data-github-results]").evaluate((node) => node.setAttribute("aria-busy", "true"));
  await page.getByRole("link", { name: "Manage personal secrets", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Save draft and leave", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Application secrets" })).toBeVisible();
});

test("Create submission has bounded pending feedback and recovers from BFCache", async ({ page }) => {
  await page.goto(fixtureUrl());
  const form = page.locator("[data-environment-form]");
  await form.evaluate((node: HTMLFormElement) => {
    node.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await expect(form).toHaveAttribute("data-create-submitting", "true");
  await expect(form.locator('[type="submit"]')).toHaveAttribute("aria-busy", "true");
  await expect(form.locator(".cw-submit-busy")).toBeVisible();
  expect(await form.evaluate((node: HTMLFormElement) => {
    let prevented = false;
    node.addEventListener("submit", (event) => { prevented = event.defaultPrevented; }, { once: true });
    node.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    return prevented;
  })).toBe(true);
  await page.evaluate(() => globalThis.dispatchEvent(new Event("pageshow")));
  await expect(form).not.toHaveAttribute("data-create-submitting");
  await expect(form.locator('[type="submit"]')).not.toHaveAttribute("aria-busy");
  await expect(form.locator(".cw-submit-idle")).toBeVisible();
});

test("viewing Create without changing anything never asks to discard", async ({ page }) => {
  await page.goto(fixtureUrl());
  // Look around: focus and leave fields, open help, browse image suggestions.
  await page.getByLabel("Name", { exact: true }).focus();
  await page.getByLabel("CPU", { exact: true }).focus();
  await page.getByRole("button", { name: "About automatic deletion", exact: true }).click();
  await page.keyboard.press("Escape");
  const image = page.getByRole("combobox", { name: "Workspace image", exact: true });
  await image.click();
  await expect(page.getByRole("listbox", { name: "Suggested images", exact: true })).toBeVisible();
  await image.press("Escape");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await expect(page.locator("dialog.cw-discard-dialog[open]")).toHaveCount(0);
  await expect(page.locator("[data-drawer]")).toBeHidden();
});

test("dirty Create Close keeps inputs and saved draft until explicit Discard", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Name", { exact: true }).fill("unsaved-name-canary");
  const form = page.locator("[data-environment-form]");
  const csrf = await form.locator('[name="_csrf"]').inputValue();
  await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(saved!).authored.name).toBe("unsaved-name-canary");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("unsaved-name-canary");
  await expect(form.locator('[name="_csrf"]')).toHaveValue(csrf);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  // Blur may legitimately refresh saved_at. Discard must remove this draft;
  // resetting the form must never trigger a new autosave.
  const beforeDiscard = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(beforeDiscard!).selections).toEqual(JSON.parse(saved!).selections);
  await prompt.getByRole("button", { name: "Discard draft", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(form.locator('[name="name"]')).toHaveValue("");
  await expect(form.locator('[name="_csrf"]')).toHaveValue(csrf);
  expect(await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()))).toBeNull();
});

test("dirty Create Close can save the draft and reopening Create restores it", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Name", { exact: true }).fill("kept-after-close");
  await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  // Closing is not a Settings detour, but the draft is already saved in this
  // tab: leaving keeps it unless the owner explicitly discards it.
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toContainText("Your draft is saved in this tab");
  await expect(prompt.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
  await expect(prompt.getByRole("button", { name: "Discard draft", exact: true })).toBeVisible();
  // All three choices stay inside the prompt at 1440 and 390.
  expect(await prompt.evaluate((dialog) => {
    const box = dialog.getBoundingClientRect();
    return Array.from(dialog.querySelectorAll("button:not([hidden])"), (button) => button.getBoundingClientRect())
      .every((choice) => choice.left >= box.left && choice.right <= box.right);
  })).toBe(true);
  await prompt.getByRole("button", { name: "Save draft and leave", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  const draft = JSON.parse(saved!) as Draft & { authored: { name: string } };
  expect(draft.authored.name).toBe("kept-after-close");
  expect(draft.selections.cpu).toBe("2000");
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: await restoredCard(page, draft) });
  });
  // Saving left a fresh form behind; the next Create opener fetches it and
  // the saved draft comes back by itself.
  await page.locator("[data-drawer-trigger]").click();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("kept-after-close");
  await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("2000");
});

test("Escape and Back from dirty Create offer the same save, discard and keep choices", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.locator("[data-drawer-trigger]").click();
  await page.getByLabel("Name", { exact: true }).fill("ask-to-save");
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  for (const leave of [() => page.keyboard.press("Escape"), () => page.evaluate(() => history.back())]) {
    await leave();
    await expect(prompt).toBeVisible();
    await expect(prompt.getByRole("button", { name: "Save draft and leave", exact: true })).toBeVisible();
    await expect(prompt.getByRole("button", { name: "Discard draft", exact: true })).toBeVisible();
    await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("ask-to-save");
    await expect(page).toHaveURL(fixtureUrl());
  }
  await page.evaluate(() => history.back());
  await prompt.getByRole("button", { name: "Save draft and leave", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(page).toHaveURL(fixtureUrl().replace("create-sandbox.html", "index.html"));
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(saved!).authored.name).toBe("ask-to-save");
});

test("dirty app-owned Create Back reconciles URL before Keep or explicit Discard", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.locator("[data-drawer-trigger]").click();
  await page.getByLabel("Name", { exact: true }).fill("keep-on-back");
  await page.evaluate(() => history.back());
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  await expect(page).toHaveURL(fixtureUrl());
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-on-back");
  await page.evaluate(() => history.back());
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Discard draft", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(page).toHaveURL(fixtureUrl().replace("create-sandbox.html", "index.html"));
});

test("Create status updates do not cancel an open Discard decision", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("keep-while-saving");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  // A deterministic late autosave status update, from the test only. The
  // form/controls are unchanged, unlike the stale-form HTMX regression.
  await page.locator("[data-create-draft-status]").evaluate((status) => {
    status.textContent = "Selections saved while awaiting a decision.";
  });
  await expect(prompt).toBeVisible();
  await expect(prompt.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-while-saving");
  await expect(page.locator("[data-drawer]")).toBeVisible();
});

test("structural Create edits are dirty without snapshots and the next opener fetches a fresh form", async ({ page }) => {
  await page.goto(fixtureUrl());
  const rows = page.locator("[data-repository-row]");
  const initial = await rows.count();
  await page.getByRole("button", { name: "Add custom Git URL", exact: true }).click();
  await expect(rows).toHaveCount(initial + 1);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Discard draft", exact: true }).click();
  await page.locator("[data-drawer-trigger]").click();
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await expect(rows).toHaveCount(initial);
});

test("Forward after structural Discard fetches a fresh authoritative Create form", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.locator("[data-drawer-trigger]").click();
  const rows = page.locator("[data-repository-row]");
  const initial = await rows.count();
  await page.getByRole("button", { name: "Add custom Git URL", exact: true }).click();
  await expect(rows).toHaveCount(initial + 1);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true }).getByRole("button", { name: "Discard draft", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await page.evaluate(() => history.forward());
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await expect(rows).toHaveCount(initial);
  await expect(page.locator("[data-drawer]")).not.toHaveAttribute("data-form-discarded", "true");
});

test("drawer Close does not intercept an already-submitted Create mutation", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("in-flight-create");
  // Durable controller-unit fixture: mark the same submit lifecycle without
  // dispatching a fabricated sandbox request from this static HTML fixture.
  await page.locator("[data-environment-form]").evaluate((form) => form.dispatchEvent(new Event("submit", { bubbles: true })));
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await expect(page.locator("dialog.cw-discard-dialog[open]")).toHaveCount(0);
  await expect(page.locator("[data-drawer]")).toBeHidden();
});

test("a Create trigger requiring a different server form still guards dirty navigation", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("keep-different-form");
  // Model the SSR exact-return URL, absent from this static fixture's router.
  // The existing canonical trigger now requires fresh navigation, not reuse.
  await page.locator("[data-drawer]").evaluate((drawer, id) => {
    drawer.setAttribute("data-create-url", `${location.pathname}?creation_draft=${id}`);
  }, draftId);
  await page.locator("[data-drawer-trigger]").dispatchEvent("click");
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-different-form");
  await expect(page).toHaveURL(fixtureUrl());
});

test("dirty Create setup navigation offers Keep or saved-draft navigation", async ({ page }) => {
  await page.goto(fixtureUrl());
  let creates = 0;
  page.on("request", (request) => { if (/PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) creates += 1; });
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Name", { exact: true }).fill("setup-private-canary");
  const link = page.locator("[data-github-setup-link]");
  const destination = new URL((await link.getAttribute("href"))!, page.url()).href;
  await link.click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page).toHaveURL(fixtureUrl());
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("setup-private-canary");
  await link.click();
  await prompt.getByRole("button", { name: "Save draft and leave", exact: true }).click();
  await expect(page).toHaveURL(destination);
  expect(new URL(page.url()).searchParams.get("creation_draft")).toBe(draftId);
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(saved!).selections.cpu).toBe("2000");
  expect(JSON.parse(saved!).authored.name).toBe("setup-private-canary");
  expect(creates).toBe(0);
});

test("Create setup navigation explains when a repository URL cannot be retained", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Repository URL", { exact: true }).fill("https://user:private-canary@git.example.test/team/repo.git");
  await page.locator("[data-github-setup-link]").click();
  const prompt = page.getByRole("dialog", { name: "Leave Create Sandbox?" });
  await expect(prompt).toContainText("You will need to re-enter that URL");
  await prompt.getByRole("button", { name: "Keep editing" }).click();
  await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("https://user:private-canary@git.example.test/team/repo.git");
  await page.locator("[data-github-setup-link]").click();
  await prompt.getByRole("button", { name: "Leave without repository URL" }).click();
  const bytes = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(bytes).not.toContain("private-canary");
});

test("Create setup navigation keeps the form open if its draft cannot be saved", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", { get() { throw new Error("synthetic storage refusal"); } }));
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("must-stay-here");
  await page.locator("[data-github-setup-link]").click();
  await expect(page).toHaveURL(fixtureUrl());
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("must-stay-here");
  await expect(page.getByRole("dialog", { name: "Leave Create Sandbox?" })).toHaveCount(0);
  await expect(page.locator("[data-create-draft-status]")).toContainText("draft cannot be saved");
});

test("native reload warns about dirty Create input and Cancel keeps the form", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("keep-on-reload");
  const warning = page.waitForEvent("dialog");
  const reload = page.reload({ timeout: 5000 }).catch((error) => error);
  const dialog = await warning;
  expect(dialog.type()).toBe("beforeunload");
  await dialog.dismiss();
  await reload;
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-on-reload");
});

test("secret settings fixture provides an explicit metadata-only Return link", async ({ page }) => {
  await page.goto(fixtureUrl().replace("create-sandbox.html", `application-secrets.html?creation_draft=${draftId}`));
  const returnLink = page.getByRole("link", { name: "Return to Sandbox creation", exact: true });
  await expect(returnLink).toBeVisible();
  await expect(returnLink).toHaveAttribute("href", `create-sandbox.html?creation_draft=${draftId}`);
  const marker = "synthetic-private-input-not-navigation";
  await page.getByLabel("Key", { exact: true }).fill("SYNTHETIC_KEY");
  await page.getByLabel("Value", { exact: true }).fill(marker);
  await expect(page.getByLabel("Value", { exact: true })).toHaveAttribute("type", "password");
  const destination = new URL(await returnLink.getAttribute("href") || "", page.url());
  expect([...destination.searchParams.entries()]).toEqual([["creation_draft", draftId]]);
  expect(destination.href).not.toContain(marker);
  // This fixture proves native presentation only. Real registered-route tests
  // own mutation/422/auth behavior; the later managed flow owns exact recovery.
});

// Controlled HTML response exercises only the browser controller. Rust DTO/
// route checks and managed journeys separately own authentication/catalog proof.
async function restoredCard(page: Page, draft: Draft): Promise<string> {
  return page.locator("#environment-create-card").evaluate((card, draft) => {
    const copy = card.cloneNode(true) as HTMLElement;
    // The server returns native markup; undo the browser's combobox enhancement.
    copy.querySelectorAll(".cw-combobox-list").forEach((list) => list.remove());
    copy.querySelectorAll<HTMLInputElement>("input[data-combobox-options]").forEach((input) => {
      input.setAttribute("list", input.dataset.comboboxOptions!);
      for (const name of ["data-combobox-options", "role", "aria-autocomplete", "aria-controls", "aria-expanded", "aria-activedescendant", "autocomplete"]) input.removeAttribute(name);
    });
    const form = copy.querySelector("form")!;
    // Server markup is never held by an automatic restore in progress.
    form.inert = false;
    form.removeAttribute("aria-busy");
    form.dataset.createDraftId = draft.draft;
    form.dataset.createDraftFresh = "false";
    form.dataset.createDraftRestored = "true";
    for (const name of ["cpu", "memory", "disk", "ttl", "secret_project", "credential_profile"] as const) {
      const field = form.elements.namedItem(name) as HTMLInputElement | HTMLSelectElement;
      const value = draft.selections[name];
      if (field instanceof HTMLSelectElement) {
        if (!Array.from(field.options).some((option) => option.value === value)) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = "Saved selection · unavailable until reviewed";
          field.append(option);
        }
        Array.from(field.options).forEach((option) => option.toggleAttribute("selected", option.value === value));
      } else field.setAttribute("value", value);
    }
    (form.querySelector('[name="include_org_secrets"]') as HTMLInputElement).toggleAttribute("checked", true);
    form.querySelector("[data-create-draft-status]")!.textContent = "Saved selections restored against current options. Review them before creating a Sandbox.";
    return copy.outerHTML;
  }, draft);
}

// The static fixture has no SSR query handler. Model only the server's closed
// explicit-return attributes; real route/auth/canonicalization proof belongs
// to the existing managed Create owner, not this controlled HTML response.
async function exactReturnFixture(page: Page, requestedId = draftId) {
  const url = fixtureUrl();
  await page.route(url, async (route) => {
    const response = await route.fetch();
    const html = (await response.text())
      .replace(`data-create-draft-id="${draftId}"`, `data-create-draft-id="${requestedId}"`)
      .replaceAll(`creation_draft=${draftId}`, `creation_draft=${requestedId}`)
      .replace('data-create-draft-exact="false"', 'data-create-draft-exact="true"');
    await route.fulfill({ response, body: html });
  });
  await page.goto(url);
}

test("Create setup links carry only the current draft handle and Edit links stay unchanged", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("name-never-navigation");
  await page.getByLabel("Repository URL", { exact: true }).fill("https://canary.invalid/private-repository");
  const links = page.locator('a[href*="settings-credentials.html"], a[href*="settings-secrets.html"], a[href*="application-secrets.html"]');
  await expect(links).not.toHaveCount(0);
  for (const link of await links.all()) {
    const href = await link.getAttribute("href");
    const target = new URL(href!, page.url());
    // Settings carries no organization; the draft handle is the only context.
    expect([...target.searchParams.entries()]).toEqual([["creation_draft", draftId]]);
    expect(href).not.toContain("name-never-navigation");
    expect(href).not.toContain("canary.invalid");
  }
  await page.goto(fixtureUrl().replace("create-sandbox.html", "edit-sandbox-sources.html"));
  const editLink = page.getByRole("link", { name: "Manage personal credentials and profiles" });
  await expect(editLink).toHaveAttribute("href", "settings-credentials.html");
});

test("explicit return restores the requested older draft by itself, never the newer draft", async ({ page }) => {
  const requested = { ...selectionsDraft(), saved_at: Date.now() - 1000 };
  const newer = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000004", saved_at: Date.now() - 100 };
  newer.selections.cpu = "1000";
  await page.addInitScript((records) => records.forEach(({ key, bytes }) => sessionStorage.setItem(key, bytes)),
    [requested, newer].map((draft) => ({ key: keyForDraft(draft), bytes: JSON.stringify(draft) })));
  let restores = 0;
  const creates: string[] = [];
  page.on("request", (request) => { if (/PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) creates.push(request.url()); });
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    restores += 1;
    const body = new URLSearchParams(route.request().postData()!);
    expect(body.get("creation_draft")).toBe(requested.draft);
    expect(JSON.parse(body.get("metadata")!).selections.cpu).toBe("2000");
    await route.fulfill({ status: 200, contentType: "text/html", body: await restoredCard(page, requested) });
  });
  await exactReturnFixture(page);
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
  expect(restores).toBe(1);
  expect(creates).toEqual([]);
});

for (const unavailable of ["missing", "future timestamp", "foreign actor", "foreign organization", "unavailable marker"] as const) {
  test(`explicit ${unavailable} return does not substitute another saved draft`, async ({ page }) => {
    const requested = { ...selectionsDraft(), saved_at: Date.now() - 1000 };
    if (unavailable === "future timestamp") requested.saved_at = Date.now() + 30 * 60 * 1000;
    if (unavailable === "foreign actor") requested.actor = "22222222222240008000000000000002";
    if (unavailable === "foreign organization") requested.organization = "00000000-0000-4000-8000-000000000005";
    const newer = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000004", saved_at: Date.now() - 100 };
    const records = unavailable === "missing" ? [newer] : [requested, newer];
    await page.addInitScript((records) => records.forEach(({ key, bytes }) => sessionStorage.setItem(key, bytes)),
      records.map((draft) => ({ key: keyForDraft(draft), bytes: JSON.stringify(draft) })));
    let mutations = 0;
    page.on("request", (request) => { if (/\/_fragments\/create-draft|PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) mutations += 1; });
    await exactReturnFixture(page, unavailable === "unavailable marker" ? "00000000-0000-4000-8000-000000000006" : draftId);
    await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeHidden();
    await expect(page.locator("[data-create-draft-status]")).toContainText("requested draft is unavailable");
    await expect(page.locator('[name="cpu"]')).toHaveValue("1000");
    await page.getByLabel("Name", { exact: true }).fill("still-editable");
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
    expect(mutations).toBe(0);
  });
}

test("explicit return with unavailable storage keeps a usable native form", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", { get() { throw new Error("synthetic storage refusal"); } }));
  await exactReturnFixture(page);
  await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeHidden();
  await expect(page.locator("[data-create-draft-status]")).toContainText("draft cannot be saved");
  await page.getByLabel("Name", { exact: true }).fill("still-editable");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
});

test("Create drafts save bounded authored fields and restore them after reload", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Memory", { exact: true }).selectOption("4096");
  await page.getByLabel("Disk", { exact: true }).selectOption("20");
  await page.getByLabel("Delete after").fill("8h");
  await page.getByLabel("Name", { exact: true }).fill("saved-name-canary");
  await page.getByLabel("Repository URL", { exact: true }).fill("https://canary.invalid/private-repository");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Internal port", { exact: true }).fill("3000");
  await page.getByLabel("Preview label", { exact: true }).fill("saved-label");
  await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
  const bytes = await page.evaluate((prefix) => {
    const key = Object.keys(sessionStorage).find((key) => key.startsWith(prefix));
    return key ? sessionStorage.getItem(key)! : "";
  }, draftPrefix);
  expect(Buffer.byteLength(bytes)).toBeLessThanOrEqual(512 * 1024);
  expect(bytes).not.toContain("synthetic-csrf");
  expect(JSON.parse(bytes).selections.ports).toEqual([{ port: "3000", access: "creator" }]);
  expect(JSON.parse(bytes).authored).toMatchObject({
    name: "saved-name-canary", repositories: [{ url: "https://canary.invalid/private-repository", branch: "main", mount: "codewire" }], port_rows: [{ port: "3000", label: "saved-label", access: "creator" }],
  });
  const draft = JSON.parse(bytes) as Draft;
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", body: await restoredCard(page, draft) });
  });
  // Reloading brings the authored values back without any action.
  await page.reload();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("2000");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("saved-name-canary");
  await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("https://canary.invalid/private-repository");
  await expect(page.getByLabel("Preview label", { exact: true })).toHaveValue("saved-label");
  // The restored form keeps the styled image suggestions.
  await page.getByRole("combobox", { name: "Workspace image", exact: true }).click();
  await expect(page.getByRole("listbox", { name: "Suggested images", exact: true })).toBeVisible();
});

test("Create drafts do not store credential-bearing repository URLs", async ({ page }) => {
  await page.goto(fixtureUrl());
  const field = page.getByLabel("Repository URL", { exact: true });
  for (const unsafe of [
    "https://user:private-canary@git.example.test/team/repo.git",
    "https://git.example.test/team/repo.git?token=private-canary",
    "https://git.example.test/team/repo.git#private-canary",
  ]) {
    await field.fill(unsafe);
    await expect(page.locator("[data-create-draft-status]")).toContainText("repository URL containing credentials or query data was not saved");
    const stored = await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key)!), keyForDraft(selectionsDraft()));
    expect(stored.authored.repositories[0].url).toBe("");
    expect(JSON.stringify(stored)).not.toContain("private-canary");
  }
  await field.fill("https://git.example.test/team/repo.git");
  await expect(page.locator("[data-create-draft-status]")).toHaveText("Draft saved in this tab.");
  const stored = await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key)!), keyForDraft(selectionsDraft()));
  expect(stored.authored.repositories[0].url).toBe("https://git.example.test/team/repo.git");
});

test("Create drafts are removed after account change and sign-out", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("account-bound-canary");
  const key = keyForDraft(selectionsDraft());
  await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
  expect(await page.evaluate((draftKey) => sessionStorage.getItem(draftKey), key)).not.toBeNull();
  await page.route(fixtureUrl(), async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace(`data-create-draft-actor="${actor}"`, 'data-create-draft-actor="22222222222240008000000000000002"');
    await route.fulfill({ response, body: html });
  });
  await page.reload();
  expect(await page.evaluate((draftKey) => sessionStorage.getItem(draftKey), key)).toBeNull();
  await page.getByLabel("Name", { exact: true }).fill("signout-canary");
  const secondKey = await page.locator("[data-environment-form]").getAttribute("data-create-draft-actor");
  const actorKey = `${draftPrefix}${secondKey}:${organization}:${draftId}`;
  expect(await page.evaluate((draftKey) => sessionStorage.getItem(draftKey), actorKey)).not.toBeNull();
  await page.goto(fixtureUrl().replace("create-sandbox.html", "settings-account.html"));
  await page.locator("form#sign-out").evaluate((form) => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  expect(await page.evaluate((draftKey) => sessionStorage.getItem(draftKey), actorKey)).toBeNull();
});

// Create lands on the new Sandbox's page; the Sandboxes list stays a valid
// landing. Both load dashboard.js, which owns the acknowledgment cleanup.
for (const landing of ["/fixture-org/", "/fixture-org/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/"]) {
  test(`acknowledged Sandbox creation removes only the submitted draft on ${landing}`, async ({ page }) => {
    await page.goto(fixtureUrl());
    await page.getByLabel("Name", { exact: true }).fill("created-canary");
    const key = keyForDraft(selectionsDraft());
    const unrelated = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000004" };
    await page.evaluate(({ otherKey, bytes }) => sessionStorage.setItem(otherKey, bytes), { otherKey: keyForDraft(unrelated), bytes: JSON.stringify(unrelated) });
    await page.locator("[data-environment-form]").evaluate((form: HTMLFormElement) => {
      form.action = `${location.origin}/fixture-org/_actions/sandboxes/create`;
      form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    });
    const acknowledged = `${landing}?message=environment-created`;
    await page.route(`**${acknowledged}`, (route) => route.fulfill({
      status: 200, contentType: "text/html", body: '<!doctype html><html><head><script defer src="/dashboard.js"></script></head><body><main>Sandbox creation started.</main></body></html>',
    }));
    await page.goto(new URL(acknowledged, fixtureUrl()).href);
    await expect.poll(() => page.evaluate((draftKey) => sessionStorage.getItem(draftKey), key)).toBeNull();
    expect(await page.evaluate((draftKey) => sessionStorage.getItem(draftKey), keyForDraft(unrelated))).not.toBeNull();
  });
}

test("Create recovery restores authored values only after current selections are checked", async ({ page }) => {
  const draft = {
    ...selectionsDraft(),
    authored: {
      name: "saved-sandbox", image: "registry.example.test/workspace:stable",
      install_command: "bun install", startup_script: "bun run dev",
      repositories: [{ url: "https://git.example.test/team/repository.git", branch: "feature", mount: "repository" }],
      port_rows: [{ port: "", label: "web", access: "creator" }], ttl: "not-a-duration",
    },
  };
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  await page.goto(fixtureUrl());
  const html = await restoredCard(page, draft);
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    const body = new URLSearchParams(route.request().postData()!);
    const metadata = JSON.parse(body.get("metadata")!);
    expect(metadata.authored).toBeUndefined();
    expect(metadata.selections.credential_profile).toBe(profile);
    expect(metadata.selections.ports).toEqual([]);
    await route.fulfill({ status: 200, contentType: "text/html", body: html });
  });
  await page.getByRole("button", { name: "Restore saved draft" }).click();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("saved-sandbox");
  await expect(page.getByLabel("Workspace image")).toHaveValue("registry.example.test/workspace:stable");
  await expect(page.getByLabel("Repository URL")).toHaveValue("https://git.example.test/team/repository.git");
  await expect(page.getByLabel("Branch", { exact: true })).toHaveValue("feature");
  await expect(page.getByLabel("Mount path", { exact: true })).toHaveValue("repository");
  await expect(page.getByLabel("Delete after")).toHaveValue("not-a-duration");
  await expect(page.getByLabel("Internal port")).toHaveValue("");
  await expect(page.getByLabel("Preview label")).toHaveValue("web");
  await page.locator("[data-create-runtime] summary").click();
  await expect(page.getByLabel("Install Command")).toHaveValue("bun install");
  await expect(page.getByLabel("Startup Script")).toHaveValue("bun run dev");
});

test("restored repositories set each GitHub row's Add or Remove", async ({ page }) => {
  const draft = {
    ...selectionsDraft(),
    authored: {
      name: "restored-repositories", image: "", install_command: "", startup_script: "",
      repositories: [{ url: "https://github.com/codewiresh/docs.git", branch: "main", mount: "docs" }],
      port_rows: [], ttl: "",
    },
  };
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  await page.goto(fixtureUrl());
  const html = await restoredCard(page, draft);
  await page.route("**/fixture/_fragments/create-draft", (route) => route.fulfill({ status: 200, contentType: "text/html", body: html }));
  const browser = page.locator("[data-github-browser]");
  // Before the restore, the fixture's own row selects codewiresh/codewire.
  await expect(browser.locator('[data-repository-name="codewiresh/codewire"]')).toHaveAccessibleName("Remove codewiresh/codewire Private");
  await page.getByRole("button", { name: "Restore saved draft" }).click();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.getByLabel("Repository URL", { exact: true })).toHaveValue("https://github.com/codewiresh/docs.git");
  await expect(browser.locator('[data-repository-name="codewiresh/docs"]')).toHaveAccessibleName("Remove codewiresh/docs Public");
  await expect(browser.locator('[data-repository-name="codewiresh/codewire"]')).toHaveAccessibleName("Add codewiresh/codewire Private");
});

test("Create recovery keeps the restored preset lifetime when the draft left it to the default", async ({ page }) => {
  const saved = selectionsDraft();
  // Drafts saved before an empty field meant the default stored "infinity".
  const draft = {
    ...saved,
    selections: { ...saved.selections, ttl: "infinity" },
    authored: {
      name: "preset-lifetime", image: "registry.example.test/workspace:stable", install_command: "", startup_script: "",
      repositories: [], port_rows: [], ttl: "infinity",
    },
  };
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  await page.goto(fixtureUrl());
  // The server shows the restored preset's default lifetime for such a draft.
  const restored = 'name="ttl" value="7d" placeholder="7d"';
  const html = (await restoredCard(page, draft)).replace('name="ttl" value="infinity" placeholder="Not scheduled"', restored);
  expect(html).toContain(restored);
  await page.route("**/fixture/_fragments/create-draft", (route) => route.fulfill({ status: 200, contentType: "text/html", body: html }));
  await page.getByRole("button", { name: "Restore saved draft" }).click();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("preset-lifetime");
  await expect(page.getByLabel("Delete after")).toHaveValue("7d");
});

test("Create draft retains in-progress preview and lifetime text", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Delete after").fill("not-a-duration");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Preview label").fill("web");
  await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
  const stored = await page.evaluate((key) => JSON.parse(sessionStorage.getItem(key)!), keyForDraft(selectionsDraft()));
  expect(stored.authored.ttl).toBe("not-a-duration");
  expect(stored.authored.port_rows).toEqual([{ port: "", label: "web", access: "creator" }]);
  expect(stored.selections.ttl).toBe("");
  expect(stored.selections.ports).toEqual([]);
});

test("explicit Create recovery keeps exact large revision bytes and makes no Create dispatch", async ({ page }) => {
  const draft = selectionsDraft();
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  await page.goto(fixtureUrl());
  // Native selects without an explicit selected attribute default to their
  // first option; that is still a pristine, explicitly restorable form.
  await page.locator('[name="cpu"]').evaluate((select: HTMLSelectElement) => {
    Array.from(select.options).forEach((option) => option.removeAttribute("selected"));
    select.selectedIndex = 0;
  });
  const html = await restoredCard(page, draft);
  let restores = 0;
  const creates: string[] = [];
  page.on("request", (request) => { if (/PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) creates.push(request.url()); });
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    restores += 1;
    const body = new URLSearchParams(route.request().postData()!);
    expect(body.get("creation_draft")).toBe(draftId);
    expect(body.get("_csrf")).toBe("synthetic-csrf");
    expect(JSON.parse(body.get("metadata")!).selections.credential_profile).toBe(profile);
    await route.fulfill({ status: 200, contentType: "text/html", body: html });
  });
  await page.getByRole("button", { name: "Restore saved draft" }).click();
  await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "true");
  await expect(page.locator('[name="credential_profile"]')).toHaveValue(profile);
  await expect(page.locator('[name="credential_profile"] option:checked')).toBeEnabled();
  await expect(page.locator('[name="secret_project"]')).toHaveValue(draft.selections.secret_project);
  await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
  await expect(page.getByLabel("Name", { exact: true })).toBeFocused();
  expect(restores).toBe(1);
  expect(creates).toEqual([]);
});

for (const interruption of ["edit", "property edit", "close", "discard", "replacement"] as const) {
  test(`late Create recovery cannot overwrite after ${interruption}`, async ({ page }) => {
    const draft = selectionsDraft();
    await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
    await page.goto(fixtureUrl());
    const html = await restoredCard(page, draft);
    let release!: () => void;
    let announced!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const requested = new Promise<void>((resolve) => { announced = resolve; });
    let completed!: () => void;
    const finished = new Promise<void>((resolve) => { completed = resolve; });
    await page.route("**/fixture/_fragments/create-draft", async (route) => {
      announced();
      await held;
      await route.fulfill({ status: 200, contentType: "text/html", body: html }).catch(() => {});
      completed();
    });
    try {
      await page.getByRole("button", { name: "Restore saved draft" }).click();
      await requested;
      if (interruption === "edit") await page.getByLabel("Name", { exact: true }).fill("keep-this-input");
      else if (interruption === "property edit") await page.getByLabel("Name", { exact: true }).evaluate((input: HTMLInputElement) => { input.value = "keep-this-input"; });
      else if (interruption === "close") {
        await page.getByRole("link", { name: "Close Create Sandbox" }).click();
        await page.locator("[data-drawer-trigger]").first().click();
      }
      else if (interruption === "discard") {
        // A property-only edit does not invalidate Restore through input/change.
        // Discard must fence it before resetting the DOM back to pristine.
        await page.getByLabel("Name", { exact: true }).evaluate((input: HTMLInputElement) => { input.value = "discard-pending-restore"; });
        await page.getByRole("link", { name: "Close Create Sandbox" }).click();
        await page.getByRole("dialog", { name: "Leave Create Sandbox?", exact: true }).getByRole("button", { name: "Discard draft", exact: true }).click();
        await expect(page.locator("[data-drawer]")).toBeHidden();
        await expect(page.locator('[name="name"]')).toHaveValue("");
      }
      else await page.locator("#environment-create-card").evaluate((card) => card.replaceWith(card.cloneNode(true)));
    } finally { release(); }
    await finished;
    if (interruption === "property edit" || interruption === "close") {
      await expect(page.locator("[data-create-draft-status]")).not.toContainText("Checking current options");
    }
    if (interruption === "property edit") await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeDisabled();
    await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "false");
    if (interruption === "edit" || interruption === "property edit") await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-this-input");
  });
}

test("Create recovery rejects invalid entries and preserves valid history across organizations", async ({ page }) => {
  const url = fixtureUrl();
  await page.goto(url);
  const drafts = Array.from({ length: 7 }, (_, index) => ({ ...selectionsDraft(), saved_at: Date.now() - index, draft: `00000000-0000-4000-8000-${String(index + 10).padStart(12, "0")}`, organization: index % 2 ? "00000000-0000-4000-8000-000000000004" : organization }));
  await page.evaluate(({ drafts, prefix }) => {
    drafts.forEach((draft) => sessionStorage.setItem(`${prefix}${draft.actor}:${draft.organization}:${draft.draft}`, JSON.stringify(draft)));
  }, { drafts, prefix: draftPrefix });
  await page.reload();
  expect(await page.evaluate((prefix) => Object.keys(sessionStorage).filter((key) => key.startsWith(prefix)).length, draftPrefix)).toBe(7);
  for (const invalid of ["malformed", "future", "oversize", "unknown field", "revision alias", "stored credential URL"] as const) {
    const draft = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000009" };
    let bytes = JSON.stringify(draft);
    if (invalid === "malformed") bytes = "not-json";
    if (invalid === "future") bytes = JSON.stringify({ ...draft, saved_at: Date.now() + 30 * 60 * 1000 });
    if (invalid === "oversize") bytes = " ".repeat(512 * 1024 + 1);
    if (invalid === "unknown field") bytes = JSON.stringify({ ...draft, password: "private-canary" });
    if (invalid === "revision alias") bytes = JSON.stringify({ ...draft, selections: { ...draft.selections, credential_profile: "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@0007" } });
    if (invalid === "stored credential URL") bytes = JSON.stringify({ ...draft, authored: {
      name: "stored-canary", image: "", install_command: "", startup_script: "",
      repositories: [{ url: "https://user:private-canary@git.example.test/team/repo.git", branch: "", mount: "" }],
      port_rows: [], ttl: "",
    } });
    await page.evaluate(({ key, bytes, prefix }) => {
      sessionStorage.setItem(key, bytes);
    }, { key: keyForDraft(draft), bytes, prefix: draftPrefix });
    await page.reload();
    expect(await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(draft))).toBeNull();
    expect(await page.evaluate((prefix) => Object.keys(sessionStorage).filter((key) => key.startsWith(prefix)).length, draftPrefix)).toBe(7);
    await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeVisible();
  }
});

test("unavailable draft storage leaves the native Create form usable", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", { get() { throw new Error("synthetic storage refusal"); } }));
  await page.goto(fixtureUrl());
  await expect(page.locator("[data-create-draft-status]")).toContainText("draft cannot be saved");
  await page.getByLabel("Name", { exact: true }).fill("still-editable");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
  await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeHidden();
});

test("automatic restore holds the form, gives it back on failure, and never runs for a rejected form", async ({ page }) => {
  const draft = selectionsDraft();
  const url = fixtureUrl();
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  let restores = 0;
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    restores += 1;
    await held;
    await route.fulfill({ status: 500, contentType: "text/html", body: "<p>rejected</p>" });
  });
  await page.goto(url);
  const form = page.locator("[data-environment-form]");
  // While the saved draft is restored, an early keystroke cannot replace it.
  await expect(form).toHaveJSProperty("inert", true);
  await expect(form).toHaveAttribute("aria-busy", "true");
  release();
  await expect(form).toHaveJSProperty("inert", false);
  await expect(page.locator("[data-create-draft-status]")).toContainText("could not be restored");
  await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeEnabled();
  await page.getByLabel("Name", { exact: true }).fill("keep-current-edits");
  await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeDisabled();
  expect(restores).toBe(1);
  await page.route("**/reference/fixtures/create-sandbox.html", async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace('data-create-draft-fresh="true"', 'data-create-draft-fresh="false"');
    await route.fulfill({ response, body: html });
  });
  await page.reload();
  await expect(page.getByRole("button", { name: "Restore saved draft" })).toBeHidden();
  expect(restores).toBe(1);
});
