import { expect, test, type Page } from "@playwright/test";

// Native form/disclosure proof only; not real auth or managed-Sandbox proof.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

test("creation keeps sources visible and closed advanced fields remain native form values", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native creation fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const resources = page.locator("[data-create-resources]");
  const runtime = page.locator("[data-create-runtime]");
  await expect(resources).not.toHaveAttribute("open", "");
  await expect(runtime).not.toHaveAttribute("open", "");
  await expect(page.getByLabel("CPU", { exact: true })).toBeHidden();
  await expect(page.getByLabel("Install Command", { exact: true })).toBeHidden();
  await expect(page.getByRole("heading", { name: "Repositories", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Application secrets", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Provider credentials", exact: true })).toBeVisible();
  await expect(page.locator(".cw-snapshot-stub, .cw-snapshot-meter")).toHaveCount(0);
  await resources.locator("summary").click();
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Memory", { exact: true }).selectOption("4096");
  await page.getByLabel("Disk", { exact: true }).selectOption("20");
  await expect(page.getByLabel("CPU", { exact: true }).locator("option:checked")).toHaveText("2 vCPU");
  await expect(page.getByLabel("Memory", { exact: true }).locator("option:checked")).toHaveText("4 GiB");
  await expect(page.getByLabel("TTL")).toHaveAccessibleDescription(/automatic deletion.*not an idle timeout/);
  await resources.locator("summary").click();
  await runtime.locator("summary").click();
  await page.getByLabel("Install Command", { exact: true }).fill("bun install");
  await page.getByLabel("Startup Script", { exact: true }).fill("bun run dev");
  await runtime.locator("summary").click();
  const fields = await page.locator("[data-environment-form]").evaluate((form: HTMLFormElement) => {
    const data = new FormData(form);
    return Object.fromEntries(["cpu", "memory", "disk", "ttl", "install_command", "startup_script"].map((name) => [name, data.get(name)]));
  });
  expect(fields).toEqual({ cpu: "2000", memory: "4096", disk: "20", ttl: "infinity", install_command: "bun install", startup_script: "bun run dev" });
});

const draftPrefix = "codewire.create-selections.v1:";
const actor = "11111111111140008000000000000001";
const organization = "00000000-0000-4000-8000-000000000002";
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

test("dirty Create Close keeps inputs and authority until explicit Discard, without overwriting saved selections", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.locator("[data-create-resources] summary").click();
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Name", { exact: true }).fill("unsaved-name-canary");
  const form = page.locator("[data-environment-form]");
  const csrf = await form.locator('[name="_csrf"]').inputValue();
  await expect(page.locator("[data-create-draft-status]")).toContainText("Selections saved");
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(saved).not.toContain("unsaved-name-canary");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("unsaved-name-canary");
  await expect(form.locator('[name="_csrf"]')).toHaveValue(csrf);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  // Blur may legitimately refresh saved_at. Discard itself must change neither
  // the saved metadata nor selections; reset must never trigger autosave.
  const beforeDiscard = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(beforeDiscard!).selections).toEqual(JSON.parse(saved!).selections);
  await prompt.getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(form.locator('[name="name"]')).toHaveValue("");
  await expect(form.locator('[name="_csrf"]')).toHaveValue(csrf);
  expect(await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()))).toBe(beforeDiscard);
});

test("dirty app-owned Create Back reconciles URL before Keep or explicit Discard", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.locator("[data-drawer-trigger]").click();
  await page.getByLabel("Name", { exact: true }).fill("keep-on-back");
  await page.evaluate(() => history.back());
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt).toBeVisible();
  await expect(page).toHaveURL(fixtureUrl());
  await expect(page.locator("[data-drawer]")).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-on-back");
  await page.evaluate(() => history.back());
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page.locator("[data-drawer]")).toBeHidden();
  await expect(page).toHaveURL(fixtureUrl().replace("create-sandbox.html", "index.html"));
});

test("Create status updates do not cancel an open Discard decision", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.getByLabel("Name", { exact: true }).fill("keep-while-saving");
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
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
  await page.getByRole("button", { name: "Custom Git URL", exact: true }).click();
  await expect(rows).toHaveCount(initial + 1);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Discard changes", exact: true }).click();
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
  await page.getByRole("button", { name: "Custom Git URL", exact: true }).click();
  await expect(rows).toHaveCount(initial + 1);
  await page.getByRole("link", { name: "Close Create Sandbox", exact: true }).click();
  await page.getByRole("dialog", { name: "Discard changes?", exact: true }).getByRole("button", { name: "Discard changes", exact: true }).click();
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
  await expect(page.getByRole("dialog", { name: "Discard changes?", exact: true })).toBeHidden();
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
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-different-form");
  await expect(page).toHaveURL(fixtureUrl());
});

test("dirty Create setup navigation offers Keep and Discard while preserving the exact saved draft", async ({ page }) => {
  await page.goto(fixtureUrl());
  let creates = 0;
  page.on("request", (request) => { if (/PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) creates += 1; });
  await page.locator("[data-create-resources] summary").click();
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Name", { exact: true }).fill("setup-private-canary");
  const link = page.getByRole("link", { name: "Connect GitHub", exact: true });
  const destination = new URL((await link.getAttribute("href"))!, page.url()).href;
  await link.click();
  const prompt = page.getByRole("dialog", { name: "Discard changes?", exact: true });
  await expect(prompt).toBeVisible();
  await prompt.getByRole("button", { name: "Keep editing", exact: true }).click();
  await expect(page).toHaveURL(fixtureUrl());
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("setup-private-canary");
  await link.click();
  await prompt.getByRole("button", { name: "Discard changes", exact: true }).click();
  await expect(page).toHaveURL(destination);
  expect(new URL(page.url()).searchParams.get("creation_draft")).toBe(draftId);
  const saved = await page.evaluate((key) => sessionStorage.getItem(key), keyForDraft(selectionsDraft()));
  expect(JSON.parse(saved!).selections.cpu).toBe("2000");
  expect(saved).not.toContain("setup-private-canary");
  expect(creates).toBe(0);
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
    const form = copy.querySelector("form")!;
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
  await expect(links).toHaveCount(6);
  for (const link of await links.all()) {
    const href = await link.getAttribute("href");
    const target = new URL(href!, page.url());
    expect([...target.searchParams.entries()]).toEqual(target.pathname.endsWith("/settings-secrets.html")
      ? [["org", "fixture-org"], ["creation_draft", draftId]]
      : [["creation_draft", draftId]]);
    expect(href).not.toContain("name-never-navigation");
    expect(href).not.toContain("canary.invalid");
  }
  await page.goto(fixtureUrl().replace("create-sandbox.html", "edit-sandbox-sources.html"));
  const editLink = page.getByRole("link", { name: "Manage personal credentials and profiles" });
  await expect(editLink).toHaveAttribute("href", "settings-credentials.html");
});

test("explicit return offers the requested older draft, never the newer draft", async ({ page }) => {
  const requested = { ...selectionsDraft(), saved_at: Date.now() - 1000 };
  const newer = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000004", saved_at: Date.now() - 100 };
  newer.selections.cpu = "1000";
  await page.addInitScript((records) => records.forEach(({ key, bytes }) => sessionStorage.setItem(key, bytes)),
    [requested, newer].map((draft) => ({ key: keyForDraft(draft), bytes: JSON.stringify(draft) })));
  let restores = 0;
  const creates: string[] = [];
  page.on("request", (request) => { if (/PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) creates.push(request.url()); });
  await exactReturnFixture(page);
  await expect(page.locator('[name="cpu"]')).toHaveValue("1000");
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeVisible();
  const html = await restoredCard(page, requested);
  await page.route("**/fixture/_fragments/create-draft", async (route) => {
    restores += 1;
    const body = new URLSearchParams(route.request().postData()!);
    expect(body.get("creation_draft")).toBe(requested.draft);
    expect(JSON.parse(body.get("metadata")!).selections.cpu).toBe("2000");
    await route.fulfill({ status: 200, contentType: "text/html", body: html });
  });
  expect(restores).toBe(0);
  await page.getByRole("button", { name: "Restore saved selections" }).click();
  await expect(page.locator('[name="cpu"]')).toHaveValue("2000");
  expect(restores).toBe(1);
  expect(creates).toEqual([]);
});

for (const unavailable of ["missing", "expired", "foreign actor", "foreign organization", "unavailable marker"] as const) {
  test(`explicit ${unavailable} return does not substitute another saved draft`, async ({ page }) => {
    const requested = { ...selectionsDraft(), saved_at: Date.now() - 1000 };
    if (unavailable === "expired") requested.saved_at = Date.now() - 30 * 60 * 1000;
    if (unavailable === "foreign actor") requested.actor = "22222222222240008000000000000002";
    if (unavailable === "foreign organization") requested.organization = "00000000-0000-4000-8000-000000000005";
    const newer = { ...selectionsDraft(), draft: "00000000-0000-4000-8000-000000000004", saved_at: Date.now() - 100 };
    const records = unavailable === "missing" ? [newer] : [requested, newer];
    await page.addInitScript((records) => records.forEach(({ key, bytes }) => sessionStorage.setItem(key, bytes)),
      records.map((draft) => ({ key: keyForDraft(draft), bytes: JSON.stringify(draft) })));
    let mutations = 0;
    page.on("request", (request) => { if (/\/_fragments\/create-draft|PrepareEnvironment|\/_actions\/sandboxes\/create/.test(request.url())) mutations += 1; });
    await exactReturnFixture(page, unavailable === "unavailable marker" ? "00000000-0000-4000-8000-000000000006" : draftId);
    await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeHidden();
    await expect(page.locator("[data-create-draft-status]")).toContainText("requested saved selections are unavailable");
    await expect(page.locator('[name="cpu"]')).toHaveValue("1000");
    await page.getByLabel("Name", { exact: true }).fill("still-editable");
    await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
    expect(mutations).toBe(0);
  });
}

test("explicit return with unavailable storage keeps a usable native form", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", { get() { throw new Error("synthetic storage refusal"); } }));
  await exactReturnFixture(page);
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeHidden();
  await expect(page.locator("[data-create-draft-status]")).toContainText("Selections cannot be saved");
  await page.getByLabel("Name", { exact: true }).fill("still-editable");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
});

test("Create drafts save only bounded selections and offer explicit recovery after reload", async ({ page }) => {
  await page.goto(fixtureUrl());
  await page.locator("[data-create-resources] summary").click();
  await page.getByLabel("CPU", { exact: true }).selectOption("2000");
  await page.getByLabel("Memory", { exact: true }).selectOption("4096");
  await page.getByLabel("Disk", { exact: true }).selectOption("20");
  await page.getByLabel("TTL").fill("8h");
  await page.getByLabel("Name", { exact: true }).fill("never-save-name-canary");
  await page.getByLabel("Repository URL", { exact: true }).fill("https://canary.invalid/private-repository");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await page.getByLabel("Internal port", { exact: true }).fill("3000");
  await page.getByLabel("Preview label", { exact: true }).fill("never-save-label");
  await expect(page.locator("[data-create-draft-status]")).toContainText("Selections saved");
  const bytes = await page.evaluate((prefix) => {
    const key = Object.keys(sessionStorage).find((key) => key.startsWith(prefix));
    return key ? sessionStorage.getItem(key)! : "";
  }, draftPrefix);
  expect(Buffer.byteLength(bytes)).toBeLessThanOrEqual(8192);
  for (const forbidden of ["never-save-name-canary", "canary.invalid", "never-save-label", "synthetic-csrf", "repo_url", "install_command", "startup_script"]) expect(bytes).not.toContain(forbidden);
  expect(JSON.parse(bytes).selections.ports).toEqual([{ port: "3000", access: "creator" }]);
  await page.reload();
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeVisible();
  await page.locator("[data-create-resources] summary").click();
  await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("1000");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("");
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
  await page.getByRole("button", { name: "Restore saved selections" }).click();
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
      await page.getByRole("button", { name: "Restore saved selections" }).click();
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
        await page.getByRole("dialog", { name: "Discard changes?", exact: true }).getByRole("button", { name: "Discard changes", exact: true }).click();
        await expect(page.locator("[data-drawer]")).toBeHidden();
        await expect(page.locator('[name="name"]')).toHaveValue("");
      }
      else await page.locator("#environment-create-card").evaluate((card) => card.replaceWith(card.cloneNode(true)));
    } finally { release(); }
    await finished;
    if (interruption === "property edit" || interruption === "close") {
      await expect(page.locator("[data-create-draft-status]")).not.toContainText("Checking current options");
    }
    if (interruption === "property edit") await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeDisabled();
    await expect(page.locator("[data-environment-form]")).toHaveAttribute("data-create-draft-restored", "false");
    if (interruption === "edit" || interruption === "property edit") await expect(page.getByLabel("Name", { exact: true })).toHaveValue("keep-this-input");
  });
}

test("Create recovery expires invalid entries and bounds history across organizations", async ({ page }) => {
  const url = fixtureUrl();
  await page.goto(url);
  const drafts = Array.from({ length: 7 }, (_, index) => ({ ...selectionsDraft(), saved_at: Date.now() - index, draft: `00000000-0000-4000-8000-${String(index + 10).padStart(12, "0")}`, organization: index % 2 ? "00000000-0000-4000-8000-000000000004" : organization }));
  await page.evaluate(({ drafts, prefix }) => {
    drafts.forEach((draft) => sessionStorage.setItem(`${prefix}${draft.actor}:${draft.organization}:${draft.draft}`, JSON.stringify(draft)));
  }, { drafts, prefix: draftPrefix });
  await page.reload();
  expect(await page.evaluate((prefix) => Object.keys(sessionStorage).filter((key) => key.startsWith(prefix)).length, draftPrefix)).toBe(5);
  for (const invalid of ["malformed", "expired", "oversize", "unknown field", "revision alias"] as const) {
    const draft = selectionsDraft();
    let bytes = JSON.stringify(draft);
    if (invalid === "malformed") bytes = "not-json";
    if (invalid === "expired") bytes = JSON.stringify({ ...draft, saved_at: Date.now() - 30 * 60 * 1000 });
    if (invalid === "oversize") bytes = " ".repeat(8193);
    if (invalid === "unknown field") bytes = JSON.stringify({ ...draft, password: "private-canary" });
    if (invalid === "revision alias") bytes = JSON.stringify({ ...draft, selections: { ...draft.selections, credential_profile: "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@0007" } });
    await page.evaluate(({ key, bytes, prefix }) => {
      Object.keys(sessionStorage).filter((key) => key.startsWith(prefix)).forEach((key) => sessionStorage.removeItem(key));
      sessionStorage.setItem(key, bytes);
    }, { key: keyForDraft(draft), bytes, prefix: draftPrefix });
    await page.reload();
    await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeHidden();
    expect(await page.evaluate((prefix) => Object.keys(sessionStorage).filter((key) => key.startsWith(prefix)).length, draftPrefix)).toBe(0);
  }
});

test("unavailable draft storage leaves the native Create form usable", async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, "sessionStorage", { get() { throw new Error("synthetic storage refusal"); } }));
  await page.goto(fixtureUrl());
  await expect(page.locator("[data-create-draft-status]")).toContainText("Selections cannot be saved");
  await page.getByLabel("Name", { exact: true }).fill("still-editable");
  await expect(page.getByLabel("Name", { exact: true })).toHaveValue("still-editable");
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeHidden();
});

test("edited and server-rejected Create forms do not offer usable restoration", async ({ page }) => {
  const draft = selectionsDraft();
  const url = fixtureUrl();
  await page.addInitScript(({ key, bytes }) => sessionStorage.setItem(key, bytes), { key: keyForDraft(draft), bytes: JSON.stringify(draft) });
  let restores = 0;
  page.on("request", (request) => { if (request.url().endsWith("/_fragments/create-draft")) restores += 1; });
  await page.goto(url);
  await page.getByLabel("Name", { exact: true }).fill("keep-current-edits");
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeDisabled();
  await page.route("**/reference/fixtures/create-sandbox.html", async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace('data-create-draft-fresh="true"', 'data-create-draft-fresh="false"');
    await route.fulfill({ response, body: html });
  });
  await page.reload();
  await expect(page.getByRole("button", { name: "Restore saved selections" })).toBeHidden();
  expect(restores).toBe(0);
});
