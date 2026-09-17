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
const actor = "00000000-0000-4000-8000-000000000001";
const organization = "00000000-0000-4000-8000-000000000002";
const draftId = "00000000-0000-4000-8000-000000000003";
const profile = "315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@9007199254740993";
const selectionsDraft = () => ({
  version: 1, actor, organization, draft: draftId, saved_at: Date.now(),
  selections: {
    preset_id: "", cpu: "2000", memory: "4096", disk: "20", ttl: "8h",
    isolation_tier: "standard", agents: [] as string[], ports: [] as { port: string; access: string }[],
    secret_project: "6bf8d155-e84c-4fc5-b479-b17022fe41dd", credential_profile: profile,
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

for (const interruption of ["edit", "property edit", "close", "replacement"] as const) {
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
