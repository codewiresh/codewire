// covers: src/credentials_connect.rs src/environment_sources.rs src/routes/credentials.rs
// covers: src/routes/environments.rs src/routes/github_repositories.rs
// covers: templates/environment-create-form.html templates/environment-source-fields.html
// covers: templates/github-repositories.html templates/organization-environments-content.html
// covers: templates/organization-environments.html templates/settings-credentials.html
import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import {
  bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser,
} from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

test.use({ storageState: { cookies: [], origins: [] } });

// Real app + existing synthetic account/session helpers. Provider discovery and
// checkout are deliberately not claimed by this empty-account browser check.
test("GitHub picker on a fresh account offers setup, preserves the draft and enforces BFF request authority", async ({ page }) => {
  const id = randomUUID();
  const email = `e2e-github-picker-${id}@codewire.sh`;
  const slug = `github-picker-${id.replaceAll("-", "")}`;
  await seedSyntheticUser(email, "GitHub picker browser check");
  try {
    await bypassTwoFactor(email);
    const owner = await getUserId(email);
    if (!owner) throw new Error("Synthetic picker owner was not created");
    await ensureTestOrg("GitHub picker browser check", slug, owner);
    const session = await createAuthenticatedSession(email);
    await page.context().addCookies([{
      name: "codewire.session_token", value: session.token, url: ssrUrl,
      httpOnly: true, sameSite: "Lax",
    }]);
    const settingsBeforeCreate = await page.goto(`/settings/credentials/?org=${slug}`);
    expect(settingsBeforeCreate?.status()).toBe(200);
    let releaseOptions!: () => void;
    const delayedOptions = new Promise<void>((resolve) => { releaseOptions = resolve; });
    await page.route(`**/${slug}/_fragments/create-options`, async (route) => {
      await delayedOptions;
      await route.continue();
    });
    const createLink = page.getByRole("link", { name: "Create Sandbox", exact: true }).first();
    if (!(await createLink.isVisible())) {
      await page.getByRole("button", { name: "Toggle sidebar" }).click();
    }
    await createLink.click();
    await expect(page).toHaveURL(new RegExp(`/${slug}/new/`));
    const createForm = page.locator("[data-environment-form]");
    await expect(createForm).toBeVisible();
    await expect(createForm).toHaveAttribute("data-create-options-loading", "true");
    await page.getByRole("textbox", { name: "Name", exact: true }).fill("my-new-sandbox");
    await page.getByLabel("Workspace image").fill("registry.example.test/custom:stable");
    const optionsResponse = page.waitForResponse((response) => response.url().endsWith(`/${slug}/_fragments/create-options`));
    releaseOptions();
    expect((await optionsResponse).status()).toBe(200);
    await expect(createForm).toHaveAttribute("data-create-options-loading", "false");
    await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("my-new-sandbox");
    await expect(page.getByLabel("Workspace image")).toHaveValue("registry.example.test/custom:stable");
    await page.unroute(`**/${slug}/_fragments/create-options`);
    const browser = page.locator("[data-github-browser]");
    await expect(browser).toBeVisible();
    // The account's one GitHub connection does not exist yet; assert the
    // state, not its wording.
    await expect(browser).toHaveAttribute("data-github-state", "not-configured");
    const draft = await page.locator("[data-environment-form]").getAttribute("data-create-draft-id");
    await expect(browser.getByRole("link", { name: "Connect GitHub" }))
      .toHaveAttribute("href", `/settings/credentials/?creation_draft=${draft}`);
    await expect(browser.getByRole("searchbox", { name: "Find a repository" })).toBeDisabled();
    await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("my-new-sandbox");

    const form = page.locator("[data-environment-form]");
    const csrf = await form.locator('[name="_csrf"]').inputValue();
    const endpoint = `/${slug}/_fragments/github-repositories`;
    // Without a connection the service refuses closed; nothing is cached.
    const notConnected = await page.request.post(endpoint, {
      headers: { Origin: ssrUrl }, form: { _csrf: csrf, page_token: "" },
    });
    expect(notConnected.status()).toBe(422);
    expect(notConnected.headers()["cache-control"]).toContain("no-store");
    // The browser never selects a credential or profile for repository listing.
    const legacySelector = await page.request.post(endpoint, {
      headers: { Origin: ssrUrl }, form: { _csrf: csrf, credential_profile: "", page_token: "" },
    });
    expect(legacySelector.status()).toBe(422);
    const wrongOrigin = await page.request.post(endpoint, {
      headers: { Origin: "https://unrelated.example.test" }, form: { _csrf: csrf },
    });
    expect(wrongOrigin.status()).toBe(403);
    const wrongCsrf = await page.request.post(endpoint, {
      headers: { Origin: ssrUrl }, form: { _csrf: "synthetic-invalid" },
    });
    expect(wrongCsrf.status()).toBe(403);

    const settings = await page.goto(`/settings/credentials/?org=${slug}`);
    expect(settings?.status()).toBe(200);
    await page.getByRole("button", { name: "Add credential", exact: true }).click();
    await page.getByRole("dialog", { name: "Add credential", exact: true })
      .getByRole("button", { name: "GitHub", exact: true }).click();
    const github = page.getByRole("dialog", { name: "Connect GitHub", exact: true });
    await expect(github.locator('[name="name"]')).toHaveCount(0);
    await expect(github.getByRole("button", { name: "Continue to GitHub", exact: true }).locator("svg use"))
      .toHaveAttribute("href", /^\/assets\/codewire\/icons-v2\.svg\?h=[0-9a-f]{16}#icon-github$/);

    // Exercise the actual bundled dialog guard without enrolling a credential
    // or contacting a provider. All entered material belongs to this owner.
    await page.keyboard.press("Escape");
    let credentialMutations = 0;
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname.startsWith("/settings/credentials/_actions/")) credentialMutations += 1;
    });
    const addCredential = page.getByRole("button", { name: "Add credential", exact: true });
    const chooser = page.getByRole("dialog", { name: "Add credential", exact: true });
    const api = page.getByRole("dialog", { name: "Add OpenAI API key", exact: true });
    const discard = page.getByRole("dialog", { name: "Discard changes?", exact: true });
    await addCredential.click();
    await chooser.getByRole("button", { name: "OpenAI API key", exact: true }).click();
    const provider = api.locator('[name="provider"]');
    await expect(provider).toHaveValue("openai");
    const credentialName = api.getByLabel("Credential name", { exact: true });
    const initialCsrf = await api.locator('[name="_csrf"]').inputValue();
    await api.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(api).not.toBeVisible();
    await expect(discard).not.toBeVisible();
    await expect(addCredential).toBeFocused();
    await addCredential.click();
    await chooser.getByRole("button", { name: "OpenAI API key", exact: true }).click();
    const key = api.getByLabel("API key", { exact: true });
    await key.fill("synthetic-discarded-key");
    await credentialName.fill("synthetic-work-key");
    await key.focus();
    await page.keyboard.press("Escape");
    await expect(discard.getByRole("button", { name: "Keep editing", exact: true })).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(discard).not.toBeVisible();
    await expect(key).toBeFocused();
    await expect(key).toHaveValue("synthetic-discarded-key");
    await expect(provider).toHaveValue("openai");
    await expect(credentialName).toHaveValue("synthetic-work-key");
    await expect(api.locator('[name="_csrf"]')).toHaveValue(initialCsrf);
    await api.getByRole("button", { name: "Cancel", exact: true }).click();
    await discard.getByRole("button", { name: "Discard changes", exact: true }).click();
    await expect(addCredential).toBeFocused();
    await addCredential.click();
    await chooser.getByRole("button", { name: "OpenAI API key", exact: true }).click();
    await expect(key).toHaveValue("");
    await expect(provider).toHaveValue("openai");
    await expect(credentialName).toHaveValue("");
    await expect(api.locator('[name="_csrf"]')).toHaveValue(initialCsrf);
    await api.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(api).not.toBeVisible();
    await expect(discard).not.toBeVisible();
    expect(credentialMutations).toBe(0);
  } finally {
    try {
      if (!page.isClosed()) await page.close();
      await page.context().clearCookies();
    } finally {
      try {
        await cleanupTestOrg(slug);
      } finally {
        await cleanupUser(email);
      }
    }
  }
});
