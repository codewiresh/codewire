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
    const response = await page.goto(`/${slug}/new/`);
    expect(response?.status()).toBe(200);
    await page.getByRole("textbox", { name: "Name", exact: true }).fill("my-new-sandbox");
    await page.getByRole("button", { name: "Choose from GitHub", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Choose a GitHub repository", exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("status")).toContainText("Choose a profile with a GitHub connection");
    await expect(dialog.getByRole("link", { name: "Connect GitHub or create a profile in Settings" }))
      .toHaveAttribute("href", `/settings/credentials/?org=${slug}`);
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("my-new-sandbox");

    const form = page.locator("[data-environment-form]");
    const csrf = await form.locator('[name="_csrf"]').inputValue();
    const endpoint = `/${slug}/_fragments/github-repositories`;
    const missingSelection = await page.request.post(endpoint, {
      headers: { Origin: ssrUrl }, form: { _csrf: csrf, credential_profile: "", page_token: "" },
    });
    expect(missingSelection.status()).toBe(422);
    expect(await missingSelection.text()).toContain("Choose a current credential profile");
    expect(missingSelection.headers()["cache-control"]).toContain("no-store");
    const wrongOrigin = await page.request.post(endpoint, {
      headers: { Origin: "https://unrelated.example.test" }, form: { _csrf: csrf, credential_profile: "" },
    });
    expect(wrongOrigin.status()).toBe(403);
    const wrongCsrf = await page.request.post(endpoint, {
      headers: { Origin: ssrUrl }, form: { _csrf: "synthetic-invalid", credential_profile: "" },
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
      .toHaveAttribute("href", "/assets/codewire/icons-v2.svg#icon-github");

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
    if (!page.isClosed()) await page.close();
    await page.context().clearCookies();
    await cleanupTestOrg(slug);
    await cleanupUser(email);
  }
});
