import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import {
  destroyGithubCheckout, githubCheckoutImage, githubCheckoutInstall, githubCheckoutName,
  githubGitCounters, verifyGithubCheckout,
} from "./helpers/github-checkout";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

async function openGithubConnection(page: Page) {
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await page.getByRole("dialog", { name: "Add credential", exact: true })
    .getByRole("button", { name: "GitHub", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Connect GitHub", exact: true })).toBeVisible();
}

async function completeGithubAppConnection(page: Page, code: string) {
  const form = page.getByRole("form", { name: "GitHub App", exact: true });
  const githubAuthorizePath = "/settings/credentials/_actions/github/authorize";
  const githubInstallationPath = "/apps/codewire-synthetic/installations/new";
  // The native form hands the browser to GitHub after this 303. The Kind
  // fixture must not load a provider-controlled page, so submit the exact
  // form action through this browser context's request client instead. It
  // shares the session and callback-state cookie jar with the page, letting
  // the test exercise the real authorization and callback routes without an
  // external-network navigation race.
  const action = await form.getAttribute("action");
  const csrf = await form.locator('[name="_csrf"]').inputValue();
  if (!action) throw new Error("GitHub App authorization form omitted its action");
  expect(new URL(action, ssrUrl).pathname).toBe(githubAuthorizePath);
  let state = "";
  const authorization = await page.context().request.post(new URL(action, ssrUrl).toString(), {
    form: { _csrf: csrf },
    headers: {
      Origin: ssrUrl,
      Referer: `${ssrUrl}/settings/credentials/`,
    },
    maxRedirects: 0,
  });
  expect(authorization.status()).toBe(303);
  expect(authorization.headers()["cache-control"]).toBe("no-store");
  const location = authorization.headers().location;
  if (!location) throw new Error("GitHub App authorization omitted its installation redirect");
  const target = new URL(location);
  expect(target.origin).toBe("https://github.com");
  expect(target.pathname).toBe(githubInstallationPath);
  state = target.searchParams.get("state") || "";
  if (!state) throw new Error("GitHub App authorization omitted its state fence");
  const cookie = authorization.headers()["set-cookie"] || "";
  expect(cookie).toContain("codewire_github_app_authorization=");
  expect(cookie).toContain("HttpOnly");
  expect(cookie).toContain("SameSite=Lax");
  expect(cookie).toContain("Path=/settings/credentials/github/");

  const callbackUrl = new URL(
    `/settings/credentials/github/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    ssrUrl,
  ).toString();
  const response = await page.context().request.get(callbackUrl, { maxRedirects: 0 });
  expect(response.status()).toBe(303);
  expect(response.headers()["cache-control"]).toBe("no-store, max-age=0");
  expect(response.headers()["referrer-policy"]).toBe("no-referrer");
  expect(response.headers()["set-cookie"] || "").toContain("Max-Age=0");
  const completion = response.headers().location;
  if (!completion) throw new Error("GitHub App callback omitted its completion redirect");
  await page.goto(new URL(completion, ssrUrl).toString());
}

test.describe("managed provider credential browser journey", () => {
  test.skip(
    process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1",
    "requires the managed non-promotable Kind credential fixture",
  );
  test.use({ storageState: { cookies: [], origins: [] } });

  test("connects GitHub, checks out a selected repository, then revokes and deletes it", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop credential lifecycle contract");
    test.setTimeout(600_000);
    const name = "synthetic-user";
    // The provider's verified fixture username is deliberately stable. A fresh
    // synthetic owner per attempt keeps retries independent without finding or
    // deleting another user's credential by its display name.
    const email = `e2e-github-${randomUUID()}@codewire.sh`;
    const slug = `github-journey-${randomUUID().replaceAll("-", "")}`;
    let orgId = "";
    let primaryFailure: unknown;
    await seedSyntheticUser(email, "GitHub enrollment fixture");
    try {
      await bypassTwoFactor(email);
      const owner = await getUserId(email);
      if (!owner) throw new Error("Synthetic GitHub owner was not created");
      orgId = await ensureTestOrg("GitHub repository journey", slug, owner);
      const session = await createAuthenticatedSession(email);
      await page.context().addCookies([{
        name: "codewire.session_token", value: session.token, url: ssrUrl,
        httpOnly: true, sameSite: "Lax",
      }]);

      const settings = await page.goto("/settings/credentials/");
      expect(settings?.status()).toBe(200);
      await expect(page.locator("dialog[open]")).toHaveCount(0);
      await openGithubConnection(page);
      const form = page.getByRole("form", { name: "GitHub App", exact: true });
      await expect(form.locator('[name="name"]')).toHaveCount(0);
      await expect(form.getByRole("button", { name: "Continue to GitHub", exact: true }).locator("svg use"))
        .toHaveAttribute("href", "/assets/codewire/icons-v2.svg#icon-github");
      await expect(form).toContainText("Your verified GitHub username names this connection");
      await expect(form).not.toContainText("one-time code");
      await completeGithubAppConnection(page, "kind-synthetic-code-one");
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=github-app-connected`);
      await expect(page.getByRole("status")).toHaveText("GitHub connected through the GitHub App.");
      let rendered = await page.locator("body").textContent();
      expect(rendered?.includes("gho_")).toBe(false);
      expect(rendered?.includes("ghu_")).toBe(false);
      expect(rendered?.includes("oauth_token")).toBe(false);

      let row = page.locator(".cw-credential-row", { hasText: name });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText("GitHub · OAuth");
      await expect(row).toContainText("synthetic-user");
      await expect(row).toContainText("Active");
      await expect(row).toContainText("Generation 1");
      await expect(row.locator("strong").first()).toHaveText(name);
      await expect(row.getByText("Rename", { exact: true })).toHaveCount(0);
      rendered = await page.locator("body").textContent();
      expect(rendered?.includes("gho_")).toBe(false);
      expect(rendered?.includes("ghu_")).toBe(false);
      expect(rendered?.includes("oauth_token")).toBe(false);

      await openGithubConnection(page);
      await completeGithubAppConnection(page, "kind-synthetic-code-two");
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?error=github-app-already-connected&dialog=connect-github`);
      await expect(page.getByRole("alert")).toContainText("This GitHub account is already connected");
      await page.goto("/settings/credentials/");
      await expect(row).toHaveCount(1);
      await expect(row).toContainText("Generation 1");

      const profileName = "github-repository-browser";
      await page.getByRole("button", { name: "Create profile", exact: true }).click();
      const createProfile = page.locator('form[action^="/settings/credentials/_actions/profiles/create"]');
      await expect(page.getByRole("dialog", { name: "Create profile", exact: true })).toBeVisible();
      await createProfile.getByRole("textbox", { name: "Profile name", exact: true }).fill(profileName);
      const githubChoice = createProfile.getByRole("combobox", { name: "GitHub", exact: true });
      const credentialId = await githubChoice.locator("option", { hasText: name }).getAttribute("value");
      if (!credentialId) throw new Error("Verified GitHub connection was not selectable");
      await githubChoice.selectOption(credentialId);
      await createProfile.getByRole("button", { name: "Create profile", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=profile-created`);
      await expect(page.getByRole("status")).toHaveText("Credential profile created.");
      let profileRow = page.locator(".cw-profile-row", { hasText: profileName });
      await expect(profileRow).toHaveCount(1);
      await expect(profileRow).toBeVisible();
      const profileId = await profileRow.locator('[name="profile_id"]').first().inputValue();

      await page.goto(`/${slug}/new/`);
      await page.getByRole("textbox", { name: "Name", exact: true }).fill(githubCheckoutName);
      const openPicker = page.getByRole("button", { name: "Choose from GitHub", exact: true });
      await openPicker.click();
      const picker = page.getByRole("dialog", { name: "Choose a GitHub repository", exact: true });
      await picker.getByRole("combobox", { name: "GitHub credential profile" }).selectOption(`${profileId}@1`);
      const choices = picker.locator("[data-select-github-repository]");
      await expect(choices).toHaveCount(50);
      await expect(picker.getByRole("button", { name: /synthetic-user\/repository-50/ })).toBeDisabled();
      await picker.getByRole("searchbox", { name: "Filter this page" }).fill("repository-01");
      await expect(picker.locator("[data-select-github-repository]:visible")).toHaveCount(1);
      await picker.getByRole("searchbox", { name: "Filter this page" }).clear();
      await picker.getByRole("button", { name: "Next page", exact: true }).click();
      await expect(choices).toHaveCount(1);
      await expect(choices.first()).toContainText("synthetic-user/repository-51");
      await picker.getByRole("button", { name: "Previous page", exact: true }).click();
      await expect(choices).toHaveCount(50);
      await picker.getByRole("button", { name: /synthetic-user\/repository-01/ }).click();
      await expect(picker).not.toBeVisible();
      const source = page.locator("[data-repository-row]").first();
      await expect(source.getByRole("textbox", { name: "Repository URL", exact: true }))
        .toHaveValue("https://github.com/synthetic-user/repository-01.git");
      await expect(source.getByRole("textbox", { name: "Branch", exact: true })).toHaveValue("main");
      await expect(source.getByRole("textbox", { name: "Mount path", exact: true })).toHaveValue("repository-01");
      await expect(page.getByRole("combobox", { name: "Credential profile", exact: true })).toHaveValue(`${profileId}@1`);
      await source.getByRole("textbox", { name: "Branch", exact: true }).fill("my-working-branch");
      await openPicker.click();
      await picker.getByRole("button", { name: /synthetic-user\/repository-01/ }).click();
      await expect(page.locator("[data-repository-row]")).toHaveCount(1);
      await expect(source.getByRole("textbox", { name: "Branch", exact: true })).toHaveValue("my-working-branch");
      await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("github-repository-draft");
      rendered = await page.locator("body").textContent();
      expect(rendered?.includes("gho_")).toBe(false);
      expect(rendered?.includes("ghu_")).toBe(false);
      expect(rendered?.includes("oauth_token")).toBe(false);

      await source.getByRole("textbox", { name: "Branch", exact: true }).fill("main");
      await page.getByLabel("Workspace image").fill(githubCheckoutImage);
      await page.locator("[data-create-runtime] > summary").click();
      await page.locator("[data-create-resources] > summary").click();
      await page.getByLabel("Install Command").fill(githubCheckoutInstall);
      await expect(page.getByLabel("Install Command")).toHaveValue(githubCheckoutInstall);
      await page.getByLabel("TTL").fill("3600s");
      const before = await githubGitCounters();
      await page.getByRole("button", { name: "Create Sandbox", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/${slug}/?message=environment-created`);
      await verifyGithubCheckout(page, orgId, profileId, before);
      await destroyGithubCheckout(page, orgId);

      // The normal destroy finished before removing its selected profile.
      await page.goto("/settings/credentials/");
      profileRow = page.locator(".cw-profile-row", { hasText: profileName });
      await profileRow.getByRole("button", { name: "Edit profile", exact: true }).click();
      await profileRow.getByText("Delete profile", { exact: true }).click();
      await profileRow.getByRole("button", { name: `Delete ${profileName}`, exact: true }).click();
      await expect(profileRow).toHaveCount(0);
      row = page.locator(".cw-credential-row", { hasText: name });

      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await row.getByText("Revoke", { exact: true }).click();
      await row.getByRole("button", { name: `Revoke ${name}`, exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-revoked`);
      await expect(page.getByRole("status")).toHaveText("Credential revoked.");
      row = page.locator(".cw-credential-row", { hasText: name });
      await expect(row).toContainText("Revoked");
      await expect(row).toContainText("Generation 2");

      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await row.getByText("Delete", { exact: true }).click();
      await row.getByRole("button", { name: `Delete ${name}`, exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-deleted`);
      await expect(page.getByRole("status")).toHaveText("Credential deleted.");
      await expect(page.locator(".cw-credential-row", { hasText: name })).toHaveCount(0);
    } catch (error) {
      primaryFailure = error;
      throw error;
    } finally {
      // Allow bounded normal teardown even when creation/verification timed out.
      test.setTimeout(test.info().timeout + 150_000);
      try {
        // Never remove ownership records unless normal destruction or absence
        // is proved. Playwright owns this test's isolated browser context and
        // closes it itself, including after a timeout.
        if (orgId) await destroyGithubCheckout(page, orgId);
        const cleanupFailures: unknown[] = [];
        for (const cleanup of [() => cleanupTestOrg(slug), () => cleanupUser(email)]) {
          try { await cleanup(); } catch (error) { cleanupFailures.push(error); }
        }
        if (cleanupFailures.length) {
          throw new AggregateError(cleanupFailures, "GitHub fixture cleanup failed", { cause: cleanupFailures[0] });
        }
      } catch (error) {
        if (primaryFailure !== undefined) {
          // Playwright serializes Error.cause, but not AggregateError.errors.
          throw new AggregateError([primaryFailure, error], "GitHub journey and cleanup failed", { cause: primaryFailure });
        }
        throw error;
      }
    }
  });
});
