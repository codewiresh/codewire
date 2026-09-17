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

async function completeGithubAppConnection(page: Page, code: string, alterCallback?: (url: URL) => void) {
  const form = page.locator('dialog[open] form[action^="/settings/credentials/_actions/github/authorize"]');
  const githubAuthorizePath = "/settings/credentials/_actions/github/authorize";
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
  if (!location) throw new Error("GitHub App authorization omitted its authorization redirect");
  const target = new URL(location);
  expect(target.origin).toBe("https://github.com");
  expect(target.pathname).toBe("/login/oauth/authorize");
  expect(target.searchParams.get("client_id")).toBe("Iv1.kindsynthetic");
  expect(target.searchParams.get("redirect_uri")).toBe(`${ssrUrl}/api/v1/github/oauth/callback`);
  expect([...target.searchParams.keys()].sort()).toEqual(["client_id", "redirect_uri", "state"]);
  state = target.searchParams.get("state") || "";
  if (!state) throw new Error("GitHub App authorization omitted its state fence");
  const cookie = authorization.headers()["set-cookie"] || "";
  expect(cookie).toContain("codewire_github_app_authorization=");
  expect(cookie).toContain("HttpOnly");
  expect(cookie).toContain("SameSite=Lax");
  expect(cookie).toContain("Path=/api/v1/github/oauth/");

  const callbackUrl = new URL(
    `/api/v1/github/oauth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
    ssrUrl,
  );
  alterCallback?.(callbackUrl);
  const response = await page.context().request.get(callbackUrl.toString(), { maxRedirects: 0 });
  expect(response.status()).toBe(303);
  expect(response.headers()["cache-control"]).toBe("no-store, max-age=0");
  expect(response.headers()["referrer-policy"]).toBe("no-referrer");
  expect(response.headers()["set-cookie"] || "").toContain("Max-Age=0");
  const completion = response.headers().location;
  if (!completion) throw new Error("GitHub App callback omitted its completion redirect");
  expect(completion).not.toContain(code);
  await page.goto(new URL(completion, ssrUrl).toString());
}

test.describe("managed provider credential browser journey", () => {
  test.skip(
    process.env.PLAYWRIGHT_KIND_CREDENTIAL_FIXTURE !== "1",
    "requires the managed non-promotable Kind credential fixture",
  );
  test.use({ storageState: { cookies: [], origins: [] } });

  test("refreshes GitHub App authorization before a protected repository checkout, then revokes and deletes it", async ({ page, isMobile }) => {
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
      const connection = page.getByRole("dialog", { name: "Connect GitHub", exact: true });
      const form = connection.locator("form");
      await expect(form.locator('[name="name"]')).toHaveCount(0);
      await expect(connection.getByRole("button", { name: "Continue to GitHub", exact: true }).locator("svg use"))
        .toHaveAttribute("href", "/assets/codewire/icons-v2.svg#icon-github");
      await expect(connection).toContainText("Your verified GitHub username names this connection");
      await expect(connection).not.toContainText("one-time code");
      await expect(connection.getByRole("link", { name: "Install/manage repository access" }))
        .toHaveAttribute("href", "https://github.com/apps/codewire-synthetic/installations/new");
      // These returns never reach provider exchange or publish a credential.
      // Each retry starts from the newly rendered form and a fresh state cookie.
      for (const alter of [
        (url: URL) => url.searchParams.append("code", "duplicate-code"),
        (url: URL) => url.searchParams.append("state", "duplicate-state"),
        (url: URL) => url.searchParams.set("state", "wrong-state"),
        (url: URL) => url.searchParams.set("code", "invalid?code"),
      ]) {
        await completeGithubAppConnection(page, "kind-synthetic-code-one", alter);
        await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?error=github-app-failed&dialog=connect-github`);
        await expect(connection).toBeVisible();
        await expect(page.locator(".cw-credential-row")).toHaveCount(0);
      }
      await completeGithubAppConnection(page, "kind-synthetic-code-uninstalled");
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?error=github-installation-required&dialog=connect-github`);
      await expect(connection.getByRole("alert")).toContainText("No credential was changed");
      await expect(page.locator(".cw-credential-row")).toHaveCount(0);
      // A newly authorized, now-installed account can complete normally.
      await completeGithubAppConnection(page, "kind-synthetic-code-one");
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=github-app-connected`);
      await expect(page.getByRole("status")).toHaveText("GitHub connected through the GitHub App.");
      const beforePicker = await githubGitCounters();
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
      await page.getByRole("dialog", { name: "Create profile", exact: true })
        .getByRole("button", { name: "Create profile", exact: true }).click();
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
      const afterPicker = await githubGitCounters();
      expect(afterPicker.appRefresh).toBe(beforePicker.appRefresh + 1);
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
      await profileRow.getByRole("button", { name: "Manage profile", exact: true }).click();
      await page.getByRole("dialog", { name: profileName, exact: true })
        .getByRole("button", { name: "Delete profile", exact: true }).click();
      await page.getByRole("dialog", { name: `Delete ${profileName}?`, exact: true })
        .getByRole("button", { name: "Delete profile", exact: true }).click();
      await expect(profileRow).toHaveCount(0);
      row = page.locator(".cw-credential-row", { hasText: name });

      await expect(row).toContainText("Active");
      await expect(row).toContainText("Generation 2");
      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await page.getByRole("dialog", { name: `Manage ${name}`, exact: true })
        .getByRole("button", { name: "Revoke credential", exact: true }).click();
      await page.getByRole("dialog", { name: `Revoke ${name}?`, exact: true })
        .getByRole("button", { name: "Revoke credential", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-revoked`);
      await expect(page.getByRole("status")).toHaveText("Credential revoked.");
      row = page.locator(".cw-credential-row", { hasText: name });
      await expect(row).toContainText("Revoked");
      await expect(row).toContainText("Generation 3");

      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await page.getByRole("dialog", { name: `Manage ${name}`, exact: true })
        .getByRole("button", { name: "Delete credential", exact: true }).click();
      await page.getByRole("dialog", { name: `Delete ${name}?`, exact: true })
        .getByRole("button", { name: "Delete credential", exact: true }).click();
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
