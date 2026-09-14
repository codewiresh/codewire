import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";
import { bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import {
  destroyGithubCheckout, githubCheckoutImage, githubCheckoutInstall, githubCheckoutName,
  githubGitCounters, verifyGithubCheckout,
} from "./helpers/github-checkout";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

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
      const form = page.getByRole("form", { name: "GitHub", exact: true });
      await expect(form.locator('[name="name"]')).toHaveCount(0);
      await expect(form.getByRole("button", { name: "Connect GitHub", exact: true }).locator("svg use"))
        .toHaveAttribute("href", "/assets/codewire/icons-v2.svg#icon-github");

      const enrollmentResponse = page.waitForResponse((response) => (
        response.url().includes("/settings/credentials/_actions/credentials/oauth/enroll")
        && response.request().method() === "POST"
      ));
      await form.getByRole("button", { name: "Connect GitHub", exact: true }).click();
      const response = await enrollmentResponse;
      expect(response.status()).toBe(200);
      expect(response.headers()["cache-control"]).toBe("no-store, no-cache, must-revalidate");
      expect(response.headers()["x-accel-buffering"]).toBeUndefined();
      const responseBody = await response.text();
      const challenge = responseBody.indexOf("ABCD-EFGH");
      const committed = responseBody.indexOf("Credential connected.");
      expect(challenge).toBeGreaterThan(-1);
      expect(committed).toBeGreaterThan(challenge);

      await expect(page.getByRole("heading", { name: "Authorize GitHub", exact: true })).toBeVisible();
      await expect(page.getByText("ABCD-EFGH", { exact: true })).toBeVisible();
      await expect(page.getByRole("link", { name: "Open GitHub authorization", exact: true }))
        .toHaveAttribute("href", "https://github.com/login/device");
      await expect(page.getByRole("status")).toHaveText("Credential connected.");
      let rendered = await page.locator("body").textContent();
      expect(rendered?.includes("gho_")).toBe(false);
      expect(rendered?.includes("oauth_token")).toBe(false);

      await page.getByRole("link", { name: "Return to credentials", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/`);
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
      expect(rendered?.includes("oauth_token")).toBe(false);

      await page.getByRole("form", { name: "GitHub", exact: true })
        .getByRole("button", { name: "Connect GitHub", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("No credential was overwritten");
      await page.getByRole("link", { name: "Return to credentials", exact: true }).click();
      await expect(row).toHaveCount(1);
      await expect(row).toContainText("Generation 1");

      const profileName = "github-repository-browser";
      const createProfile = page.locator('form[action^="/settings/credentials/_actions/profiles/create"]');
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
      expect(rendered?.includes("oauth_token")).toBe(false);

      await source.getByRole("textbox", { name: "Branch", exact: true }).fill("main");
      await page.getByLabel("Workspace image").fill(githubCheckoutImage);
      await page.getByLabel("Install Command").fill(githubCheckoutInstall);
      await page.getByLabel("TTL").fill("3600s");
      const before = await githubGitCounters();
      await page.getByRole("button", { name: "Create Sandbox", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/${slug}/?message=environment-created`);
      await verifyGithubCheckout(page, orgId, profileId, before);
      await destroyGithubCheckout(page, orgId);

      // The normal destroy finished before removing its selected profile.
      await page.goto("/settings/credentials/");
      profileRow = page.locator(".cw-profile-row", { hasText: profileName });
      await profileRow.getByText("Delete profile", { exact: true }).click();
      await profileRow.getByRole("button", { name: `Delete ${profileName}`, exact: true }).click();
      await expect(profileRow).toHaveCount(0);
      row = page.locator(".cw-credential-row", { hasText: name });

      await row.getByText("Revoke", { exact: true }).click();
      await row.getByRole("button", { name: `Revoke ${name}`, exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-revoked`);
      await expect(page.getByRole("status")).toHaveText("Credential revoked.");
      row = page.locator(".cw-credential-row", { hasText: name });
      await expect(row).toContainText("Revoked");
      await expect(row).toContainText("Generation 2");

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
