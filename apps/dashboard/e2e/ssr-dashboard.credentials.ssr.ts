import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import { bypassTwoFactor, cleanupUser, createAuthenticatedSession, getUserId, seedSyntheticUser } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import {
  destroyGithubCheckout, githubCheckoutImage, githubCheckoutInstall, githubCheckoutName,
  githubConnectionMetadata, githubGitCounters, verifyGithubCheckout,
} from "./helpers/github-checkout";

const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");

async function openGithubConnection(page: Page) {
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await page.getByRole("dialog", { name: "Add credential", exact: true })
    .getByRole("button", { name: "GitHub", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Connect GitHub", exact: true })).toBeVisible();
}

async function completeGithubAppConnection(page: Page, code: string, alterCallback?: (url: URL) => void) {
  const dialog = page.locator("dialog[open]");
  const form = dialog.locator('form[action^="/settings/credentials/_actions/github/authorize"]');
  const githubAuthorizePath = "/settings/credentials/_actions/github/authorize";
  const action = await form.getAttribute("action");
  if (!action) throw new Error("GitHub App authorization form omitted its action");
  expect(new URL(action, ssrUrl).pathname).toBe(githubAuthorizePath);
  const formId = await form.getAttribute("id");
  if (!formId) throw new Error("GitHub App authorization form omitted its identity");
  const continueButton = dialog.getByRole("button", { name: "Continue to GitHub", exact: true });
  await expect(continueButton).toHaveAttribute("form", formId);
  // Only GitHub's external authorization navigation is synthetic. Native form
  // submission, redirects, Origin/CSRF, cookies, the real local callback, token
  // exchange and protected storage all keep their checked-in implementation.
  // page.route only intercepts the first request in a redirect chain. Use the
  // pinned Chromium transport's exact external Request-stage interception so
  // the native BFF POST and its redirect are not replaced by a request client.
  const transport = await page.context().newCDPSession(page);
  let mainFrameId = "";
  let callbackUrl = "";
  const pending = new Set<string>();
  let resolveProvider!: () => void;
  let rejectProvider!: (error: unknown) => void;
  const providerReturn = new Promise<void>((resolve, reject) => {
    resolveProvider = resolve;
    rejectProvider = reject;
  });
  const authorizeProvider = async (event: {
    requestId: string; frameId: string; resourceType: string; request: { method: string; url: string };
  }) => {
    expect(event.frameId).toBe(mainFrameId);
    expect(event.resourceType).toBe("Document");
    expect(event.request.method).toBe("GET");
    expect(callbackUrl).toBe("");
    const target = new URL(event.request.url);
    expect(target.origin).toBe("https://github.com");
    expect(target.pathname).toBe("/login/oauth/authorize");
    expect(target.searchParams.get("client_id")).toBe("Iv1.kindsynthetic");
    expect(target.searchParams.get("redirect_uri")).toBe(`${ssrUrl}/api/v1/github/oauth/callback`);
    expect([...target.searchParams.keys()].sort()).toEqual(["client_id", "redirect_uri", "state"]);
    const state = target.searchParams.get("state");
    if (!state) throw new Error("GitHub App authorization omitted its state fence");
    const stateCookie = (await page.context().cookies(`${ssrUrl}/api/v1/github/oauth/callback`))
      .find((cookie) => cookie.name === "codewire_github_app_authorization");
    // Assert cookie behavior in the browser as well as the server's wire
    // policy: Chromium may omit raw Set-Cookie after a fulfilled redirect.
    expect(stateCookie?.httpOnly).toBe(true);
    expect(stateCookie?.sameSite).toBe("Lax");
    expect(stateCookie?.path).toBe("/api/v1/github/oauth/");
    const callback = new URL(target.searchParams.get("redirect_uri")!);
    callback.searchParams.set("code", code);
    callback.searchParams.set("state", state);
    alterCallback?.(callback);
    callbackUrl = callback.toString();
    await transport.send("Fetch.fulfillRequest", {
      requestId: event.requestId, responseCode: 302,
      responseHeaders: [{ name: "Location", value: callbackUrl }, { name: "Cache-Control", value: "no-store" }],
      body: "",
    });
  };
  const onPaused = (event: Parameters<typeof authorizeProvider>[0]) => {
    pending.add(event.requestId);
    void authorizeProvider(event).then(() => {
      pending.delete(event.requestId);
      resolveProvider();
    }, async (error: unknown) => {
      try {
        await transport.send("Fetch.failRequest", { requestId: event.requestId, errorReason: "Aborted" });
        pending.delete(event.requestId);
      } catch { /* Final cleanup retries; preserve the failed provider assertion. */ }
      rejectProvider(error);
    });
  };
  transport.on("Fetch.requestPaused", onPaused);
  let primaryFailure: unknown;
  try {
    const { frameTree } = await transport.send("Page.getFrameTree");
    mainFrameId = frameTree.frame.id;
    await transport.send("Fetch.enable", { patterns: [{
      urlPattern: "https://github.com/login/oauth/authorize*", resourceType: "Document", requestStage: "Request",
    }] });
    const [authorization, response] = await Promise.all([
      page.waitForResponse((response) => response.request().method() === "POST"
        && response.url() === new URL(action, ssrUrl).toString(), { timeout: 30_000 }),
      page.waitForResponse((response) => response.request().method() === "GET"
        && new URL(response.url()).origin === ssrUrl
        && new URL(response.url()).pathname === "/api/v1/github/oauth/callback", { timeout: 30_000 }),
      continueButton.click({ timeout: 30_000 }),
      providerReturn,
    ]);
    expect(authorization.status()).toBe(303);
    expect(await authorization.request().headerValue("origin")).toBe(ssrUrl);
    expect(authorization.headers()["cache-control"]).toBe("no-store");
    const cookie = await authorization.headerValue("set-cookie") || "";
    expect(cookie).toContain("codewire_github_app_authorization=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/api/v1/github/oauth/");
    expect(response.status()).toBe(303);
    expect(response.headers()["cache-control"]).toBe("no-store, max-age=0");
    expect(response.headers()["referrer-policy"]).toBe("no-referrer");
    const completion = response.headers().location;
    if (!completion) throw new Error("GitHub App callback omitted its completion redirect");
    expect(completion).not.toContain(code);
    await expect(page).toHaveURL(new URL(completion, ssrUrl).toString());
    // The exact Max-Age=0 clearing header is covered by security.rs. Here
    // require its observable effect before replaying the consumed callback.
    expect((await page.context().cookies()).some((cookie) => cookie.name === "codewire_github_app_authorization"))
      .toBe(false);
    return callbackUrl;
  } catch (error) {
    primaryFailure = error;
    throw error;
  } finally {
    const cleanupFailures: unknown[] = [];
    for (const requestId of pending) {
      try { await transport.send("Fetch.failRequest", { requestId, errorReason: "Aborted" }); }
      catch (error) { cleanupFailures.push(error); }
    }
    try { await transport.send("Fetch.disable"); } catch (error) { cleanupFailures.push(error); }
    transport.off("Fetch.requestPaused", onPaused);
    try { await transport.detach(); } catch (error) { cleanupFailures.push(error); }
    if (!primaryFailure && cleanupFailures.length) {
      throw new AggregateError(cleanupFailures, "Synthetic GitHub navigation cleanup failed");
    }
  }
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

      // Begin in the real Create form and take its native setup link. The
      // Settings detour must retain this draft, not invent a fresh one after
      // provider authorization or implicitly attach the newly added profile.
      const setupDispatches: string[] = [];
      const observeSetup = (request: import("@playwright/test").Request) => {
        if (/PrepareEnvironment|\/_actions\/sandboxes\/(?:create|prepare)/.test(request.url())) setupDispatches.push(request.url());
      };
      page.on("request", observeSetup);
      const create = await page.goto(`/${slug}/new/`);
      expect(create?.status()).toBe(200);
      const draftForm = page.locator("[data-environment-form]");
      await expect(draftForm).toHaveAttribute("data-create-draft-actor", owner);
      await expect(draftForm).toHaveAttribute("data-create-draft-organization", orgId);
      const draft = await draftForm.getAttribute("data-create-draft-id");
      expect(draft).toMatch(/^[0-9a-f-]{36}$/);
      await page.locator("[data-create-resources] > summary").click();
      await page.getByLabel("CPU", { exact: true }).selectOption("2000");
      const ttl = page.getByLabel("Delete after", { exact: true });
      await expect(ttl).toBeVisible();
      await ttl.fill("3600s");
      await page.getByRole("textbox", { name: "Name", exact: true }).fill("setup-name-not-persisted");
      await expect(page.locator("[data-create-draft-status]")).toContainText("Draft saved");
      const settingsPath = `/settings/credentials/?org=${slug}&creation_draft=${draft}`;
      const setupLink = page.getByRole("link", { name: "Connect GitHub", exact: true });
      await expect(setupLink).toHaveAttribute("href", settingsPath);
      await setupLink.click();
      const discard = page.getByRole("dialog", { name: "Discard changes?", exact: true });
      await expect(discard).toBeVisible();
      await discard.getByRole("button", { name: "Keep editing", exact: true }).click();
      await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("setup-name-not-persisted");
      await expect(draftForm).toHaveAttribute("data-create-draft-id", draft!);
      await setupLink.click();
      await discard.getByRole("button", { name: "Discard changes", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}`);
      const returnLink = page.getByRole("link", { name: "Return to Create Sandbox", exact: true });
      await expect(returnLink).toHaveAttribute("href", `/${slug}/new/?creation_draft=${draft}`);
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
      expect(await githubConnectionMetadata(owner)).toEqual([]);
      // These returns never reach provider exchange or publish a credential.
      // Each retry starts from the newly rendered form and a fresh state cookie.
      for (const { alter, preservesNavigation } of [
        { alter: (url: URL) => url.searchParams.append("code", "duplicate-code"), preservesNavigation: false },
        { alter: (url: URL) => url.searchParams.append("state", "duplicate-state"), preservesNavigation: false },
        { alter: (url: URL) => url.searchParams.set("state", "wrong-state"), preservesNavigation: false },
        { alter: (url: URL) => url.searchParams.set("code", "invalid?code"), preservesNavigation: true },
      ]) {
        await page.goto(settingsPath);
        await openGithubConnection(page);
        await completeGithubAppConnection(page, "kind-synthetic-code-one", alter);
        const failurePath = preservesNavigation ? `${settingsPath}&` : "/settings/credentials/?";
        await expect(page).toHaveURL(`${ssrUrl}${failurePath}error=github-app-failed&dialog=connect-github`);
        await expect(connection).toBeVisible();
        await expect(page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row")).toHaveCount(0);
        expect(await githubConnectionMetadata(owner)).toEqual([]);
      }
      await page.goto(settingsPath);
      await openGithubConnection(page);
      await completeGithubAppConnection(page, "kind-synthetic-code-uninstalled");
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}&error=github-installation-required&dialog=connect-github`);
      await expect(connection.getByRole("alert")).toContainText("No credential was changed");
      await expect(page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row")).toHaveCount(0);
      expect(await githubConnectionMetadata(owner)).toEqual([]);
      // A newly authorized, now-installed account can complete normally.
      const completedCallback = await completeGithubAppConnection(page, "kind-synthetic-code-one");
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}&message=github-app-connected`);
      await expect(page.getByRole("status")).toHaveText("GitHub connected through the GitHub App.");
      const enrolled = await githubConnectionMetadata(owner);
      expect(enrolled).toHaveLength(1);
      // App user authorization publishes OAuth material; the separate
      // github_app auth kind does not describe this user-token connection.
      expect(enrolled[0]).toMatchObject({
        user_id: owner, organization_id: null, provider: "github", authentication_kind: "oauth",
        status: "active", revocation_generation: "1", material_generation: "1", protected_material_present: true,
      });
      // A consumed callback must not publish again or advance either generation.
      await page.goto(completedCallback);
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?error=github-app-failed&dialog=connect-github`);
      expect(await githubConnectionMetadata(owner)).toEqual(enrolled);
      await page.goto(settingsPath);
      const beforePicker = await githubGitCounters();
      let rendered = await page.locator("body").textContent();
      expect(rendered?.includes("gho_")).toBe(false);
      expect(rendered?.includes("ghu_")).toBe(false);
      expect(rendered?.includes("oauth_token")).toBe(false);

      let row = page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row", { hasText: name });
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
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}&error=github-app-already-connected&dialog=connect-github`);
      await expect(page.getByRole("alert")).toContainText("This GitHub account is already connected");
      const savedConnections = page.getByRole("region", { name: "Saved GitHub connections", exact: true });
      await expect(savedConnections.getByRole("button", { name: "Reconnect synthetic-user", exact: true })).toBeVisible();
      await expect(savedConnections).toContainText("Active");
      await page.goto(settingsPath);
      await expect(row).toHaveCount(1);
      await expect(row).toContainText("Generation 1");

      const profileName = "github-repository-browser";
      await page.getByRole("button", { name: "Create profile", exact: true }).click();
      const createProfile = page.locator('form[action^="/settings/credentials/_actions/profiles/create"]');
      await expect(page.getByRole("dialog", { name: "Create profile", exact: true })).toBeVisible();
      // The native pattern already blocks malformed names. Prove the server
      // negative separately through this same browser cookie jar and the exact
      // real form action, without changing the pattern or any auth guard.
      const profileAction = await createProfile.getAttribute("action");
      if (!profileAction) throw new Error("Create profile omitted its native action");
      const profileCsrf = await createProfile.locator('[name="_csrf"]').inputValue();
      const validation = await page.context().request.post(new URL(profileAction, ssrUrl).toString(), {
        form: { _csrf: profileCsrf, name: " ", codex: "", openai: "", github: "", anthropic: "", ssh: "" },
        headers: { Origin: ssrUrl, Referer: page.url() },
        maxRedirects: 0,
      });
      expect(validation.status()).toBe(303);
      expect(validation.headers().location).toBe(`${settingsPath}&error=profile-invalid&dialog=create-profile`);
      await page.goto(new URL(validation.headers().location, ssrUrl).toString());
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}&error=profile-invalid&dialog=create-profile`);
      await expect(page.getByRole("dialog", { name: "Create profile", exact: true })).toBeVisible();
      await expect(page.getByRole("alert")).toContainText("Check the profile name and selected credentials");
      await expect(returnLink).toHaveAttribute("href", `/${slug}/new/?creation_draft=${draft}`);
      await createProfile.getByRole("textbox", { name: "Profile name", exact: true }).fill(profileName);
      const githubChoice = createProfile.getByRole("combobox", { name: "GitHub", exact: true });
      const credentialId = await githubChoice.locator("option", { hasText: name }).getAttribute("value");
      if (!credentialId) throw new Error("Verified GitHub connection was not selectable");
      await githubChoice.selectOption(credentialId);
      await page.getByRole("dialog", { name: "Create profile", exact: true })
        .getByRole("button", { name: "Create profile", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}${settingsPath}&message=profile-created`);
      await expect(page.getByRole("status")).toHaveText("Credential profile created.");
      let profileRow = page.locator(".cw-profile-row", { hasText: profileName });
      await expect(profileRow).toHaveCount(1);
      await expect(profileRow).toBeVisible();
      const profileId = await profileRow.locator('[name="profile_id"]').first().inputValue();

      await returnLink.click();
      await expect(page).toHaveURL(`${ssrUrl}/${slug}/new/?creation_draft=${draft}`);
      await expect(draftForm).toHaveAttribute("data-create-draft-id", draft!);
      await expect(draftForm).toHaveAttribute("data-create-draft-actor", owner);
      await expect(draftForm).toHaveAttribute("data-create-draft-organization", orgId);
      await expect(page.getByRole("combobox", { name: "Credential profile", exact: true }).locator(`option[value="${profileId}@1"]`)).toContainText(profileName);
      await expect(page.getByRole("combobox", { name: "Credential profile", exact: true })).toHaveValue("");
      await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
      const currentCsrf = await draftForm.locator('[name="_csrf"]').inputValue();
      const restored = page.waitForResponse((response) => response.url().endsWith(`/${slug}/_fragments/create-draft`));
      await page.getByRole("button", { name: "Restore saved draft", exact: true }).click();
      const restoreResponse = await restored;
      expect(restoreResponse.status()).toBe(200);
      expect(restoreResponse.headers()["cache-control"]).toBe("private, no-store");
      await expect(draftForm.locator('[name="_csrf"]')).toHaveValue(currentCsrf);
      await expect(draftForm).toHaveAttribute("data-create-draft-id", draft!);
      await expect(draftForm).toHaveAttribute("data-create-draft-actor", owner);
      await expect(draftForm).toHaveAttribute("data-create-draft-organization", orgId);
      await expect(page.getByLabel("CPU", { exact: true })).toHaveValue("2000");
      await expect(ttl).toHaveValue("3600s");
      await expect(page.getByRole("combobox", { name: "Credential profile", exact: true })).toHaveValue("");
      await expect(page.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("");
      expect(setupDispatches).toEqual([]);
      await page.getByRole("textbox", { name: "Name", exact: true }).fill(githubCheckoutName);
      const browser = page.locator("[data-github-browser]");
      await expect(browser.getByRole("combobox", { name: "GitHub account" }).locator(`option[value="${profileId}@1"]`)).toContainText("synthetic-user");
      await browser.getByRole("combobox", { name: "GitHub account" }).selectOption(`${profileId}@1`);
      await expect(browser.getByText("Connected as @synthetic-user")).toBeVisible();
      const choices = browser.locator("[data-select-github-repository]");
      await expect(choices).toHaveCount(50);
      const afterPicker = await githubGitCounters();
      expect(afterPicker.appRefresh).toBe(beforePicker.appRefresh + 1);
      await expect(browser.getByRole("button", { name: /synthetic-user\/repository-50/ })).toBeDisabled();
      await browser.getByRole("searchbox", { name: "Find a repository" }).fill("repository-51");
      await expect(browser.getByRole("status")).toContainText("matching repositories found across 2 pages");
      await expect(choices).toHaveCount(1);
      await expect(choices.first()).toContainText("synthetic-user/repository-51");
      await browser.getByRole("searchbox", { name: "Find a repository" }).clear();
      await expect(choices).toHaveCount(50);
      await browser.getByRole("button", { name: "Load more", exact: true }).click();
      await expect(choices).toHaveCount(51);
      await browser.getByRole("button", { name: /synthetic-user\/repository-01/ }).click();
      const source = page.locator("[data-repository-row]").first();
      await expect(source.getByRole("textbox", { name: "Repository URL", exact: true }))
        .toHaveValue("https://github.com/synthetic-user/repository-01.git");
      await expect(source.getByRole("textbox", { name: "Branch", exact: true })).toHaveValue("main");
      await expect(source.getByRole("textbox", { name: "Mount path", exact: true })).toHaveValue("repository-01");
      await expect(page.getByRole("combobox", { name: "Credential profile", exact: true })).toHaveValue("");
      await page.getByRole("combobox", { name: "Credential profile", exact: true }).selectOption(`${profileId}@1`);
      await source.getByRole("textbox", { name: "Branch", exact: true }).fill("my-working-branch");
      await browser.getByRole("button", { name: /synthetic-user\/repository-01/ }).click();
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
      if (await page.locator("[data-create-resources]").getAttribute("open") === null) {
        await page.locator("[data-create-resources] > summary").click();
      }
      await page.getByLabel("Install Command").fill(githubCheckoutInstall);
      await expect(page.getByLabel("Install Command")).toHaveValue(githubCheckoutInstall);
      await page.getByLabel("Delete after").fill("3600s");
      const before = await githubGitCounters();
      expect(setupDispatches).toEqual([]);
      page.off("request", observeSetup);
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
      row = page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row", { hasText: name });

      await expect(row).toContainText("Active");
      await expect(row).toContainText("Generation 2");
      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await page.getByRole("dialog", { name: `Manage ${name}`, exact: true })
        .getByRole("button", { name: "Revoke credential", exact: true }).click();
      await page.getByRole("dialog", { name: `Revoke ${name}?`, exact: true })
        .getByRole("button", { name: "Revoke credential", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-revoked`);
      await expect(page.getByRole("status")).toHaveText("Credential revoked.");
      row = page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row", { hasText: name });
      await expect(row).toContainText("Revoked");
      await expect(row).toContainText("Generation 3");

      await row.getByRole("button", { name: `Manage ${name}`, exact: true }).click();
      await page.getByRole("dialog", { name: `Manage ${name}`, exact: true })
        .getByRole("button", { name: "Delete credential", exact: true }).click();
      await page.getByRole("dialog", { name: `Delete ${name}?`, exact: true })
        .getByRole("button", { name: "Delete credential", exact: true }).click();
      await expect(page).toHaveURL(`${ssrUrl}/settings/credentials/?message=credential-deleted`);
      await expect(page.getByRole("status")).toHaveText("Credential deleted.");
      await expect(page.getByRole("region", { name: "Credentials", exact: true }).locator(".cw-credential-row", { hasText: name })).toHaveCount(0);
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
