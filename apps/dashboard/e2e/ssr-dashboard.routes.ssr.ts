import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getUserId } from "./helpers/db";
import { cleanupTestOrg, ensureTestOrg } from "./helpers/org";
import { USERS } from "./helpers/seed";

const dashboardDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const authState = path.join(dashboardDir, "playwright/.auth/user.json");
const ssrUrl = (process.env.PLAYWRIGHT_BASE_URL || "http://127.0.0.1:5173").replace(/\/$/, "");
const cleanRoutesOrgSlug = "e2e-clean-routes";
// A second organization, so switching never depends on data from other specs.
const switchRoutesOrgSlug = "e2e-clean-routes-switch";

test.describe("homepage", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("story assets and sign-in stay on the Rust origin", async ({ page }) => {
    const requests: string[] = [];
    const errors: string[] = [];
    page.on("request", (request) => requests.push(request.url()));
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    const response = await page.goto("/");
    expect(response?.status()).toBe(200);
    expect(response?.headers()["content-security-policy"]).not.toContain("unsafe-inline");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Cloud environments for agents and their humans.");
    await expect(page.locator(".cw-brand img")).toHaveAttribute("alt", "Codewire");
    await expect(page.locator("script:not([src]), style")).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Read the docs" })).toHaveAttribute("href", "/docs");
    await expect(page.getByRole("link", { name: "See pricing →" })).toHaveAttribute("href", "/docs/reference/subscription-plans");
    await expect(page.getByRole("link", { name: "Request access" }).last()).toHaveAttribute("href", "/signup");
    expect(await page.locator("body").evaluate((body) => body.scrollWidth <= window.innerWidth)).toBe(true);
    await page.waitForLoadState("networkidle");
    expect(errors).toEqual([]);
    await page.getByRole("link", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(`${ssrUrl}/login`);
    await expect(page.getByRole("heading", { name: "Log in to Codewire", exact: true })).toBeVisible();
    expect(requests.every((url) => url.startsWith(`${ssrUrl}/`))).toBe(true);
  });

  test("network modes support keyboard interaction", async ({ page }) => {
    await page.goto("/");
    const mesh = page.getByRole("button", { name: "Encrypted meshes" });
    await mesh.focus();
    await mesh.press("Enter");
    await expect(mesh).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator(".cw-parallel-state--mesh")).toHaveAttribute("aria-hidden", "false");
    await expect(page.locator("#parallel-operator-meta")).toHaveText("4 sessions");
    await page.getByRole("button", { name: "Independent sessions" }).click();
    await expect(mesh).toHaveAttribute("aria-pressed", "false");
    await expect(page.locator(".cw-parallel-state--independent")).toHaveAttribute("aria-hidden", "false");
  });

  test("reduced motion shows the complete workflow", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    const steps = page.locator(".cw-workflow-list > li");
    await expect(steps).toHaveCount(9);
    for (const step of await steps.all()) {
      await expect(step).toBeVisible();
      await expect(step).toHaveCSS("opacity", "1");
    }
    await expect(page.locator(".cw-workflow-terminal-column")).toBeHidden();
    await expect(page.locator(".cw-flow-packet").first()).toBeHidden();
    await page.emulateMedia({ reducedMotion: "no-preference" });
    await expect(page.locator(".cw-workflow-stage")).toHaveClass(/is-enhanced/);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await expect(page.locator(".cw-workflow-stage")).not.toHaveClass(/is-enhanced/);
    for (const step of await steps.all()) await expect(step).toHaveCSS("opacity", "1");
  });

  test("without JavaScript the workflow and access link remain usable", async ({ browser }) => {
    const context = await browser.newContext({ baseURL: ssrUrl, javaScriptEnabled: false, storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();
    try {
      await page.goto("/");
      const steps = page.locator(".cw-workflow-list > li");
      await expect(steps).toHaveCount(9);
      for (const step of await steps.all()) {
        await expect(step).toBeVisible();
        await expect(step).toHaveCSS("opacity", "1");
      }
      await expect(page.getByRole("link", { name: "Request access" }).last()).toHaveAttribute("href", "/signup");
      await expect(page.locator(".cw-parallel-mode-switch")).toBeHidden();
    } finally {
      await context.close();
    }
  });
});

test.describe("server-rendered public, auth, and account routes", () => {
  test.beforeAll(async ({}, testInfo) => {
    if (testInfo.project.use.isMobile) return;
    const ownerId = await getUserId(USERS.master.email);
    if (!ownerId) throw new Error(`Missing clean-routes fixture owner ${USERS.master.email}`);
    await ensureTestOrg("Clean Routes Organization", cleanRoutesOrgSlug, ownerId);
    await ensureTestOrg("Switch Routes Organization", switchRoutesOrgSlug, ownerId);
  });

  test.afterAll(async ({}, testInfo) => {
    if (testInfo.project.use.isMobile) return;
    await cleanupTestOrg(cleanRoutesOrgSlug);
    await cleanupTestOrg(switchRoutesOrgSlug);
  });

  test("password-reset token is moved to a scoped HttpOnly cookie and removed from the URL", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop security contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    const token = "opaque-reset-token-for-browser-proof";
    await page.goto(`/reset-password?token=${token}`);
    await expect(page).toHaveURL(`${ssrUrl}/reset-password`);
    await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
    expect(await page.content()).not.toContain(token);
    const resetCookie = (await context.cookies()).find((cookie) => cookie.name === "codewire_password_reset");
    expect(resetCookie).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/reset-password" });
    await context.close();
  });

  test("unauthenticated device approval keeps a local continuation", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "covered by the desktop redirect contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    await page.goto("/device?user_code=ABCD-1234");
    await expect(page).toHaveURL(
      `${ssrUrl}/login?return_to=%2Fdevice%3Fuser_code%3DABCD-1234`,
    );
    await context.close();
  });

  test("device code entry groups and distributes all eight characters", async ({ page }) => {
    await page.goto("/device");

    const group = page.getByRole("group", { name: "Device code" });
    const slots = group.getByRole("textbox");
    const slotValues = () => slots.evaluateAll((inputs) => inputs.map((input) => (
      input instanceof HTMLInputElement ? input.value : ""
    )));
    await expect(slots).toHaveCount(8);
    // Count and overflow checks also pass a vertical stack. Protect the actual
    // four-separator-four row on every configured desktop/mobile viewport.
    await expect(page.locator('link[href="/assets/codewire/routes/auth-v2.css"]')).toHaveCount(1);
    const boxes = await slots.evaluateAll((inputs) => inputs.map((input) => {
      const { x, y, width, height } = input.getBoundingClientRect();
      return { x, y, width, height };
    }));
    for (let index = 0; index < boxes.length; index += 1) {
      expect(boxes[index].width).toBeGreaterThan(0);
      expect(boxes[index].height).toBeGreaterThan(0);
      expect(Math.abs(boxes[index].y - boxes[0].y)).toBeLessThanOrEqual(1);
      if (index > 0) expect(boxes[index].x).toBeGreaterThanOrEqual(boxes[index - 1].x + boxes[index - 1].width);
    }
    await expect(group.locator(".cw-device-code-separator")).toHaveText("-");
    await expect(group.locator(".cw-device-code-separator")).toHaveAttribute("aria-hidden", "true");
    await expect(slots.first()).toHaveAttribute("autocomplete", "one-time-code");
    await expect(slots.first()).toHaveAttribute("inputmode", "text");
    for (let index = 0; index < 8; index += 1) {
      await expect(page.getByLabel(`Character ${index + 1} of 8`)).toHaveCount(1);
    }

    await slots.first().focus();
    await page.keyboard.type("bcdf-ghjk");
    expect(await slotValues()).toEqual("BCDFGHJK".split(""));

    await page.keyboard.press("Backspace");
    await page.keyboard.press("Backspace");
    await expect(slots.nth(6)).toBeFocused();
    expect(await slotValues()).toEqual(["B", "C", "D", "F", "G", "H", "", ""]);

    const paste = async (value: string) => slots.first().evaluate((input, pasted) => {
      const clipboard = new DataTransfer();
      clipboard.setData("text", pasted);
      input.dispatchEvent(new ClipboardEvent("paste", {
        bubbles: true,
        cancelable: true,
        clipboardData: clipboard,
      }));
    }, value);
    await paste("bcdf-ghjk");
    expect(await slotValues()).toEqual("BCDFGHJK".split(""));
    await paste("bcdfghjk");
    expect(await slotValues()).toEqual("BCDFGHJK".split(""));

    await slots.first().fill("ghjkbcdf");
    expect(await slotValues()).toEqual("GHJKBCDF".split(""));
    await paste("bcdf!ghjk");
    expect(await slotValues()).toEqual("GHJKBCDF".split(""));
    await paste("bcdf-ghjkx");
    expect(await slotValues()).toEqual("GHJKBCDF".split(""));
    await slots.first().fill("bcdf-ghjkx");
    expect(await slotValues()).toEqual("GHJKBCDF".split(""));
    expect(await page.locator("body").evaluate((body) => body.scrollWidth <= window.innerWidth)).toBe(true);
  });

  test("settings render the current account surfaces and no-JS forms", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop settings contract");
    const response = await page.goto("/settings/");
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Account", exact: true }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "GitHub", exact: true })).toHaveCount(0);
    for (const name of ["Account details", "Security", "Active sessions"]) {
      await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
    }
    await expect(page.getByRole("heading", { name: /Git (commit )?identity/i })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Git authentication" })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "SSH key" })).toHaveCount(0);
    await expect(page.locator('form[action^="/settings/_actions/credentials/"]')).toHaveCount(0);
    await expect(page.locator('form[action^="/settings/_actions/ssh/"]')).toHaveCount(0);
    await expect(page.locator('form[action^="/settings/_actions/github/"]')).toHaveCount(0);
    await expect(page.locator('a[href*="/api/v1/github/"]')).toHaveCount(0);
    await expect(page.locator('form#sign-out[action="/settings/_actions/sign-out"]')).toHaveCount(1);
    await expect(page.locator('.cw-sidebar-slot form[data-sign-out][method="post"][action="/settings/_actions/sign-out"]')).toHaveCount(1);
    await expect(page.locator('a[href$="#sign-out"]')).toHaveCount(0);
    await expect(page.locator('input[name="_csrf"]')).not.toHaveCount(0);
  });

  test("credential settings expose write-only enrollment and identity-only profile forms", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop credential settings contract");
    const response = await page.goto("/settings/credentials/");
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Credentials", exact: true, level: 1 })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Profiles", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Git commit identity", exact: true })).toBeVisible();
    await expect(page.locator("dialog[open]")).toHaveCount(0);
    await expect(page.locator('form[action="/settings/credentials/_actions/profiles/create"]')).toHaveCount(1);
    await expect(page.locator('form[action$="/credentials/oauth/enroll"]')).toHaveCount(1);
    await expect(page.locator('form[action$="/github/authorize"]')).toHaveCount(1);
    for (const provider of ["GitHub", "Codex"]) {
      await page.getByRole("button", { name: "Add credential", exact: true }).click();
      await page.getByRole("dialog", { name: "Add credential", exact: true })
        .getByRole("button", { name: provider, exact: true }).click();
      const connection = page.getByRole("dialog", { name: provider === "GitHub" ? "Connect GitHub" : "Connect Codex", exact: true });
      if (provider === "GitHub") {
        const github = connection.locator("form");
        await expect(github).toHaveAttribute("action", "/settings/credentials/_actions/github/authorize");
        await expect(github.locator('[name="name"]')).toHaveCount(0);
        const submit = connection.getByRole("button", { name: "Continue to GitHub", exact: true });
        await expect(submit).toBeVisible();
        expect(await submit.evaluate((button: HTMLButtonElement) => button.form?.id)).toBe("connect-github-form");
      } else {
        await expect(connection.locator("form"))
          .toHaveAttribute("action", "/settings/credentials/_actions/credentials/oauth/enroll");
        await expect(connection).toContainText(/enable device code authorization for Codex/i);
        await expect(connection.getByRole("link", { name: "ChatGPT Security settings", exact: true }))
          .toHaveAttribute("href", "https://chatgpt.com/#settings/Security");
      }
      await connection.getByRole("button", { name: "Cancel", exact: true }).click();
    }
    await page.getByRole("button", { name: "Create profile", exact: true }).click();
    const profileName = page.getByRole("textbox", { name: "Profile name", exact: true });
    await expect(profileName).toHaveAttribute("maxlength", "128");
    await expect(profileName).toHaveAccessibleDescription(/lowercase letters/);
    for (const name of ["Work", "work profile", "-work", "work."]) {
      await profileName.fill(name);
      expect(await profileName.evaluate((input: HTMLInputElement) => input.validity.patternMismatch)).toBe(true);
    }
    await profileName.fill("work_1.github");
    expect(await profileName.evaluate((input: HTMLInputElement) => input.checkValidity())).toBe(true);
    await profileName.clear();
    await page.getByRole("dialog", { name: "Create profile", exact: true })
      .getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(page.locator('form[action$="/credentials/api-key/add"]')).toHaveCount(2);
    await expect(page.locator('form[action$="/credentials/ssh/generate"]')).toHaveCount(1);
    await expect(page.locator('form[action$="/credentials/ssh/import"]')).toHaveCount(1);
    const protectedInputs = page.locator('#add-openai-api-key input[type="password"], #add-anthropic-api-key input[type="password"], #import-ssh input[type="password"]');
    await expect(protectedInputs).toHaveCount(3);
    await expect(protectedInputs.nth(0)).toHaveValue("");
    await expect(protectedInputs.nth(1)).toHaveValue("");
    await expect(protectedInputs.nth(2)).toHaveValue("");
    await expect(page.locator('textarea[name="private_key"]')).toHaveValue("");
  });

  test("clean console routes redirect canonically and legacy paths stay retired", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop clean-route contract");
    await page.goto("/dashboard/");
    const organizationRoot = await page
      .locator(".cw-sidebar-slot")
      .getByRole("link", { name: "View all sandboxes" })
      .getAttribute("href");
    expect(organizationRoot).toMatch(/^\/[a-z0-9-]+\/$/);
    const snapshotsHref = `${organizationRoot}snapshots/`;

    for (const canonical of ["/dashboard/", snapshotsHref!]) {
      const response = await page.request.get(canonical.slice(0, -1), { maxRedirects: 0 });
      expect(response.status()).toBe(308);
      expect(response.headers().location).toBe(canonical);
    }

    for (const legacy of [
      "/dashboard/settings",
      "/dashboard/orgs/legacy/environments",
      "/terminal/legacy/environment",
      "/favicon.ico",
    ]) {
      expect((await page.request.get(legacy)).status()).toBe(404);
    }
    expect((await page.request.get(`${organizationRoot}not-a-uuid/`)).status()).toBe(404);
    expect((await page.request.get("/dashboard/?org=not-a-member")).status()).toBe(404);

    const snapshots = await page.goto(snapshotsHref!);
    expect(snapshots?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Snapshots", exact: true })).toBeVisible();
    // An unavailable feature says so once; it offers no inactive controls.
    await expect(page.getByText("Snapshots are not available yet.", { exact: false })).toBeVisible();
    await expect(page.getByRole("button", { name: "Create Snapshot" })).toHaveCount(0);
  });

  test("Account and Credentials preserve authenticated navigation with consolidated sections", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop account contract");
    for (const [route, heading] of [
      ["/settings/", "Account"],
      ["/settings/credentials/", "Credentials"],
      ["/settings/secrets/", "Secrets"],
      ["/settings/security/", "Security"],
      ["/settings/sessions/", "Active sessions"],
    ] as const) {
      const response = await page.goto(route);
      expect(response?.status()).toBe(200);
      await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
      if (route.includes("security") || route.includes("sessions")) {
        await expect(page).toHaveURL(`/settings/#${route.includes("security") ? "security" : "sessions"}`);
        await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
      }
    }
  });

  test("personal and admin routes carry no organization and switching stays on the page", async ({ page, isMobile }) => {
    test.skip(!!isMobile, "desktop organization-context contract");

    for (const route of ["/settings/", "/settings/credentials/", "/settings/secrets/"]) {
      const switched = await page.request.get(`${route}?org=${cleanRoutesOrgSlug}`, { maxRedirects: 0 });
      expect(switched.status()).toBe(303);
      expect(switched.headers().location).toBe(route);
      const response = await page.goto(`${route}?org=${cleanRoutesOrgSlug}`);
      expect(response?.status()).toBe(200);
      await expect(page).toHaveURL(route);
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
        "Clean Routes Organization",
      );
      await expect(page.locator(".cw-sidebar-slot").getByRole("link", { name: "Settings" }))
        .toHaveAttribute("href", "/settings/");
      // Only the switcher's relative links name an organization.
      await expect(page.locator('a[href*="org="]:not([href^="?org="])')).toHaveCount(0);
      await expect(page.locator('form[action*="org="]')).toHaveCount(0);
    }
    for (const section of ["security", "sessions"]) {
      await page.goto(`/settings/${section}/`);
      await expect(page).toHaveURL(`/settings/#${section}`);
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
        "Clean Routes Organization",
      );
    }

    // Switching organization from a personal page keeps the page.
    await page.goto("/settings/credentials/");
    await page.locator(".cw-sidebar-slot .cw-org-switcher summary").click();
    const other = switchRoutesOrgSlug;
    await page.locator(`.cw-sidebar-slot .cw-org-menu a[href="?org=${other}"]`).click();
    await expect(page).toHaveURL("/settings/credentials/");
    await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText(
      "Switch Routes Organization",
    );

    // Switching from an organization page keeps its section.
    await page.goto(`/${cleanRoutesOrgSlug}/snapshots/`);
    await page.locator(".cw-sidebar-slot .cw-org-switcher summary").click();
    await page.locator(`.cw-sidebar-slot .cw-org-menu a[href="?org=${other}"]`).click();
    await expect(page).toHaveURL(`/${other}/snapshots/`);

    // The account home is the remembered organization's home.
    const home = await page.request.get("/dashboard/", { maxRedirects: 0 });
    expect(home.status()).toBe(303);
    expect(home.headers().location).toBe(`/${other}/`);

    const adminRedirect = await page.request.get(`/admin/?org=${cleanRoutesOrgSlug}`, {
      maxRedirects: 0,
    });
    expect(adminRedirect.status()).toBe(303);
    expect(adminRedirect.headers().location).toBe("/admin/");

    for (const route of [
      "/settings/?org=not-a-member",
      "/settings/credentials/?org=not-a-member",
      "/settings/secrets/?org=not-a-member",
    ]) {
      const response = await page.goto(route);
      expect(response?.status()).toBe(200);
      await expect(page).toHaveURL(route.split("?")[0]);
      await expect(page.locator(".cw-context-nav").getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
      await expect(page.locator('a[href*="not-a-member"]')).toHaveCount(0);
      await expect(page.locator(".cw-sidebar-slot .cw-org-switcher-label")).toHaveText("Choose organization");
    }
    for (const route of ["/admin/?org=not-a-member", "/admin/billing/?org=not-a-member", "/admin/audit/?org=not-a-member"]) {
      const response = await page.goto(route);
      expect(page.url()).not.toContain("not-a-member");
      expect(response?.status()).toBe(200);
    }
  });

  test("auth layout remains responsive on mobile", async ({ page, isMobile }) => {
    test.skip(!isMobile, "mobile visual contract");
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Log in to Codewire", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Log in to Codewire", exact: true })).toBeInViewport();
  });
});

test.describe("server-rendered no-JavaScript auth", () => {
  test.use({ storageState: authState });

  test("wrong credentials return a safe complete HTML page without reflecting secrets", async ({ browser, isMobile }) => {
    test.skip(!!isMobile, "desktop no-JavaScript contract");
    const context = await browser.newContext({
      baseURL: ssrUrl,
      javaScriptEnabled: false,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    await page.goto("/login");
    const password = "NeverReflectThisPassword9!";
    await page.getByLabel("Email").fill("not-a-real-user@example.test");
    await page.getByLabel("Password").fill(password);
    const responsePromise = page.waitForResponse((response) => (
      response.url().endsWith("/login/_actions/sign-in")
      && response.request().method() === "POST"
    ));
    await page.getByLabel("Password").press("Enter");
    const response = await responsePromise;
    expect(response.status()).toBe(401);
    await expect(page.getByRole("alert")).toContainText("Email or password is incorrect");
    expect(await page.content()).not.toContain(password);
    await context.close();
  });
});
