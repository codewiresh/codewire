import { expect, test } from "./helpers/fixture-test";

// Editable Account fixture with production dialog behavior. Synthetic POSTs
// are intercepted externally; no instrumentation enters the product assets.
test.use({ storageState: { cookies: [], origins: [] } });

test("Account sections share a page and exact-session confirmation cancels safely", { tag: "@mobile" }, async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const requests: string[] = [];
  await page.route("**/settings/_actions/sessions/revoke", async (route) => {
    requests.push(route.request().postData() || "");
    await route.fulfill({ status: 200, contentType: "text/plain", body: "Synthetic session signed out" });
  });
  await page.goto(`${origin}/reference/fixtures/settings-account.html`);
  for (const name of ["Account details", "Security", "Active sessions"]) {
    await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
  }
  await expect(page.getByRole("link", { name: "Credentials", exact: true })).toHaveAttribute("href", "settings-credentials.html");
  const button = page.getByRole("button", { name: "Sign out session", exact: true });
  await button.click();
  const dialog = page.getByRole("dialog", { name: "Sign out session?", exact: true });
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeFocused();
  await expect(dialog).toContainText("session-other");
  await expect(dialog.locator('[name="account_id"]')).toHaveValue("fixture-account");
  await expect(dialog.locator('[name="session_id"]')).toHaveValue("session-other");
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(button).toBeFocused();
  expect(requests).toEqual([]);
  await button.click();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(button).toBeFocused();
  expect(requests).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("account-sections.png"), fullPage: true });
  await button.click();
  await dialog.getByRole("button", { name: "Sign out session", exact: true }).click();
  await expect(page.getByText("Synthetic session signed out", { exact: true })).toBeVisible();
  expect(requests).toHaveLength(1);
  const form = new URLSearchParams(requests[0]);
  expect(Object.fromEntries(form)).toEqual({ _csrf: "design-fixture-only", account_id: "fixture-account", session_id: "session-other" });
});

const fixture = (name: string) => `${process.env.CODEWIRE_DESIGN_ORIGIN}/reference/fixtures/${name}`;

test("Security replaces the authenticator and regenerates codes through focused proof dialogs", { tag: "@mobile" }, async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const posts: { url: string; body: string }[] = [];
  for (const path of ["replace/start", "recovery-codes/regenerate"]) {
    await page.route(`**/settings/_actions/two-factor/${path}`, async (route) => {
      posts.push({ url: route.request().url(), body: route.request().postData() || "" });
      await route.fulfill({ status: 200, contentType: "text/plain", body: `Synthetic ${path} accepted` });
    });
  }
  await page.goto(fixture("settings-account.html"));
  const security = page.getByRole("region", { name: "Security", exact: true });
  await expect(security).toContainText("Sign-in asks for a code from your authenticator app. Recovery codes each work once.");
  for (const [launcher, title, submit] of [
    ["Replace authenticator", "Replace authenticator", "Continue"],
    ["Regenerate recovery codes", "Regenerate recovery codes", "Regenerate codes"],
  ]) {
    const submitted = posts.length;
    const button = security.getByRole("button", { name: launcher, exact: true });
    await button.click();
    const proof = page.getByRole("dialog", { name: title, exact: true });
    const password = proof.getByLabel("Password", { exact: true });
    const code = proof.getByLabel("Current code or recovery code", { exact: true });
    await expect(password).toBeFocused();
    await expect(proof).toContainText(/keeps? working/);
    await password.fill("synthetic-password-canary");
    await code.fill("123456");
    // Cancelling clears the write-only values and returns focus to the launcher.
    await page.keyboard.press("Escape");
    await expect(proof).not.toBeVisible();
    await expect(button).toBeFocused();
    await button.click();
    await expect(password).toHaveValue("");
    await expect(code).toHaveValue("");
    await proof.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(proof).not.toBeVisible();
    await expect(button).toBeFocused();
    expect(posts).toHaveLength(submitted);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await button.click();
    await password.fill("synthetic-password-canary");
    await code.fill("abcdef0123");
    await proof.getByRole("button", { name: submit, exact: true }).click();
    await expect(page.getByText(/^Synthetic .* accepted$/)).toBeVisible();
    await page.goto(fixture("settings-account.html"));
  }
  expect(posts).toHaveLength(2);
  for (const post of posts) {
    // Secrets travel only in the POST body, never in a URL.
    expect(new URL(post.url).search).toBe("");
    expect(Object.fromEntries(new URLSearchParams(post.body))).toEqual({
      _csrf: "design-fixture-only", account_id: "fixture-account",
      password: "synthetic-password-canary", proof: "abcdef0123",
    });
  }
  expect(errors).toEqual([]);
});

test("the new-authenticator state shows its one-time key and code field", { tag: "@mobile" }, async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(fixture("settings-account-replace-authenticator.html"));
  const confirm = page.getByRole("dialog", { name: "Add your new authenticator", exact: true });
  await expect(confirm).toBeVisible();
  await expect(confirm.getByRole("img", { name: "QR code for your new authenticator", exact: true })).toBeVisible();
  await expect(confirm.getByTestId("replacement-totp-secret")).toHaveText("GALLERYEXAMPLEKEYNOTAREALSECRET2");
  await expect(confirm.getByLabel("Code from your new authenticator", { exact: true })).toBeFocused();
  await expect(confirm).toContainText("Your current authenticator keeps working until you confirm.");
  await expect(confirm.getByRole("button", { name: "Replace authenticator", exact: true })).toBeVisible();
  expect(await confirm.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("account-new-authenticator.png") });
});

test("the replaced state shows ten new codes and withholds revoked sessions", { tag: "@mobile" }, async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  await page.goto(fixture("settings-account-authenticator-replaced.html"));
  const done = page.getByRole("dialog", { name: "Authenticator replaced", exact: true });
  await expect(done).toBeVisible();
  await expect(done.getByRole("status")).toContainText("your other browsers were signed out");
  await expect(done.getByRole("list", { name: "New recovery codes", exact: true }).getByRole("listitem")).toHaveCount(10);
  await expect(done.getByRole("link", { name: "Done", exact: true })).toHaveAttribute("href", "settings-account.html#security");
  await expect(page.getByText("session-other")).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("account-authenticator-replaced.png") });
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("factor dialogs open through native GET launchers and one-time states render in place", async ({ page }) => {
    test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
    await page.goto(fixture("settings-account.html"));
    for (const [name, value] of [
      ["Replace authenticator", "replace-authenticator"],
      ["Regenerate recovery codes", "regenerate-recovery-codes"],
    ]) {
      const launcher = page.locator("form.cw-dialog-launcher").filter({ has: page.locator(`input[name="dialog"][value="${value}"]`) });
      await expect(launcher).toHaveAttribute("method", "get");
      await expect(launcher).toHaveAttribute("action", `settings-account.html#${value}`);
      await expect(launcher.locator("input")).toHaveCount(1);
      await expect(launcher.getByRole("button", { name, exact: true })).toHaveAttribute("type", "submit");
    }
    const opened = page.waitForRequest((request) => request.url().includes("dialog=replace-authenticator"));
    await page.route("**/settings-account.html?**", (route) => route.fulfill({ status: 204 }));
    await page.getByRole("button", { name: "Replace authenticator", exact: true }).click();
    expect(Object.fromEntries(new URL((await opened).url()).searchParams)).toEqual({ dialog: "replace-authenticator" });

    await page.goto(fixture("settings-account-replace-authenticator.html"));
    await expect(page.locator("#replace-authenticator-confirm")).toBeVisible();
    await expect(page.getByTestId("replacement-totp-secret")).toBeVisible();
    await expect(page.locator("#replace-authenticator")).toBeHidden();
    const cancel = page.locator("#replace-authenticator-confirm form.cw-dialog-launcher");
    await expect(cancel).toHaveAttribute("method", "get");
    await expect(cancel).toHaveAttribute("action", "settings-account.html#security");
  });
});

test("Account deletion is a danger card, confirmed by typing the email, and refused for a sole owner", { tag: "@mobile" }, async ({ page }) => {
  test.skip(!process.env.CODEWIRE_DESIGN_ORIGIN, "Run make design-system with CODEWIRE_DESIGN_ORIGIN");
  const posts: string[] = [];
  await page.route("**/settings/_actions/delete-account", async (route) => {
    posts.push(route.request().postData() || "");
    await route.fulfill({ status: 200, contentType: "text/plain", body: "Synthetic deletion started" });
  });

  await page.goto(fixture("settings-account.html"));
  const card = page.getByRole("region", { name: "Delete account", exact: true });
  await expect(card).toBeVisible();
  await expect(card.getByRole("link", { name: "Delete account", exact: true })).toHaveAttribute("href", "settings-delete-account.html");

  await page.goto(fixture("settings-delete-account.html"));
  const confirm = page.getByRole("region", { name: "Delete your account", exact: true });
  await expect(confirm).toContainText("Owner's sandbox lab");
  await expect(confirm).toContainText("You leave");
  await expect(confirm).toContainText("The remaining credit of €37.50 is forfeited.");
  const email = confirm.getByLabel("Type owner@example.test to confirm");
  const submit = confirm.getByRole("button", { name: "Delete account", exact: true });
  const opacity = () => submit.evaluate((button) => Number(getComputedStyle(button).opacity));
  // Empty and wrong addresses leave the button unavailable, and the browser
  // refuses the submit.
  for (const value of ["", "someone@example.test"]) {
    await email.fill(value);
    expect(await opacity()).toBeLessThan(1);
    await submit.click();
    expect(posts).toEqual([]);
  }
  await email.fill("owner@example.test");
  expect(await opacity()).toBe(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await submit.click();
  await expect(page.getByText("Synthetic deletion started", { exact: true })).toBeVisible();
  expect(posts).toHaveLength(1);
  expect(Object.fromEntries(new URLSearchParams(posts[0]))).toEqual({
    _csrf: "design-fixture-only",
    account_id: "fixture-account",
    confirm_email: "owner@example.test",
  });

  await page.goto(fixture("settings-delete-account-blocked.html"));
  const blocked = page.getByRole("region", { name: "Transfer or delete these organizations first", exact: true });
  await expect(blocked.getByRole("link", { name: "Acme Platform", exact: true })).toHaveAttribute("href", "/acme-platform/members/");
  await expect(page.locator('form[action="/settings/_actions/delete-account"]')).toHaveCount(0);
});
