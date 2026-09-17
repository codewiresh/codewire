import { expect, test } from "@playwright/test";

// Native successful-controls proof; authorization and pre-dispatch validation
// are covered by owning Rust route tests, not by this design fixture.
test.use({ storageState: { cookies: [], origins: [] }, screenshot: "off", trace: "off" });

test("stale sources retain exact native values until an explicit recovery choice", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native source recovery checks");
  await page.goto(`${origin}/reference/fixtures/source-selection-recovery.html`);
  const form = page.getByRole("form", { name: "Unavailable selection" });
  const project = form.getByLabel("Secret project", { exact: true });
  const profile = form.getByLabel("Credential profile", { exact: true });
  await expect(project).toBeEnabled();
  await expect(profile).toBeEnabled();
  await expect(project).toHaveAccessibleDescription(/Choose no project secrets or an available project/);
  await expect(profile).toHaveAccessibleDescription(/Choose no provider credentials or an available revision/);
  const fields = () => form.evaluate((element: HTMLFormElement) => {
    const data = new FormData(element);
    return { project: data.getAll("secret_project"), profile: data.getAll("credential_profile") };
  });
  expect(await fields()).toEqual({ project: ["6bf8d155-e84c-4fc5-b479-b17022fe41dd"], profile: ["315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@7"] });
  await profile.selectOption("315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@8");
  expect((await fields()).profile).toEqual(["315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@8"]);
  await project.selectOption("315dd4c2-6bf2-4c3b-9d8f-68fc97654a76");
  expect((await fields()).project).toEqual(["315dd4c2-6bf2-4c3b-9d8f-68fc97654a76"]);
  await project.selectOption("");
  await profile.selectOption("");
  expect(await fields()).toEqual({ project: [""], profile: [""] });
});

for (const name of ["Catalog unavailable", "Catalog load failed"]) {
test(`${name} keeps exact metadata without duplicate successful names`, async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for native source recovery checks");
  await page.goto(`${origin}/reference/fixtures/source-selection-recovery.html`);
  const form = page.getByRole("form", { name, exact: true });
  await expect(form.getByLabel("Secret project", { exact: true })).toBeDisabled();
  await expect(form.getByLabel("Credential profile", { exact: true })).toBeDisabled();
  expect(await form.evaluate((element: HTMLFormElement) => {
    const data = new FormData(element);
    return Object.fromEntries(["secret_project", "credential_profile", "include_org_secrets", "include_user_secrets"].map((name) => [name, data.getAll(name)]));
  })).toEqual({ secret_project: ["6bf8d155-e84c-4fc5-b479-b17022fe41dd"], credential_profile: ["315dd4c2-6bf2-4c3b-9d8f-68fc97654a76@7"], include_org_secrets: ["platform"], include_user_secrets: ["platform"] });
});
}
