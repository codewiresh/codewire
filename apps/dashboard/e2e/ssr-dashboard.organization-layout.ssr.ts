import { expect, test } from "./helpers/fixture-test";

test.use({ storageState: { cookies: [], origins: [] } });

test("Create Organization keeps a readable title and bounded form at desktop and mobile widths", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-organization.html`);

  const title = page.getByRole("heading", { name: "Create Organization", exact: true });
  const form = page.locator("#organization-form");
  await expect(title).toBeVisible();
  await expect(page.getByLabel("Organization name", { exact: true })).toBeVisible();
  await expect(page.locator(".cw-form-icon")).toHaveCount(0);
  await expect(page.getByText("Organizations group your Sandboxes and team members together")).toHaveCount(0);

  const layout = await page.evaluate(() => {
    const panel = document.querySelector(".cw-form-page") as HTMLElement;
    const heading = document.querySelector(".cw-form-page .cw-page-title") as HTMLElement;
    const input = document.querySelector("#organization-name") as HTMLElement;
    return {
      viewport: innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      panelWidth: panel.getBoundingClientRect().width,
      inputWidth: input.getBoundingClientRect().width,
      textTransform: getComputedStyle(heading).textTransform,
      fontSize: parseFloat(getComputedStyle(heading).fontSize),
    };
  });
  expect(layout.documentWidth).toBeLessThanOrEqual(layout.viewport);
  expect(layout.panelWidth).toBeLessThanOrEqual(512);
  expect(layout.inputWidth).toBeLessThan(layout.panelWidth);
  expect(layout.textTransform).toBe("none");
  expect(layout.fontSize).toBeGreaterThanOrEqual(24);
  await expect(form.getByRole("button", { name: "Create Organization" })).toBeVisible();
});

test("the sidebar stays a sidebar except on a phone and keeps its footer at the bottom without an organization", async ({ browser }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system and set CODEWIRE_DESIGN_ORIGIN for fixture checks");
  // Each case opens its own context: the mobile project emulates touch, and touch decides here.
  const open = async (width: number, hasTouch: boolean) => {
    const context = await browser.newContext({ hasTouch, viewport: { width, height: 900 } });
    const page = await context.newPage();
    await page.goto(`${origin}/reference/fixtures/settings-secrets-empty.html`);
    return { context, sidebar: page.locator(".cw-sidebar-slot .cw-sidebar"), mobileBar: page.locator(".cw-mobile-bar"), page };
  };

  // A mouse keeps the sidebar down to 640px; a touch screen keeps it above 768px.
  for (const [width, hasTouch] of [[640, false], [715, false], [768, false], [1023, false], [1440, false], [769, true]] as const) {
    const { context, sidebar, mobileBar, page } = await open(width, hasTouch);
    try {
      await expect(sidebar).toBeVisible();
      await expect(mobileBar).toBeHidden();
      const gap = await page.evaluate(() => {
        const column = document.querySelector(".cw-sidebar-slot .cw-sidebar") as HTMLElement;
        const footer = column.querySelector(".cw-console-footer") as HTMLElement;
        return column.getBoundingClientRect().bottom - footer.getBoundingClientRect().bottom;
      });
      expect(gap, `footer distance from the sidebar's bottom at ${width}px`).toBeLessThanOrEqual(1);
    } finally {
      await context.close();
    }
  }

  // A phone: any screen narrower than 640px, or a touch screen up to 768px.
  for (const [width, hasTouch] of [[639, false], [768, true]] as const) {
    const { context, sidebar, mobileBar } = await open(width, hasTouch);
    try {
      await expect(mobileBar).toBeVisible();
      await expect(sidebar).toBeHidden();
    } finally {
      await context.close();
    }
  }
});
