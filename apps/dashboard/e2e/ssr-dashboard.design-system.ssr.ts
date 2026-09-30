import { readdirSync, readFileSync } from "node:fs";

import { expect, test, type Page } from "@playwright/test";

test.use({ storageState: { cookies: [], origins: [] }, contextOptions: { reducedMotion: "reduce" } });

// The rendered side of the design contract: what Chromium draws for every
// editable fixture page at the project's desktop or mobile width. The token
// guard (scripts/checks/repo_checks.py design-tokens) owns the source side.
//
// `pending` caps the findings each fixture may still have per width, owned by a
// W2A burn-down slice (#2203). More findings than the cap fails, and so does a
// cap whose page is now clean: delete the entry so the list only shrinks.
// Incidental improvements below the cap pass without bookkeeping.
type Check = "scale" | "contrast" | "focus";
type Viewport = "desktop" | "mobile";
type Pending = Partial<Record<`${Viewport} ${Check}`, number>>;

const pending: Record<string, Pending> = {
  // Shell and organizations slice: dashboard.css, organizations.css
  "application-secrets.html": { "desktop scale": 4, "desktop contrast": 1, "mobile scale": 4, "mobile contrast": 1 },
  "sandboxes.html": { "desktop scale": 1, "desktop contrast": 2, "mobile contrast": 2 },
  "settings-secrets-empty.html": { "desktop scale": 2, "desktop contrast": 1 },
  "terminal-tabs.html": { "desktop contrast": 2 },
  // Auth and public slice: auth.css, public.css
  "home.html": { "desktop scale": 62, "desktop contrast": 17, "mobile scale": 57, "mobile contrast": 17 },
  "login.html": { "desktop scale": 3, "desktop focus": 1, "mobile scale": 3, "mobile focus": 1 },
  "signup.html": { "desktop scale": 6, "desktop focus": 2, "mobile scale": 6, "mobile focus": 2 },
};

const fixtureDirectory = new URL("../../../packages/codewire-design/reference/fixtures/", import.meta.url);
// Whole pages only. A fragment such as terminal-ports.html has no stylesheets of
// its own: terminal.html loads it into the ports dialog, which
// ssr-dashboard.terminal-renderer.ssr.ts exercises. It is not measured here.
const fixtures = readdirSync(fixtureDirectory)
  .filter((name) => name.endsWith(".html"))
  .filter((name) => /^<!doctype html>/i.test(readFileSync(new URL(name, fixtureDirectory), "utf8").trimStart()))
  .sort();

test("every pending exception names an existing fixture", () => {
  expect(Object.keys(pending).filter((name) => !fixtures.includes(name))).toEqual([]);
});

// Font sizes, radii, contrast and native select rendering, measured in the page.
async function inspect(page: Page) {
  return page.evaluate(() => {
    const px = (value: string) => Number.parseFloat(value);
    const fontScale = new Set([11, 12, 13, 14, 17]);
    const onFontScale = (size: number) => fontScale.has(size) || (size >= 24 && size <= 30);
    const onRadiusScale = (value: string) =>
      value.endsWith("%") || [0, 4, 8, 12].includes(px(value)) || px(value) >= 999;
    const shown = (element: Element) => {
      const style = getComputedStyle(element);
      const box = element.getBoundingClientRect();
      return style.visibility !== "hidden" && style.display !== "none" && box.width > 1 && box.height > 1;
    };
    const ownText = (element: Element) =>
      [...element.childNodes].some((node) => node.nodeType === Node.TEXT_NODE && node.textContent?.trim());
    const describe = (element: Element) =>
      `${element.tagName.toLowerCase()}${element.classList.length ? `.${[...element.classList].join(".")}` : ""}`;

    type Rgba = { r: number; g: number; b: number; a: number };
    const parse = (color: string): Rgba | null => {
      const match = color.match(/rgba?\(([^)]+)\)/);
      if (!match) return null;
      const [r, g, b, a = 1] = match[1].split(/[\s,/]+/).filter(Boolean).map(Number);
      return { r, g, b, a };
    };
    const over = (top: Rgba, bottom: Rgba): Rgba => ({
      r: top.r * top.a + bottom.r * (1 - top.a),
      g: top.g * top.a + bottom.g * (1 - top.a),
      b: top.b * top.a + bottom.b * (1 - top.a),
      a: 1,
    });
    const luminance = ({ r, g, b }: Rgba) => {
      const channel = (value: number) => {
        const c = value / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
    };
    const canvas = { r: 255, g: 255, b: 255, a: 1 };
    const background = (element: Element) => {
      const layers: Rgba[] = [];
      for (let node: Element | null = element; node; node = node.parentElement) {
        const layer = parse(getComputedStyle(node).backgroundColor);
        if (layer && layer.a > 0) {
          layers.push(layer);
          if (layer.a >= 1) break;
        }
      }
      return layers.reverse().reduce((base, layer) => over(layer, base), { ...canvas, a: 1 });
    };

    const scale: string[] = [];
    const contrast: string[] = [];
    for (const element of document.body.querySelectorAll("*")) {
      if (!shown(element)) continue;
      const style = getComputedStyle(element);
      if (!onRadiusScale(style.borderTopLeftRadius)) scale.push(`${describe(element)} radius ${style.borderTopLeftRadius}`);
      if (!ownText(element)) continue;
      const size = px(style.fontSize);
      if (!onFontScale(size)) scale.push(`${describe(element)} font-size ${style.fontSize}`);
      if (element.closest("[disabled], [aria-disabled='true'], .xterm")) continue;
      const foreground = parse(style.color);
      if (!foreground) {
        contrast.push(`${describe(element)} unreadable colour ${style.color}`);
        continue;
      }
      const behind = background(element);
      const [light, dark] = [luminance(over(foreground, behind)), luminance(behind)].sort((a, b) => b - a);
      const ratio = (light + 0.05) / (dark + 0.05);
      const large = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700);
      if (ratio < (large ? 3 : 4.5)) contrast.push(`${describe(element)} ${ratio.toFixed(2)}:1 "${element.textContent?.trim().slice(0, 40)}"`);
    }
    const select = [...document.querySelectorAll("select")]
      .filter((element) => getComputedStyle(element).appearance !== "base-select")
      .map((element) => `${describe(element)} appearance ${getComputedStyle(element).appearance}`);
    const root = document.scrollingElement ?? document.documentElement;
    return { overflow: root.scrollWidth - root.clientWidth, scale, contrast, select };
  });
}

// Keyboard focus must always be visible: tabbing to a control must add a
// non-transparent outline or a shadow compared with the resting state, on the
// control itself or where its primitive draws the ring (an input group, a
// wrapping label, a toggle chip's label span). A terminal keeps Tab as input.
const tabLimit = 400;

async function focusGaps(page: Page) {
  await page.evaluate(() => {
    const look = (element: Element) => {
      const style = getComputedStyle(element);
      return {
        outline: [style.outlineStyle, style.outlineWidth, style.outlineColor].join(" "),
        shadow: style.boxShadow,
      };
    };
    const resting = new Map<Element, ReturnType<typeof look>>();
    for (const element of document.querySelectorAll("*")) resting.set(element, look(element));
    Object.assign(window, { __designFocus: { resting, look } });
  });
  const gaps = new Set<string>();
  let first: string | null = null;
  for (let step = 0; step <= tabLimit; step += 1) {
    if (step === tabLimit) {
      gaps.add(`focus order did not cycle within ${tabLimit} Tab presses`);
      break;
    }
    await page.keyboard.press("Tab");
    const focused = await page.evaluate(() => {
      const element = document.activeElement;
      if (!element || element === document.body) return null;
      if (element.closest(".xterm")) return { id: "terminal", key: "terminal", visible: true, terminal: true };
      type Look = { outline: string; shadow: string };
      const { resting, look } = (window as unknown as {
        __designFocus: { resting: Map<Element, Look>; look: (element: Element) => Look };
      }).__designFocus;
      const shows = (candidate: Element) => {
        const before = resting.get(candidate);
        const now = look(candidate);
        const style = getComputedStyle(candidate);
        const alpha = style.outlineColor.match(/rgba?\(([^)]+)\)/)?.[1].split(/[\s,/]+/).filter(Boolean).map(Number)[3] ?? 1;
        const outline = style.outlineStyle !== "none" && Number.parseFloat(style.outlineWidth) > 0 && alpha > 0
          && now.outline !== before?.outline;
        return outline || (now.shadow !== "none" && now.shadow !== before?.shadow);
      };
      const parent = element.parentElement;
      const related = [element, element.nextElementSibling, parent, parent?.parentElement, parent?.parentElement?.parentElement];
      const id = `${element.tagName.toLowerCase()}${element.classList.length ? `.${[...element.classList].join(".")}` : ""}`;
      return {
        id,
        key: String([...document.querySelectorAll("*")].indexOf(element)),
        visible: related.some((candidate) => candidate && shows(candidate)),
        terminal: false,
      };
    });
    if (!focused || focused.terminal || focused.key === first) break;
    first ??= focused.key;
    if (!focused.visible) gaps.add(focused.id);
  }
  return [...gaps];
}

for (const fixture of fixtures) {
  test(`${fixture} renders within the design contract`, async ({ page }, testInfo) => {
    const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
    test.skip(!origin, "Run make design-check");
    await page.goto(`${origin}/reference/fixtures/${fixture}`);
    await page.evaluate(() => document.fonts.ready);

    const findings = { ...(await inspect(page)), focus: await focusGaps(page) };
    const viewport: Viewport = testInfo.project.name.endsWith("mobile") ? "mobile" : "desktop";
    expect.soft(findings.overflow, "the page scrolls sideways").toBe(0);
    expect.soft(findings.select, "selects must render the styled base-select picker").toEqual([]);
    for (const check of ["scale", "contrast", "focus"] as const) {
      const cap = pending[fixture]?.[`${viewport} ${check}`] ?? 0;
      expect.soft(findings[check].length, `${viewport} ${check} findings (cap ${cap}): ${findings[check].join(" | ")}`)
        .toBeLessThanOrEqual(cap);
      if (cap > 0) {
        expect.soft(findings[check].length, `${viewport} ${check} is clean; delete its pending entry`).toBeGreaterThan(0);
      }
    }
  });
}
