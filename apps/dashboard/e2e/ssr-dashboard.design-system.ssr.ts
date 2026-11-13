import { readdirSync, readFileSync, readlinkSync } from "node:fs";

import { expect, test, type Locator, type Page } from "./helpers/fixture-test";

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

const pending: Record<string, Pending> = {};

// The public site (home.html, pricing.html, privacy.html, terms.html) uses public.css's own scale: it keeps an 11px text floor, not the console type and radius scale.
const ownScale = new Set(["home.html", "pricing.html", "privacy.html", "terms.html"]);

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
async function inspect(page: Page, marketing: boolean) {
  return page.evaluate((marketing) => {
    const px = (value: string) => Number.parseFloat(value);
    const fontScale = new Set([11, 12, 13, 14, 17]);
    const onFontScale = (size: number) =>
      marketing ? size >= 11 : fontScale.has(size) || (size >= 24 && size <= 30);
    const onRadiusScale = (value: string) =>
      marketing || value.endsWith("%") || [0, 4, 8, 12].includes(px(value)) || px(value) >= 999;
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
    // A button that holds an icon or other element keeps its label in a span:
    // the capital-height trim cannot reach a bare text node. Hidden dialogs and
    // <template> content count too.
    const labels = [document, ...[...document.querySelectorAll("template")].map((template) => template.content)]
      .flatMap((scope) => [...scope.querySelectorAll(".cw-button")])
      .filter((element) => element.firstElementChild && ownText(element))
      .map((element) => `${describe(element)} "${element.textContent?.trim().replace(/\s+/g, " ").slice(0, 40)}"`);
    const root = document.scrollingElement ?? document.documentElement;
    return { overflow: root.scrollWidth - root.clientWidth, scale, contrast, select, labels };
  }, marketing);
}

// Keyboard focus must always be visible: tabbing to a control must add a
// non-transparent outline or a shadow compared with the resting state, on the
// control itself or where its primitive draws the ring (an input group, a
// wrapping label, a toggle chip's label span). A terminal keeps Tab as input.
//
// Tab is pressed in batches while the page records each control as it takes
// focus, and the controls are then checked in one call, each focused again
// as the keyboard shows it (focusVisible). The order is walked once, in the
// first colour scheme, and recorded as each control's structural path; the
// other scheme's reload is checked from those paths. Every press waits for a
// frame, and at a phone's pixel density home.html took over 50 s with a
// round trip per press in both schemes, against a 60 s limit.
const tabLimit = 400;
const tabBatch = 20;

async function focusGaps(page: Page, walked?: string[]): Promise<{ gaps: string[]; order: string[] }> {
  // Let the page's own first-frame work run before walking: an open drawer
  // moves focus to its first field on the next animation frame, and a frame
  // asked for now runs after it. Walking earlier, on a loaded host, starts on
  // a page link outside the drawer; the drawer then takes focus and keeps Tab
  // inside, so the walk never comes back to where it began (#4389).
  await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => done())));
  await page.evaluate(() => {
    // Measure every control unfocused: an autofocused field would otherwise
    // record its focus ring as its resting look.
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    const look = (element: Element) => {
      const style = getComputedStyle(element);
      return {
        outline: [style.outlineStyle, style.outlineWidth, style.outlineColor].join(" "),
        shadow: style.boxShadow,
      };
    };
    const resting = new Map<Element, ReturnType<typeof look>>();
    for (const element of document.querySelectorAll("*")) resting.set(element, look(element));
    const order: Element[] = [];
    document.addEventListener("focusin", (event) => { if (event.target instanceof Element) order.push(event.target); }, true);
    // A control's place in the document, stable across reloads of a fixture.
    const path = (element: Element) => {
      const steps: string[] = [];
      for (let node: Element | null = element; node && node !== document.documentElement; node = node.parentElement) {
        steps.unshift(`${node.tagName.toLowerCase()}:nth-child(${[...node.parentElement!.children].indexOf(node) + 1})`);
      }
      return `html > ${steps.join(" > ")}`;
    };
    Object.assign(window, { __designFocus: { resting, look, order, path } });
  });
  type Focus = { order: Element[] };
  // The walk ends when focus leaves the page after its last control, comes
  // back to the first one, or enters a terminal, or when a whole batch finds
  // nothing to focus. Presses after that only revisit what is recorded.
  const ended = () => page.evaluate(() => {
    const { order } = (window as unknown as { __designFocus: Focus }).__designFocus;
    const left = !document.activeElement || document.activeElement === document.body;
    return order.length === 0 || left || order.slice(1).includes(order[0])
      || order.some((element) => element.closest(".xterm") !== null);
  });
  let cycled = walked !== undefined;
  for (let pressed = 0; pressed < tabLimit && !cycled; ) {
    for (let batch = 0; batch < tabBatch && pressed < tabLimit; batch += 1, pressed += 1) await page.keyboard.press("Tab");
    cycled = await ended();
  }
  const result = await page.evaluate((walked) => {
    type Look = { outline: string; shadow: string };
    const { resting, look, order, path } = (window as unknown as {
      __designFocus: { resting: Map<Element, Look>; look: (element: Element) => Look; order: Element[]; path: (element: Element) => string };
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
    const stops: Element[] = [];
    const hidden: string[] = [];
    if (walked) {
      for (const place of walked) {
        const element = document.querySelector(place);
        if (element) stops.push(element);
        else hidden.push(`the walked control ${place} is missing after reload`);
      }
    } else {
      for (const element of order) {
        if (element.closest(".xterm") || stops.includes(element)) break;
        stops.push(element);
      }
    }
    for (const element of stops) {
      if (element instanceof HTMLElement || element instanceof SVGElement) element.focus({ focusVisible: true });
      const parent = element.parentElement;
      const related = [element, element.nextElementSibling, parent, parent?.parentElement, parent?.parentElement?.parentElement];
      if (!related.some((candidate) => candidate && shows(candidate))) {
        hidden.push(`${element.tagName.toLowerCase()}${element.classList.length ? `.${[...element.classList].join(".")}` : ""}`);
      }
    }
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    return { hidden, order: stops.map(path) };
  }, walked);
  const gaps = [...result.hidden];
  if (!cycled) gaps.push(`focus order did not cycle within ${tabLimit} Tab presses`);
  return { gaps: [...new Set(gaps)], order: result.order };
}

test("the account menu's theme switch cycles system, light and dark and is kept on the next page", async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-check");
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(`${origin}/reference/fixtures/sandboxes.html`);
  const html = page.locator("html");
  // The theme is chosen in one place: the account menu at the foot of the sidebar.
  const menu = page.locator(".cw-sidebar-slot .cw-account-menu");
  const theme = menu.locator("[data-theme-switch]");
  await expect(page.locator(".cw-console-header [data-theme-switch]")).toHaveCount(0);
  await menu.locator(":scope > summary").click();
  await expect(theme).toHaveText("Theme: System");
  await expect(html).not.toHaveAttribute("data-theme", /./);
  const background = () => page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor);
  const dark = await background();
  await theme.click();
  await expect(html).toHaveAttribute("data-theme", "light");
  await expect(theme).toHaveText("Theme: Light");
  await expect(theme.locator(".cw-theme-icon--light")).toBeVisible();
  await expect(theme.locator(".cw-theme-icon--system")).toBeHidden();
  expect(await background()).not.toBe(dark);
  await page.goto(`${origin}/reference/fixtures/login.html`);
  await expect(html).toHaveAttribute("data-theme", "light");
  await page.goto(`${origin}/reference/fixtures/sandboxes.html`);
  await menu.locator(":scope > summary").click();
  await expect(theme).toHaveText("Theme: Light");
  await theme.click();
  await expect(html).toHaveAttribute("data-theme", "dark");
  await theme.click();
  await expect(html).not.toHaveAttribute("data-theme", /./);
  await expect(theme).toHaveText("Theme: System");
});


for (const fixture of fixtures) {
  test(`${fixture} renders within the design contract`, { tag: "@mobile" }, async ({ page }, testInfo) => {
    const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
    test.skip(!origin, "Run make design-check");
    const viewport: Viewport = testInfo.project.name.endsWith("mobile") ? "mobile" : "desktop";
    // Every page follows the system theme (theme.js), so each is measured in both.
    let walked: string[] | undefined;
    for (const colorScheme of ["dark", "light"] as const) {
      await page.emulateMedia({ colorScheme });
      await page.goto(`${origin}/reference/fixtures/${fixture}`);
      await page.evaluate(() => document.fonts.ready);

      const inspected = await inspect(page, ownScale.has(fixture));
      const focus = await focusGaps(page, walked);
      walked ??= focus.order;
      const findings = { ...inspected, focus: focus.gaps };
      expect.soft(findings.overflow, `${colorScheme}: the page scrolls sideways`).toBe(0);
      expect.soft(findings.select, `${colorScheme}: selects must render the styled base-select picker`).toEqual([]);
      expect.soft(findings.labels, `${colorScheme}: buttons with an icon must wrap their label in a span`).toEqual([]);
      for (const check of ["scale", "contrast", "focus"] as const) {
        const cap = pending[fixture]?.[`${viewport} ${check}`] ?? 0;
        expect.soft(findings[check].length, `${viewport} ${colorScheme} ${check} findings (cap ${cap}): ${findings[check].join(" | ")}`)
          .toBeLessThanOrEqual(cap);
        if (cap > 0) {
          expect.soft(findings[check].length, `${viewport} ${colorScheme} ${check} is clean; delete its pending entry`).toBeGreaterThan(0);
        }
      }
    }
  });
}

// Distance from the centre of a control's padding box (a row's separator
// border is not part of what its label centres in) to the centre of its
// label's capitals. The label is the first visible text in `label`, wherever
// it sits. The baseline sits the font's ascent below the top of the text's own
// box (a Range over the text, never the line box, so leading cannot hide in
// it), and the capitals rise their cap height above it. Both come from the
// page's own layout of the label's font, at the page's own scale: a probe set
// beside the page, never a canvas, whose metrics are rounded differently
// (#4358: under DejaVu Sans at 2.75 a canvas put centred capitals 1.23 px off).
async function capitalsOffset(control: Locator, label: Locator = control) {
  const middle = await control.evaluate((node) => node.getBoundingClientRect().top + node.clientTop + node.clientHeight / 2);
  const centre = await label.evaluate((node) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, {
      acceptNode: (child) => child.textContent!.trim() && !child.parentElement!.closest(".cw-sr-only")
        ? NodeFilter.FILTER_ACCEPT
        : NodeFilter.FILTER_REJECT,
    });
    const text = walker.nextNode()!;
    const range = document.createRange();
    range.selectNodeContents(text);
    const style = getComputedStyle(text.parentElement!);
    // Its text box gives the ascent: an empty inline-block's bottom is the
    // baseline. A second "H", trimmed to its capitals, gives the cap height.
    const probe = document.createElement("div");
    probe.style.cssText = "position:absolute;top:0;left:0;visibility:hidden;white-space:nowrap;line-height:normal";
    for (const property of ["fontFamily", "fontSize", "fontWeight", "fontStyle", "fontStretch"] as const) {
      probe.style[property] = style[property];
    }
    probe.innerHTML = '<span>H<span style="display:inline-block;width:0;height:0"></span></span>'
      + '<span style="display:inline-block;text-box:trim-both cap alphabetic">H</span>';
    document.body.append(probe);
    const [line, capitals] = probe.children as unknown as [HTMLElement, HTMLElement];
    const lineText = document.createRange();
    lineText.selectNodeContents(line.firstChild!);
    const ascent = line.lastElementChild!.getBoundingClientRect().top - lineText.getClientRects()[0].top;
    const capHeight = capitals.getBoundingClientRect().height;
    probe.remove();
    return range.getClientRects()[0].top + ascent - capHeight / 2;
  });
  return centre - middle;
}

test("single-line controls centre their capitals, not a line box", { tag: "@mobile" }, async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for fixture checks");
  await page.goto(`${origin}/reference/fixtures/create-sandbox.html`);
  const submit = page.locator(".cw-drawer-footer .cw-button");
  const docs = page.locator('[data-repository-name="codewiresh/docs"]');
  const pill = docs.locator(".cw-badge");
  const chip = page.locator(".cw-toggle-chip > span").first();
  for (const [name, control, label] of [
    ["Create Sandbox button", submit, submit.locator(".cw-submit-idle")],
    ["Public pill", pill, pill],
    ["+ Add row action", docs, docs.locator("[data-github-repository-action]")],
    ["agent chip", chip, chip],
  ] as const) {
    expect.soft(Math.abs(await capitalsOffset(control, label)), name).toBeLessThanOrEqual(0.75);
  }
});

// What drew a control's label, named when its capitals are off centre: the
// platform fonts Chromium used for the text, the label's computed font and
// the self-hosted faces' load states. CI measured the login buttons 1.23 px
// off in every run while the same Chromium measured them centred on a
// workstation (run 44624, PR #4351), so a failure names its fonts.
async function labelFonts(page: Page, control: Locator) {
  const marker = "data-label-font-probe";
  const computed = await control.evaluate((node, attribute) => {
    const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, {
      acceptNode: (child) => child.textContent!.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT,
    });
    const label = walker.nextNode()!.parentElement!;
    label.setAttribute(attribute, "");
    const faces = [...document.fonts].map((face) => `${face.family} ${face.weight} ${face.status}`).join(", ");
    return `computed ${getComputedStyle(label).font}; faces ${faces || "none"}`;
  }, marker);
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send("DOM.enable");
    await cdp.send("CSS.enable");
    const { root } = await cdp.send("DOM.getDocument", { depth: 0 });
    const { nodeId } = await cdp.send("DOM.querySelector", { nodeId: root.nodeId, selector: `[${marker}]` });
    const { fonts } = await cdp.send("CSS.getPlatformFontsForNode", { nodeId });
    const used = fonts.map((font) => `${font.familyName}${font.isCustomFont ? " (web)" : " (system)"} ×${font.glyphCount}`);
    return `drawn with ${used.join(", ") || "nothing"}; ${computed}`;
  } finally {
    await control.evaluate((node, attribute) => node.querySelector(`[${attribute}]`)?.removeAttribute(attribute)
      ?? node.removeAttribute(attribute), marker);
    await cdp.detach();
  }
}

// An icon beside a bare text node keeps the label off centre by up to 1.5 px
// at 390; a span label is trimmed like a text-only button's.
test("buttons with an icon centre their label's capitals", { tag: "@mobile" }, async ({ page }) => {
  const origin = process.env.CODEWIRE_DESIGN_ORIGIN;
  test.skip(!origin, "Run make design-system for fixture checks");
  for (const [fixture, name, control] of [
    ["sandboxes.html", "+ Create Sandbox", page.locator("main").getByRole("link", { name: "Create Sandbox" })],
    ["create-sandbox.html", "+ Add custom Git URL", page.getByRole("button", { name: "Add custom Git URL" })],
    ["settings-credentials.html", "Reconnect", page.getByRole("button", { name: "Reconnect Work Codex" })],
    ["components.html", "< Back", page.getByRole("button", { name: "Back" })],
    ["login.html", "Continue with GitHub", page.getByRole("link", { name: "Continue with GitHub" })],
    ["login.html", "Continue with Google", page.getByRole("link", { name: "Continue with Google" })],
  ] as const) {
    await page.goto(`${origin}/reference/fixtures/${fixture}`);
    await page.evaluate(() => document.fonts.ready);
    const offset = Math.abs(await capitalsOffset(control));
    const fonts = offset > 0.75 ? `: ${await labelFonts(page, control)}` : "";
    expect.soft(offset, `${name}${fonts}`).toBeLessThanOrEqual(0.75);
  }
});

// What draws every fixture: the browser's GPU process. A host GPU driver in it
// can block, and then no frame arrives and every click waits out its timeout
// for a stable element (#3019). playwright.config.ts keeps the browser off the
// host GPU; this checks the running browser. On a runner without a GPU it
// holds nothing either way; the workstation is where it matters.
const hostGpuDevice = /^\/dev\/(?:nvidia|dri\/)/;

function processIds() {
  return readdirSync("/proc").filter((name) => /^\d+$/.test(name)).map(Number);
}

// The parent from /proc/<pid>/stat; the command name before it may hold spaces.
function parentOf(pid: number) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
  } catch {
    return undefined;
  }
}

function descendantsOf(root: number) {
  const children = new Map<number, number[]>();
  for (const pid of processIds()) {
    const parent = parentOf(pid);
    if (parent !== undefined) children.set(parent, [...(children.get(parent) ?? []), pid]);
  }
  const found: number[] = [];
  const queue = [root];
  while (queue.length) {
    for (const child of children.get(queue.shift()!) ?? []) {
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

function commandLine(pid: number) {
  try {
    return readFileSync(`/proc/${pid}/cmdline`, "utf8");
  } catch {
    return "";
  }
}

function openDevices(pid: number) {
  try {
    return readdirSync(`/proc/${pid}/fd`).flatMap((fd) => {
      try {
        return [readlinkSync(`/proc/${pid}/fd/${fd}`)];
      } catch {
        return [];
      }
    });
  } catch {
    return [];
  }
}

test("the browser draws without a host GPU driver", async ({ browser }) => {
  test.skip(process.platform !== "linux", "Reads the browser's GPU process from /proc");
  const page = await browser.newPage();
  await page.setContent("<p>frame</p>");
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  // This worker launched the browser, so its GPU process descends from it.
  const gpuProcesses = descendantsOf(process.pid).filter((pid) => commandLine(pid).includes("--type=gpu-process"));
  expect(gpuProcesses.length, "the browser's GPU process").toBeGreaterThan(0);
  const held = gpuProcesses.flatMap((pid) => openDevices(pid).filter((target) => hostGpuDevice.test(target)));
  expect([...new Set(held)].sort(), "host GPU devices the GPU process holds").toEqual([]);
  await page.close();
});

// Nor can it reach the desktop session: playwright.config.ts launches it
// without the display variables (#3019). Its environment is the launch
// options' env as this run resolves them for the project; an unset env would
// hand it the runner's whole environment. (Chromium rewrites its own
// /proc/<pid>/environ for process titles, so that cannot be read instead.)
const desktopVariables = new Set(["DISPLAY", "WAYLAND_DISPLAY"]);

test("the browser launches without the desktop display variables", async ({ browser }, testInfo) => {
  expect(browser.isConnected()).toBe(true);
  const { launchOptions } = testInfo.project.use as { launchOptions?: { env?: Record<string, unknown> } };
  expect(launchOptions?.env, "the browser's launch environment is set, not inherited").toBeDefined();
  expect(Object.keys(launchOptions!.env!).filter((name) => desktopVariables.has(name)), "desktop variables").toEqual([]);
});
