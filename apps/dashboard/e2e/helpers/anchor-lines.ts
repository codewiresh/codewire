import { expect, type Page } from "@playwright/test";

// Anchor lines (codewire-design skill, "Anchor lines"): a layout names one
// vertical line by a CSS length measured from its container's left edge (or
// right edge), and every mark centres on it while text with no mark beside it
// starts on it. A check names each element and how it meets the line:
// - "centre": the element's box centres on the line (an icon, a badge, a dot);
// - "text": its first visible character starts on the line;
// - "start": its box starts on the line.
// `plus` (a CSS length) is added to the point measured: the wordmark's c sits
// --sidebar-logo-anchor into the logo, and an icon's visible glyph starts
// --icon-glyph-inset into its box. Every selector must match at least one
// visible element, so a renamed class fails instead of passing on nothing.
// Only the first visible match counts.
export type AnchorCheck = { selector: string; at: "centre" | "text" | "start"; plus?: string; side?: "left" | "right" };

export async function anchorDistances(page: Page, container: string, line: string, checks: AnchorCheck[]) {
  return page.evaluate(({ container, line, checks }) => {
    const box = document.querySelector(container);
    if (!box || !box.getClientRects().length) return [`${container}: not shown`];
    // Resolve a CSS length in an element's context.
    const length = (value: string, host: Element) => {
      const ruler = document.createElement("span");
      ruler.style.cssText = `position:absolute;visibility:hidden;left:${value}`;
      host.append(ruler);
      const left = parseFloat(getComputedStyle(ruler).left);
      ruler.remove();
      return left;
    };
    const edges = box.getBoundingClientRect();
    const anchor = length(line, box);
    const shown = (node: Element) => node.getClientRects().length > 0 && getComputedStyle(node).visibility !== "hidden";
    const firstText = (node: Element) => {
      const walker = document.createTreeWalker(node, NodeFilter.SHOW_TEXT, { acceptNode: (text) =>
        text.textContent!.trim() && !text.parentElement!.closest(".cw-sr-only") && shown(text.parentElement!)
          ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT });
      const text = walker.nextNode();
      if (!text) return null;
      const range = document.createRange();
      const offset = text.textContent!.search(/\S/);
      range.setStart(text, offset);
      range.setEnd(text, offset + 1);
      return range.getBoundingClientRect().left;
    };
    return checks.map(({ selector, at, plus, side = "left" }) => {
      const node = [...box.querySelectorAll(selector)].find(shown);
      if (!node) return `${selector}: not shown`;
      const rect = node.getBoundingClientRect();
      const point = at === "centre" ? rect.left + rect.width / 2 : at === "text" ? firstText(node) : rect.left;
      if (point === null) return `${selector}: no text`;
      // An image or icon holds no ruler; its parent resolves the length.
      const x = point + (plus ? length(plus, node instanceof HTMLElement && node.tagName !== "IMG" ? node : node.parentElement!) : 0);
      const target = side === "left" ? edges.left + anchor : edges.right - anchor;
      return Math.abs(x - target) <= 1 ? "" : `${selector} (${at}, ${side}): ${(x - target).toFixed(1)} px off the line at ${target.toFixed(1)}`;
    }).filter(Boolean);
  }, { container, line, checks });
}

export async function expectOnAnchorLines(page: Page, label: string, container: string, line: string, checks: AnchorCheck[]) {
  expect(await anchorDistances(page, container, line, checks), label).toEqual([]);
}

// The sidebar's grid (routes/dashboard.css) puts every mark on one of two
// anchor lines: on the left the logo's c, the organization badge, the create
// plus, the sort icon, the rail's dots, the footer icons and the account
// badge, with the Admin label and links starting on it; on the right the
// collapse icon, the chevrons, the view-all icon and the region labels. The
// Admin rows render only for an administrator, so a check on a live page
// leaves them out unless its account is one.
export const sidebarLeftAnchors: AnchorCheck[] = [
  { selector: ".cw-console-brand img", at: "start", plus: "var(--sidebar-logo-anchor)" },
  { selector: ".cw-org-switcher > summary .cw-org-initial", at: "centre" },
  { selector: ".cw-console-create > .cw-icon", at: "centre" },
  { selector: "[data-rail-sort] .cw-icon", at: "centre" },
  { selector: ".cw-rail-dot", at: "centre" },
  { selector: ".cw-console-get-started .cw-nav-link > .cw-icon", at: "centre" },
  { selector: ".cw-account-menu > summary .cw-org-initial", at: "centre" },
];
export const sidebarAdminAnchors: AnchorCheck[] = [
  { selector: ".cw-console-admin .cw-section-label", at: "text" },
  { selector: ".cw-console-admin .cw-nav-link", at: "text" },
];
export const sidebarRightAnchors: AnchorCheck[] = [
  { selector: "[data-sidebar-close] .cw-icon", at: "centre", side: "right" },
  { selector: ".cw-org-chevron", at: "centre", side: "right" },
  { selector: "[aria-label='View all sandboxes'] .cw-icon", at: "centre", side: "right" },
  { selector: ".cw-rail-state", at: "centre", side: "right" },
  { selector: ".cw-account-chevrons", at: "centre", side: "right" },
];
