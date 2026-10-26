(() => {
  "use strict";

  const svgNamespace = "http://www.w3.org/2000/svg";
  const canCopy = Boolean(navigator.clipboard && window.isSecureContext);

  const icon = (paths) => {
    const svg = document.createElementNS(svgNamespace, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    paths.forEach(([tag, attributes]) => {
      const shape = document.createElementNS(svgNamespace, tag);
      Object.entries(attributes).forEach(([name, value]) => shape.setAttribute(name, value));
      svg.append(shape);
    });
    return svg;
  };
  const copyIcon = () => icon([["rect", { x: "9", y: "9", width: "11", height: "11", rx: "2" }], ["path", { d: "M5 15V6a2 2 0 0 1 2-2h9" }]]);
  const checkIcon = () => icon([["path", { d: "m5 12 5 5 9-10" }]]);

  // Briefly mark a control as copied, for sighted and screen reader users alike.
  const flash = (button, label, idleText) => {
    button.dataset.copied = "true";
    if (label) label.textContent = "Copied";
    button.setAttribute("aria-label", "Copied");
    window.clearTimeout(Number(button.dataset.timer || 0));
    button.dataset.timer = String(window.setTimeout(() => {
      delete button.dataset.copied;
      if (label) label.textContent = idleText;
      button.setAttribute("aria-label", idleText);
    }, 1600));
  };

  // Wide tables scroll inside their own frame instead of widening the page.
  document.querySelectorAll(".docs-prose table").forEach((table) => {
    const frame = document.createElement("div");
    frame.className = "docs-table";
    table.replaceWith(frame);
    frame.append(table);
  });

  // Command blocks get a copy button; output blocks (`text`, rendered as `plain`) do not.
  if (canCopy) {
    document.querySelectorAll(".docs-prose pre").forEach((pre) => {
      const code = pre.querySelector("code");
      if (!code || ["plain", "text"].includes(code.dataset.lang)) return;
      const frame = document.createElement("div");
      frame.className = "docs-code";
      pre.replaceWith(frame);
      frame.append(pre);
      const button = document.createElement("button");
      button.type = "button";
      button.className = "docs-code-copy";
      button.setAttribute("aria-label", "Copy to clipboard");
      button.append(copyIcon(), checkIcon());
      button.addEventListener("click", () => {
        navigator.clipboard.writeText(code.textContent.replace(/\n$/, "")).then(() => flash(button, null, "Copy to clipboard"));
      });
      frame.append(button);
    });

    document.querySelectorAll("[data-docs-copy-markdown]").forEach((button) => {
      const label = button.querySelector("[data-docs-copy-label]");
      button.hidden = false;
      button.addEventListener("click", () => {
        fetch(button.dataset.docsCopyMarkdown, { credentials: "same-origin" })
          .then((response) => (response.ok ? response.text() : Promise.reject(new Error(String(response.status)))))
          .then((markdown) => navigator.clipboard.writeText(markdown))
          .then(() => flash(button, label, "Copy as Markdown"))
          .catch(() => { if (label) label.textContent = "Copy failed"; });
      });
    });
  }

  // Top-level sidebar groups start open and sub-groups start folded, except
  // the one holding this page; the folds a reader makes stay across pages.
  // Storage can be unavailable, so it is only a convenience.
  const groups = [...document.querySelectorAll(".docs-nav-group")];
  const storageKey = "codewire-docs-nav";
  const groupTitle = (group) => group.querySelector(":scope > summary").textContent.trim();
  const groupName = (group) => {
    const link = group.querySelector(":scope > summary .docs-nav-link");
    if (link) return link.getAttribute("href");
    const parent = group.parentElement.closest(".docs-nav-group");
    return `${parent ? groupName(parent) : ""}/${groupTitle(group)}`;
  };
  let folds = {};
  try {
    folds = JSON.parse(window.localStorage.getItem(storageKey) || "{}");
  } catch (_error) {
    folds = {};
  }
  groups.forEach((group) => {
    const name = groupName(group);
    if (name in folds && !group.querySelector("[aria-current=page]")) group.open = folds[name];
  });
  let filtering = false;
  groups.forEach((group) => group.addEventListener("toggle", () => {
    if (filtering) return;
    folds[groupName(group)] = group.open;
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(folds));
    } catch (_error) {
      // Private windows and blocked storage keep the default.
    }
  }));

  // Mark the section in view in the "On this page" rail. The guide line is
  // traced as one SVG path through every link, curving where the depth
  // changes; a dash shows the active link's stretch, so it slides there.
  const toc = document.querySelector("[data-docs-toc]");
  const tocLinks = [...document.querySelectorAll("[data-docs-toc] a")];
  const tocTargets = tocLinks.map((link) => document.getElementById(decodeURIComponent(link.hash.slice(1))));
  const rail = document.createElementNS(svgNamespace, "svg");
  const railPath = document.createElementNS(svgNamespace, "path");
  rail.setAttribute("class", "docs-toc-rail");
  rail.setAttribute("aria-hidden", "true");
  rail.append(railPath);
  let railSegments = [];
  let railLength = 0;
  let activeSection = -1;
  let tocFrame = 0;
  // Below the wide layout the list is a select; choosing a section scrolls
  // there, and tracking pauses until the scroll settles.
  const jump = document.querySelector("[data-docs-toc-jump]");
  let jumping = 0;
  jump?.addEventListener("change", () => {
    const target = document.getElementById(jump.value);
    if (!target) return;
    window.clearTimeout(jumping);
    jumping = window.setTimeout(() => { jumping = 0; activeSection = -2; markSection(); }, 1000);
    const smooth = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (jump.value === "docs-content") window.scrollTo({ top: 0, behavior: smooth ? "smooth" : "auto" });
    else target.scrollIntoView({ behavior: smooth ? "smooth" : "auto" });
    history.replaceState(null, "", `#${jump.value}`);
  });
  const traceRail = () => {
    const box = toc.getBoundingClientRect();
    const length = (d) => { railPath.setAttribute("d", d); return railPath.getTotalLength(); };
    let d = "";
    let total = 0;
    railSegments = tocLinks.map((link, index) => {
      const rect = link.getBoundingClientRect();
      const x = rect.left - box.left + 1;
      const top = rect.top - box.top;
      const bottom = rect.bottom - box.top;
      if (index === 0) {
        d += `M ${x} ${top} `;
      } else {
        const previous = tocLinks[index - 1].getBoundingClientRect();
        const fromX = previous.left - box.left + 1;
        const fromY = previous.bottom - box.top;
        const middle = (fromY + top) / 2;
        const join = Math.abs(fromX - x) < 0.5 ? `L ${x} ${top} ` : `C ${fromX} ${middle}, ${x} ${middle}, ${x} ${top} `;
        d += join;
        total += length(`M ${fromX} ${fromY} ${join}`);
      }
      d += `L ${x} ${bottom} `;
      const segment = { start: total, length: bottom - top };
      total += segment.length;
      return segment;
    });
    railPath.setAttribute("d", d);
    railLength = total;
  };
  const showSection = (index, instantly) => {
    const segment = railSegments[index];
    if (!segment) return;
    if (instantly) {
      railPath.setAttribute("data-initial", "");
      railPath.getBoundingClientRect();
    }
    railPath.style.strokeDasharray = `${segment.length} ${railLength + 1}`;
    railPath.style.strokeDashoffset = `${-segment.start}`;
    if (instantly) {
      window.requestAnimationFrame(() => {
        railPath.setAttribute("data-ready", "");
        window.requestAnimationFrame(() => railPath.removeAttribute("data-initial"));
      });
    }
  };
  const markSection = () => {
    tocFrame = 0;
    const offset = (document.querySelector(".docs-topbar")?.offsetHeight || 0) + (jump?.parentElement.offsetHeight || 0) + 32;
    let current = 0;
    tocTargets.forEach((target, index) => {
      if (index > 0 && target && target.getBoundingClientRect().top - offset <= 0) current = index;
    });
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) current = tocLinks.length - 1;
    if (current === activeSection) return;
    if (jump && !jumping) jump.selectedIndex = current;
    tocLinks.forEach((link, index) => link.toggleAttribute("data-active", index === current));
    showSection(current, activeSection === -1);
    activeSection = current;
  };
  if (tocLinks.length) {
    toc.append(rail);
    traceRail();
    new ResizeObserver(() => {
      traceRail();
      if (activeSection >= 0) showSection(activeSection, true);
    }).observe(toc);
    window.addEventListener("scroll", () => { if (!tocFrame) tocFrame = window.requestAnimationFrame(markSection); }, { passive: true });
    markSection();
  }

  // Filter the sidebar by link text; matching groups open while a filter is set.
  const filter = document.querySelector("[data-docs-filter]");
  const initiallyOpen = new Map(groups.map((group) => [group, group.open]));
  filter?.addEventListener("focus", () => {
    groups.forEach((group) => initiallyOpen.set(group, group.open));
  });
  filter?.addEventListener("input", () => {
    const query = filter.value.trim().toLocaleLowerCase();
    const matches = (text) => !query || text.toLocaleLowerCase().includes(query);
    const titled = (link) => {
      for (let group = link.closest(".docs-nav-group"); group; group = group.parentElement.closest(".docs-nav-group")) {
        if (matches(groupTitle(group))) return true;
      }
      return false;
    };
    document.querySelectorAll(".docs-nav > .docs-nav-link").forEach((link) => {
      link.hidden = !matches(link.textContent);
    });
    document.querySelectorAll(".docs-nav-group-items > .docs-nav-link").forEach((link) => {
      link.hidden = !matches(link.textContent) && !titled(link);
    });
    filtering = true;
    groups.forEach((group) => {
      const anyItem = [...group.querySelectorAll(".docs-nav-group-items > .docs-nav-link")].some((link) => !link.hidden);
      group.hidden = !matches(groupTitle(group)) && !anyItem;
      group.open = query ? anyItem : initiallyOpen.get(group);
    });
    window.setTimeout(() => { filtering = false; });
  });
})();
