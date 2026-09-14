const app = document.querySelector("[data-dashboard-app]");

const nameToSlug = (name) => name
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, "-")
  .replace(/^-+|-+$/g, "")
  .slice(0, 48);

const initializeSlugSuggestion = (root = document) => {
  const source = root.querySelector?.("[data-slug-source]");
  const target = root.querySelector?.("[data-slug-target]");
  if (source && target) target.dataset.suggested = nameToSlug(source.value);
};

initializeSlugSuggestion();

document.addEventListener("input", (event) => {
  const target = event.target instanceof HTMLInputElement ? event.target : null;
  if (target?.matches("[data-slug-source]")) {
    const slug = document.querySelector("[data-slug-target]");
    if (!(slug instanceof HTMLInputElement)) return;
    const previous = slug.dataset.suggested || "";
    const suggested = nameToSlug(target.value);
    if (!slug.value || slug.value === previous) slug.value = suggested;
    slug.dataset.suggested = suggested;
  } else if (target?.matches("[data-slug-target]")) {
    target.value = target.value.toLowerCase();
  }
});

document.addEventListener("htmx:afterSwap", (event) => {
  const target = event.target instanceof Element ? event.target : document;
  initializeSlugSuggestion(target);
});

if (app) {
  const closeSidebar = () => app.setAttribute("data-mobile-open", "false");
  const currentDrawer = () => document.querySelector("[data-drawer]");

  const drawerPathMatches = (drawer) => {
    const createUrl = drawer?.getAttribute("data-create-url");
    // A rejected native form submission renders the open drawer at its POST URL.
    // Keep that response visible, including when background fragments refresh.
    const actionUrl = drawer?.querySelector("form")?.getAttribute("action");
    return [createUrl, actionUrl].some((url) => {
      if (!url) return false;
      const target = new URL(url, window.location.origin);
      return target.pathname === window.location.pathname && target.search === window.location.search;
    });
  };

  const focusDrawer = (drawer) => {
    const panel = drawer?.querySelector("[data-drawer-panel]");
    const target = panel?.querySelector("#environment-name")
      || panel?.querySelector("input:not([type='hidden']):not(:disabled), select:not(:disabled), textarea:not(:disabled), button:not(:disabled), a[href]");
    if (target instanceof HTMLElement) target.focus({ preventScroll: true });
    else if (panel instanceof HTMLElement) panel.focus({ preventScroll: true });
  };

  const setDrawerOpen = (open, focus = true) => {
    const drawer = currentDrawer();
    if (!(drawer instanceof HTMLElement)) return;
    drawer.hidden = !open;
    drawer.dataset.open = String(open);
    drawer.setAttribute("aria-hidden", String(!open));
    document.body.toggleAttribute("data-drawer-open", open);
    if (open && focus) window.requestAnimationFrame(() => focusDrawer(drawer));
  };

  const openDrawer = (href) => {
    const drawer = currentDrawer();
    if (!drawer) return false;
    const target = new URL(href || drawer.getAttribute("data-create-url"), window.location.origin);
    const rendered = new URL(drawer.getAttribute("data-create-url"), window.location.origin);
    // A different form needs fresh server-rendered selection and concurrency metadata.
    if (target.pathname !== rendered.pathname || target.search !== rendered.search) return false;
    setDrawerOpen(true);
    if (target.pathname !== window.location.pathname || target.search !== window.location.search) {
      window.history.pushState({ codewireDrawer: true }, "", `${target.pathname}${target.search}${target.hash}`);
    }
    return true;
  };

  const closeDrawer = () => {
    const drawer = currentDrawer();
    if (!drawer || drawer.hidden) return false;
    if (window.history.state?.codewireDrawer) {
      window.history.back();
    } else {
      const closeUrl = new URL(drawer.getAttribute("data-close-url") || window.location.pathname, window.location.origin);
      window.history.replaceState(null, "", `${closeUrl.pathname}${closeUrl.search}${closeUrl.hash}`);
      setDrawerOpen(false, false);
    }
    return true;
  };

  const openQuickSearch = () => {
    const dialog = document.querySelector("[data-quick-search]");
    if (!(dialog instanceof HTMLDialogElement)) return;
    if (!dialog.open) dialog.showModal();
    const input = dialog.querySelector("[data-quick-search-input]");
    if (input instanceof HTMLInputElement) {
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
    }
  };

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    document.querySelectorAll(".cw-org-details[open]").forEach((details) => {
      const panel = details.querySelector(":scope > .cw-card");
      const summary = details.querySelector(":scope > summary");
      if (target && !panel?.contains(target) && !summary?.contains(target)) details.removeAttribute("open");
    });
    const drawerTrigger = target?.closest("[data-drawer-trigger]");
    if (drawerTrigger instanceof HTMLAnchorElement && openDrawer(drawerTrigger.href)) {
      event.preventDefault();
      return;
    }
    if (target?.closest("[data-drawer-close]")) {
      event.preventDefault();
      closeDrawer();
      return;
    }
    if (target?.closest("[data-sidebar-toggle]")) {
      const open = app.getAttribute("data-mobile-open") === "true";
      app.setAttribute("data-mobile-open", String(!open));
      return;
    }
    if (target?.closest("[data-quick-search-open]")) {
      openQuickSearch();
      return;
    }
    if (target?.closest("[data-sidebar-close], .cw-mobile-drawer a")) {
      closeSidebar();
    }
  });

  document.addEventListener("keydown", (event) => {
    // Native modal dialogs own Escape, focus and keyboard interaction above a
    // drawer. Do not close the underlying Create Sandbox draft as well.
    if (document.querySelector("dialog:modal")) return;
    const target = event.target instanceof HTMLElement ? event.target : null;
    const isEditing = target?.matches("input, textarea, select, [contenteditable='true']");
    if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey && !isEditing) {
      event.preventDefault();
      openQuickSearch();
      return;
    }
    if (event.key === "Escape" && closeDrawer()) {
      event.preventDefault();
      return;
    }
    if (event.key === "Escape") {
      const openDetails = document.querySelector(".cw-org-details[open]");
      if (openDetails) openDetails.removeAttribute("open");
      closeSidebar();
    }
  });

  document.addEventListener("input", (event) => {
    const input = event.target instanceof HTMLInputElement ? event.target : null;
    if (!input?.matches("[data-quick-search-input]")) return;
    const dialog = input.closest("[data-quick-search]");
    if (!dialog) return;
    const query = input.value.trim().toLowerCase();
    let visible = 0;
    dialog.querySelectorAll("[data-search-item]").forEach((item) => {
      const matches = !query || (item.getAttribute("data-search-text") || item.textContent || "")
        .toLowerCase()
        .includes(query);
      const result = item.closest("li") || item;
      result.toggleAttribute("hidden", !matches);
      if (matches) visible += 1;
    });
    const empty = dialog.querySelector("[data-quick-search-empty]");
    if (empty instanceof HTMLElement) empty.hidden = visible !== 0;
  });

  window.addEventListener("popstate", () => setDrawerOpen(drawerPathMatches(currentDrawer())));
  document.addEventListener("codewire:drawer-replaced", () => setDrawerOpen(true));
  document.addEventListener("htmx:afterSwap", () => setDrawerOpen(drawerPathMatches(currentDrawer()), false));
  document.addEventListener("keydown", (event) => {
    if (document.querySelector("dialog:modal")) return;
    if (event.key !== "Tab") return;
    const drawer = currentDrawer();
    if (!drawer || drawer.hidden) return;
    const panel = drawer.querySelector("[data-drawer-panel]");
    if (!panel) return;
    const focusable = Array.from(panel.querySelectorAll("a[href], button:not(:disabled), input:not([type='hidden']):not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])"))
      .filter((element) => element instanceof HTMLElement && element.offsetParent !== null);
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  setDrawerOpen(drawerPathMatches(currentDrawer()));
}
