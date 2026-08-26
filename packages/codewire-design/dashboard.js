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
    const target = event.target instanceof HTMLElement ? event.target : null;
    const isEditing = target?.matches("input, textarea, select, [contenteditable='true']");
    if (event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey && !isEditing) {
      event.preventDefault();
      openQuickSearch();
      return;
    }
    if (event.key === "Escape") closeSidebar();
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
      item.toggleAttribute("hidden", !matches);
      if (matches) visible += 1;
    });
    const empty = dialog.querySelector("[data-quick-search-empty]");
    if (empty instanceof HTMLElement) empty.hidden = visible !== 0;
  });
}
