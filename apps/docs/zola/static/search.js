(() => {
  "use strict";

  const app = document.querySelector("[data-docs-app]");
  const navToggle = document.querySelector("[data-docs-nav-toggle]");
  const navClose = document.querySelector("[data-docs-nav-close]");
  const searchRoot = document.querySelector("[data-docs-search]");
  const searchInput = document.querySelector("[data-docs-search-input]");
  const searchPanel = document.querySelector("[data-docs-search-panel]");
  const searchResults = document.querySelector("[data-docs-search-results]");
  const searchStatus = document.querySelector("[data-docs-search-status]");
  const rootMetadata = document.querySelector("meta[name='codewire-docs-root']");
  const searchMetadata = document.querySelector("meta[name='codewire-docs-search-index']");
  const docsRoot = rootMetadata ? new URL(rootMetadata.content, window.location.origin).pathname.replace(/\/+$/, "") || "/" : "/docs";
  const searchIndexUrl = searchMetadata ? searchMetadata.content : `${docsRoot}/search_index.en.json`;
  const maximumResults = 8;

  let indexPromise;
  let visibleResults = [];
  let activeResult = -1;

  const setNavigationOpen = (open) => {
    if (!app || !navToggle) return;
    app.dataset.navOpen = String(open);
    navToggle.setAttribute("aria-expanded", String(open));
    navToggle.setAttribute(
      "aria-label",
      open ? "Close documentation navigation" : "Open documentation navigation",
    );
  };

  const normalizeResultPath = (value) => {
    const path = new URL(value, window.location.origin).pathname.replace(/\/+$/, "");
    return path || docsRoot;
  };

  const loadIndex = () => {
    if (!indexPromise) {
      indexPromise = fetch(searchIndexUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      }).then((response) => {
        if (!response.ok) throw new Error(`Search index returned ${response.status}`);
        return response.json();
      });
    }
    return indexPromise;
  };

  const termsFor = (query) => query
    .toLocaleLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 8);

  const scoreEntry = (entry, terms) => {
    const title = (entry.title || "").toLocaleLowerCase();
    const description = (entry.description || "").toLocaleLowerCase();
    const path = normalizeResultPath(entry.url).toLocaleLowerCase();
    const body = (entry.body || "").toLocaleLowerCase();
    let score = 0;

    for (const term of terms) {
      const titleIndex = title.indexOf(term);
      const descriptionIndex = description.indexOf(term);
      const pathIndex = path.indexOf(term);
      const bodyIndex = body.indexOf(term);
      if (titleIndex < 0 && descriptionIndex < 0 && pathIndex < 0 && bodyIndex < 0) return -1;
      if (titleIndex === 0) score += 32;
      else if (titleIndex > 0) score += 16;
      if (descriptionIndex >= 0) score += 8;
      if (pathIndex >= 0) score += 4;
      if (bodyIndex >= 0) score += 1;
    }

    return score;
  };

  const setActiveResult = (nextIndex) => {
    if (!searchInput || !searchResults || visibleResults.length === 0) return;
    activeResult = (nextIndex + visibleResults.length) % visibleResults.length;
    const options = searchResults.querySelectorAll("[role='option']");
    options.forEach((option, index) => option.setAttribute("aria-selected", String(index === activeResult)));
    const activeOption = options[activeResult];
    searchInput.setAttribute("aria-activedescendant", activeOption.id);
    activeOption.scrollIntoView({ block: "nearest" });
  };

  const closeSearch = () => {
    if (!searchInput || !searchPanel || !searchResults || !searchStatus) return;
    searchPanel.hidden = true;
    searchInput.setAttribute("aria-expanded", "false");
    searchInput.removeAttribute("aria-activedescendant");
    searchResults.replaceChildren();
    searchStatus.textContent = "";
    visibleResults = [];
    activeResult = -1;
  };

  const renderResults = (entries, terms) => {
    if (!searchInput || !searchPanel || !searchResults || !searchStatus) return;
    visibleResults = entries;
    activeResult = -1;
    searchResults.replaceChildren();
    searchPanel.hidden = false;
    searchInput.setAttribute("aria-expanded", "true");

    if (entries.length === 0) {
      searchStatus.textContent = `No results for “${terms.join(" ")}”`;
      return;
    }

    searchStatus.textContent = `${entries.length} result${entries.length === 1 ? "" : "s"}`;
    entries.forEach((entry, index) => {
      const item = document.createElement("li");
      const link = document.createElement("a");
      const title = document.createElement("strong");
      const description = document.createElement("span");
      item.id = `docs-search-result-${index}`;
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", "false");
      link.href = normalizeResultPath(entry.url);
      title.textContent = entry.title || normalizeResultPath(entry.url);
      description.textContent = entry.description || normalizeResultPath(entry.url);
      link.append(title, description);
      item.append(link);
      searchResults.append(item);
    });
  };

  const runSearch = async () => {
    if (!searchInput || !searchStatus) return;
    const query = searchInput.value.trim();
    const terms = termsFor(query);
    if (terms.length === 0) {
      closeSearch();
      return;
    }

    searchStatus.textContent = "Searching…";
    try {
      const index = await loadIndex();
      const matches = index
        .map((entry) => ({ entry, score: scoreEntry(entry, terms) }))
        .filter((candidate) => candidate.score >= 0)
        .sort((left, right) => right.score - left.score || (left.entry.title || "").localeCompare(right.entry.title || ""))
        .slice(0, maximumResults)
        .map((candidate) => candidate.entry);
      if (searchInput.value.trim() === query) renderResults(matches, terms);
    } catch (_error) {
      searchPanel.hidden = false;
      searchInput.setAttribute("aria-expanded", "true");
      searchStatus.textContent = "Search is unavailable right now.";
    }
  };

  let searchTimer;
  searchInput?.addEventListener("input", () => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(runSearch, 80);
  });

  searchInput?.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveResult(activeResult + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveResult(activeResult - 1);
    } else if (event.key === "Enter" && activeResult >= 0) {
      event.preventDefault();
      window.location.assign(normalizeResultPath(visibleResults[activeResult].url));
    } else if (event.key === "Escape") {
      closeSearch();
      searchInput.blur();
    }
  });

  navToggle?.addEventListener("click", () => setNavigationOpen(app?.dataset.navOpen !== "true"));
  navClose?.addEventListener("click", () => setNavigationOpen(false));
  document.querySelectorAll(".docs-nav-link").forEach((link) => link.addEventListener("click", () => setNavigationOpen(false)));

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      setNavigationOpen(false);
      if (document.activeElement !== searchInput) closeSearch();
    }
    if ((event.key === "/" && !event.metaKey && !event.ctrlKey && !event.altKey) || ((event.metaKey || event.ctrlKey) && event.key.toLocaleLowerCase() === "k")) {
      const target = event.target;
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target?.isContentEditable) return;
      event.preventDefault();
      searchInput?.focus();
    }
  });

  document.addEventListener("click", (event) => {
    if (searchRoot && event.target instanceof Node && !searchRoot.contains(event.target)) closeSearch();
  });
})();
