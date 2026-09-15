(() => {
  const nextIndex = (container, selector, minimum = 0) => {
    let highest = minimum - 1;
    container.querySelectorAll(selector).forEach((row) => {
      row.querySelectorAll("[name]").forEach((field) => {
        const match = field.getAttribute("name")?.match(/_(\d+)$/);
        if (match) highest = Math.max(highest, Number(match[1]));
      });
    });
    return highest + 1;
  };

  const appendTemplateRow = (form, templateSelector, containerSelector, rowSelector, minimum = 0) => {
    const template = document.querySelector(templateSelector);
    const container = form.querySelector(containerSelector);
    if (!(template instanceof HTMLTemplateElement) || !container) return;
    const index = nextIndex(container, rowSelector, minimum);
    const fragment = template.content.cloneNode(true);
    fragment.querySelectorAll("[data-name-prefix]").forEach((field) => {
      const name = `${field.getAttribute("data-name-prefix")}${index}`;
      field.setAttribute("name", name);
      field.id = name.replaceAll("_", "-");
      const label = field.closest(".cw-field")?.querySelector("label");
      if (label instanceof HTMLLabelElement) label.htmlFor = field.id;
      field.removeAttribute("data-name-prefix");
    });
    container.querySelector("[data-empty-app-ports]")?.remove();
    container.append(fragment);
    return container.lastElementChild;
  };

  const pickers = new WeakMap();
  const pickerForm = (dialog) => dialog?.closest("[data-drawer-panel]")?.querySelector("[data-environment-form]");
  const selectedProfile = (dialog) => pickerForm(dialog)?.querySelector('[name="credential_profile"]');
  const setStatus = (dialog, message) => {
    const status = dialog.querySelector("[data-github-status]");
    if (status) status.textContent = message;
  };
  const filterRepositories = (dialog) => {
    const query = dialog.querySelector("[data-github-filter]")?.value.trim().toLowerCase() || "";
    const rows = dialog.querySelectorAll("[data-select-github-repository]");
    let visible = 0;
    rows.forEach((button) => {
      const matches = (button.dataset.repositoryName || "").toLowerCase().includes(query);
      button.closest("li")?.toggleAttribute("hidden", !matches);
      if (matches) visible += 1;
    });
    const empty = dialog.querySelector("[data-github-filter-empty]");
    if (empty) empty.hidden = !rows.length || visible > 0;
  };
  const pickerState = (dialog) => {
    if (!pickers.has(dialog)) {
      pickers.set(dialog, { controller: null, history: [""], profile: "" });
      dialog.addEventListener("close", () => {
        pickers.get(dialog)?.controller?.abort();
      });
    }
    return pickers.get(dialog);
  };
  const loadRepositories = async (dialog, token = "", history = [""]) => {
    const state = pickerState(dialog);
    state.controller?.abort();
    const profile = selectedProfile(dialog);
    const results = dialog.querySelector("[data-github-results]");
    if (!(profile instanceof HTMLSelectElement) || !results) return;
    state.profile = profile.value;
    if (!profile.value || profile.disabled) {
      results.replaceChildren();
      results.inert = false;
      results.removeAttribute("aria-busy");
      setStatus(dialog, "Choose a profile with a GitHub connection. You can connect GitHub and create a profile in Settings.");
      const previous = dialog.querySelector("[data-github-previous]");
      if (previous) previous.hidden = true;
      filterRepositories(dialog);
      return;
    }
    const controller = new AbortController();
    state.controller = controller;
    results.inert = true;
    results.setAttribute("aria-busy", "true");
    setStatus(dialog, "Loading GitHub repositories…");
    const originalProfile = profile.value;
    const timer = window.setTimeout(() => controller.abort(), 40_000);
    try {
      const endpoint = new URL(dialog.dataset.repositoriesUrl, window.location.origin);
      if (endpoint.origin !== window.location.origin || !endpoint.pathname.endsWith("/_fragments/github-repositories")) throw new Error("invalid endpoint");
      const csrf = pickerForm(dialog)?.querySelector('[name="_csrf"]')?.value || "";
      const response = await fetch(endpoint, {
        method: "POST", credentials: "same-origin", redirect: "error",
        headers: { Accept: "text/html" },
        body: new URLSearchParams({ _csrf: csrf, credential_profile: originalProfile, page_token: token }),
        signal: controller.signal,
      });
      if (!response.headers.get("content-type")?.startsWith("text/html")) throw new Error("invalid content type");
      const text = await response.text();
      if (text.length > 1024 * 1024) throw new Error("oversized response");
      if (state.controller !== controller || !dialog.isConnected || !dialog.open || profile.value !== originalProfile) return;
      const parsed = new DOMParser().parseFromString(text, "text/html");
      const page = parsed.querySelector("[data-github-results-page]");
      if (!page || parsed.querySelector("script") || page.dataset.githubProfile !== originalProfile) throw new Error("invalid repository response");
      results.replaceChildren(document.importNode(page, true));
      if (response.ok) state.history = history;
      const previous = dialog.querySelector("[data-github-previous]");
      if (previous) previous.hidden = state.history.length < 2;
      setStatus(dialog, response.ok ? "Choose a repository to add it to this Sandbox." : "Repositories could not be loaded. See the message below.");
      filterRepositories(dialog);
    } catch {
      if (state.controller !== controller || !dialog.isConnected || !dialog.open || profile.value !== originalProfile) return;
      results.replaceChildren();
      setStatus(dialog, "GitHub repositories could not be loaded. Check your connection and selected profile, then close and reopen the picker to retry.");
      filterRepositories(dialog);
    } finally {
      window.clearTimeout(timer);
      if (state.controller === controller) {
        results.inert = false;
        results.removeAttribute("aria-busy");
      }
    }
  };

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const opener = event.target.closest("[data-open-github-repositories]");
    if (opener) {
      const dialog = opener.closest("[data-drawer-panel]")?.querySelector("[data-github-repository-picker]");
      if (!(dialog instanceof HTMLDialogElement)) return;
      const profile = selectedProfile(dialog);
      const choice = dialog.querySelector("[data-github-profile]");
      if (profile && choice) choice.value = profile.value;
      const filter = dialog.querySelector("[data-github-filter]");
      if (filter) filter.value = "";
      pickerState(dialog).history = [""];
      dialog.showModal();
      if (profile?.value) dialog.querySelector("[data-github-filter]")?.focus();
      else choice?.focus();
      void loadRepositories(dialog);
      return;
    }
    const dialog = event.target.closest("[data-github-repository-picker]");
    if (!(dialog instanceof HTMLDialogElement)) return;
    if (event.target.closest("[data-close-github-repositories]")) {
      dialog.close();
      return;
    }
    // Backdrop clicks target the dialog itself; padding clicks remain inside.
    if (event.target === dialog) {
      const box = dialog.getBoundingClientRect();
      if (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom) dialog.close();
      return;
    }
    const state = pickerState(dialog);
    const next = event.target.closest("[data-github-next]");
    if (next) {
      const token = next.getAttribute("data-page-token");
      if (token && state.history.length < 1000 && !state.history.includes(token)) void loadRepositories(dialog, token, [...state.history, token]);
      return;
    }
    if (event.target.closest("[data-github-previous]") && state.history.length > 1) {
      const history = state.history.slice(0, -1);
      void loadRepositories(dialog, history.at(-1), history);
      return;
    }
    const repository = event.target.closest("[data-select-github-repository]");
    if (!(repository instanceof HTMLButtonElement) || repository.disabled) return;
    const form = pickerForm(dialog);
    const current = selectedProfile(dialog)?.value;
    if (!(form instanceof HTMLFormElement) || !current || current !== repository.closest("[data-github-results-page]")?.dataset.githubProfile) return;
    const existing = Array.from(form.querySelectorAll("[data-repository-row]"));
    let row = existing.find((item) => item.querySelector('[name^="repo_url_"]')?.value === repository.dataset.repositoryUrl);
    if (row) {
      dialog.close();
      row.querySelector('[name^="repo_url_"]')?.focus();
      return;
    }
    row ||= existing.find((item) => !item.querySelector('[name^="repo_url_"]')?.value.trim());
    row ||= appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]");
    if (!row) return;
    row.querySelector('[name^="repo_url_"]').value = repository.dataset.repositoryUrl || "";
    row.querySelector('[name^="repo_branch_"]').value = repository.dataset.repositoryBranch || "";
    const mount = row.querySelector('[name^="repo_mount_"]');
    if (mount && !mount.value) mount.value = repository.dataset.repositoryName?.split("/").at(-1) || "";
    dialog.close();
    row.querySelector('[name^="repo_url_"]')?.focus();
  });

  document.addEventListener("change", (event) => {
    if (!(event.target instanceof HTMLSelectElement)) return;
    if (event.target.matches("[data-github-profile]")) {
      const dialog = event.target.closest("[data-github-repository-picker]");
      const profile = selectedProfile(dialog);
      if (profile && !profile.disabled) {
        profile.value = event.target.value;
        profile.dispatchEvent(new Event("change", { bubbles: true }));
      }
    } else if (event.target.name === "credential_profile") {
      const dialog = event.target.closest("[data-drawer-panel]")?.querySelector("[data-github-repository-picker]");
      if (!(dialog instanceof HTMLDialogElement)) return;
      const choice = dialog.querySelector("[data-github-profile]");
      if (choice) choice.value = event.target.value;
      pickerState(dialog).controller?.abort();
      pickerState(dialog).history = [""];
      if (dialog.open) void loadRepositories(dialog);
    }
  });
  document.addEventListener("input", (event) => {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches("[data-github-filter]")) return;
    const dialog = event.target.closest("[data-github-repository-picker]");
    if (dialog) filterRepositories(dialog);
  });

  document.addEventListener("focusout", (event) => {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches("[data-ttl-input]")) return;
    const value = event.target.value.trim().toLocaleLowerCase();
    if (value === "" || value === "0" || value === "∞" || value === "infinity") {
      event.target.value = "infinity";
      return;
    }
    const duration = value.match(/^(\d+)\s*([smhd])$/);
    if (duration) event.target.value = `${duration[1]}${duration[2]}`;
  });

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-form]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.closest("[data-add-repository]")) {
      appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]");
    } else if (event.target.closest("[data-remove-repository]")) {
      const rows = form.querySelectorAll("[data-repository-row]");
      if (rows.length > 1) event.target.closest("[data-repository-row]")?.remove();
    } else if (event.target.closest("[data-add-app-port]")) {
      appendTemplateRow(form, "[data-app-port-template]", "[data-app-port-rows]", "[data-app-port-row]");
    } else if (event.target.closest("[data-remove-app-port]")) {
      event.target.closest("[data-app-port-row]")?.remove();
    } else if (event.target.closest("[data-reset-workspace-image]")) {
      const image = form.querySelector('[name="image"]');
      if (image instanceof HTMLInputElement) image.value = "ghcr.io/codewiresh/workspace@sha256:18af6b9ff1ac123754aff20b3229ecf882b5553117d9c5fbe43ab2f36f282cff";
    }
  });
})();
