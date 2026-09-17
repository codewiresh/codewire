(() => {
  const draftPrefix = "codewire.create-selections.v1:";
  const draftLimit = 8192;
  const draftAge = 30 * 60 * 1000;
  const draftCount = 5;
  const draftStates = new WeakMap();
  const canonicalId = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== "00000000-0000-0000-0000-000000000000";
  const actorId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  const draftNumber = (value, minimum, maximum) => typeof value === "string" && /^\d{1,7}$/.test(value) && Number(value) >= minimum && Number(value) <= maximum;
  const draftTtl = (value) => {
    if (["", "0", "infinity"].includes(value)) return true;
    if (typeof value !== "string" || value.length > 10) return false;
    const match = value.match(/^(\d+)([smhd]?)$/);
    const seconds = match && Number(match[1]) * ({ s: 1, m: 60, h: 3600, d: 86400, "": 60 }[match[2]]);
    return seconds >= 60 && seconds <= 31_536_000;
  };
  const validDraft = (draft) => {
    if (!exactKeys(draft, ["version", "actor", "organization", "draft", "saved_at", "selections"]) || draft.version !== 1 || !actorId(draft.actor) || ![draft.organization, draft.draft].every(canonicalId) || !Number.isSafeInteger(draft.saved_at) || draft.saved_at < 0 || draft.saved_at > Date.now() || Date.now() - draft.saved_at >= draftAge) return false;
    const value = draft.selections;
    if (!exactKeys(value, ["preset_id", "cpu", "memory", "disk", "ttl", "isolation_tier", "agents", "ports", "secret_project", "credential_profile", "include_org_secrets", "include_user_secrets"])) return false;
    if (!(value.preset_id === "" || canonicalId(value.preset_id)) || !draftNumber(value.cpu, 100, 128000) || !draftNumber(value.memory, 128, 1048576) || !draftNumber(value.disk, 1, 16384) || !draftTtl(value.ttl) || !["standard", "confidential"].includes(value.isolation_tier)) return false;
    if (!Array.isArray(value.agents) || value.agents.length > 6 || new Set(value.agents).size !== value.agents.length || value.agents.some((id) => !["claude-code", "codex", "gemini-cli", "kimi-code", "pi", "aider"].includes(id))) return false;
    if (!Array.isArray(value.ports) || value.ports.length > 16 || value.ports.some((port) => !exactKeys(port, ["port", "access"]) || !draftNumber(port.port, 1, 65535) || !["creator", "org_members", "public"].includes(port.access))) return false;
    if (!(value.secret_project === "" || canonicalId(value.secret_project)) || typeof value.credential_profile !== "string" || typeof value.include_org_secrets !== "boolean" || typeof value.include_user_secrets !== "boolean") return false;
    if (value.credential_profile !== "") {
      const parts = value.credential_profile.split("@");
      // Revision bytes stay decimal text, including values beyond JS Number.
      if (parts.length !== 2 || !canonicalId(parts[0]) || !/^[1-9]\d{0,18}$/.test(parts[1]) || BigInt(parts[1]) > 9223372036854775807n) return false;
    }
    return true;
  };
  const draftStatus = (form, message) => {
    const status = form.querySelector("[data-create-draft-status]");
    if (status) status.textContent = message;
  };
  const draftKey = (draft) => `${draftPrefix}${draft.actor}:${draft.organization}:${draft.draft}`;
  const storedDrafts = (form) => {
    const storage = window.sessionStorage;
    const namespace = `${draftPrefix}${form.dataset.createDraftActor}:${form.dataset.createDraftOrganization}:`;
    // Read only this feature's keys/values, with a finite scan and entry bound.
    if (storage.length > 1000) throw new Error("storage scan limit");
    const found = [];
    const stale = [];
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (!key?.startsWith(draftPrefix)) continue;
      const bytes = storage.getItem(key);
      let draft = null;
      if (bytes && new TextEncoder().encode(bytes).length <= draftLimit) {
        try { draft = JSON.parse(bytes); } catch { /* Invalid owned data is discarded. */ }
      }
      if (!validDraft(draft) || draftKey(draft) !== key) stale.push(key);
      else found.push(draft);
    }
    stale.forEach((key) => storage.removeItem(key));
    found.sort((a, b) => b.saved_at - a.saved_at);
    found.slice(draftCount).forEach((draft) => storage.removeItem(draftKey(draft)));
    return found.slice(0, draftCount).filter((draft) => draftKey(draft).startsWith(namespace));
  };
  const draftFormValue = (form, name) => form.elements.namedItem(name)?.value?.trim() || "";
  const currentDraft = (form) => ({
    version: 1, actor: form.dataset.createDraftActor, organization: form.dataset.createDraftOrganization,
    draft: form.dataset.createDraftId, saved_at: Date.now(),
    selections: {
      preset_id: draftFormValue(form, "preset_id"), cpu: draftFormValue(form, "cpu"),
      memory: draftFormValue(form, "memory"), disk: draftFormValue(form, "disk"),
      ttl: draftFormValue(form, "ttl").toLowerCase(), isolation_tier: draftFormValue(form, "isolation_tier"),
      agents: Array.from(form.querySelectorAll('[name="agent"]:checked'), (field) => field.value),
      ports: Array.from(form.querySelectorAll("[data-app-port-row]"), (row) => ({
        port: row.querySelector('[name^="app_port_"]')?.value.trim() || "",
        access: row.querySelector('[name^="app_access_"]')?.value || "",
      })),
      secret_project: draftFormValue(form, "secret_project"), credential_profile: draftFormValue(form, "credential_profile"),
      include_org_secrets: form.querySelector('[name="include_org_secrets"]')?.checked === true,
      include_user_secrets: form.querySelector('[name="include_user_secrets"]')?.checked === true,
    },
  });
  const pristineDraftForm = (form) => Array.from(form.elements).every((field) => {
    if (field instanceof HTMLSelectElement) {
      const options = Array.from(field.options);
      const defaults = options.filter((option) => option.defaultSelected);
      return field.selectedIndex === (defaults.length ? options.indexOf(defaults.at(-1)) : 0);
    }
    if (field instanceof HTMLInputElement && ["checkbox", "radio"].includes(field.type)) return field.checked === field.defaultChecked;
    if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) return field.value === field.defaultValue;
    return true;
  });
  const draftIsOpen = (form) => {
    const drawer = form.closest("[data-drawer]");
    return form.isConnected && (!drawer || (!drawer.hidden && drawer.dataset.open === "true"));
  };
  const cancelDraftRestore = (state, form) => {
    if (state.controller && form?.isConnected) draftStatus(form, "Restore cancelled. Your inputs have been kept; review them or restore again before creating a Sandbox.");
    state.sequence += 1;
    state.controller?.abort();
    state.controller = null;
  };
  const saveDraft = (form, state) => {
    if (!form.isConnected || state.storageFailed) return;
    const draft = currentDraft(form);
    if (!validDraft(draft)) {
      draftStatus(form, "Some selections are not ready to save. Complete their fields; free-form inputs are never saved.");
      return;
    }
    try {
      const bytes = JSON.stringify(draft);
      if (new TextEncoder().encode(bytes).length > draftLimit) throw new Error("draft size limit");
      const storage = window.sessionStorage;
      storage.setItem(draftKey(draft), bytes);
      if (storage.getItem(draftKey(draft)) !== bytes) throw new Error("draft storage mismatch");
      storedDrafts(form);
      draftStatus(form, "Selections saved in this tab.");
    } catch {
      state.storageFailed = true;
      draftStatus(form, "Selections cannot be saved in this browser. Keep this form open or re-enter them after returning.");
    }
  };
  const readDraftHtml = async (response) => {
    if (!response.body) throw new Error("missing draft response");
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let size = 0;
    let text = "";
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 1024 * 1024) throw new Error("draft response limit");
        text += decoder.decode(value, { stream: true });
      }
      return text + decoder.decode();
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  };
  const restoreDraft = async (form, state) => {
    if (!state || !state.saved || state.edited || state.storageFailed || form.dataset.createDraftFresh !== "true" || !draftIsOpen(form) || !pristineDraftForm(form)) return;
    cancelDraftRestore(state, form);
    const sequence = state.sequence;
    const controller = new AbortController();
    state.controller = controller;
    const button = form.querySelector("[data-restore-create-draft]");
    if (button) button.disabled = true;
    draftStatus(form, "Checking current options before restoring selections…");
    const timer = window.setTimeout(() => controller.abort(), 40_000);
    try {
      if (!validDraft(state.saved)) throw new Error("draft expired");
      const endpoint = new URL(form.dataset.createDraftUrl, window.location.origin);
      if (endpoint.origin !== window.location.origin || !endpoint.pathname.endsWith("/_fragments/create-draft") || endpoint.search || endpoint.hash) throw new Error("invalid draft endpoint");
      const response = await fetch(endpoint, {
        method: "POST", credentials: "same-origin", redirect: "error", signal: controller.signal,
        headers: { Accept: "text/html" },
        body: new URLSearchParams({ _csrf: draftFormValue(form, "_csrf"), creation_draft: state.saved.draft, metadata: JSON.stringify(state.saved) }),
      });
      if (!response.ok || !response.headers.get("content-type")?.startsWith("text/html")) throw new Error("draft rejected");
      const text = await readDraftHtml(response);
      if (controller.signal.aborted || state.sequence !== sequence || state.edited || !draftIsOpen(form)) return;
      if (!pristineDraftForm(form)) {
        state.edited = true;
        draftStatus(form, "Restore cancelled because this form changed. Your inputs have been kept; review them before creating a Sandbox.");
        return;
      }
      const parsed = new DOMParser().parseFromString(text, "text/html");
      const cards = parsed.querySelectorAll("#environment-create-card");
      const replacement = cards.length === 1 && cards[0];
      const restored = replacement?.querySelector("[data-environment-form]");
      if (!restored || restored.dataset.createDraftActor !== form.dataset.createDraftActor || restored.dataset.createDraftOrganization !== form.dataset.createDraftOrganization || restored.dataset.createDraftId !== state.saved.draft || restored.dataset.createDraftRestored !== "true" || parsed.querySelector("script")) throw new Error("invalid restored form");
      form.closest("#environment-create-card")?.replaceWith(replacement);
      wireDraftForms();
      restored.querySelector('[name="name"]')?.focus();
    } catch {
      if (!state.edited && state.sequence === sequence && draftIsOpen(form)) draftStatus(form, "Saved selections could not be restored. Reload and review current options; no Sandbox was created.");
    } finally {
      window.clearTimeout(timer);
      if (state.controller === controller) state.controller = null;
      if (button && form.isConnected) button.disabled = state.edited || state.storageFailed || !pristineDraftForm(form);
    }
  };
  const wireDraftForms = () => {
    document.querySelectorAll("[data-environment-form][data-create-draft-id]").forEach((form) => {
      if (!(form instanceof HTMLFormElement) || draftStates.has(form)) return;
      const state = { saved: null, edited: false, storageFailed: false, sequence: 0, controller: null };
      draftStates.set(form, state);
      if (!actorId(form.dataset.createDraftActor) || ![form.dataset.createDraftOrganization, form.dataset.createDraftId].every(canonicalId)) return;
      try {
        const saved = storedDrafts(form);
        const exactReturn = form.dataset.createDraftExact === "true";
        state.saved = saved.find((draft) => draft.draft === form.dataset.createDraftId) || (!exactReturn && saved[0]) || null;
        const button = form.querySelector("[data-restore-create-draft]");
        if (button) button.hidden = !state.saved || form.dataset.createDraftFresh !== "true";
        if (exactReturn && !state.saved) draftStatus(form, "The requested saved selections are unavailable in this tab. Re-enter them; no Sandbox was created.");
      } catch {
        state.storageFailed = true;
        draftStatus(form, "Selections cannot be saved in this browser. Keep this form open or re-enter them after returning.");
      }
      const owner = form.closest("[data-drawer]") || form.parentElement;
      if (owner) {
        const observer = new MutationObserver(() => {
          if (!form.isConnected) { cancelDraftRestore(state, form); observer.disconnect(); }
          else if (!draftIsOpen(form)) cancelDraftRestore(state, form);
        });
        observer.observe(owner, { childList: true, attributes: true, attributeFilter: ["hidden", "data-open"] });
      }
    });
  };
  const editDraft = (form) => {
    const state = draftStates.get(form);
    if (!state) return;
    state.edited = true;
    cancelDraftRestore(state, form);
    const button = form.querySelector("[data-restore-create-draft]");
    if (button) button.disabled = true;
    queueMicrotask(() => saveDraft(form, state));
  };
  ["input", "change"].forEach((eventName) => document.addEventListener(eventName, (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-form]");
    if (form instanceof HTMLFormElement) editDraft(form);
  }, true));
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const card = event.target.closest("#environment-create-card");
    const form = card?.querySelector("[data-environment-form]");
    if (!(form instanceof HTMLFormElement)) return;
    const restore = event.target.closest("[data-restore-create-draft]");
    if (restore) { void restoreDraft(form, draftStates.get(form)); return; }
    if (event.target.closest("button")) editDraft(form);
  }, true);
  document.addEventListener("htmx:beforeSwap", (event) => {
    document.querySelectorAll("[data-environment-form]").forEach((form) => {
      if (event.detail?.target?.contains(form)) {
        const state = draftStates.get(form);
        if (state) cancelDraftRestore(state, form);
      }
    });
  });
  document.addEventListener("htmx:afterSwap", wireDraftForms);
  window.addEventListener("pagehide", () => {
    document.querySelectorAll("[data-environment-form]").forEach((form) => {
      const state = draftStates.get(form);
      if (state) cancelDraftRestore(state, form);
    });
  });
  window.addEventListener("pageshow", wireDraftForms);
  wireDraftForms();

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
