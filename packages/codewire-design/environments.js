(() => {
  const draftPrefix = "codewire.create-selections.v1:";
  const draftActorKey = "codewire.create-draft-actor.v1";
  const pendingCreateKey = `${draftPrefix}pending-create`;
  const draftLimit = 512 * 1024;
  const draftStates = new WeakMap();
  const optionStates = new WeakMap();
  const canonicalId = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && value !== "00000000-0000-0000-0000-000000000000";
  // Account and organization IDs are opaque (currently 32 hex bytes), not UUIDs.
  const opaqueId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
  const actorId = opaqueId;
  const organizationId = opaqueId;
  const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  const draftNumber = (value, minimum, maximum) => typeof value === "string" && /^\d{1,7}$/.test(value) && Number(value) >= minimum && Number(value) <= maximum;
  // Empty uses the saved configuration's default lifetime. "0", "infinity"
  // and "∞" meant the same in older input and drafts; they are still read,
  // but never written back.
  const defaultTtl = (value) => ["", "0", "infinity", "∞"].includes(value.trim().toLocaleLowerCase());
  const draftTtl = (value) => {
    if (["", "0", "infinity"].includes(value)) return true;
    if (typeof value !== "string" || value.length > 10) return false;
    const match = value.match(/^(\d+)([smhd]?)$/);
    const seconds = match && Number(match[1]) * ({ s: 1, m: 60, h: 3600, d: 86400, "": 60 }[match[2]]);
    return seconds >= 60 && seconds <= 31_536_000;
  };
  const safeStoredRepositoryUrl = (raw) => {
    if (!raw || /[?#\u0000-\u001f\u007f]/.test(raw)) return "";
    const authority = raw.match(/^([a-z][a-z0-9+.-]*):\/\/([^/]*)/i);
    if (authority && authority[2].includes("@")) {
      const user = authority[2].slice(0, authority[2].lastIndexOf("@"));
      if (!(["ssh", "git+ssh"].includes(authority[1].toLowerCase()) && user === "git")) return "";
    } else if (!authority && raw.includes("@") && !/^git@[^:]+:.+$/.test(raw)) return "";
    return raw;
  };
  const authoredText = (value, limit) => typeof value === "string" && value.length <= limit;
  const validAuthored = (value) => exactKeys(value, ["name", "image", "install_command", "startup_script", "repositories", "port_rows", "ttl"])
    && authoredText(value.name, 128) && authoredText(value.image, 2048)
    && authoredText(value.install_command, 16384) && authoredText(value.startup_script, 16384)
    && authoredText(value.ttl, 64)
    && Array.isArray(value.repositories) && value.repositories.length <= 108
    && value.repositories.every((row) => exactKeys(row, ["url", "branch", "mount"])
      && authoredText(row.url, 4096) && safeStoredRepositoryUrl(row.url) === row.url
      && authoredText(row.branch, 512) && authoredText(row.mount, 512))
    && Array.isArray(value.port_rows) && value.port_rows.length <= 16
    && value.port_rows.every((row) => exactKeys(row, ["port", "label", "access"])
      && authoredText(row.port, 16) && authoredText(row.label, 22)
      && ["creator", "org_members", "public"].includes(row.access));
  const validDraft = (draft) => {
    const hasAuthored = exactKeys(draft, ["version", "actor", "organization", "draft", "saved_at", "selections", "authored"]);
    if (!(hasAuthored || exactKeys(draft, ["version", "actor", "organization", "draft", "saved_at", "selections"])) || draft.version !== 1 || !actorId(draft.actor) || !organizationId(draft.organization) || !canonicalId(draft.draft) || !Number.isSafeInteger(draft.saved_at) || draft.saved_at < 0 || draft.saved_at > Date.now()) return false;
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
    return !hasAuthored || validAuthored(draft.authored);
  };
  const draftStatus = (form, message, announce = false) => {
    const status = form.querySelector("[data-create-draft-status]");
    if (status) {
      status.textContent = message;
      if (announce) status.setAttribute("role", "alert");
      else status.removeAttribute("role");
    }
  };
  const hasUnstoredRepositoryUrl = (form) => Array.from(form.querySelectorAll('[name^="repo_url_"]'))
    .some((field) => safeStoredRepositoryUrl(field.value) !== field.value);
  const draftKey = (draft) => `${draftPrefix}${draft.actor}:${draft.organization}:${draft.draft}`;
  const clearOwnedDrafts = () => {
    try {
      const storage = window.sessionStorage;
      const keys = [];
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (key?.startsWith(draftPrefix)) keys.push(key);
      }
      keys.forEach((key) => storage.removeItem(key));
    } catch { /* Storage denial must not block the form. */ }
  };
  const reconcileDraftActor = (actor) => {
    try {
      const storage = window.sessionStorage;
      const previous = storage.getItem(draftActorKey);
      if (previous && previous !== actor) clearOwnedDrafts();
      storage.setItem(draftActorKey, actor);
    } catch { /* A storage-denied form remains usable without recovery. */ }
  };
  const storedDrafts = (form) => {
    const storage = window.sessionStorage;
    const namespace = `${draftPrefix}${form.dataset.createDraftActor}:${form.dataset.createDraftOrganization}:`;
    // Keep the scan finite, but never evict a valid draft merely by count.
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
    return found.filter((draft) => draftKey(draft).startsWith(namespace));
  };
  const draftFormValue = (form, name) => form.elements.namedItem(name)?.value?.trim() || "";
  const currentDraft = (form) => {
    const ttl = draftFormValue(form, "ttl").toLowerCase();
    const portRows = Array.from(form.querySelectorAll("[data-app-port-row]"), (row) => ({
      port: row.querySelector('[name^="app_port_"]')?.value || "",
      label: row.querySelector('[name^="app_label_"]')?.value || "",
      access: row.querySelector('[name^="app_access_"]')?.value || "creator",
    }));
    return ({
    version: 1, actor: form.dataset.createDraftActor, organization: form.dataset.createDraftOrganization,
    draft: form.dataset.createDraftId, saved_at: Date.now(),
    selections: {
      preset_id: draftFormValue(form, "preset_id"), cpu: draftFormValue(form, "cpu"),
      memory: draftFormValue(form, "memory"), disk: draftFormValue(form, "disk"),
      ttl: draftTtl(ttl) && !defaultTtl(ttl) ? ttl : "", isolation_tier: draftFormValue(form, "isolation_tier"),
      agents: Array.from(form.querySelectorAll('[name="agent"]:checked'), (field) => field.value),
      ports: portRows.filter((row) => draftNumber(row.port.trim(), 1, 65535))
        .map((row) => ({ port: row.port.trim(), access: row.access })),
      secret_project: draftFormValue(form, "secret_project"), credential_profile: draftFormValue(form, "credential_profile"),
      include_org_secrets: form.querySelector('[name="include_org_secrets"]')?.checked === true,
      include_user_secrets: form.querySelector('[name="include_user_secrets"]')?.checked === true,
    },
    authored: {
      name: form.elements.namedItem("name")?.value || "",
      image: form.elements.namedItem("image")?.value || "",
      install_command: form.elements.namedItem("install_command")?.value || "",
      startup_script: form.elements.namedItem("startup_script")?.value || "",
      repositories: Array.from(form.querySelectorAll("[data-repository-row]"), (row) => ({
        url: safeStoredRepositoryUrl(row.querySelector('[name^="repo_url_"]')?.value || ""),
        branch: row.querySelector('[name^="repo_branch_"]')?.value || "",
        mount: row.querySelector('[name^="repo_mount_"]')?.value || "",
      })),
      port_rows: portRows,
      ttl: form.elements.namedItem("ttl")?.value || "",
    },
  });
  };
  const pristineDraftForm = (form) => Array.from(form.elements).every((field) => {
    if (field.closest?.("[data-github-browser]")) return true;
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
    if (!form.isConnected || state.storageFailed) return false;
    const draft = currentDraft(form);
    if (!validDraft(draft)) {
      draftStatus(form, "This draft could not be saved. Check the form fields and keep this tab open.", true);
      return false;
    }
    try {
      const bytes = JSON.stringify(draft);
      if (new TextEncoder().encode(bytes).length > draftLimit) throw new Error("draft size limit");
      const storage = window.sessionStorage;
      storage.setItem(draftKey(draft), bytes);
      if (storage.getItem(draftKey(draft)) !== bytes) throw new Error("draft storage mismatch");
      storedDrafts(form);
      const redacted = hasUnstoredRepositoryUrl(form);
      draftStatus(form, redacted ? "Draft saved, but a repository URL containing credentials or query data was not saved. Re-enter it when you return." : "Draft saved in this tab.");
      return true;
    } catch {
      state.storageFailed = true;
      draftStatus(form, "This draft cannot be saved in this browser. Keep the form open until you finish.", true);
      return false;
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
  const restoreAuthored = (form, authored) => {
    if (!authored) return;
    const fields = ["name", "image", "install_command", "startup_script", "ttl"];
    for (const name of fields) {
      const field = form.elements.namedItem(name);
      if (!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement)) throw new Error("invalid authored field");
      // A lifetime left to the default keeps the restored preset's default.
      if (name === "ttl" && defaultTtl(authored.ttl)) continue;
      field.value = authored[name];
    }
    const rows = form.querySelector("[data-repository-rows]");
    if (!rows) throw new Error("invalid repository rows");
    while (rows.querySelectorAll("[data-repository-row]").length > authored.repositories.length) rows.lastElementChild?.remove();
    while (rows.querySelectorAll("[data-repository-row]").length < authored.repositories.length) {
      if (!appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]")) throw new Error("invalid repository template");
    }
    Array.from(rows.querySelectorAll("[data-repository-row]")).forEach((row, index) => {
      for (const [prefix, key] of [["repo_url_", "url"], ["repo_branch_", "branch"], ["repo_mount_", "mount"]]) {
        const field = row.querySelector(`[name^="${prefix}"]`);
        if (!(field instanceof HTMLInputElement)) throw new Error("invalid repository field");
        field.value = authored.repositories[index][key];
      }
    });
    const portContainer = form.querySelector("[data-app-port-rows]");
    if (!portContainer) throw new Error("invalid restored ports");
    portContainer.querySelectorAll("[data-app-port-row]").forEach((row) => row.remove());
    authored.port_rows.forEach((port) => {
      const row = appendTemplateRow(form, "[data-app-port-template]", "[data-app-port-rows]", "[data-app-port-row]");
      if (!row) throw new Error("invalid preview port template");
      const number = row.querySelector('[name^="app_port_"]');
      const label = row.querySelector('[name^="app_label_"]');
      const access = row.querySelector('[name^="app_access_"]');
      if (!(number instanceof HTMLInputElement) || !(label instanceof HTMLInputElement) || !(access instanceof HTMLSelectElement)) throw new Error("invalid preview port");
      number.value = port.port;
      label.value = port.label;
      access.value = port.access;
    });
  };
  const restoreDraft = async (form, state, automatic = false) => {
    if (!state || !state.saved || state.edited || state.storageFailed || form.dataset.createDraftFresh !== "true" || !draftIsOpen(form) || !pristineDraftForm(form)) return;
    suspendCreateOptions(form);
    cancelDraftRestore(state, form);
    const sequence = state.sequence;
    const controller = new AbortController();
    state.controller = controller;
    const button = form.querySelector("[data-restore-create-draft]");
    if (button) button.disabled = true;
    draftStatus(form, "Checking current options before restoring selections…");
    // An automatic restore holds the form briefly so an early keystroke cannot
    // replace the saved draft with an empty one; a slow restore gives it back.
    if (automatic) { form.inert = true; form.setAttribute("aria-busy", "true"); }
    const timer = window.setTimeout(() => controller.abort(), automatic ? 8_000 : 40_000);
    try {
      if (!validDraft(state.saved)) throw new Error("invalid draft");
      const endpoint = new URL(form.dataset.createDraftUrl, window.location.origin);
      if (endpoint.origin !== window.location.origin || !endpoint.pathname.endsWith("/_fragments/create-draft") || endpoint.search || endpoint.hash) throw new Error("invalid draft endpoint");
      const metadata = { ...state.saved };
      delete metadata.authored;
      const response = await fetch(endpoint, {
        method: "POST", credentials: "same-origin", redirect: "error", signal: controller.signal,
        headers: { Accept: "text/html" },
        body: new URLSearchParams({ _csrf: draftFormValue(form, "_csrf"), creation_draft: state.saved.draft, metadata: JSON.stringify(metadata) }),
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
      restoreAuthored(restored, state.saved.authored);
      form.closest("#environment-create-card")?.replaceWith(replacement);
      wireDraftForms();
      wireGithubBrowsers();
      enhanceComboboxes();
      restored.querySelector('[name="name"]')?.focus();
    } catch {
      if (!state.edited && state.sequence === sequence && draftIsOpen(form)) draftStatus(form, "The draft could not be restored. Reload and review current options; no Sandbox was created.", true);
    } finally {
      window.clearTimeout(timer);
      if (state.controller === controller) state.controller = null;
      if (automatic && form.isConnected) { form.inert = false; form.removeAttribute("aria-busy"); }
      if (button && form.isConnected) button.disabled = state.edited || state.storageFailed || !pristineDraftForm(form);
      resumeCreateOptions(form);
    }
  };

  const cancelCreateOptions = (form) => {
    const state = optionStates.get(form);
    if (!state) return;
    state.sequence += 1;
    state.controller?.abort();
    state.controller = null;
  };
  const suspendCreateOptions = (form) => {
    const state = optionStates.get(form);
    if (state) {
      state.suspended = true;
      cancelCreateOptions(form);
    }
  };
  const resumeCreateOptions = (form) => {
    const state = optionStates.get(form);
    if (state && form.isConnected) {
      state.suspended = false;
      if (form.dataset.createOptionsLoading === "true") void loadCreateOptions(form, state);
    }
  };
  const loadCreateOptions = async (form, state) => {
    if (!state || state.suspended || !form.isConnected || form.dataset.createOptionsLoading !== "true") return;
    cancelCreateOptions(form);
    const sequence = state.sequence;
    const controller = new AbortController();
    state.controller = controller;
    const slot = form.querySelector("[data-create-optional-options]");
    const status = slot?.querySelector('[role="status"], [role="alert"]');
    if (status) { status.textContent = "Loading provider, secret, agent, and isolation choices…"; status.setAttribute("role", "status"); }
    const retry = slot?.querySelector("[data-retry-create-options]");
    if (retry) retry.hidden = true;
    const timer = window.setTimeout(() => controller.abort(), 40_000);
    try {
      const endpoint = new URL(form.dataset.createOptionsUrl, window.location.origin);
      if (endpoint.origin !== window.location.origin || !endpoint.pathname.endsWith("/_fragments/create-options") || endpoint.search || endpoint.hash) throw new Error("invalid options endpoint");
      const response = await fetch(endpoint, {
        method: "POST", credentials: "same-origin", redirect: "error", signal: controller.signal,
        headers: { Accept: "text/html" },
        body: new URLSearchParams({
          _csrf: draftFormValue(form, "_csrf"), actor: form.dataset.createDraftActor,
          organization: form.dataset.createDraftOrganization, draft_id: form.dataset.createDraftId,
          draft_return: form.dataset.createDraftReturn || "",
        }),
      });
      if (!response.ok || !response.headers.get("content-type")?.startsWith("text/html")) throw new Error("options unavailable");
      const html = await readDraftHtml(response);
      if (controller.signal.aborted || state.sequence !== sequence || state.suspended || !form.isConnected) return;
      const parsed = new DOMParser().parseFromString(html, "text/html");
      const replacement = parsed.querySelector("#environment-create-card [data-environment-form]");
      if (!replacement || parsed.querySelector("script") || replacement.dataset.createOptionsLoading !== "false" ||
          replacement.dataset.createDraftActor !== form.dataset.createDraftActor ||
          replacement.dataset.createDraftOrganization !== form.dataset.createDraftOrganization ||
          replacement.dataset.createDraftId !== form.dataset.createDraftId ||
          replacement.dataset.createDraftReturn !== form.dataset.createDraftReturn ||
          replacement.querySelector('[name="_csrf"]')?.value !== draftFormValue(form, "_csrf")) throw new Error("invalid options response");
      const regions = ["[data-create-image-options]", "[data-create-preview-hint]", "[data-create-optional-options]", "[data-github-browser]"];
      const updates = regions.map((selector) => {
        const current = form.querySelectorAll(selector);
        const next = replacement.querySelectorAll(selector);
        if (current.length !== 1 || next.length !== 1) throw new Error("invalid options region");
        return [current[0], next[0]];
      });
      if (controller.signal.aborted || state.sequence !== sequence || state.suspended || !form.isConnected) return;
      updates.forEach(([current, next]) => current.replaceWith(next));
      form.dataset.createOptionsLoading = "false";
      form.querySelector('[type="submit"]')?.removeAttribute("disabled");
      wireGithubBrowsers();
    } catch {
      if (state.sequence !== sequence || state.suspended || !form.isConnected) return;
      if (status) { status.textContent = "Choices could not be loaded. Your entries are still here; retry to finish setting up this Sandbox."; status.setAttribute("role", "alert"); }
      if (retry) retry.hidden = false;
      const browser = form.querySelector("[data-github-browser]");
      if (browser) {
        setStatus(browser, "Repository access unavailable. Retry loading choices.");
        const connection = browser.querySelector("[data-github-connection-status]");
        if (connection) connection.textContent = "GitHub connections are unavailable until choices load.";
      }
    } finally {
      window.clearTimeout(timer);
      if (state.controller === controller) state.controller = null;
    }
  };
  const wireCreateOptions = () => {
    document.querySelectorAll('[data-environment-form][data-create-options-loading="true"]').forEach((form) => {
      if (!(form instanceof HTMLFormElement) || optionStates.has(form)) return;
      const state = { controller: null, sequence: 0, suspended: false };
      optionStates.set(form, state);
      const owner = form.closest("[data-drawer]") || form.parentElement;
      if (owner) {
        const observer = new MutationObserver(() => {
          if (!form.isConnected) { cancelCreateOptions(form); observer.disconnect(); }
        });
        observer.observe(owner, { childList: true, subtree: true });
      }
      void loadCreateOptions(form, state);
    });
  };
  const wireDraftForms = () => {
    document.querySelectorAll("[data-environment-form][data-create-draft-id]").forEach((form) => {
      if (!(form instanceof HTMLFormElement) || draftStates.has(form)) return;
      const state = { saved: null, edited: false, storageFailed: false, sequence: 0, controller: null, autoRestore: false };
      draftStates.set(form, state);
      if (!actorId(form.dataset.createDraftActor) || !organizationId(form.dataset.createDraftOrganization) || !canonicalId(form.dataset.createDraftId)) return;
      reconcileDraftActor(form.dataset.createDraftActor);
      try {
        const saved = storedDrafts(form);
        const exactReturn = form.dataset.createDraftExact === "true";
        state.saved = saved.find((draft) => draft.draft === form.dataset.createDraftId) || (!exactReturn && saved[0]) || null;
        const button = form.querySelector("[data-restore-create-draft]");
        if (button) button.hidden = !state.saved || form.dataset.createDraftFresh !== "true";
        // Authored values come back on their own when this fresh form opens;
        // the button remains to retry if that restore fails or is interrupted.
        state.autoRestore = !!state.saved && form.dataset.createDraftFresh === "true";
        if (exactReturn && !state.saved) draftStatus(form, "The requested draft is unavailable in this tab. No Sandbox was created.", true);
      } catch {
        state.storageFailed = true;
        draftStatus(form, "This draft cannot be saved in this browser. Keep the form open until you finish.", true);
      }
      const owner = form.closest("[data-drawer]") || form.parentElement;
      if (owner) {
        const observer = new MutationObserver(() => {
          if (!form.isConnected) { cancelDraftRestore(state, form); observer.disconnect(); }
          else if (!draftIsOpen(form)) cancelDraftRestore(state, form);
          else if (state.autoRestore) { state.autoRestore = false; void restoreDraft(form, state, true); }
        });
        observer.observe(owner, { childList: true, attributes: true, attributeFilter: ["hidden", "data-open"] });
      }
      if (state.autoRestore && draftIsOpen(form)) { state.autoRestore = false; void restoreDraft(form, state, true); }
    });
  };
  const editDraft = (form) => {
    const state = draftStates.get(form);
    if (!state) return;
    state.edited = true;
    cancelDraftRestore(state, form);
    const button = form.querySelector("[data-restore-create-draft]");
    if (button) button.disabled = true;
    const sequence = state.sequence;
    queueMicrotask(() => { if (state.sequence === sequence) saveDraft(form, state); });
  };
  document.addEventListener("codewire:discard-edits", (event) => {
    if (!(event.target instanceof Element)) return;
    event.target.querySelectorAll("[data-environment-form]").forEach((form) => {
      const state = draftStates.get(form);
      if (state) {
        state.edited = true;
        cancelDraftRestore(state, form);
        if (!event.detail?.preserveDraft) {
          try { window.sessionStorage.removeItem(draftKey(currentDraft(form))); } catch { /* Storage denial is already surfaced by autosave. */ }
        }
      }
    });
  });
  document.addEventListener("codewire:save-create-draft", (event) => {
    const form = event.target instanceof Element && event.target.querySelector("[data-environment-form]");
    const state = draftStates.get(form);
    if (form instanceof HTMLFormElement && state && event.detail) {
      event.detail.saved = saveDraft(form, state);
      event.detail.incomplete = event.detail.saved && hasUnstoredRepositoryUrl(form);
    }
  });
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-environment-form]")) return;
    try {
      const action = new URL(form.action, window.location.origin);
      const match = action.origin === window.location.origin && action.pathname.match(/^\/([a-z0-9][a-z0-9-]{0,62})\/_actions\/sandboxes\/create$/);
      if (match) window.sessionStorage.setItem(pendingCreateKey, JSON.stringify({ key: draftKey(currentDraft(form)), slug: match[1], at: Date.now() }));
    } catch { /* A storage-denied form can still submit. */ }
  });
  ["input", "change"].forEach((eventName) => document.addEventListener(eventName, (event) => {
    if (!(event.target instanceof Element)) return;
    if (event.target.closest("[data-github-browser]")) return;
    const form = event.target.closest("[data-environment-form]");
    if (form instanceof HTMLFormElement) editDraft(form);
  }, true));
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const card = event.target.closest("#environment-create-card");
    const form = card?.querySelector("[data-environment-form]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.closest("[data-retry-create-options]")) { void loadCreateOptions(form, optionStates.get(form)); return; }
    const restore = event.target.closest("[data-restore-create-draft]");
    if (restore) { void restoreDraft(form, draftStates.get(form)); return; }
    if (event.target.closest("[data-field-help-trigger], [data-github-browser]")) return;
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
  document.addEventListener("htmx:afterSwap", () => { wireDraftForms(); wireCreateOptions(); wireGithubBrowsers(); });
  window.addEventListener("pagehide", () => {
    document.querySelectorAll("[data-environment-form]").forEach((form) => {
      const state = draftStates.get(form);
      if (state) cancelDraftRestore(state, form);
      cancelCreateOptions(form);
      form.querySelectorAll("[data-github-browser]").forEach((browser) => { const state = browsers.get(browser); if (state) cancelBrowser(state); });
    });
  });
  window.addEventListener("pageshow", (event) => {
    wireDraftForms();
    wireCreateOptions();
    wireGithubBrowsers();
    if (!event.persisted) return;
    document.querySelectorAll('[data-environment-form][data-create-options-loading="true"]').forEach((form) => {
      const state = optionStates.get(form);
      if (state && !state.controller && !state.suspended) void loadCreateOptions(form, state);
    });
  });
  const environmentListError = (event) => {
    const list = event.target instanceof Element && event.target.id === "environment-list" ? event.target : null;
    if (!list) return;
    const status = document.querySelector("[data-environment-list-error]");
    if (status) {
      // The page has one polite status. It announces the failure once; the
      // note stays until a refresh succeeds.
      const announcer = document.querySelector("[data-inventory-status]");
      if (status.hidden && announcer) showInventoryStatus(announcer, status.textContent);
      status.hidden = false;
    }
    if (list.dataset.environmentsLoading === "true") {
      const loading = list.querySelector('[role="status"]');
      if (loading) { loading.textContent = "Sandbox list is unavailable. Retrying…"; loading.setAttribute("role", "alert"); }
    }
  };
  ["htmx:sendError", "htmx:responseError", "htmx:timeout"].forEach((name) => document.addEventListener(name, environmentListError));
  // Each list refresh is compared with the rows it replaces, and every
  // observed lifecycle transition is announced once in the polite inventory
  // status. Rows are tracked by Sandbox id and state in memory only: an
  // unchanged row announces nothing on later refreshes, and a reload simply
  // shows the current state. A Sandbox being deleted that leaves the list
  // under the same search and filter is gone.
  const inventoryStatusMs = 8_000;
  let inventory = null;
  let inventoryStatusTimer = 0;
  const inventorySnapshot = (list) => {
    const shell = list.querySelector("[data-list-state]");
    const rows = new Map();
    list.querySelectorAll("tr[data-environment-id]").forEach((row) => {
      const { environmentId: id, environmentName: name, environmentState: state } = row.dataset;
      if (canonicalId(id) && name && state) rows.set(id, { name, state });
    });
    return { query: shell ? `${shell.dataset.listSearch ?? ""}\n${shell.dataset.listState}` : null, rows };
  };
  const transitionMessage = (name, before, after) => {
    if (before === "destroying") {
      if (after === undefined || after === "destroyed") return `${name} deleted.`;
      return after === "error" ? `${name} could not be deleted.` : "";
    }
    if (after === "destroying") return `Deleting ${name}…`;
    if (after === "stopped") return `${name} stopped.`;
    // Resize reports its own outcome; every other return to running is news.
    if (after === "running" && before !== "resizing") return `${name} is running.`;
    return "";
  };
  const showInventoryStatus = (status, message) => {
    window.clearTimeout(inventoryStatusTimer);
    status.textContent = message;
    inventoryStatusTimer = window.setTimeout(() => { status.textContent = ""; }, inventoryStatusMs);
  };
  const observeInventory = (list) => {
    const next = inventorySnapshot(list);
    const status = document.querySelector("[data-inventory-status]");
    if (status && inventory && inventory.query !== null && inventory.query === next.query) {
      const messages = [];
      inventory.rows.forEach((before, id) => {
        const after = next.rows.get(id);
        if (after?.state === before.state) return;
        const message = transitionMessage(after?.name ?? before.name, before.state, after?.state);
        if (message) messages.push(message);
      });
      if (messages.length) showInventoryStatus(status, messages.join(" "));
    }
    inventory = next;
  };
  const initialList = document.getElementById("environment-list");
  if (initialList) inventory = inventorySnapshot(initialList);
  // The server names what became of a just-deleted Sandbox. Setting it again
  // once the page has loaded announces it, and starts its timer.
  const initialStatus = document.querySelector("[data-inventory-status]");
  if (initialStatus?.textContent) showInventoryStatus(initialStatus, initialStatus.textContent);
  document.addEventListener("htmx:afterSwap", (event) => {
    const list = event.target instanceof Element && event.target.id === "environment-list" ? event.target : null;
    if (!list) return;
    list.dataset.environmentsLoading = "false";
    const status = document.querySelector("[data-environment-list-error]");
    if (status) status.hidden = true;
    observeInventory(list);
  });

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
  const restoreEmptyAppPorts = (form) => {
    const container = form.querySelector("[data-app-port-rows]");
    if (!container || container.querySelector("[data-app-port-row]")) return;
    const empty = document.createElement("li");
    empty.className = "cw-empty-inline";
    empty.dataset.emptyAppPorts = "";
    empty.textContent = "No preview ports configured";
    container.append(empty);
  };

  const browsers = new WeakMap();
  const browserForm = (browser) => browser?.closest("[data-environment-form]");
  const selectedProfile = (browser) => browserForm(browser)?.querySelector('[name="credential_profile"]');
  const setStatus = (browser, message) => {
    const status = browser.querySelector("[data-github-status]");
    if (status) status.textContent = message;
  };
  const connectionState = (browser) => browser.dataset.githubState || "not-configured";
  // The account's one GitHub connection is connected, needs reconnecting,
  // could not be loaded, or does not exist yet.
  const githubStateMessage = (browser, connected) => ({
    connected,
    inactive: "Reconnect required. Reconnect GitHub in Settings.",
    unavailable: "Repository access unavailable. Retry loading choices.",
  })[connectionState(browser)] || "Connect GitHub to browse repositories.";
  const updateConnectionStatus = (browser) => {
    const message = browser.querySelector("[data-github-connection-status]");
    if (!message) return;
    const profileHint = " Every credential profile includes it for private repository checkout.";
    const account = browser.dataset.githubAccount;
    if (browserForm(browser)?.dataset.createOptionsLoading === "true") message.textContent = "Loading GitHub account…";
    else message.textContent = `${githubStateMessage(browser, account ? `Connected as @${account}.` : "GitHub connected.")}${profileHint}`;
    const setup = browser.querySelector("[data-github-setup-link]");
    if (setup) {
      // Until choices load the connection is unknown; never offer Connect early.
      setup.hidden = browserForm(browser)?.dataset.createOptionsLoading === "true";
      setup.textContent = { connected: "Manage GitHub connection", inactive: "Reconnect GitHub" }[connectionState(browser)] || "Connect GitHub";
    }
  };
  const browserCurrent = (browser, state, sequence) => browser.isConnected
    && state.sequence === sequence
    && browserForm(browser)?.isConnected && draftIsOpen(browserForm(browser));
  const cancelBrowser = (state) => {
    state.sequence += 1;
    state.controller?.abort();
    state.controller = null;
    window.clearTimeout(state.queryTimer);
    state.loading = false;
  };
  const resetBrowser = (browser, state) => {
    cancelBrowser(state);
    state.query = browser.querySelector("[data-github-filter]")?.value.trim().toLowerCase().slice(0, 128) || "";
    state.nextToken = "";
    state.seenTokens = new Set();
    state.pages = 0;
    state.matches = 0;
    state.rendered = 0;
    state.pruned = false;
    state.complete = false;
    browser.querySelector("[data-github-results]")?.replaceChildren();
    browser.querySelector("[data-github-filter-empty]")?.setAttribute("hidden", "");
    browser.querySelector("[data-github-retry]")?.setAttribute("hidden", "");
    browser.querySelector("[data-github-next]")?.setAttribute("hidden", "");
    updateConnectionStatus(browser);
    const filter = browser.querySelector("[data-github-filter]");
    if (filter) filter.disabled = connectionState(browser) !== "connected";
    if (browserForm(browser)?.dataset.createOptionsLoading === "true") setStatus(browser, "Loading GitHub account…");
    else if (connectionState(browser) !== "connected") setStatus(browser, githubStateMessage(browser, ""));
  };
  const loadRepositories = async (browser, state) => {
    if (state.loading || state.complete || connectionState(browser) !== "connected") return;
    if (state.pages >= 10_000 || state.seenTokens.has(state.nextToken)) {
      setStatus(browser, "Repository paging did not finish safely. Refine the search or retry from the beginning.");
      browser.querySelector("[data-github-retry]").hidden = false;
      return;
    }
    const sequence = state.sequence;
    const token = state.nextToken;
    const controller = new AbortController();
    state.controller = controller;
    state.loading = true;
    browser.querySelector("[data-github-results]")?.setAttribute("aria-busy", "true");
    browser.querySelector("[data-github-next]").hidden = true;
    browser.querySelector("[data-github-retry]").hidden = true;
    setStatus(browser, state.query ? `Searching all accessible repositories… ${state.pages} pages checked.` : "Loading GitHub repositories…");
    const timer = window.setTimeout(() => controller.abort(), 40_000);
    try {
      const endpoint = new URL(browser.dataset.repositoriesUrl, window.location.origin);
      if (endpoint.origin !== window.location.origin || !endpoint.pathname.endsWith("/_fragments/github-repositories") || endpoint.search || endpoint.hash) throw new Error("invalid endpoint");
      const response = await fetch(endpoint, {
        method: "POST", credentials: "same-origin", redirect: "error", signal: controller.signal,
        headers: { Accept: "text/html" },
        body: new URLSearchParams({ _csrf: browserForm(browser)?.querySelector('[name="_csrf"]')?.value || "", page_token: token }),
      });
      if (!response.headers.get("content-type")?.startsWith("text/html")) throw new Error("invalid content type");
      const html = await readDraftHtml(response);
      if (!browserCurrent(browser, state, sequence) || controller.signal.aborted) return;
      const parsed = new DOMParser().parseFromString(html, "text/html");
      const pages = parsed.querySelectorAll("[data-github-results-page]");
      if (pages.length !== 1 || parsed.querySelector("script")) throw new Error("invalid repository response");
      if (!response.ok) throw new Error(pages[0].querySelector(".cw-field-error")?.textContent?.trim().slice(0, 240) || "Repository access unavailable. Try again.");
      const next = pages[0].querySelector("[data-github-next]")?.getAttribute("data-page-token") || "";
      if (next && (next === token || state.seenTokens.has(next))) throw new Error("Repository paging returned a repeated page. Retry from the beginning.");
      const page = document.importNode(pages[0], true);
      page.querySelector("[data-github-next]")?.remove();
      const entries = Array.from(page.querySelectorAll("[data-select-github-repository]"));
      entries.forEach((entry) => {
        const name = entry.dataset.repositoryName?.toLowerCase() || "";
        if (state.query && !name.includes(state.query)) entry.closest("li")?.remove();
        else state.matches += 1;
      });
      if (state.query) {
        const visible = Array.from(page.querySelectorAll("[data-select-github-repository]"));
        visible.slice(Math.max(0, 200 - state.rendered)).forEach((entry) => entry.closest("li")?.remove());
      }
      const retained = page.querySelectorAll("[data-select-github-repository]").length;
      const results = browser.querySelector("[data-github-results]");
      if (retained) {
        results.append(page);
        state.rendered += retained;
      }
      if (!state.query) {
        while (state.rendered > 200 && results.firstElementChild) {
          const first = results.firstElementChild;
          const scroll = browser.querySelector("[data-github-scroll]");
          const height = first.getBoundingClientRect().height;
          state.rendered -= first.querySelectorAll("[data-select-github-repository]").length;
          first.remove();
          state.pruned = true;
          if (scroll) scroll.scrollTop = Math.max(0, scroll.scrollTop - height);
        }
      }
      state.seenTokens.add(token);
      state.pages += 1;
      state.nextToken = next;
      state.complete = !next;
      browser.querySelector("[data-github-filter-empty]").hidden = !state.complete || state.matches !== 0 || !state.query;
      browser.querySelector("[data-github-next]").hidden = state.complete || !!state.query;
      setStatus(browser, state.query
        ? state.complete ? `${state.matches} matching repositories found across ${state.pages} pages.${state.matches > 200 ? " Showing the first 200; refine your search." : ""}` : `Searching all accessible repositories… ${state.pages} pages checked, ${state.matches} matches.`
        : state.complete && state.matches === 0 ? "No repositories are available through this GitHub connection. Change the repositories the Codewire GitHub App can access, or use Add custom Git URL."
        : state.complete ? `${state.matches} repositories loaded. Choose one to add.${state.pruned ? " Earlier rows can be found with search." : ""}` : `${state.matches} repositories loaded. Scroll or load more.${state.pruned ? " Earlier rows can be found with search." : ""}`);
    } catch (error) {
      if (browserCurrent(browser, state, sequence)) {
        setStatus(browser, error?.message && !["invalid endpoint", "invalid content type", "invalid repository response", "draft response limit"].includes(error.message) ? error.message : "Repository access unavailable. Retry loading repositories.");
        browser.querySelector("[data-github-retry]").hidden = false;
      }
    } finally {
      window.clearTimeout(timer);
      if (state.controller === controller) {
        state.controller = null;
        state.loading = false;
        browser.querySelector("[data-github-results]")?.removeAttribute("aria-busy");
        if (state.query && !state.complete && browserCurrent(browser, state, sequence) && browser.querySelector("[data-github-retry]").hidden) void loadRepositories(browser, state);
      }
    }
  };
  const wireGithubBrowsers = () => {
    document.querySelectorAll("[data-github-browser]").forEach((browser) => {
      if (browsers.has(browser)) return;
      const state = { sequence: 0, controller: null, queryTimer: 0, query: "", nextToken: "", seenTokens: new Set(), pages: 0, matches: 0, rendered: 0, pruned: false, complete: false, loading: false };
      browsers.set(browser, state);
      if (browser.querySelector("[data-github-results-page]")) {
        state.complete = true; // Static design fixture already contains its example rows.
        updateConnectionStatus(browser);
      } else {
        resetBrowser(browser, state);
        if (connectionState(browser) === "connected") void loadRepositories(browser, state);
      }
      const owner = browser.closest("[data-drawer]") || browserForm(browser)?.parentElement;
      if (owner) {
        const observer = new MutationObserver(() => {
          if (!browser.isConnected) { cancelBrowser(state); observer.disconnect(); }
          else if (!draftIsOpen(browserForm(browser))) cancelBrowser(state);
        });
        observer.observe(owner, { childList: true, attributes: true, attributeFilter: ["hidden", "data-open"] });
      }
    });
  };
  document.addEventListener("input", (event) => {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches("[data-github-filter]")) return;
    const browser = event.target.closest("[data-github-browser]");
    const state = browsers.get(browser);
    if (!state) return;
    resetBrowser(browser, state);
    if (connectionState(browser) === "connected") state.queryTimer = window.setTimeout(() => void loadRepositories(browser, state), 250);
  });
  document.addEventListener("submit", (event) => {
    if (event.submitter?.closest?.("[data-github-browser]")) event.preventDefault();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && event.target instanceof Element && event.target.matches("[data-github-filter]")) event.preventDefault();
  });
  document.addEventListener("scroll", (event) => {
    const scroll = event.target;
    if (!(scroll instanceof Element) || !scroll.matches("[data-github-scroll]")) return;
    const browser = scroll.closest("[data-github-browser]");
    const state = browsers.get(browser);
    if (state && !state.query && scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 48) void loadRepositories(browser, state);
  }, true);
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) return;
    const browser = event.target.closest("[data-github-browser]");
    const state = browsers.get(browser);
    if (!state) return;
    if (event.target.closest("[data-github-next]")) { void loadRepositories(browser, state); return; }
    if (event.target.closest("[data-github-retry]")) {
      if (state.pages >= 10_000 || state.seenTokens.has(state.nextToken)) resetBrowser(browser, state);
      void loadRepositories(browser, state);
      return;
    }
    const repository = event.target.closest("[data-select-github-repository]");
    if (!(repository instanceof HTMLButtonElement) || repository.disabled) return;
    const form = browserForm(browser);
    if (!(form instanceof HTMLFormElement) || !draftIsOpen(form)) return;
    const existing = Array.from(form.querySelectorAll("[data-repository-row]"));
    let row = existing.find((item) => item.querySelector('[name^="repo_url_"]')?.value === repository.dataset.repositoryUrl);
    if (!row) row = existing.find((item) => ["repo_url_", "repo_branch_", "repo_mount_"].every((prefix) => !item.querySelector(`[name^="${prefix}"]`)?.value.trim()));
    row ||= appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]");
    if (!row) return;
    row.querySelector('[name^="repo_url_"]').value = repository.dataset.repositoryUrl || "";
    if (!row.querySelector('[name^="repo_branch_"]').value) row.querySelector('[name^="repo_branch_"]').value = repository.dataset.repositoryBranch || "";
    const mount = row.querySelector('[name^="repo_mount_"]');
    if (mount && !mount.value) mount.value = repository.dataset.repositoryName?.split("/").at(-1) || "";
    form.dispatchEvent(new Event("codewire:form-structure-edited", { bubbles: true }));
    editDraft(form);
    // Every profile includes the account's GitHub connection for checkout.
    if (!selectedProfile(browser)?.value && repository.dataset.repositoryPrivate === "true") setStatus(browser, "Repository added. Select a credential profile for private checkout.");
    row.querySelector('[name^="repo_branch_"]')?.focus();
  });
  // dashboard.js clears the acknowledged Create draft on every page Create
  // can land on: the Sandboxes list and the new Sandbox's own page.
  wireDraftForms();
  wireCreateOptions();
  wireGithubBrowsers();

  document.addEventListener("focusout", (event) => {
    if (!(event.target instanceof HTMLInputElement) || !event.target.matches("[data-ttl-input]")) return;
    const value = event.target.value.trim().toLocaleLowerCase();
    if (defaultTtl(value)) {
      event.target.value = "";
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
      const row = appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]");
      form.dispatchEvent(new Event("codewire:form-structure-edited", { bubbles: true }));
      row?.querySelector('[name^="repo_url_"]')?.focus();
    } else if (event.target.closest("[data-remove-repository]")) {
      event.target.closest("[data-repository-row]")?.remove();
      form.dispatchEvent(new Event("codewire:form-structure-edited", { bubbles: true }));
      if (!form.querySelector("[data-repository-row]")) form.querySelector("[data-github-filter], [data-add-repository]")?.focus();
    } else if (event.target.closest("[data-add-app-port]")) {
      const row = appendTemplateRow(form, "[data-app-port-template]", "[data-app-port-rows]", "[data-app-port-row]");
      form.dispatchEvent(new Event("codewire:form-structure-edited", { bubbles: true }));
      row?.querySelector('[name^="app_port_"]')?.focus();
    } else if (event.target.closest("[data-remove-app-port]")) {
      event.target.closest("[data-app-port-row]")?.remove();
      form.dispatchEvent(new Event("codewire:form-structure-edited", { bubbles: true }));
      restoreEmptyAppPorts(form);
    } else if (event.target.closest("[data-reset-workspace-image]")) {
      const image = form.querySelector('[name="image"]');
      if (image instanceof HTMLInputElement) image.value = image.placeholder;
    }
  });

  const resetCreateSubmission = (form) => {
    form.removeAttribute("data-create-submitting");
    form.querySelector('[type="submit"]')?.removeAttribute("aria-busy");
  };
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-environment-form]")) return;
    if (form.dataset.createSubmitting === "true") {
      event.preventDefault();
      return;
    }
    form.dataset.createSubmitting = "true";
    form.querySelector('[type="submit"]')?.setAttribute("aria-busy", "true");
  }, true);
  window.addEventListener("pageshow", () => {
    document.querySelectorAll("[data-environment-form]").forEach(resetCreateSubmission);
  });

  // Workspace image choices open as a listbox on the menu surface instead of
  // the browser's datalist popup. Without scripting the datalist still works.
  // Options are read when the list opens, because Create choices load late.
  const comboboxStates = new WeakMap();
  const comboboxInput = (node) => node instanceof HTMLInputElement && node.matches("[data-combobox] input[data-combobox-options]") ? node : null;
  const enhanceComboboxes = () => {
    document.querySelectorAll("[data-combobox] input[list]").forEach((input) => {
      if (!(input instanceof HTMLInputElement) || !input.id) return;
      const listbox = document.createElement("ul");
      listbox.id = `${input.id}-choices`;
      listbox.className = "cw-combobox-list";
      listbox.setAttribute("role", "listbox");
      listbox.setAttribute("aria-label", input.closest("[data-combobox]").dataset.comboboxLabel || "Suggestions");
      listbox.hidden = true;
      input.dataset.comboboxOptions = input.getAttribute("list");
      input.removeAttribute("list");
      input.setAttribute("role", "combobox");
      input.setAttribute("aria-autocomplete", "list");
      input.setAttribute("aria-controls", listbox.id);
      input.setAttribute("aria-expanded", "false");
      input.autocomplete = "off";
      input.closest("[data-combobox]").append(listbox);
      comboboxStates.set(input, { listbox, options: [], active: -1 });
    });
  };
  const closeCombobox = (input) => {
    const state = comboboxStates.get(input);
    if (!state || state.listbox.hidden) return false;
    state.listbox.hidden = true;
    state.active = -1;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
    return true;
  };
  const activateOption = (input, index) => {
    const state = comboboxStates.get(input);
    if (!state || !state.options.length) return;
    state.active = (index + state.options.length) % state.options.length;
    state.options.forEach((option, position) => option.setAttribute("aria-selected", String(position === state.active)));
    const active = state.options[state.active];
    input.setAttribute("aria-activedescendant", active.id);
    active.scrollIntoView({ block: "nearest" });
  };
  const openCombobox = (input, filter) => {
    const state = comboboxStates.get(input);
    const source = document.getElementById(input.dataset.comboboxOptions || "");
    if (!state || !(source instanceof HTMLDataListElement)) return;
    const query = filter ? input.value.trim().toLowerCase() : "";
    const found = [...source.options].filter((option) => option.value
      && (!query || option.value.toLowerCase().includes(query) || option.label.toLowerCase().includes(query)));
    // While typing, a value that already equals every match needs no suggestion.
    const matches = filter && found.every((option) => option.value === input.value) ? [] : found;
    state.options = matches.map((option, index) => {
      const item = document.createElement("li");
      item.id = `${state.listbox.id}-${index}`;
      item.className = "cw-combobox-option";
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", "false");
      item.dataset.value = option.value;
      const name = document.createElement("strong");
      name.textContent = option.label || option.value;
      if (option.dataset.official === "true") {
        const badge = document.createElement("span");
        badge.className = "cw-badge";
        badge.dataset.tone = "info";
        badge.textContent = "Official";
        name.append(" ", badge);
      }
      const reference = document.createElement("code");
      reference.textContent = option.value;
      item.append(name, reference);
      if (option.dataset.description) {
        const description = document.createElement("span");
        description.textContent = option.dataset.description;
        item.append(description);
      }
      return item;
    });
    state.listbox.replaceChildren(...state.options);
    state.active = -1;
    input.removeAttribute("aria-activedescendant");
    const open = state.options.length > 0;
    state.listbox.hidden = !open;
    input.setAttribute("aria-expanded", String(open));
  };
  const chooseOption = (input, option) => {
    closeCombobox(input);
    input.value = option.dataset.value || "";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  };
  document.addEventListener("keydown", (event) => {
    const input = comboboxInput(event.target);
    const state = input && comboboxStates.get(input);
    if (!state) return;
    const open = !state.listbox.hidden;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!open) openCombobox(input, false);
      activateOption(input, event.key === "ArrowDown" ? state.active + 1 : state.active < 0 ? -1 : state.active - 1);
    } else if (event.key === "Enter" && open && state.active >= 0) {
      event.preventDefault();
      chooseOption(input, state.options[state.active]);
    } else if (event.key === "Escape" && closeCombobox(input)) {
      // Close only the list, not the Create drawer around it.
      event.preventDefault();
      event.stopPropagation();
    } else if (event.key === "Tab") {
      closeCombobox(input);
    }
  }, true);
  document.addEventListener("input", (event) => {
    const input = comboboxInput(event.target);
    if (!input || !event.isTrusted) return;
    if (input.value.trim()) openCombobox(input, true); else closeCombobox(input);
  });
  document.addEventListener("click", (event) => {
    const input = comboboxInput(event.target);
    if (input) {
      const state = comboboxStates.get(input);
      if (state?.listbox.hidden) openCombobox(input, false); else closeCombobox(input);
      return;
    }
    const option = event.target instanceof Element ? event.target.closest(".cw-combobox-option") : null;
    const owner = option && document.querySelector(`[aria-controls="${option.parentElement?.id}"]`);
    if (option && comboboxInput(owner)) chooseOption(owner, option);
  });
  // Keep focus in the field while a pointer picks an option.
  document.addEventListener("mousedown", (event) => {
    if (event.target instanceof Element && event.target.closest(".cw-combobox-list")) event.preventDefault();
  });
  document.addEventListener("focusout", (event) => {
    const input = comboboxInput(event.target);
    if (input) closeCombobox(input);
  });
  enhanceComboboxes();
  document.addEventListener("htmx:afterSwap", enhanceComboboxes);
  window.addEventListener("pageshow", enhanceComboboxes);
})();
