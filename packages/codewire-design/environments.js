(() => {
  let activeController = null;

  const activeMode = () => "image";

  const setDisabled = (root, disabled) => {
    root?.querySelectorAll("input, select, textarea, button").forEach((control) => {
      if (control.matches('[name="mode"], [data-reset-environment-source]')) return;
      control.disabled = disabled;
    });
  };

  const modePanels = (form) => {
    const selected = activeMode(form);
    form.querySelectorAll("[data-environment-mode-panel]").forEach((panel) => {
      const hidden = panel.getAttribute("data-environment-mode-panel") !== selected;
      panel.hidden = hidden;
      setDisabled(panel, hidden);
    });
    syncRepositorySource(form);
    syncRepositorySelection(form);
    syncPresetSelection(form);
    syncAgentCards(form);
    syncSecretProject(form);
  };

  const syncRepositorySource = (form) => {
    const github = form.querySelector("[data-github-repository-picker]");
    const manual = form.querySelector("[data-manual-repositories]");
    if (!manual) return;
    setDisabled(github, github.hidden);
    setDisabled(manual, manual.hidden);
    syncAnalyzeButton(form);
  };

  const syncRepositorySelection = (form) => {
    let selected = 0;
    form.querySelectorAll("[data-repository-option]").forEach((option) => {
      const checkbox = option.querySelector('input[type="checkbox"]');
      const index = option.getAttribute("data-repository-index");
      const mount = form.querySelector(`[data-repository-mount-option="${index}"]`);
      const checked = checkbox instanceof HTMLInputElement && checkbox.checked;
      if (checked) selected += 1;
      if (mount instanceof HTMLElement) {
        mount.hidden = !checked;
        mount.querySelectorAll("input").forEach((input) => { input.disabled = !checked; });
      }
    });
    const mountPoints = form.querySelector("[data-selected-mounts]");
    if (mountPoints instanceof HTMLElement) mountPoints.hidden = selected === 0;
    syncAnalyzeButton(form);
  };

  const syncAnalyzeButton = (form) => {
    const button = form.querySelector("[data-environment-prepare-submit]");
    const help = form.querySelector("[data-environment-prepare-help]");
    if (!(button instanceof HTMLButtonElement)) return;
    const hasRepository = Array.from(form.querySelectorAll('[name^="repo_url_"]')).some((input) => (
      input instanceof HTMLInputElement
      && !input.disabled
      && (input.type === "checkbox" ? input.checked : input.value.trim() !== "")
    ));
    button.disabled = !hasRepository;
    if (help) {
      help.textContent = hasRepository
        ? "Reads the selected repositories and fills in install and startup steps."
        : "Select a repository above to generate these steps.";
    }
  };

  const syncPresetSelection = (form) => {
    const picker = form.querySelector("[data-preset-picker]");
    const submit = form.querySelector("[data-preset-submit]");
    if (!(picker instanceof HTMLSelectElement) || !(submit instanceof HTMLButtonElement)) return;
    submit.value = picker.value;
    submit.disabled = picker.value === "";
  };

  const syncAgentCards = (form) => {
    const selected = new Set(
      Array.from(form.querySelectorAll('input[name="agent"]:checked'), (input) => input.value),
    );
    form.querySelectorAll("[data-agent-card]").forEach((card) => {
      card.hidden = !selected.has(card.getAttribute("data-agent-card"));
    });
  };

  const syncSecretProject = (form) => {
    const picker = form.querySelector("[data-secret-project-picker]");
    const manage = form.querySelector("[data-manage-secret-project]");
    if (!(picker instanceof HTMLSelectElement) || !(manage instanceof HTMLAnchorElement)) return;
    const option = picker.selectedOptions[0];
    const projectId = option?.dataset.projectId;
    manage.hidden = !projectId;
    if (projectId) manage.href = `${manage.href.replace(/\/secrets\/(?:[^/?#]+\/)?$/, "/secrets/")}${encodeURIComponent(projectId)}/`;
  };

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
  };

  const initializeForm = (form) => {
    if (!(form instanceof HTMLFormElement)) return;
    modePanels(form);
  };

  const replaceCreateCard = (html) => {
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const replacement = parsed.querySelector("#environment-create-card");
    const current = document.querySelector("#environment-create-card");
    if (!replacement || !current) return;
    const imported = document.importNode(replacement, true);
    current.replaceWith(imported);
    if (window.htmx) window.htmx.process(imported);
    initializeForm(imported.querySelector("[data-environment-prepare]"));
    document.dispatchEvent(new CustomEvent("codewire:drawer-replaced"));
  };

  const decodeHtml = (encoded) => {
    const binary = atob(encoded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  };

  const consumeEventStream = async (response, form, controller) => {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("stream unavailable");
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done }).replaceAll("\r\n", "\n");
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        let eventName = "message";
        const data = [];
        block.split("\n").forEach((line) => {
          if (line.startsWith("event:")) eventName = line.slice(6).trim();
          if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
        });
        const payload = data.join("\n");
        const status = form.querySelector("[data-environment-stream-message]");
        if (eventName === "progress" && status) {
          const [, message] = payload.split("|", 3);
          status.textContent = message || "Preparing environment…";
        } else if (eventName === "repo") {
          const [, repo, ok] = payload.split("|", 3);
          const progress = form.querySelector("[data-environment-repo-progress]");
          if (progress) {
            const line = document.createElement("p");
            line.className = ok === "true" ? "cw-stream-repo-ok" : "cw-stream-repo-warning";
            line.textContent = `${ok === "true" ? "Fetched" : "Could not fetch"} ${repo}`;
            progress.append(line);
          }
        } else if (eventName === "complete") {
          replaceCreateCard(decodeHtml(payload));
          return;
        } else if (eventName === "error") {
          throw new Error(payload || "Repository preparation failed");
        }
      }
      if (done || controller.signal.aborted) return;
    }
  };

  document.addEventListener("input", (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-prepare]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.matches("[data-repository-search]") && event.target instanceof HTMLInputElement) {
      const query = event.target.value.trim().toLocaleLowerCase();
      let visible = 0;
      form.querySelectorAll("[data-repository-option]").forEach((option) => {
        const matches = query === "" || (option.getAttribute("data-search-text") || "").toLocaleLowerCase().includes(query);
        option.hidden = !matches;
        if (matches) visible += 1;
      });
      const empty = form.querySelector("[data-repository-no-match]");
      if (empty instanceof HTMLElement) empty.hidden = visible !== 0;
    } else if (event.target.matches('[name^="repo_url_"]')) {
      syncAnalyzeButton(form);
    } else if (event.target.matches("[data-advanced-image]")) {
      const preset = form.querySelector("[data-prepared-preset-id]");
      if (preset instanceof HTMLInputElement) preset.value = "";
    }
  });

  document.addEventListener("change", (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-prepare]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.matches('[data-repository-option] input[type="checkbox"]')) {
      syncRepositorySelection(form);
    } else if (event.target.matches("[data-preset-picker]")) {
      syncPresetSelection(form);
    } else if (event.target.matches('input[name="agent"]')) {
      syncAgentCards(form);
    } else if (event.target.matches("[data-secret-project-picker]")) {
      syncSecretProject(form);
    }
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

  document.addEventListener("click", async (event) => {
    if (!(event.target instanceof Element)) return;
    const form = event.target.closest("[data-environment-prepare]");
    if (!(form instanceof HTMLFormElement)) return;
    if (event.target.closest("[data-add-repository]")) {
      appendTemplateRow(form, "[data-repository-template]", "[data-repository-rows]", "[data-repository-row]", 100);
    } else if (event.target.closest("[data-remove-repository]")) {
      const rows = form.querySelectorAll("[data-repository-row]");
      if (rows.length > 1) {
        event.target.closest("[data-repository-row]")?.remove();
        syncAnalyzeButton(form);
      }
    } else if (event.target.closest("[data-add-app-port]")) {
      appendTemplateRow(form, "[data-app-port-template]", "[data-app-port-rows]", "[data-app-port-row]");
    } else if (event.target.closest("[data-remove-app-port]")) {
      event.target.closest("[data-app-port-row]")?.remove();
    } else if (event.target.closest("[data-show-manual-repositories]")) {
      const manual = form.querySelector("[data-manual-repositories]");
      if (manual) { manual.hidden = false; syncRepositorySource(form); }
    } else if (event.target.closest("[data-show-github-repositories]")) {
      const manual = form.querySelector("[data-manual-repositories]");
      if (manual) { manual.hidden = true; syncRepositorySource(form); }
    } else if (event.target.closest("[data-unselect-repository]")) {
      const index = event.target.closest("[data-unselect-repository]").getAttribute("data-unselect-repository");
      const checkbox = form.querySelector(`[data-repository-index="${index}"] input[type="checkbox"]`);
      if (checkbox instanceof HTMLInputElement) checkbox.checked = false;
      syncRepositorySelection(form);
    } else if (event.target.closest("[data-reset-workspace-image]")) {
      const image = form.querySelector('[name="image"]');
      if (image instanceof HTMLInputElement) image.value = "ghcr.io/codewiresh/workspace@sha256:03571275319488cd317d7f405fc22057214906fba0c6727160090286a17f7467";
    } else if (event.target.closest("[data-environment-cancel]")) {
      activeController?.abort();
    } else if (event.target.closest("[data-create-secret-project]")) {
      const button = event.target.closest("[data-create-secret-project]");
      const input = form.querySelector("[data-new-secret-project-name]");
      const error = form.querySelector("[data-secret-project-error]");
      const csrf = form.querySelector('[name="_csrf"]');
      if (!(button instanceof HTMLButtonElement) || !(input instanceof HTMLInputElement) || !(csrf instanceof HTMLInputElement)) return;
      const name = input.value.trim();
      if (!name) { if (error) { error.textContent = "Enter a project name."; error.hidden = false; } return; }
      button.disabled = true;
      try {
        const body = new URLSearchParams({ _csrf: csrf.value, name });
        const response = await fetch(button.dataset.action, { method: "POST", body, credentials: "same-origin", headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error((await response.text()) || "The secret project could not be created.");
        const project = await response.json();
        const picker = form.querySelector("[data-secret-project-picker]");
        if (picker instanceof HTMLSelectElement) {
          const option = new Option(`${project.name} — ${project.secret_count} secrets`, project.name, true, true);
          option.dataset.projectId = project.id;
          option.dataset.secretCount = String(project.secret_count);
          picker.add(option);
          syncSecretProject(form);
        }
        input.value = "";
        if (error) error.hidden = true;
      } catch (failure) {
        if (error) { error.textContent = failure instanceof Error ? failure.message : "The secret project could not be created."; error.hidden = false; }
      } finally {
        button.disabled = false;
      }
    }
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-environment-prepare]")) return;
    if (!(event.submitter instanceof Element) || !event.submitter.matches("[data-environment-prepare-submit]")) return;
    event.preventDefault();
    activeController?.abort();
    const controller = new AbortController();
    activeController = controller;
    const status = form.querySelector("[data-environment-stream-status]");
    const message = form.querySelector("[data-environment-stream-message]");
    const progress = form.querySelector("[data-environment-repo-progress]");
    if (status instanceof HTMLElement) {
      status.hidden = false;
      status.dataset.state = "running";
    }
    if (message) message.textContent = "Analyzing repositories…";
    if (progress) progress.replaceChildren();
    try {
      const body = new URLSearchParams();
      const data = new FormData(form, event.submitter instanceof HTMLElement ? event.submitter : undefined);
      data.forEach((value, key) => { if (typeof value === "string") body.append(key, value); });
      const response = await fetch(form.dataset.eventAction, {
        method: "POST",
        body,
        credentials: "same-origin",
        headers: { Accept: "text/event-stream" },
        signal: controller.signal,
      });
      const contentType = response.headers.get("content-type") || "";
      if (contentType.startsWith("text/html")) { replaceCreateCard(await response.text()); return; }
      if (!response.ok || !contentType.startsWith("text/event-stream")) throw new Error("Environment preparation is unavailable");
      await consumeEventStream(response, form, controller);
    } catch (error) {
      if (controller.signal.aborted) {
        if (message) message.textContent = "Preparation cancelled.";
      } else if (message) {
        message.textContent = error instanceof Error ? error.message : "Environment preparation failed.";
        if (status instanceof HTMLElement) status.dataset.state = "error";
      }
    } finally {
      if (activeController === controller) activeController = null;
    }
  });

  window.addEventListener("pagehide", () => activeController?.abort(), { once: true });
  document.querySelectorAll("[data-environment-prepare]").forEach(initializeForm);
})();
