(() => {
  "use strict";
  const P = globalThis.CodewireTerminalProtocol;
  if (!P) return;
  const operationId = (value) => typeof value === "string" && /^[0-9a-f]{32}$/.test(value);
  const resources = (value) => P.closed(value, ["cpuMillicores", "memoryMib", "diskGib"])
    && [["cpuMillicores", 100, 128000], ["memoryMib", 128, 1048576], ["diskGib", 1, 16384]]
      .every(([key, min, max]) => Number.isSafeInteger(value[key]) && value[key] >= min && value[key] <= max);
  const equalResources = (left, right) => resources(left) && resources(right)
    && ["cpuMillicores", "memoryMib", "diskGib"].every((key) => left[key] === right[key]);
  const validAttempt = (value) => P.closed(value, ["version", "requestId", "desiredResources", "allowRestart", "force", "operationId"])
    && value.version === 1 && operationId(value.requestId) && resources(value.desiredResources)
    && typeof value.allowRestart === "boolean" && typeof value.force === "boolean"
    && (!value.force || value.allowRestart) && (value.operationId === null || operationId(value.operationId));
  const validPlan = (value, actor, environment, desired) => P.closed(value,
    ["accountId", "environmentId", "requestId", "previousResources", "desiredResources", "mode", "restartRequired", "sessionsWillTerminate", "activeSessionCount"])
    && value.accountId === actor && value.environmentId === environment && operationId(value.requestId)
    && resources(value.previousResources) && equalResources(value.desiredResources, desired)
    && ["noop", "apply-on-start", "in-place", "restart"].includes(value.mode)
    && value.restartRequired === (value.mode === "restart")
    && Number.isSafeInteger(value.activeSessionCount) && value.activeSessionCount >= 0 && value.activeSessionCount <= 1000000
    && value.sessionsWillTerminate === (value.restartRequired && value.activeSessionCount > 0);
  const validOperation = (value, actor, environment, attempt) => P.closed(value,
    ["accountId", "environmentId", "operationId", "requestId", "desiredResources", "policy", "state"])
    && value.accountId === actor && value.environmentId === environment && operationId(value.operationId)
    && (attempt.operationId === null || value.operationId === attempt.operationId)
    && value.requestId === attempt.requestId && equalResources(value.desiredResources, attempt.desiredResources)
    && value.policy === (attempt.allowRestart ? "allow-restart" : "live-only")
    && ["pending", "applying", "restarting", "completed", "failed"].includes(value.state);
  // Same units as the choices and the Sandbox's resources line.
  const memory = (mib) => mib % 1024 === 0 ? `${mib / 1024} GiB` : `${mib} MiB`;
  const describe = (value) => `${value.cpuMillicores / 1000} vCPU · ${memory(value.memoryMib)} memory · ${value.diskGib} GiB disk`;

  // The one refusal Review explains: setup still owns the running Sandbox.
  // Only its closed code is read; server text is never shown.
  class SetupInProgress extends Error {}
  async function boundedJson(response) {
    const refusal = response.status === 409;
    if ((!response.ok && !refusal) || response.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") {
      await response.body?.cancel();
      throw new Error("Resize response unavailable");
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Resize response unavailable");
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let text = "";
    let size = 0;
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 2048) { await reader.cancel(); throw new Error("Resize response unavailable"); }
      text += decoder.decode(part.value, { stream: true });
    }
    const value = JSON.parse(text + decoder.decode());
    if (response.ok) return value;
    throw P.closed(value, ["error"]) && value.error === "setup-in-progress"
      ? new SetupInProgress("Setup is still running") : new Error("Resize response unavailable");
  }

  function mount(dialog) {
    const actor = dialog.dataset.resizeAccountId;
    const environment = dialog.dataset.resizeEnvironmentId;
    const slug = dialog.dataset.resizeOrgSlug;
    if (!P.accountId(actor) || !P.uuid.test(environment || "")
      || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug || "") || slug.length < 3 || slug.length > 48) return;
    const base = `/${encodeURIComponent(slug)}/${environment}`;
    const storageKey = `codewire.resize.v1:${actor}:${slug}:${environment}`;
    const planForm = dialog.querySelector("[data-resize-plan-form]");
    const applyForm = dialog.querySelector("[data-resize-apply-form]");
    const content = dialog.querySelector("[data-resize-content]");
    const review = dialog.querySelector("[data-resize-plan]");
    const status = dialog.querySelector("[data-resize-status]");
    const observeButton = dialog.querySelector("[data-resize-observe]");
    const inputs = dialog.querySelector("[data-resize-inputs]");
    const consents = dialog.querySelector("[data-resize-consents]");
    const opener = document.querySelector("[data-resize-open]");
    const back = dialog.querySelector("[data-resize-back]");
    const cancel = dialog.querySelector("[data-resize-cancel]");
    const done = dialog.querySelector("[data-resize-done]");
    const reviewButton = dialog.querySelector("[data-resize-review]");
    const applyButton = dialog.querySelector("[data-resize-apply]");
    if (!planForm || !applyForm || !content || !review || !status || !observeButton || !inputs || !consents || !opener
      || !back || !cancel || !done || !reviewButton || !applyButton) return;
    let plan = null;
    let attempt = null;
    let result = false;
    let storageBlocked = false;
    let eligible = false;
    let busy = null;
    let epoch = 0;
    let timer = null;
    const locked = () => storageBlocked || attempt !== null;
    // Choosing and reviewing are editor steps (Cancel plus one primary action,
    // and Back while reviewing). A submitted change and its outcome are
    // read-only, so they offer Done.
    const step = () => locked() ? "pending" : result ? "result" : plan ? "review" : "choose";
    const firstControl = () => ({ review: back, choose: inputs.disabled ? cancel : inputs.elements[0] })[step()] || done;
    const notify = () => document.dispatchEvent(new CustomEvent("codewire:resize-mutation-status", {
      detail: { environmentId: environment, locked: locked() },
    }));
    function controls() {
      opener.hidden = false;
      // Recovery must remain inspectable even when lifecycle mutation is
      // locked or the last readiness observation is unavailable.
      opener.disabled = !locked() && !eligible;
      inputs.disabled = !eligible || !!busy || locked();
      consents.disabled = !eligible || !!busy || locked() || plan === null;
      content.inert = !!busy;
      content.setAttribute("aria-busy", String(!!busy));
      observeButton.hidden = attempt?.operationId == null;
      observeButton.disabled = !!busy;
      const current = step();
      planForm.hidden = current === "review" || current === "result";
      back.hidden = current !== "review";
      cancel.hidden = current !== "choose" && current !== "review";
      done.hidden = current !== "pending" && current !== "result";
      reviewButton.hidden = current !== "choose";
      reviewButton.disabled = inputs.disabled;
      applyButton.hidden = current !== "review";
      applyButton.disabled = consents.disabled;
    }
    function unresolved() {
      review.hidden = true;
      status.textContent = storageBlocked
        ? "A previous resize cannot be safely recovered from this tab's storage. Resize and lifecycle actions are paused. No resize was retried."
        : attempt.operationId === null
          ? `The resize outcome is unknown. Keep request ${attempt.requestId} for operator reconciliation. Reopening or reloading will not retry it or unlock another change.`
          : "Resize submitted. Check its operation status; requested resources are not proof that they were applied.";
      controls();
    }
    function save(value) {
      const encoded = JSON.stringify(value);
      if (!validAttempt(value) || encoded.length > 1024) throw new Error("Invalid resize attempt");
      sessionStorage.setItem(storageKey, encoded);
      if (sessionStorage.getItem(storageKey) !== encoded) throw new Error("Resize storage unavailable");
    }
    try {
      const encoded = sessionStorage.getItem(storageKey);
      if (encoded !== null) {
        if (encoded.length > 1024) throw new Error("Invalid resize attempt");
        attempt = JSON.parse(encoded);
        if (!validAttempt(attempt)) throw new Error("Invalid resize attempt");
      }
    } catch { attempt = null; storageBlocked = true; }
    dialog.dataset.resizeEnhanced = "true";
    notify();
    if (locked()) unresolved();
    controls();

    function invalidate() {
      epoch += 1;
      clearTimeout(timer);
      timer = null;
      busy?.abort();
      busy = null;
      controls();
    }
    async function request(url, init, accept, unavailable) {
      if (busy || !dialog.open || document.hidden) return;
      const version = ++epoch;
      const controller = new AbortController();
      busy = controller;
      controls();
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(url, { ...init, credentials: "same-origin", cache: "no-store",
          redirect: "error", signal: controller.signal });
        const value = await boundedJson(response);
        if (version === epoch && dialog.open && !document.hidden && dialog.isConnected) accept(value);
      } catch (error) {
        if (version === epoch && dialog.open && dialog.isConnected) unavailable(error);
      } finally {
        clearTimeout(timeout);
        if (busy === controller) busy = null;
        if (version === epoch) controls();
      }
    }
    const selectedResources = () => ({ cpuMillicores: Number(planForm.elements.cpu_millicores.value),
      memoryMib: Number(planForm.elements.memory_mb.value), diskGib: Number(planForm.elements.disk_gb.value) });
    const body = (desired) => new URLSearchParams({ _csrf: planForm.elements._csrf.value, account_id: actor,
      cpu_millicores: String(desired.cpuMillicores), memory_mb: String(desired.memoryMib), disk_gb: String(desired.diskGib) });
    function observe(value) {
      if (!attempt || !validOperation(value, actor, environment, attempt)) throw new Error("Invalid resize operation");
      attempt = { ...attempt, operationId: value.operationId };
      try { save(attempt); } catch { storageBlocked = true; }
      if (["completed", "failed"].includes(value.state) && !storageBlocked) {
        try {
          sessionStorage.removeItem(storageKey);
          if (sessionStorage.getItem(storageKey) !== null) throw new Error("Resize storage unavailable");
          attempt = null;
          plan = null;
          result = true;
          review.hidden = true;
          notify();
          status.textContent = value.state === "completed"
            ? "Resize completed. Current resources are shown when Sandbox status refreshes."
            : "The resize operation failed. Current resources are shown when Sandbox status refreshes; nothing was retried.";
          controls();
          if (!dialog.contains(document.activeElement) || document.activeElement === observeButton) done.focus();
        } catch { storageBlocked = true; unresolved(); }
      } else {
        status.textContent = `Resize ${value.state}. Requested: ${describe(value.desiredResources)}. Current resources remain source-owned Sandbox status.`;
        if (storageBlocked) unresolved();
      }
    }
    async function poll() {
      if (!attempt?.operationId || storageBlocked || busy || !dialog.open || document.hidden) return;
      clearTimeout(timer);
      await request(`${base}/_fragments/resize-operation?${new URLSearchParams({ account_id: actor, operation_id: attempt.operationId })}`,
        { headers: { Accept: "application/json" } }, observe,
        () => { status.textContent = "Resize status is unavailable. The submitted change stays locked; nothing was retried."; });
      if (attempt?.operationId && !storageBlocked && dialog.open && !document.hidden) timer = setTimeout(poll, 5000);
    }
    planForm.addEventListener("input", () => { plan = null; review.hidden = true; controls(); });
    planForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!eligible || busy || locked()) return;
      const desired = selectedResources();
      if (!resources(desired)) return;
      plan = null;
      review.hidden = true;
      status.textContent = "Reviewing proposed resources…";
      void request(`${base}/_actions/resize/plan`, { method: "POST", headers: { Accept: "application/json" }, body: body(desired) }, (value) => {
        if (!validPlan(value, actor, environment, desired)) throw new Error("Invalid resize plan");
        plan = value;
        applyForm.reset();
        dialog.querySelector("[data-resize-summary]").textContent = `${describe(value.previousResources)} → ${describe(value.desiredResources)}`;
        dialog.querySelector("[data-resize-mode]").textContent = ({ noop: "These resources are already requested.",
          "apply-on-start": "The requested resources will be used when the Sandbox starts.",
          "in-place": "This change can be applied without restarting the Sandbox.",
          restart: `This change requires a restart. ${value.activeSessionCount} active terminal session(s) were observed.` })[value.mode];
        dialog.querySelector("[data-resize-disk-warning]").hidden = value.desiredResources.diskGib <= value.previousResources.diskGib;
        dialog.querySelector("[data-resize-restart-consent]").hidden = !value.restartRequired;
        dialog.querySelector("[data-resize-session-consent]").hidden = !value.sessionsWillTerminate;
        consents.hidden = !value.restartRequired && !value.sessionsWillTerminate;
        review.hidden = false;
        status.textContent = "Review complete. Nothing has been applied. The server will recheck this change and its required consent.";
        controls();
        back.focus();
      }, (error) => {
        plan = null;
        status.textContent = error instanceof SetupInProgress
          ? "Setup is still running. Nothing was applied. You can resize when it finishes."
          : "The resize could not be reviewed. Nothing was applied. Check current status before reviewing again.";
      });
    });
    // Back returns to the chosen values without a request.
    function chooseAgain(message) {
      plan = null;
      review.hidden = true;
      status.textContent = message;
      controls();
      firstControl().focus();
    }
    back.addEventListener("click", () => { if (plan && !busy && !locked()) chooseAgain(""); });
    applyForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!eligible || busy || locked() || !plan || !equalResources(plan.desiredResources, selectedResources())) return;
      const allowRestart = plan.restartRequired && applyForm.elements.allow_restart.checked;
      const force = plan.sessionsWillTerminate && applyForm.elements.force.checked;
      if ((plan.restartRequired && !allowRestart) || (plan.sessionsWillTerminate && !force)) {
        status.textContent = "Confirm the required restart and terminal-session consequences before applying.";
        return;
      }
      const candidate = { version: 1, requestId: plan.requestId, desiredResources: { ...plan.desiredResources },
        allowRestart, force, operationId: null };
      try { save(candidate); } catch { storageBlocked = true; notify(); unresolved(); done.focus(); return; }
      attempt = candidate;
      plan = null;
      notify();
      unresolved();
      done.focus();
      const payload = body(candidate.desiredResources);
      payload.set("request_id", candidate.requestId);
      payload.set("allow_restart", String(candidate.allowRestart));
      payload.set("force", String(candidate.force));
      void request(`${base}/_actions/resize/apply`, { method: "POST", headers: { Accept: "application/json" }, body: payload }, observe, unresolved)
        .then(() => { if (attempt?.operationId && dialog.open && !document.hidden) timer = setTimeout(poll, 5000); });
    });
    observeButton.addEventListener("click", () => { void poll(); });
    dialog.addEventListener("codewire:dialog-open", () => {
      if (plan && !equalResources(plan.desiredResources, selectedResources())) {
        chooseAgain("The current resources changed while Resize was closed. Review the requested resources again before applying.");
      }
      if (locked()) unresolved();
      controls();
      if (attempt?.operationId) void poll();
    });
    // A finished outcome is read once; reopening starts a new choice.
    dialog.addEventListener("close", () => {
      if (result) { result = false; status.textContent = ""; }
      invalidate();
    });
    window.addEventListener("pagehide", invalidate);
    window.addEventListener("pageshow", (event) => { if (event.persisted && attempt?.operationId) void poll(); });
    document.addEventListener("visibilitychange", () => { if (document.hidden) invalidate(); else if (attempt?.operationId) void poll(); });
    document.addEventListener("codewire:sandbox-status", (event) => {
      if (event.detail?.environmentId !== environment) return;
      eligible = event.detail.available === true && event.detail.actionsAllowed === true && event.detail.pending === false
        && event.detail.setupRunning !== true;
      controls();
    });
  }
  document.querySelectorAll("dialog[data-resize-account-id]").forEach(mount);
})();
