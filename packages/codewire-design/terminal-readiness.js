(() => {
  "use strict";
  const P = globalThis.CodewireTerminalProtocol;
  const states = ["pending", "pending build", "building", "build failed", "pulling snapshot", "creating", "starting", "running", "stopping", "stopped", "archiving", "archived", "restoring", "resizing", "destroying", "destroyed", "error", "unknown"];
  const detailFields = ["state", "desiredState", "tone", "lastEvent", "resources", "cpuMillicores", "memoryMib", "diskGib", "startEligible", "stopEligible", "deleteEligible", "actionsAllowed", "pending"];

  function validDetail(value) {
    return P.closed(value, detailFields) && states.includes(value.state)
      && ["started", "stopped", "destroyed", "archived", "resized", "unknown"].includes(value.desiredState)
      && ["success", "danger", "neutral", "warning"].includes(value.tone)
      && ["lastEvent", "resources"].every((key) => typeof value[key] === "string" && value[key].length <= 128)
      && [["cpuMillicores", 100, 128000], ["memoryMib", 128, 1048576], ["diskGib", 1, 16384]]
        .every(([key, min, max]) => Number.isSafeInteger(value[key]) && value[key] >= min && value[key] <= max)
      && ["startEligible", "stopEligible", "deleteEligible", "actionsAllowed", "pending"].every((key) => typeof value[key] === "boolean");
  }

  function mount(root) {
    const environmentId = root.dataset.terminalEnvironmentId;
    const slug = root.dataset.terminalOrgSlug;
    if (!P.uuid.test(environmentId || "") || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug || "") || slug.length < 3 || slug.length > 48) return;
    const url = `/${encodeURIComponent(slug)}/${environmentId}/_fragments/terminal-readiness`;
    const button = root.querySelector("[data-terminal-readiness-refresh]");
    const heading = document.querySelector("[data-sandbox-observation]");
    const observesDetail = heading?.dataset.sandboxEnvironmentId === environmentId;
    let submissionPending = false;
    let returnedAfterSubmission = false;
    let resizeLocked = false;
    let lastObservation = null;
    function observe(available, value) {
      if (!observesDetail) return;
      const detail = value?.detail;
      const status = heading.querySelector("[data-sandbox-observation-status]");
      const reload = heading.querySelector("[data-sandbox-observation-reload]");
      heading.dataset.observationAvailable = String(available);
      if (available) {
        const state = heading.querySelector("[data-sandbox-state]");
        state.textContent = detail.state;
        state.dataset.tone = detail.tone;
        heading.querySelector("[data-sandbox-last-event]").textContent = detail.lastEvent;
        document.querySelectorAll("[data-sandbox-resources]").forEach((node) => { node.textContent = detail.resources; });
        // Never overwrite a draft while its Resize menu is open or focused.
        const resize = document.querySelector('dialog[data-resize-enhanced="true"]') || document.querySelector("details[data-sandbox-resize]");
        if (resize && !resize.open && !resize.contains(document.activeElement)) {
          for (const [name, key] of [["cpu_millicores", "cpuMillicores"], ["memory_mb", "memoryMib"], ["disk_gb", "diskGib"]]) {
            resize.querySelector(`[name="${name}"]`).value = String(detail[key]);
          }
        }
        if (resize instanceof HTMLDetailsElement && !resize.open) resize.hidden = !detail.actionsAllowed;
        // The enhanced Resize dialog owns its controls and unknown-outcome
        // latch. Never re-expose its native fallback behind that latch.
        if (document.querySelector("[data-resize-open]")) {
          const fallback = document.querySelector("details[data-sandbox-resize]");
          if (fallback && document.querySelector('dialog[data-resize-enhanced="true"]')) fallback.hidden = true;
        }
      }
      status.textContent = !available ? "Sandbox status is unavailable. Last known values are shown; actions are paused."
        : submissionPending ? returnedAfterSubmission
          ? "The submitted action's outcome is not confirmed. Reload this page to reconcile it before taking another action. No action was retried."
          : "Action submitted. Waiting for its response; no action will be retried automatically."
        : detail.pending ? "A Sandbox operation is pending. Waiting for the observed state to match its requested state."
        : ["error", "build failed"].includes(detail.state) ? "The Sandbox operation failed. Refresh status to check its current state; no action was retried."
        : "";
      status.hidden = status.textContent.length === 0;
      if (reload) reload.hidden = !returnedAfterSubmission;
      for (const control of document.querySelectorAll("[data-sandbox-action]")) {
        const action = control.dataset.sandboxAction;
        const eligible = available && !submissionPending && !(resizeLocked && ["start", "stop", "delete", "resize"].includes(action))
          && ({ start: detail.startEligible, stop: detail.stopEligible,
          delete: detail.deleteEligible, resize: detail.actionsAllowed && !detail.pending,
          ports: detail.actionsAllowed, connect: value.running && value.setupComplete })[action] === true;
        if (control instanceof HTMLButtonElement) control.disabled = !eligible;
        if (control instanceof HTMLAnchorElement) {
          control.hidden = !eligible;
          control.setAttribute("aria-disabled", String(!eligible));
          continue;
        }
        // Keep an open confirmation and its Cancel/Close usable while disabling
        // its stale submit. Only header controls change their visibility.
        if (!control.hasAttribute("data-sandbox-confirm")) {
          control.hidden = !eligible && available && !submissionPending;
        }
      }
    }
    let epoch = 0;
    let pending = null;
    let timer = null;
    let paused = document.hidden;
    let lastRequest = -Infinity;
    const report = (available, value) => {
      lastObservation = { available, value };
      observe(available, value);
      document.dispatchEvent(new CustomEvent("codewire:sandbox-status", {
        detail: { environmentId, available, running: value?.running === true,
          setupComplete: value?.setupComplete === true, actionsAllowed: value?.detail?.actionsAllowed === true,
          pending: value?.detail?.pending !== false },
      }));
    };
    document.addEventListener("codewire:resize-mutation-status", (event) => {
      if (event.detail?.environmentId !== environmentId || typeof event.detail.locked !== "boolean") return;
      resizeLocked = event.detail.locked;
      // Lock lifecycle controls without reporting the terminal unavailable or
      // detaching it. Only source-owned running/setup observation can do that.
      if (lastObservation) observe(lastObservation.available, lastObservation.value);
    });
    const controls = () => { if (button) button.disabled = !!pending || paused; };
    function invalidate() {
      epoch += 1;
      clearTimeout(timer);
      timer = null;
      pending?.abort();
      pending = null;
      controls();
      report(false);
    }
    async function refresh() {
      if (paused || document.hidden || pending || !root.isConnected) return;
      clearTimeout(timer);
      const version = ++epoch;
      const controller = new AbortController();
      pending = controller;
      lastRequest = Date.now();
      controls();
      const timeout = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch(url, { credentials: "same-origin", cache: "no-store",
          redirect: "error", signal: controller.signal, headers: { Accept: "application/json" } });
        if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") {
          await response.body?.cancel();
          throw new Error("Readiness unavailable");
        }
        const reader = response.body?.getReader();
        if (!reader) throw new Error("No readiness response");
        const decoder = new TextDecoder("utf-8", { fatal: true });
        let text = "";
        let size = 0;
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.length;
          if (size > 2048) { await reader.cancel(); throw new Error("Oversize readiness"); }
          text += decoder.decode(part.value, { stream: true });
        }
        text += decoder.decode();
        const value = JSON.parse(text);
        if (!P.closed(value, ["environmentId", "running", "setupComplete", "detail"])
          || value.environmentId !== environmentId || typeof value.running !== "boolean"
          || typeof value.setupComplete !== "boolean" || !validDetail(value.detail)) throw new Error("Invalid readiness");
        if (version === epoch && !paused && !document.hidden && root.isConnected) report(true, value);
      } catch {
        if (version === epoch && !paused && root.isConnected) report(false);
      } finally {
        clearTimeout(timeout);
        if (pending === controller) pending = null;
        if (version === epoch) {
          controls();
          if (!paused && !document.hidden && root.isConnected) timer = setTimeout(refresh, 5000);
        }
      }
    }
    button?.addEventListener("click", () => { void refresh(); });
    document.addEventListener("visibilitychange", () => {
      paused = document.hidden;
      if (paused) invalidate();
      else void refresh();
    });
    window.addEventListener("pagehide", () => { paused = true; invalidate(); });
    window.addEventListener("pageshow", (event) => {
      if (event.persisted) {
        returnedAfterSubmission = submissionPending;
        paused = document.hidden;
        report(false);
        void refresh();
      }
    });
    window.addEventListener("focus", () => {
      if (!paused && Date.now() - lastRequest >= 1000) void refresh();
    });
    document.addEventListener("submit", (event) => {
      if (!observesDetail || !(event.target instanceof HTMLFormElement)) return;
      const submit = event.submitter;
      if (!(submit instanceof HTMLButtonElement) || !submit.matches("[data-sandbox-action]")) return;
      if (submissionPending || submit.disabled || heading.dataset.observationAvailable !== "true") {
        event.preventDefault();
        return;
      }
      // Review resize only prepares a plan; it is not a lifecycle mutation.
      if (!["start", "stop", "delete"].includes(submit.dataset.sandboxAction)) return;
      submissionPending = true;
      // Disable on the next task, after the native form captures its successful
      // controls. A subsequent poll cannot clear a still-unacknowledged submit.
      setTimeout(() => {
        if (event.defaultPrevented) submissionPending = false;
        if (root.isConnected) report(false);
      }, 0);
    });
    controls();
    report(false);
    void refresh();
  }
  document.querySelectorAll("[data-terminal-readiness]").forEach(mount);
})();
