(() => {
  "use strict";
  const P = globalThis.CodewireTerminalProtocol;
  const states = ["pending", "pending build", "building", "build failed", "pulling snapshot", "creating", "starting", "running", "stopping", "stopped", "archiving", "archived", "restoring", "resizing", "destroying", "destroyed", "error", "unknown"];
  const detailFields = ["state", "desiredState", "tone", "lastEvent", "resources", "deletionState", "shutdownAt", "cpuMillicores", "memoryMib", "diskGib", "startEligible", "stopEligible", "deleteEligible", "actionsAllowed", "pending"];

  function validDeadline(value) {
    if (value.deletionState !== "scheduled") {
      return ["unscheduled", "protected", "unavailable"].includes(value.deletionState) && value.shutdownAt === null;
    }
    if (typeof value.shutdownAt !== "string" || !/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/.test(value.shutdownAt)) return false;
    const date = new Date(value.shutdownAt);
    // Date parsing alone normalizes impossible calendar days. Require an exact
    // UTC round trip, preserving the original nanoseconds in <time datetime>.
    return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 23) === value.shutdownAt.slice(0, 23);
  }

  function showDeadline(node, detail) {
    if (detail.deletionState !== "scheduled") {
      node.textContent = { unscheduled: "Not currently scheduled", protected: "Protected from automatic deletion",
        unavailable: "Deletion deadline unavailable" }[detail.deletionState];
      return;
    }
    const date = new Date(detail.shutdownAt);
    const pad = (value) => String(value).padStart(2, "0");
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const time = document.createElement("time");
    time.dateTime = detail.shutdownAt;
    time.textContent = `${pad(date.getUTCDate())} ${months[date.getUTCMonth()]} ${String(date.getUTCFullYear()).padStart(4, "0")}, ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
    node.replaceChildren(time);
  }

  // Resize offers Create's fixed CPU and memory choices. A current value
  // outside them keeps one "(current)" option, added before the value is set:
  // a select given a value without an option would show nothing selected.
  const currentUnits = { cpu_millicores: "millicores", memory_mb: "MiB" };
  function showResource(field, value) {
    const text = String(value);
    if (field instanceof HTMLSelectElement) {
      let current = field.querySelector("option[data-resize-current]");
      if (Array.from(field.options).some((option) => option !== current && option.value === text)) current?.remove();
      else {
        if (!current) {
          current = document.createElement("option");
          current.dataset.resizeCurrent = "";
          field.prepend(current);
        }
        current.value = text;
        current.textContent = `${text} ${currentUnits[field.name]} (current)`;
      }
    }
    field.value = text;
  }

  function validDetail(value) {
    return P.closed(value, detailFields) && states.includes(value.state) && validDeadline(value)
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
    // Ask for setupRunning explicitly: the server omits it for pages that
    // predate it, whose closed-shape check would otherwise reject the response.
    const url = `/${encodeURIComponent(slug)}/${environmentId}/_fragments/terminal-readiness?fields=setup`;
    const button = root.querySelector("[data-terminal-readiness-refresh]");
    const heading = document.querySelector("[data-sandbox-observation]");
    const observesDetail = heading?.dataset.sandboxEnvironmentId === environmentId;
    let submissionPending = false;
    let returnedAfterSubmission = false;
    let resizeLocked = false;
    let lastObservation = null;
    // Until the first readiness response settles, keep the rendered values and
    // controls (disabled) instead of calling status unavailable.
    let settled = false;
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
        heading.querySelectorAll("[data-sandbox-lifetime]").forEach((node) => { showDeadline(node, detail); });
        // Never overwrite a draft while its Resize menu is open or focused.
        const resize = document.querySelector('dialog[data-resize-enhanced="true"]') || document.querySelector("details[data-sandbox-resize]");
        if (resize && !resize.open && !resize.contains(document.activeElement)) {
          for (const [name, key] of [["cpu_millicores", "cpuMillicores"], ["memory_mb", "memoryMib"], ["disk_gb", "diskGib"]]) {
            showResource(resize.querySelector(`[name="${name}"]`), detail[key]);
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
      status.textContent = !available ? !settled ? ""
          : "Sandbox status is unavailable. Last known values are shown; actions are paused."
        : submissionPending ? returnedAfterSubmission
          ? "The submitted action's outcome is not confirmed. Reload this page to reconcile it before taking another action. No action was retried."
          : "Action submitted. Waiting for its response; no action will be retried automatically."
        : detail.pending ? "A Sandbox operation is pending. Waiting for the observed state to match its requested state."
        : ["error", "build failed"].includes(detail.state) ? detail.startEligible
          ? "The Sandbox operation failed. Choose Start to try again."
          : "The Sandbox operation failed. Refresh status to check its current state; no action was retried."
        : "";
      status.hidden = status.textContent.length === 0;
      if (reload) reload.hidden = !returnedAfterSubmission;
      for (const control of document.querySelectorAll("[data-sandbox-action]")) {
        const action = control.dataset.sandboxAction;
        const eligible = available && !submissionPending && !(resizeLocked && ["start", "stop", "delete", "resize"].includes(action))
          && ({ start: detail.startEligible, stop: detail.stopEligible,
          delete: detail.deleteEligible, resize: detail.actionsAllowed && !detail.pending && value.setupRunning !== true,
          ports: detail.actionsAllowed, connect: value.running && value.setupComplete })[action] === true;
        if (control instanceof HTMLButtonElement) control.disabled = !eligible;
        if (control instanceof HTMLAnchorElement) {
          control.hidden = !eligible;
          control.setAttribute("aria-disabled", String(!eligible));
          continue;
        }
        // Keep an open confirmation and its Cancel/Close usable while disabling
        // its stale submit. Only header controls change their visibility.
        if (!control.hasAttribute("data-sandbox-confirm") && settled) {
          control.hidden = !eligible && available && !submissionPending;
        }
      }
      // Resize waits while setup owns the running Sandbox, as New terminal
      // does, and says why. The rendered reason stands until status settles.
      const setupNote = document.querySelector("[data-resize-setup-note]");
      if (setupNote && settled) {
        const waiting = available && !submissionPending && !resizeLocked && value.setupRunning === true
          && detail.actionsAllowed && !detail.pending;
        setupNote.hidden = !waiting;
        for (const control of document.querySelectorAll('[data-resize-open], [data-sandbox-action="resize"]')) {
          if (waiting) control.setAttribute("aria-describedby", setupNote.id);
          else control.removeAttribute("aria-describedby");
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
          setupComplete: value?.setupComplete === true, setupRunning: value?.setupRunning === true,
          actionsAllowed: value?.detail?.actionsAllowed === true,
          pending: value?.detail?.pending !== false, checking: !settled },
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
        // A server from before setupRunning omits it; that reads as false, so
        // Resize behaves as before and the server's refusal covers setup.
        if (!P.closed(value, ["environmentId", "running", "setupComplete", "detail"], ["setupRunning"])
          || value.environmentId !== environmentId || typeof value.running !== "boolean"
          || typeof value.setupComplete !== "boolean"
          || (Object.hasOwn(value, "setupRunning") && typeof value.setupRunning !== "boolean")
          || !validDetail(value.detail)) throw new Error("Invalid readiness");
        if (version === epoch && !paused && !document.hidden && root.isConnected) { settled = true; report(true, value); }
      } catch {
        if (version === epoch && !paused && root.isConnected) { settled = true; report(false); }
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
        settled = false;
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
