(() => {
  "use strict";
  const P = globalThis.CodewireTerminalProtocol;
  const states = ["pending", "pending build", "building", "build failed", "pulling snapshot", "creating", "starting", "running", "stopping", "stopped", "archiving", "archived", "restoring", "resizing", "destroying", "destroyed", "error", "unknown"];
  // Deletion reads in the product's Delete language; other states as named.
  const stateLabels = { destroying: "deleting…", destroyed: "deleted" };
  const deletionStates = ["destroying", "destroyed"];
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
      // Read after the status bar's "Auto-delete" label.
      node.textContent = { unscheduled: "off", protected: "off (protected)",
        unavailable: "unavailable" }[detail.deletionState];
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

  // The one thing the page says about the Sandbox's state, and its action (#3772).
  // A banner sits above whatever still shows below it; a message is centred
  // where nothing runs; setup lists its steps there.
  const noticeActions = { "": [""], start: ["Start", "Start again"], retry: ["Try again"], delete: ["Delete"],
    refresh: ["Refresh status"] };
  function validNotice(value) {
    return P.closed(value, ["kind", "text", "tone", "action", "label", "dismissible", "graphic"])
      && ["none", "banner", "message", "setup"].includes(value.kind)
      && typeof value.text === "string" && [...value.text].length <= 300
      && ["neutral", "info", "warning", "danger"].includes(value.tone)
      && Object.hasOwn(noticeActions, value.action) && noticeActions[value.action].includes(value.label)
      && typeof value.dismissible === "boolean"
      && ["", "crashed", "no-capacity", "stopped"].includes(value.graphic);
  }
  const NONE = { kind: "none", text: "", tone: "neutral", action: "", label: "", dismissible: false, graphic: "" };

  function mount(root) {
    const environmentId = root.dataset.terminalEnvironmentId;
    const slug = root.dataset.terminalOrgSlug;
    if (!P.uuid.test(environmentId || "") || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug || "") || slug.length < 3 || slug.length > 48) return;
    // Ask for setupRunning and the status message explicitly: the server omits
    // them for pages that predate them, whose closed-shape check would
    // otherwise reject the response.
    const url = `/${encodeURIComponent(slug)}/${environmentId}/_fragments/terminal-readiness?fields=status`;
    const heading = document.querySelector("[data-sandbox-observation]");
    const observesDetail = heading?.dataset.sandboxEnvironmentId === environmentId;
    let submissionPending = false;
    let returnedAfterSubmission = false;
    let resizeLocked = false;
    let lastObservation = null;
    // Until the first readiness response settles, keep the rendered values and
    // controls (disabled) instead of calling status unavailable.
    let settled = false;
    let everSettled = false;
    // Deletion is final: once observed, the page stops asking for status.
    let deleted = false;
    const notice = root.querySelector("[data-sandbox-notice]");
    const dismissedKey = `codewire:sandbox-notice-dismissed:${environmentId}`;
    const messageOffersStart = () => !!notice && !notice.hidden && notice.dataset.kind === "message"
      && notice.querySelector('[data-sandbox-notice-action="start"]')?.hidden === false;
    function dismissed(text) {
      try { return localStorage.getItem(dismissedKey) === text; } catch { return false; }
    }
    // One place says the state and offers its action. A dismissible banner's
    // dismissal lasts until its text changes.
    function showNotice(value) {
      if (!notice) return;
      const setup = notice.querySelector("[data-setup-progress]");
      const text = notice.querySelector("[data-sandbox-notice-text]");
      notice.hidden = value.kind === "none" || (value.dismissible && dismissed(value.text));
      notice.dataset.kind = value.kind;
      notice.dataset.tone = value.tone;
      notice.dataset.graphic = value.graphic;
      if (text.textContent !== value.text) text.textContent = value.text;
      text.hidden = value.kind === "setup" && !!setup;
      if (setup) setup.hidden = value.kind !== "setup";
      for (const action of notice.querySelectorAll("[data-sandbox-notice-action]")) {
        const name = action.dataset.sandboxNoticeAction;
        action.hidden = name === "start" ? !["start", "retry"].includes(value.action) : name !== value.action;
        if (name === "start" && value.label && action.textContent !== value.label) action.textContent = value.label;
      }
      notice.querySelector("[data-sandbox-notice-dismiss]").hidden = !value.dismissible;
    }
    notice?.querySelector("[data-sandbox-notice-dismiss]")?.addEventListener("click", () => {
      const text = notice.querySelector("[data-sandbox-notice-text]").textContent;
      try { localStorage.setItem(dismissedKey, text); } catch { /* Dismissed for this page view only. */ }
      notice.hidden = true;
    });
    // A banner dismissed earlier stays dismissed from the first paint.
    if (notice && !notice.hidden && !notice.querySelector("[data-sandbox-notice-dismiss]").hidden
      && dismissed(notice.querySelector("[data-sandbox-notice-text]").textContent)) notice.hidden = true;
    notice?.querySelector('[data-sandbox-notice-action="refresh"]')?.addEventListener("click", (event) => {
      event.preventDefault();
      void refresh();
    });
    function observe(available, value) {
      if (!observesDetail) return;
      const detail = value?.detail;
      const status = heading.querySelector("[data-sandbox-observation-status]");
      const reload = heading.querySelector("[data-sandbox-observation-reload]");
      heading.dataset.observationAvailable = String(available);
      // "Sandbox creation started." is news only until the Sandbox runs.
      if (value?.running === true) {
        for (const notice of document.querySelectorAll("[data-sandbox-creation-notice]")) notice.hidden = true;
      }
      if (available) {
        const state = heading.querySelector("[data-sandbox-state]");
        state.textContent = stateLabels[detail.state] || detail.state;
        state.dataset.tone = detail.tone;
        // A Sandbox being deleted has no actions and no terminal; a deleted
        // one says so and links back. A failed deletion (error) restores
        // the actions that recover it.
        const ending = deletionStates.includes(detail.state);
        deleted = detail.state === "destroyed";
        // A server from before the notice sends none; the page keeps what it
        // rendered and the status line below says the rest.
        if (Object.hasOwn(value, "notice")) showNotice(ending ? NONE : value.notice);
        const actions = heading.querySelector("[data-sandbox-actions]");
        if (actions) actions.hidden = ending;
        const back = heading.querySelector("[data-sandbox-deleted]");
        if (back) back.hidden = !deleted;
        root.hidden = ending;
        heading.querySelector("[data-sandbox-last-event]").textContent = detail.lastEvent;
        document.querySelectorAll("[data-sandbox-resources]").forEach((node) => { node.textContent = detail.resources; });
        heading.querySelectorAll("[data-sandbox-lifetime]").forEach((node) => { showDeadline(node, detail); });
        // Never overwrite a draft while the Resize dialog is open or focused.
        // Its no-script form sits in <noscript>, so it is never here (#4542).
        const resize = document.querySelector('dialog[data-resize-enhanced="true"]');
        if (resize && !resize.open && !resize.contains(document.activeElement)) {
          for (const [name, key] of [["cpu_millicores", "cpuMillicores"], ["memory_mb", "memoryMib"], ["disk_gb", "diskGib"]]) {
            showResource(resize.querySelector(`[name="${name}"]`), detail[key]);
          }
        }
      }
      // Before any response the page keeps its rendered status (a deletion
      // message, or nothing) rather than calling the Sandbox unavailable.
      const noticed = available && Object.hasOwn(value, "notice");
      status.textContent = !available ? !settled ? everSettled ? "" : status.textContent
          : "Sandbox status is unavailable. Last known values are shown; actions are paused."
        : submissionPending ? returnedAfterSubmission
          ? "The submitted action's outcome is not confirmed. Reload this page to reconcile it before taking another action. No action was retried."
          : "Action submitted. Waiting for its response; no action will be retried automatically."
        : detail.state === "destroyed" ? "This Sandbox was deleted."
        : detail.state === "destroying" ? "This Sandbox is being deleted."
        // The notice says the state and offers its action.
        : noticed ? ""
        : detail.pending ? "A Sandbox operation is pending. Waiting for the observed state to match its requested state."
        : ["error", "build failed"].includes(detail.state) ? detail.desiredState === "destroyed"
          ? detail.deleteEligible
            ? "This Sandbox could not be deleted. Choose Delete to try again."
            : "This Sandbox could not be deleted. No action was retried; its status here updates on its own."
          : detail.startEligible
            ? "The Sandbox operation failed. Choose Start to try again."
            : "The Sandbox operation failed. No action was retried; its status here updates on its own."
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
        // its stale submit. Only header controls change their visibility, and
        // the header's Start waits while a centred message offers its own.
        if (!control.hasAttribute("data-sandbox-confirm") && settled) {
          control.hidden = (!eligible && available && !submissionPending)
            || (action === "start" && messageOffersStart());
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
          // Asked to run and on its way up, not stopped and not failed.
          starting: value?.running !== true && value?.detail?.desiredState === "started"
            && !["error", "build failed"].includes(value?.detail?.state),
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
    // The status line is busy while a check runs, so a screen reader waits for
    // its result instead of reading a line about to change (#4542).
    const checking = () => {
      const status = heading?.querySelector("[data-sandbox-observation-status]");
      if (!status) return;
      if (pending) status.setAttribute("aria-busy", "true");
      else status.removeAttribute("aria-busy");
    };
    function invalidate() {
      epoch += 1;
      clearTimeout(timer);
      timer = null;
      pending?.abort();
      pending = null;
      checking();
      report(false);
    }
    async function refresh() {
      if (paused || document.hidden || pending || !root.isConnected) return;
      clearTimeout(timer);
      const version = ++epoch;
      const controller = new AbortController();
      pending = controller;
      checking();
      lastRequest = Date.now();
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
        if (!P.closed(value, ["environmentId", "running", "setupComplete", "detail"], ["setupRunning", "notice"])
          || value.environmentId !== environmentId || typeof value.running !== "boolean"
          || typeof value.setupComplete !== "boolean"
          || (Object.hasOwn(value, "setupRunning") && typeof value.setupRunning !== "boolean")
          || (Object.hasOwn(value, "notice") && !validNotice(value.notice))
          || !validDetail(value.detail)) throw new Error("Invalid readiness");
        if (version === epoch && !paused && !document.hidden && root.isConnected) { settled = everSettled = true; report(true, value); }
      } catch {
        if (version === epoch && !paused && root.isConnected) { settled = everSettled = true; report(false); }
      } finally {
        clearTimeout(timeout);
        if (pending === controller) pending = null;
        checking();
        if (version === epoch) {
          if (!paused && !document.hidden && root.isConnected && !deleted) timer = setTimeout(refresh, 5000);
        }
      }
    }
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
    report(false);
    void refresh();
  }
  document.querySelectorAll("[data-terminal-readiness]").forEach(mount);
})();
