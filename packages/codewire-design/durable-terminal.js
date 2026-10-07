(() => {
  "use strict";

  const P = globalThis.CodewireTerminalProtocol;
  const styleNonce = document.currentScript?.nonce || "";
  const storagePrefix = "codewire:terminal:v1:";
  const maxTabs = 8;
  const validLabel = (value) => typeof value === "string" && value.length > 0 && value.length <= 64
    && value.isWellFormed() && value === value.trim()
    && !/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u.test(value);
  const live = (state) => ["starting", "running"].includes(state);
  // Session states in plain words; an exit code is shown only when known.
  const stateLabel = (state, exitCode) => ({
    starting: "Starting…", running: "Running", stopping: "Stopping…", stopped: "Stopped",
    failed: "Failed", interrupted: "Interrupted",
    exited: exitCode === undefined ? "Exited" : `Exited with code ${exitCode}`,
  })[state] ?? state;
  const ended = (state) => !["starting", "running", "stopping"].includes(state);
  // The status bar's dot: green while a live session is attached, amber while
  // it is on its way back, red when it cannot continue without help.
  const stateTone = (state) => live(state) ? "success" : state === "stopping" ? "warning"
    : ["failed", "interrupted"].includes(state) ? "danger" : "neutral";
  // Automatic re-attachment waits 1, 2, 4 and 8 s, then 15 s, while the tab is
  // wanted and the page is visible. Only a connection that stays open resets it.
  const retryBaseMs = 1000;
  const retryMaxMs = 15000;
  const stableMs = 5000;
  const revalidateEvery = 3;

  function clearReferences() {
    try {
      for (let index = sessionStorage.length - 1; index >= 0; index -= 1) {
        const key = sessionStorage.key(index);
        if (key?.startsWith(storagePrefix)) sessionStorage.removeItem(key);
      }
    } catch { /* Storage can be unavailable; terminal output is never stored. */ }
  }

  function mount(root) {
    const tabs = new Map();
    const tabList = root.querySelector("[data-terminal-tabs]");
    const panels = root.querySelector("[data-terminal-panels]");
    // Each tab also owns its status-bar group and its terminal-menu actions.
    const statuses = root.querySelector("[data-terminal-statuses]");
    const tabActions = root.querySelector("[data-terminal-tab-actions]");
    const template = root.querySelector("[data-terminal-tab-template]");
    const newButton = root.querySelector("[data-terminal-new]");
    const limitNote = root.querySelector("[data-terminal-limit]");
    const renameButton = root.querySelector("[data-terminal-rename]");
    const refreshButton = root.querySelector("[data-terminal-refresh]");
    const message = root.querySelector("[data-terminal-message]");
    const existing = root.querySelector("[data-terminal-existing]");
    const existingForm = root.querySelector("[data-terminal-existing-form]");
    const dialog = root.querySelector("[data-terminal-close-dialog]");
    const confirm = dialog.querySelector("[data-terminal-confirm-close]");
    const renameDialog = root.querySelector("[data-terminal-rename-dialog]");
    const renameForm = renameDialog.querySelector("form");
    const renameInput = renameForm.querySelector("[data-terminal-name]");
    const renameSave = renameForm.querySelector('[type="submit"]');
    const org = root.dataset.terminalOrgId;
    const environment = root.dataset.terminalEnvironmentId;
    const slug = root.dataset.terminalOrgSlug;
    const csrf = root.querySelector('[name="_csrf"]')?.value;
    let account = null;
    let active = null;
    let authorized = false;
    let suspended = false;
    let pending = false;
    let uncertain = false;
    let needsReload = false;
    let epoch = 0;
    let number = 0;
    let inventory = [];
    let closeTarget = null;
    // Where focus returns when the Close dialog closes: the tab's close
    // button, or the tab itself when Delete opened it from the keyboard.
    let closeReturn = null;
    let renameTarget = null;
    let renameOpener = null;
    let renameReturn = null;
    let requestController = null;
    let foregroundCheck = false;
    // Readiness returned while another request was pending: re-list before
    // re-attaching, because the Sandbox may have restarted.
    let relist = false;
    // Rendered lifecycle state is not fresh setup readiness. Wait for the
    // authenticated status controller before opening a transport or a shell.
    let runtimeAvailable = false;
    let runtimeRunning = false;
    let setupComplete = false;
    let initialStatusReceived = false;
    let runtimeChecking = true;
    const runtimeControlReady = () => runtimeAvailable && runtimeRunning;
    const runtimeReady = () => runtimeControlReady() && setupComplete;
    const readinessMessage = () => runtimeChecking ? "Checking Sandbox status before restoring terminals…"
      : !runtimeAvailable ? "Sandbox status is unavailable. Terminal controls are paused."
      : !runtimeRunning ? "Start this Sandbox to use its terminals."
        : "Sandbox setup is not complete. Terminal controls will be available when setup completes.";
    const readinessTone = () => runtimeAvailable && !runtimeRunning ? "neutral" : "warning";

    function announce(text) { message.textContent = text; }
    // Output, status-bar groups and tab actions are shown or withheld together.
    function showSessions(visible) {
      panels.hidden = !visible;
      statuses.hidden = !visible;
      tabActions.hidden = !visible;
    }
    function storageKey() { return `${storagePrefix}${account}:${org}:${environment}`; }
    function store() {
      if (!authorized || !account) return;
      try {
        sessionStorage.setItem(`${storagePrefix}account`, account);
        sessionStorage.setItem(storageKey(), JSON.stringify({ version: 1, accountId: account,
          organizationId: org, environmentId: environment, sessions: [...tabs.keys()], activeSessionId: active,
          labels: [...tabs.values()].map((tab) => ({ sessionId: tab.id, label: tab.label })) }));
      } catch { /* An unavailable store does not prevent an explicit terminal. */ }
    }
    function references() {
      try {
        const raw = sessionStorage.getItem(storageKey());
        if (!raw || raw.length > 4096) return null;
        const value = JSON.parse(raw);
        if (!P.closed(value, ["version", "accountId", "organizationId", "environmentId", "sessions", "activeSessionId"], ["labels"])
          || value.version !== 1 || value.accountId !== account || value.organizationId !== org
          || value.environmentId !== environment || !Array.isArray(value.sessions) || value.sessions.length > maxTabs
          || value.sessions.some((id) => !P.sessionId(id)) || new Set(value.sessions).size !== value.sessions.length
          || (value.activeSessionId !== null && !value.sessions.includes(value.activeSessionId))) return null;
        // Display labels never confer session authority. Ignore malformed
        // optional labels without discarding valid, scoped session references.
        const labels = value.labels;
        const labelsValid = Array.isArray(labels) && labels.length <= maxTabs
          && labels.every((item) => P.closed(item, ["sessionId", "label"])
            && value.sessions.includes(item.sessionId) && validLabel(item.label))
          && new Set(labels.map((item) => item.sessionId)).size === labels.length;
        return { ...value, labels: labelsValid ? labels : [] };
      } catch { return null; }
    }
    function updateControls() {
      const controlBlocked = !authorized || pending || uncertain || needsReload || suspended || !runtimeControlReady();
      const blocked = controlBlocked || !setupComplete;
      tabList.hidden = !authorized || suspended;
      renameSave.disabled = !authorized || pending || uncertain || needsReload || suspended;
      renameButton.disabled = renameSave.disabled || !tabs.has(active);
      root.querySelector("[data-terminal-reload]").hidden = !needsReload;
      newButton.disabled = blocked || tabs.size >= maxTabs;
      // Explain the tab limit where it applies instead of only disabling New.
      const atLimit = authorized && !suspended && tabs.size >= maxTabs;
      if (limitNote) {
        limitNote.hidden = !atLimit;
        if (atLimit) newButton.setAttribute("aria-describedby", limitNote.id);
        else newButton.removeAttribute("aria-describedby");
      }
      refreshButton.disabled = pending || suspended;
      existing.disabled = blocked || tabs.size >= maxTabs || existing.options.length <= 1;
      existingForm.querySelector("button").disabled = existing.disabled || !existing.value;
      for (const tab of tabs.values()) {
        // An ended session has nothing to reconnect to; Replay still shows its output.
        tab.toggle.disabled = blocked || !tab.available || tab.renderFailed
          || (ended(tab.state) && tab.socket?.readyState !== WebSocket.OPEN);
        tab.reset.disabled = blocked || !tab.available;
        const removable = !tab.available || ended(tab.state);
        tab.close.hidden = removable;
        tab.close.disabled = controlBlocked || removable;
        tab.remove.hidden = !removable;
        tab.remove.disabled = !authorized || pending || suspended;
        tab.presentation.terminal.options.disableStdin = blocked || tab.socket?.readyState !== WebSocket.OPEN || !live(tab.state);
      }
    }
    function clearRename() {
      renameTarget = null;
      renameInput.value = "";
      renameInput.setCustomValidity("");
    }
    function invalidateRename() {
      clearRename();
      renameOpener = null;
      renameDialog.close();
    }
    function label(tab, text) {
      tab.label = text;
      tab.labelNode.textContent = text;
      tab.panel.querySelector("h2").textContent = text;
      tab.close.setAttribute("aria-label", `Close ${text}`);
      tab.remove.setAttribute("aria-label", `Remove ${text} tab`);
    }
    // Keep the selected tab in view inside the tab strip, which scrolls on its
    // own; never scroll the page for it.
    function reveal(tab) {
      const strip = tabList.closest("nav");
      if (!strip) return;
      const box = tab.item.getBoundingClientRect();
      const view = strip.getBoundingClientRect();
      if (box.left < view.left) strip.scrollLeft -= view.left - box.left;
      else if (box.right > view.right) strip.scrollLeft += box.right - view.right;
    }
    function choose(id, focus = false) {
      if (!tabs.has(id)) return;
      active = id;
      for (const tab of tabs.values()) {
        const selected = tab.id === id;
        tab.button.setAttribute("aria-selected", String(selected));
        tab.button.tabIndex = selected ? 0 : -1;
        tab.panel.hidden = !selected;
        tab.status.hidden = !selected;
        tab.actions.hidden = !selected;
        if (selected) {
          tab.presentation.fitAndResize();
          reveal(tab);
          if (focus) tab.button.focus();
        }
      }
      updateControls();
      store();
    }
    function connectionText(tab, text, tone = "neutral") {
      tab.connectionLabel.textContent = text;
      tab.connection.dataset.tone = tone;
    }
    function finalAfterRender(tab, text, tone) {
      const renderEpoch = tab.renderEpoch;
      const attempt = tab.attempt;
      void tab.writes.then(() => {
        if (!tab.disposed && !tab.renderFailed && renderEpoch === tab.renderEpoch && attempt === tab.attempt) {
          connectionText(tab, text, tone);
          tab.root.dataset.terminalSettled = "true";
        }
      });
    }
    function discardInput(tab) {
      clearTimeout(tab.inputTimer);
      tab.inputTimer = null;
      tab.stagedInput = null;
    }
    function detach(tab, text = "Disconnected", keepWanted = false, tone = "neutral") {
      if (!keepWanted) {
        tab.wanted = false;
        tab.failures = 0;
      }
      clearTimeout(tab.retryTimer);
      tab.retryTimer = null;
      clearTimeout(tab.stableTimer);
      tab.stableTimer = null;
      tab.attempt += 1;
      const socket = tab.socket;
      tab.socket = null;
      clearTimeout(tab.sendTimer);
      tab.sendTimer = null;
      tab.sendQueue = [];
      tab.queuedBytes = 0;
      discardInput(tab);
      if (socket && [WebSocket.OPEN, WebSocket.CONNECTING].includes(socket.readyState)) socket.close(1000, "browser detached");
      tab.toggle.textContent = "Reconnect";
      tab.root.dataset.terminalSettled = String(tab.pendingFrames === 0);
      tab.presentation.terminal.options.disableStdin = true;
      connectionText(tab, text, tone);
    }
    // Transport loss is not a decision to stop. Re-attach the same wanted
    // session automatically; explicit Disconnect, final status, unverifiable
    // output, render failure and unavailable sessions stay manual. Nothing
    // here launches a shell, and input is never resent.
    function automatic(tab) {
      return tab.wanted && tab.available && !tab.disposed && !tab.renderFailed && !ended(tab.state);
    }
    function scheduleReconnect(tab) {
      clearTimeout(tab.retryTimer);
      tab.retryTimer = null;
      if (!automatic(tab) || suspended || document.hidden) return;
      const delay = Math.min(retryBaseMs * 2 ** Math.min(tab.failures, 4), retryMaxMs);
      tab.failures += 1;
      tab.retryTimer = setTimeout(() => {
        tab.retryTimer = null;
        retry(tab);
      }, delay);
    }
    function lose(tab, text) {
      const automatically = automatic(tab);
      detach(tab, `${text} ${automatically ? "Reconnecting…" : "Reconnect to resume this terminal."}`, automatically,
        automatically ? "warning" : "neutral");
      if (automatically) scheduleReconnect(tab);
    }
    function retry(tab) {
      // Foreground and readiness recovery own hidden, suspended and not-ready
      // waits; each reconnects wanted tabs when it completes.
      if (!automatic(tab) || tab.socket || suspended || document.hidden) return;
      if (!runtimeReady()) detach(tab, readinessMessage(), true, readinessTone());
      else if (pending) scheduleReconnect(tab);
      else if (!authorized || relist) void refresh();
      else if (tab.failures % revalidateEvery === 0) void revalidate(tab);
      else void connect(tab);
    }
    // Identity checks pause every transport. Wanted tabs reconnect when the
    // check completes; the others keep their last state.
    function pauseForIdentity(tab) {
      detach(tab, tab.wanted ? "Checking account…" : tab.connection.textContent, true,
        tab.wanted ? "warning" : tab.connection.dataset.tone);
    }
    function sendDeadline(tab) {
      return Math.min(tab.stagedInput?.deadline ?? Infinity, ...tab.sendQueue.map((frame) => frame.deadline));
    }
    function pauseInput(tab) {
      lose(tab, "Connection paused. Some input may not have arrived and will not be resent.");
      return false;
    }
    function reconcileSendQueue(tab, socket) {
      const buffered = socket.bufferedAmount;
      if (buffered > tab.queuedBytes) {
        return pauseInput(tab);
      }
      let drained = tab.queuedBytes - buffered;
      while (drained > 0 && tab.sendQueue.length) {
        const oldest = tab.sendQueue[0];
        if (drained < oldest.bytes) { oldest.bytes -= drained; break; }
        drained -= oldest.bytes;
        tab.sendQueue.shift();
      }
      tab.queuedBytes = buffered;
      if (sendDeadline(tab) <= performance.now()) return pauseInput(tab);
      return true;
    }
    function watchSendQueue(tab, socket) {
      clearTimeout(tab.sendTimer);
      tab.sendTimer = null;
      const deadline = sendDeadline(tab);
      if (!Number.isFinite(deadline)) return;
      tab.sendTimer = setTimeout(() => {
        if (tab.socket !== socket) return;
        tab.sendTimer = null;
        if (reconcileSendQueue(tab, socket)) watchSendQueue(tab, socket);
      }, Math.max(1, deadline - performance.now()));
    }
    function send(tab, socket, frame, deadline = performance.now() + 5000) {
      if (suspended || !authorized || tab.socket !== socket || socket.readyState !== WebSocket.OPEN) return false;
      let encoded;
      try { encoded = P.encodeClient(frame); } catch {
        connectionText(tab, "Input is too large to send. Paste a smaller amount.", "warning");
        return false;
      }
      if (!reconcileSendQueue(tab, socket)) return false;
      const bytes = P.bytes(encoded);
      if (tab.queuedBytes + bytes + (tab.stagedInput?.bytes ?? 0) > P.limits.pendingInputBytes
        || tab.sendQueue.length + (tab.stagedInput ? 1 : 0) >= P.limits.pendingInputFrames) return pauseInput(tab);
      try { socket.send(encoded); } catch {
        lose(tab, "Connection closed. Input will not be resent.");
        return false;
      }
      // Metadata only: drained bytes are not a receipt, and input is never replayed.
      tab.sendQueue.push({ bytes, deadline });
      tab.queuedBytes += bytes;
      watchSendQueue(tab, socket);
      return true;
    }
    function flushInput(tab, socket) {
      if (tab.socket !== socket) return false;
      if (socket.readyState !== WebSocket.OPEN || suspended || !authorized || !runtimeReady() || !live(tab.state)) {
        discardInput(tab);
        watchSendQueue(tab, socket);
        return false;
      }
      clearTimeout(tab.inputTimer);
      tab.inputTimer = null;
      const staged = tab.stagedInput;
      if (!staged) return true;
      if (staged.deadline <= performance.now()) return pauseInput(tab);
      tab.stagedInput = null;
      return send(tab, socket, { type: "input", data: staged.data }, staged.deadline);
    }
    function queueInput(tab, socket, data) {
      if (tab.socket !== socket || socket.readyState !== WebSocket.OPEN || suspended || !authorized || !runtimeReady() || !live(tab.state)) return;
      let encoded;
      try { encoded = P.encodeClient({ type: "input", data }); } catch {
        connectionText(tab, "Input is too large to send. Paste a smaller amount.", "warning");
        return;
      }
      if (!reconcileSendQueue(tab, socket)) return;
      let combined = data;
      if (tab.stagedInput) {
        try {
          combined = tab.stagedInput.data + data;
          encoded = P.encodeClient({ type: "input", data: combined });
        } catch {
          if (!flushInput(tab, socket)) return;
          combined = data;
          encoded = P.encodeClient({ type: "input", data });
        }
      }
      const bytes = P.bytes(encoded);
      if (tab.queuedBytes + bytes > P.limits.pendingInputBytes
        || tab.sendQueue.length >= P.limits.pendingInputFrames) { pauseInput(tab); return; }
      tab.stagedInput = { data: combined, bytes, deadline: tab.stagedInput?.deadline ?? performance.now() + 5000 };
      // Leading-edge batching, not debounce: continuous typing never renews
      // either the 16-ms flush or the original five-second send deadline.
      if (tab.inputTimer === null) tab.inputTimer = setTimeout(() => {
        if (tab.socket !== socket) return;
        void flushInput(tab, socket);
      }, 16);
      watchSendQueue(tab, socket);
    }

    function render(tab, socket, data, next, bytes, historyGap) {
      const renderEpoch = tab.renderEpoch;
      const signal = tab.renderAbort.signal;
      // Serialize invocation as well as callbacks. A gap notice must follow
      // older writes, and later bytes must follow that notice's cursor advance.
      tab.writes = tab.writes.then(() => new Promise((resolve) => {
        if (signal.aborted || tab.disposed || renderEpoch !== tab.renderEpoch) { resolve(); return; }
        const finish = () => { signal.removeEventListener("abort", finish); resolve(); };
        // xterm disposal need not call pending callbacks. Resolve the owned
        // wait on epoch retirement so queued output can be released promptly.
        signal.addEventListener("abort", finish, { once: true });
        try {
          if (historyGap) tab.historyGap.hidden = false;
          tab.presentation.terminal.write(data, () => {
            try {
              if (!signal.aborted && !tab.disposed && renderEpoch === tab.renderEpoch) {
                tab.rendered = next;
                tab.pendingFrames -= 1;
                tab.pendingBytes -= bytes;
                if (!tab.socket && tab.pendingFrames === 0) tab.root.dataset.terminalSettled = "true";
                if (tab.socket === socket) send(tab, socket, { type: "ack", offset: next.toString() });
              }
            } finally { finish(); }
          });
        } catch {
          tab.renderFailed = true;
          detach(tab, "Output could not be rendered. Choose Replay recent output to recover.", false, "danger");
          tab.renderAbort.abort();
          updateControls();
          finish();
        }
      }));
    }

    function websocketUrl(tab) {
      const url = new URL(document.body.dataset.terminalWebsocketOrigin || location.origin.replace(/^http/, "ws"));
      if (!["ws:", "wss:"].includes(url.protocol) || url.hostname !== location.hostname
        || url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) throw new Error("Invalid endpoint");
      url.pathname = `/api/v1/organizations/${org}/environments/${environment}/terminal`;
      url.searchParams.set("session_id", tab.id);
      url.searchParams.set("account_id", account);
      url.searchParams.set("output_offset", tab.rendered.toString());
      return url;
    }
    async function connect(tab) {
      if (tab.renderFailed) return;
      if (!runtimeReady()) { detach(tab, readinessMessage(), true, readinessTone()); return; }
      detach(tab, "Connecting…", true, "warning");
      tab.wanted = true;
      const attempt = tab.attempt;
      const identityEpoch = epoch;
      // Old write callbacks still advance this retained presentation. Complete
      // them before choosing the reconnect cursor; never ACK them on a new WS.
      let timer;
      const drained = await Promise.race([tab.writes.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 5000); })]);
      clearTimeout(timer);
      if (tab.disposed || tab.renderFailed || suspended || document.hidden || !authorized || !runtimeReady() || epoch !== identityEpoch || attempt !== tab.attempt) return;
      if (!drained) { detach(tab, "Output is still rendering. Replay output before reconnecting.", false, "danger"); return; }
      tab.received = tab.rendered;
      let socket;
      try { socket = new WebSocket(websocketUrl(tab), [P.protocol]); } catch {
        detach(tab, "The terminal connection is unavailable.", false, "danger"); return;
      }
      tab.socket = socket;
      let finalStatus = false;
      let finalText;
      let finalTone;
      tab.root.dataset.terminalSettled = "false";
      socket.addEventListener("open", () => {
        if (tab.socket !== socket || suspended || !authorized) { socket.close(); return; }
        if (socket.protocol !== P.protocol) { detach(tab, "The terminal protocol is unavailable.", false, "danger"); return; }
        tab.toggle.textContent = "Disconnect";
        connectionText(tab, live(tab.state) ? "Connected" : stateLabel(tab.state), stateTone(tab.state));
        // A server that accepts and then closes must not reset the backoff.
        tab.stableTimer = setTimeout(() => {
          tab.stableTimer = null;
          if (tab.socket === socket) tab.failures = 0;
        }, stableMs);
        updateControls();
        tab.presentation.fitAndResize();
      });
      socket.addEventListener("message", (event) => {
        if (tab.socket !== socket || !authorized || suspended) return;
        try {
          const frame = P.decodeServer(event.data);
          if (finalStatus) throw new Error("Output after final terminal state");
          if (frame.type === "status") {
            finalStatus = !["starting", "running", "stopping"].includes(frame.state);
            tab.state = frame.state;
            if (!live(tab.state)) { discardInput(tab); watchSendQueue(tab, socket); }
            // A live session on an open socket reads Connected, as on open.
            const text = live(frame.state) ? "Connected" : stateLabel(frame.state, frame.exitCode);
            if (finalStatus) {
              finalText = text;
              finalTone = stateTone(frame.state);
              finalAfterRender(tab, text, finalTone);
            } else connectionText(tab, text, stateTone(frame.state));
            updateControls();
            return;
          }
          let data;
          let bytes;
          let next;
          if (frame.type === "historyGap") {
            if (frame.requestedOffset !== tab.received || tab.pendingFrames >= P.limits.unacknowledgedOutputFrames) throw new Error("Invalid output gap");
            data = "\x18\x1b[0m\r\n[Older terminal output is unavailable. Showing recent history.]\r\n";
            bytes = 0;
            next = frame.retainedStartOffset;
          } else {
            if (frame.offset !== tab.received || tab.pendingFrames >= P.limits.unacknowledgedOutputFrames
              || tab.pendingBytes + frame.data.length > P.limits.unacknowledgedOutputBytes) throw new Error("Invalid output window");
            data = frame.data;
            bytes = frame.data.length;
            next = frame.nextOffset;
          }
          tab.received = next;
          tab.pendingFrames += 1;
          tab.pendingBytes += bytes;
          render(tab, socket, data, next, bytes, frame.type === "historyGap");
        } catch { detach(tab, "Connection closed because terminal output could not be verified.", false, "danger"); }
      });
      socket.addEventListener("error", () => {
        if (tab.socket === socket) lose(tab, "Connection closed.");
      });
      socket.addEventListener("close", (event) => {
        if (tab.socket !== socket) return;
        if (finalStatus && event.code === 1000) {
          detach(tab, "Rendering terminal output…", false, "warning");
          finalAfterRender(tab, finalText, finalTone);
        } else if (finalStatus) {
          detach(tab, "Connection closed before terminal output could be confirmed.", false, "danger");
        } else lose(tab, "Disconnected.");
      });
    }
    // Every third automatic attempt re-reads the inventory for this tab only,
    // so a vanished session stops retrying without detaching healthy siblings.
    // Account and authorization changes still use the full refresh.
    async function revalidate(tab) {
      const current = epoch;
      const attempt = tab.attempt;
      const stale = () => current !== epoch || attempt !== tab.attempt || suspended || document.hidden
        || foregroundCheck || !automatic(tab) || !!tab.socket;
      let data;
      try { data = await request("list"); } catch (error) {
        if (stale()) return;
        // Identity doubts pause every transport and hide output.
        if (error.authorization) doubtAccount();
        else scheduleReconnect(tab);
        return;
      }
      if (stale()) return;
      if (data.accountId !== account) { doubtAccount(); return; }
      const session = data.sessions.find((item) => item.sessionId === tab.id);
      if (!session) {
        tab.available = false;
        inventory = inventory.filter((item) => item.sessionId !== tab.id);
        detach(tab, "This terminal is no longer available.", false, "danger");
        announce("A saved terminal is no longer available. Choose an existing terminal or start a new one.");
        showInventory();
        return;
      }
      tab.state = session.state;
      void connect(tab);
    }
    function presentation(tab) {
      tab.root.replaceChildren();
      tab.presentation = globalThis.CodewireTerminalPresentation.open(tab.root, styleNonce, {
        onResize: ({ cols, rows }) => { if (tab.socket && live(tab.state)) send(tab, tab.socket, { type: "resize", columns: cols, rows }); },
        copyButton: tab.copy, copyStatus: tab.copyStatus,
      });
      tab.input = tab.presentation.terminal.onData((data) => {
        if (tab.socket && live(tab.state)) queueInput(tab, tab.socket, data);
      });
      tab.presentation.terminal.options.disableStdin = true;
    }
    function dispose(tab) {
      if (renameTarget?.tab === tab) invalidateRename();
      detach(tab);
      tab.disposed = true;
      tab.renderEpoch += 1;
      tab.renderAbort.abort();
      tab.input.dispose();
      tab.presentation.dispose();
      tab.panel.remove();
      tab.item.remove();
      tab.status.remove();
      tab.actions.remove();
      tabs.delete(tab.id);
    }
    function clearPresentations() {
      invalidateRename();
      for (const tab of tabs.values()) dispose(tab);
      active = null;
      dialog.close();
      closeTarget = null;
      closeReturn = null;
    }
    function add(session) {
      if (tabs.has(session.sessionId) || tabs.size >= maxTabs) return tabs.get(session.sessionId);
      number += 1;
      // The template holds one tab's four parts: its tab, its output panel,
      // its status-bar group and its terminal-menu actions.
      const parts = template.content.cloneNode(true);
      const part = (name) => parts.querySelector(`[${name}]`);
      const item = part("data-terminal-tab-item");
      const button = part("data-terminal-tab");
      const panel = part("data-terminal-tab-panel");
      const status = part("data-terminal-session-status");
      const actions = part("data-terminal-tab-action-group");
      panel.id = `terminal-panel-${number}`;
      panel.dataset.terminalSessionId = session.sessionId;
      status.dataset.terminalSessionId = session.sessionId;
      let displayNumber = number;
      while ([...tabs.values()].some((tab) => tab.label === `Terminal ${displayNumber}`)) displayNumber += 1;
      const defaultLabel = `Terminal ${displayNumber}`;
      button.id = `terminal-tab-${number}`;
      button.setAttribute("aria-controls", panel.id);
      panel.setAttribute("aria-labelledby", button.id);
      tabList.append(item);
      panels.append(panel);
      statuses.append(status);
      tabActions.append(actions);
      const tab = { id: session.sessionId, state: session.state, item, button, panel, status, actions,
        label: defaultLabel, labelNode: button.querySelector("[data-terminal-tab-label]"),
        root: panel.querySelector("[data-terminal-root]"), connection: status.querySelector("[data-terminal-connection]"),
        connectionLabel: status.querySelector("[data-terminal-connection-label]"),
        historyGap: panel.querySelector("[data-terminal-history-gap]"),
        toggle: status.querySelector("[data-terminal-toggle]"), reset: actions.querySelector("[data-terminal-replay]"),
        copy: actions.querySelector("[data-terminal-copy]"), copyStatus: status.querySelector("[data-terminal-copy-status]"),
        close: item.querySelector("[data-terminal-close-session]"), remove: item.querySelector("[data-terminal-remove-tab]"),
        socket: null, attempt: 0, renderEpoch: 0, renderAbort: new AbortController(), renderFailed: false,
        rendered: 0n, received: 0n, pendingBytes: 0, pendingFrames: 0, writes: Promise.resolve(),
        sendQueue: [], queuedBytes: 0, sendTimer: null, stagedInput: null, inputTimer: null,
        retryTimer: null, stableTimer: null, failures: 0,
        wanted: true, available: true, disposed: false };
      label(tab, defaultLabel);
      status.hidden = true;
      actions.hidden = true;
      presentation(tab);
      tabs.set(tab.id, tab);
      button.addEventListener("click", () => choose(tab.id));
      button.addEventListener("dblclick", () => { if (tab.id === active) startRename(button); });
      tab.toggle.addEventListener("click", () => {
        // Disconnect is sticky until Reconnect. Reconnect acts immediately,
        // including while an automatic attempt is waiting or connecting.
        if ([WebSocket.OPEN, WebSocket.CLOSING].includes(tab.socket?.readyState)) { detach(tab); updateControls(); return; }
        tab.failures = 0;
        void refresh(tab.id);
      });
      tab.reset.addEventListener("click", async () => {
        detach(tab);
        tab.renderEpoch += 1;
        tab.renderAbort.abort();
        tab.renderAbort = new AbortController();
        tab.renderFailed = false;
        tab.historyGap.hidden = true;
        tab.input.dispose();
        tab.presentation.dispose();
        tab.rendered = 0n;
        tab.received = 0n;
        tab.pendingBytes = 0;
        tab.pendingFrames = 0;
        tab.writes = Promise.resolve();
        presentation(tab);
        await refresh(tab.id);
      });
      tab.close.addEventListener("click", () => {
        closeTarget = tab.id;
        closeReturn = closeReturn ?? tab.close;
        dialog.showModal();
        dialog.querySelector("[data-terminal-cancel-close]").focus();
      });
      tab.remove.addEventListener("click", () => {
        if (!authorized || pending || suspended || (tab.available && !ended(tab.state))) return;
        dispose(tab);
        if (!tabs.size) active = null;
        choose(tabs.keys().next().value, true);
        store();
        showInventory();
        announce("Tab removed from this browser. No terminal stop was requested.");
      });
      return tab;
    }
    function showInventory() {
      const placeholder = new Option("Choose an existing terminal", "");
      existing.replaceChildren(placeholder);
      for (const session of inventory) {
        if (!tabs.has(session.sessionId)) existing.add(new Option(`${session.sessionId.slice(-8)} · ${session.state}`, session.sessionId));
      }
      root.querySelector("[data-terminal-empty]").hidden = tabs.size > 0;
      updateControls();
    }
    async function request(action, sessionId) {
      const controller = new AbortController();
      requestController = controller;
      const timeout = setTimeout(() => controller.abort(), action === "list" ? 15000 : 90000);
      const base = `/${encodeURIComponent(slug)}/${environment}/`;
      const url = action === "list" ? `${base}_fragments/terminal-sessions` : `${base}_actions/terminal-sessions/${action}`;
      const options = { credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal };
      if (action !== "list") {
        options.method = "POST";
        options.body = new URLSearchParams({ _csrf: csrf, account_id: account });
        if (sessionId) options.body.set("session_id", sessionId);
      }
      try {
        const response = await fetch(url, options);
        const reader = response.body?.getReader();
        if (!reader) throw new Error("No session response");
        let text = "";
        let size = 0;
        const decoder = new TextDecoder("utf-8", { fatal: true });
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.length;
          if (size > 65536) { await reader.cancel(); throw new Error("Oversize session response"); }
          text += decoder.decode(part.value, { stream: true });
        }
        text += decoder.decode();
        const value = JSON.parse(text);
        if (!response.ok) {
          const error = new Error("Session request failed");
          error.reload = value?.error === "request-rejected";
          error.limit = value?.error === "session-limit";
          error.authorization = response.status === 401 || (response.status === 403 && !error.reload) || value?.error === "account-changed";
          throw error;
        }
        return action === "list" ? P.inventory(value) : P.session(value);
      } finally { clearTimeout(timeout); if (requestController === controller) requestController = null; }
    }
    async function refresh(reconnectId) {
      if (pending || suspended || document.hidden) return;
      foregroundCheck = false;
      const current = ++epoch;
      pending = true;
      authorized = false;
      invalidateRename();
      showSessions(false);
      for (const tab of tabs.values()) pauseForIdentity(tab);
      updateControls();
      announce("Refreshing terminal sessions…");
      try {
        const data = await request("list");
        if (current !== epoch || suspended || document.hidden || foregroundCheck) return;
        let previous;
        try { previous = sessionStorage.getItem(`${storagePrefix}account`); } catch { /* Optional storage. */ }
        if ((account && account !== data.accountId) || (previous && previous !== data.accountId)) {
          clearReferences();
          clearPresentations();
          reconnectId = null;
        }
        account = data.accountId;
        inventory = data.sessions;
        authorized = true;
        if (runtimeControlReady()) initialStatusReceived = true;
        uncertain = false;
        const available = new Map(inventory.map((session) => [session.sessionId, session]));
        let missing = false;
        if (!tabs.size) {
          const saved = references();
          const selected = saved ? saved.sessions : inventory.filter((session) => live(session.state)).slice(0, maxTabs).map((session) => session.sessionId);
          missing = selected.some((id) => !available.has(id));
          for (const id of selected) if (available.has(id)) {
            const tab = add(available.get(id));
            const savedLabel = saved?.labels.find((item) => item.sessionId === id);
            if (savedLabel) label(tab, savedLabel.label);
          }
          active = saved?.activeSessionId ?? null;
        }
        for (const tab of tabs.values()) {
          const session = available.get(tab.id);
          tab.available = !!session;
          if (session) tab.state = session.state;
          else { missing = true; detach(tab, "This terminal is no longer available.", false, "danger"); }
          if (tab.id === reconnectId && tab.available) tab.wanted = true;
        }
        showSessions(true);
        choose(tabs.has(active) ? active : tabs.keys().next().value);
        store();
        announce(missing ? "A saved terminal is no longer available. Choose an existing terminal or start a new one." : "");
        relist = false;
        for (const tab of tabs.values()) if (tab.available && tab.wanted) void connect(tab);
      } catch (error) {
        if (current !== epoch || suspended) return;
        if (error.authorization) { clearReferences(); clearPresentations(); account = null; }
        else for (const tab of tabs.values()) if (automatic(tab)) lose(tab, "Terminal sessions are unavailable.");
        announce(error.authorization ? "Sign in with access to this Sandbox, then refresh sessions." : "Terminal sessions are unavailable. Refresh sessions to try again.");
      } finally {
        if (current === epoch) {
          pending = false;
          showInventory();
          if (foregroundCheck && !document.hidden) void refresh();
        }
      }
    }
    async function mutate(action, id) {
      if (!authorized || pending || uncertain || needsReload || suspended
        || !(action === "stop" ? runtimeControlReady() : runtimeReady())) return;
      const current = epoch;
      pending = true;
      updateControls();
      announce(action === "launch" ? "Starting a terminal…" : "Closing terminal…");
      try {
        const session = await request(action, id);
        if (current !== epoch || suspended || document.hidden || foregroundCheck) return;
        if (action === "launch") {
          if (tabs.has(session.sessionId)) throw new Error("Unexpected session identity");
          inventory.push(session);
          const tab = add(session);
          choose(tab.id);
          void connect(tab);
        } else {
          if (session.sessionId !== id || !["stopped", "exited"].includes(session.state)) throw new Error("Uncertain stop");
          const tab = tabs.get(id);
          const focused = !!tab?.item.contains(document.activeElement);
          if (tab) dispose(tab);
          inventory = inventory.filter((item) => item.sessionId !== id);
          choose(tabs.keys().next().value, focused);
          if (!tabs.size) active = null;
        }
        announce("");
        store();
      } catch (error) {
        if (current !== epoch || suspended) return;
        if (error.authorization) {
          authorized = false;
          clearReferences();
          clearPresentations();
          account = null;
          announce("Your account or access changed. Refresh sessions before continuing.");
        } else if (error.reload) {
          needsReload = true;
          announce("Reload this page before changing terminals. The change was not retried.");
        } else if (error.limit) {
          announce("This Sandbox has reached its terminal session limit. Close a terminal you no longer need, then try again.");
        } else {
          uncertain = true;
          announce("The terminal change could not be confirmed. Refresh sessions to inspect the result before another change.");
        }
      } finally {
        if (current === epoch) {
          pending = false;
          showInventory();
          if (foregroundCheck && !document.hidden) void refresh();
          else if (relist && runtimeReady() && !document.hidden) void refresh();
        }
      }
    }
    newButton.addEventListener("click", () => { void mutate("launch"); });
    // Rename starts from the terminal menu, F2 or a double-click on the
    // selected tab; focus returns to whichever started it.
    function startRename(returnTo) {
      const tab = tabs.get(active);
      if (renameButton.disabled || !authorized || pending || uncertain || needsReload || suspended || !tab) return;
      renameTarget = { tab, account, epoch };
      renameOpener = tab;
      renameReturn = returnTo;
      renameInput.value = tab.label;
      renameInput.setCustomValidity("");
      renameDialog.showModal();
      renameInput.focus();
      renameInput.select();
    }
    renameButton.addEventListener("click", () => startRename(renameButton));
    refreshButton.addEventListener("click", () => { void refresh(); });
    existing.addEventListener("change", updateControls);
    existingForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!authorized || pending || uncertain || needsReload || !runtimeReady() || tabs.size >= maxTabs) return;
      const session = inventory.find((item) => item.sessionId === existing.value);
      if (!session) return;
      const tab = add(session);
      choose(tab.id);
      void connect(tab);
      showInventory();
    });
    dialog.querySelector("[data-terminal-cancel-close]").addEventListener("click", () => dialog.close());
    confirm.addEventListener("click", () => {
      const id = closeTarget;
      dialog.close();
      const tab = tabs.get(id);
      if (!tab) return;
      if (!tab.available || ended(tab.state)) {
        announce("This terminal is no longer live. Remove its tab to clear it from this browser.");
        return;
      }
      void mutate("stop", id);
    });
    dialog.addEventListener("close", () => {
      const tab = tabs.get(closeTarget);
      const target = closeReturn;
      closeTarget = null;
      closeReturn = null;
      if (tab && target?.isConnected) target.focus();
    });
    renameInput.addEventListener("input", () => renameInput.setCustomValidity(""));
    renameForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const target = renameTarget;
      if (!renameDialog.open || !target || !authorized || pending || uncertain || needsReload || suspended
        || target.account !== account || target.epoch !== epoch || tabs.get(target.tab.id) !== target.tab) {
        invalidateRename();
        return;
      }
      const name = renameInput.value.trim();
      if (!validLabel(name)) {
        renameInput.setCustomValidity("Enter a terminal name of 1–64 characters without control characters.");
        renameInput.reportValidity();
        return;
      }
      label(target.tab, name);
      store();
      clearRename();
      renameDialog.close();
      announce("Terminal renamed in this browser tab.");
    });
    renameDialog.addEventListener("close", () => {
      if (renameDialog.open) return; // A queued older close must not clear a new editor.
      const opener = renameOpener;
      const target = renameReturn;
      clearRename();
      renameOpener = null;
      renameReturn = null;
      if (!renameButton.disabled && opener && tabs.get(opener.id) === opener && target?.isConnected) target.focus();
    });
    tabList.addEventListener("keydown", (event) => {
      const tab = tabs.get(active);
      const focused = event.target instanceof Element && event.target.closest("[role='tab']") === tab?.button;
      if (event.key === "F2" && focused && !event.altKey && !event.ctrlKey && !event.metaKey) {
        event.preventDefault();
        startRename(tab.button);
        return;
      }
      // Delete closes the focused tab the way its close button does: a live
      // terminal asks first, an ended one is removed from this browser.
      if (event.key === "Delete" && focused && !event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
        event.preventDefault();
        if (!tab.close.hidden && !tab.close.disabled) {
          closeReturn = tab.button;
          tab.close.click();
        } else if (!tab.remove.hidden && !tab.remove.disabled) tab.remove.click();
        return;
      }
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const ids = [...tabs.keys()];
      if (!ids.length) return;
      event.preventDefault();
      const index = ids.indexOf(active);
      const next = event.key === "Home" ? 0 : event.key === "End" ? ids.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + ids.length) % ids.length;
      choose(ids[next], true);
    });
    // A narrower window or a rotated phone keeps the selected tab in view.
    const strip = tabList.closest("nav");
    if (strip && typeof ResizeObserver === "function") {
      new ResizeObserver(() => { if (tabs.has(active)) reveal(tabs.get(active)); }).observe(strip);
    }
    window.addEventListener("pagehide", () => {
      suspended = true;
      epoch += 1;
      requestController?.abort();
      pending = false;
      authorized = false;
      invalidateRename();
      showSessions(false);
      tabList.hidden = true;
      for (const tab of tabs.values()) detach(tab, "Disconnected", true);
      dialog.close();
    });
    window.addEventListener("pageshow", (event) => {
      if (!event.persisted) return;
      suspended = false;
      void refresh();
    });
    // An identity doubt pauses every terminal and hides output until a full
    // refresh re-reads the account, clearing this page's terminals if it
    // changed or access ended.
    function doubtAccount() {
      if (suspended) return;
      authorized = false;
      invalidateRename();
      showSessions(false);
      foregroundCheck = true;
      for (const tab of tabs.values()) pauseForIdentity(tab);
      updateControls();
      if (!document.hidden && !pending) void refresh();
    }
    // Returning to the page re-reads the account in the background, as a
    // desktop terminal keeps its windows: the terminals stay connected and on
    // screen, and only a changed account or ended access tears them down.
    async function checkAccount() {
      const current = epoch;
      let data;
      try { data = await request("list"); } catch (error) {
        if (current === epoch && !suspended && error.authorization) doubtAccount();
        return;
      }
      if (current !== epoch || suspended || pending || document.hidden) return;
      let previous;
      try { previous = sessionStorage.getItem(`${storagePrefix}account`); } catch { /* Optional storage. */ }
      if ((account && account !== data.accountId) || (previous && previous !== data.accountId)) {
        doubtAccount();
        return;
      }
      inventory = data.sessions;
      const available = new Map(inventory.map((session) => [session.sessionId, session]));
      for (const tab of tabs.values()) {
        const session = available.get(tab.id);
        if (!session) {
          if (tab.available) {
            detach(tab, "This terminal is no longer available.", false, "danger");
            announce("A saved terminal is no longer available. Choose an existing terminal or start a new one.");
          }
          tab.available = false;
          continue;
        }
        tab.state = session.state;
        // A reconnect paused while the page was hidden resumes now.
        if (automatic(tab) && !tab.socket && !tab.retryTimer) void connect(tab);
      }
      showInventory();
    }
    function foreground() {
      if (suspended || document.hidden) return;
      if (pending) { foregroundCheck = true; return; }
      void checkAccount();
    }
    document.addEventListener("visibilitychange", foreground);
    window.addEventListener("focus", foreground);
    document.addEventListener("codewire:sandbox-status", (event) => {
      const status = event.detail;
      if (!status || status.environmentId !== environment || typeof status.running !== "boolean"
        || typeof status.available !== "boolean" || typeof status.setupComplete !== "boolean") return;
      const wasReady = runtimeReady();
      runtimeAvailable = status.available;
      runtimeChecking = !status.available && status.checking === true;
      runtimeRunning = status.running;
      setupComplete = status.setupComplete;
      const ready = runtimeReady();
      root.dataset.terminalAvailable = String(runtimeAvailable);
      root.dataset.terminalRunning = String(runtimeRunning);
      for (const tab of tabs.values()) {
        // Readiness loss pauses the transport without withdrawing intent.
        if (!ready) detach(tab, readinessMessage(), true, readinessTone());
        else if (!wasReady && !tab.socket) {
          if (automatic(tab)) connectionText(tab, "Reconnecting…", "warning");
          else connectionText(tab, "Disconnected. Reconnect to resume this terminal.");
        }
      }
      root.querySelector("[data-terminal-empty]").textContent = !ready ? readinessMessage()
        : "Choose New terminal to start a shell. Leaving this page disconnects the browser; the shell keeps running until you close it or stop the Sandbox.";
      updateControls();
      if (ready && !initialStatusReceived && !pending && !suspended && !document.hidden) {
        initialStatusReceived = true;
        // Initial restoration must wait until setup stops owning workspace
        // replacement. Explicit Refresh/Stop remain available during setup.
        void refresh();
      } else if (ready && !wasReady && initialStatusReceived) {
        // The Sandbox may have restarted: re-list before re-attaching so ended
        // sessions become unavailable. Readiness never launches a shell.
        const waiting = [...tabs.values()].filter((tab) => automatic(tab) && !tab.socket);
        if (!waiting.length) return;
        if (!pending) void refresh();
        else {
          relist = true;
          for (const tab of waiting) scheduleReconnect(tab);
        }
      }
    });
    document.addEventListener("submit", (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || form.method.toLowerCase() !== "post") return;
      const action = new URL(event.submitter?.getAttribute("formaction") || form.action, location.href);
      if (action?.origin === location.origin && action.pathname === "/settings/_actions/sign-out") {
        epoch += 1;
        authorized = false;
        requestController?.abort();
        clearReferences();
        clearPresentations();
      }
    }, true);
    if (!P.organizationId(org) || !P.uuid.test(environment || "") || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug || "") || !csrf) {
      announce("Terminal settings are unavailable. Reload this page.");
      return;
    }
    // Until a Sandbox status arrives, the empty state explains the wait.
    announce("");
    root.querySelector("[data-terminal-empty]").textContent = readinessMessage();
    updateControls();
  }

  if (P && globalThis.CodewireTerminalPresentation) {
    for (const root of document.querySelectorAll("[data-durable-terminal]")) mount(root);
  }
})();
