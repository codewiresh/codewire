(() => {
  "use strict";

  const P = globalThis.CodewireTerminalProtocol;
  const styleNonce = document.currentScript?.nonce || "";
  const storagePrefix = "codewire:terminal:v1:";
  const maxTabs = 8;
  const live = (state) => ["starting", "running"].includes(state);
  const ended = (state) => !["starting", "running", "stopping"].includes(state);

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
    const template = root.querySelector("[data-terminal-tab-template]");
    const newButton = root.querySelector("[data-terminal-new]");
    const refreshButton = root.querySelector("[data-terminal-refresh]");
    const message = root.querySelector("[data-terminal-message]");
    const existing = root.querySelector("[data-terminal-existing]");
    const existingForm = root.querySelector("[data-terminal-existing-form]");
    const dialog = root.querySelector("[data-terminal-close-dialog]");
    const confirm = dialog.querySelector("[data-terminal-confirm-close]");
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
    let requestController = null;
    let foregroundCheck = false;
    // Rendered lifecycle state is not fresh setup readiness. Wait for the
    // authenticated status controller before opening a transport or a shell.
    let runtimeAvailable = false;
    let runtimeRunning = false;
    let setupComplete = false;
    let initialStatusReceived = false;
    const runtimeControlReady = () => runtimeAvailable && runtimeRunning;
    const runtimeReady = () => runtimeControlReady() && setupComplete;
    const readinessMessage = () => !runtimeAvailable ? "Sandbox status is unavailable. Terminal controls are paused."
      : !runtimeRunning ? "Start this Sandbox to use its terminals."
        : "Sandbox setup is not complete. Terminal controls will be available when setup completes.";

    function announce(text) { message.textContent = text; }
    function storageKey() { return `${storagePrefix}${account}:${org}:${environment}`; }
    function store() {
      if (!authorized || !account) return;
      try {
        sessionStorage.setItem(`${storagePrefix}account`, account);
        sessionStorage.setItem(storageKey(), JSON.stringify({ version: 1, accountId: account,
          organizationId: org, environmentId: environment, sessions: [...tabs.keys()], activeSessionId: active }));
      } catch { /* An unavailable store does not prevent an explicit terminal. */ }
    }
    function references() {
      try {
        const raw = sessionStorage.getItem(storageKey());
        if (!raw || raw.length > 4096) return null;
        const value = JSON.parse(raw);
        if (!P.closed(value, ["version", "accountId", "organizationId", "environmentId", "sessions", "activeSessionId"])
          || value.version !== 1 || value.accountId !== account || value.organizationId !== org
          || value.environmentId !== environment || !Array.isArray(value.sessions) || value.sessions.length > maxTabs
          || value.sessions.some((id) => !P.sessionId(id)) || new Set(value.sessions).size !== value.sessions.length
          || (value.activeSessionId !== null && !value.sessions.includes(value.activeSessionId))) return null;
        return value;
      } catch { return null; }
    }
    function updateControls() {
      const controlBlocked = !authorized || pending || uncertain || needsReload || suspended || !runtimeControlReady();
      const blocked = controlBlocked || !setupComplete;
      root.querySelector("[data-terminal-reload]").hidden = !needsReload;
      newButton.disabled = blocked || tabs.size >= maxTabs;
      refreshButton.disabled = pending || suspended;
      existing.disabled = blocked || tabs.size >= maxTabs || existing.options.length <= 1;
      existingForm.querySelector("button").disabled = existing.disabled || !existing.value;
      for (const tab of tabs.values()) {
        tab.toggle.disabled = blocked || !tab.available || tab.renderFailed;
        tab.reset.disabled = blocked || !tab.available;
        const removable = !tab.available || ended(tab.state);
        tab.close.hidden = removable;
        tab.close.disabled = controlBlocked || removable;
        tab.remove.hidden = !removable;
        tab.remove.disabled = !authorized || pending || suspended;
        tab.presentation.terminal.options.disableStdin = blocked || tab.socket?.readyState !== WebSocket.OPEN || !live(tab.state);
      }
    }
    function choose(id, focus = false) {
      if (!tabs.has(id)) return;
      active = id;
      for (const tab of tabs.values()) {
        const selected = tab.id === id;
        tab.button.setAttribute("aria-selected", String(selected));
        tab.button.tabIndex = selected ? 0 : -1;
        tab.panel.hidden = !selected;
        if (selected) {
          tab.presentation.fitAndResize();
          if (focus) tab.button.focus();
        }
      }
      store();
    }
    function connectionText(tab, text) { tab.connection.textContent = text; }
    function finalAfterRender(tab, text) {
      const renderEpoch = tab.renderEpoch;
      const attempt = tab.attempt;
      void tab.writes.then(() => {
        if (!tab.disposed && !tab.renderFailed && renderEpoch === tab.renderEpoch && attempt === tab.attempt) {
          connectionText(tab, text);
          tab.root.dataset.terminalSettled = "true";
        }
      });
    }
    function discardInput(tab) {
      clearTimeout(tab.inputTimer);
      tab.inputTimer = null;
      tab.stagedInput = null;
    }
    function detach(tab, text = "Disconnected", keepWanted = false) {
      if (!keepWanted) tab.wanted = false;
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
      connectionText(tab, text);
    }
    function sendDeadline(tab) {
      return Math.min(tab.stagedInput?.deadline ?? Infinity, ...tab.sendQueue.map((frame) => frame.deadline));
    }
    function pauseInput(tab) {
      detach(tab, "Connection paused. Some input may not have arrived and will not be resent.");
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
        connectionText(tab, "Input is too large to send. Paste a smaller amount.");
        return false;
      }
      if (!reconcileSendQueue(tab, socket)) return false;
      const bytes = P.bytes(encoded);
      if (tab.queuedBytes + bytes + (tab.stagedInput?.bytes ?? 0) > P.limits.pendingInputBytes
        || tab.sendQueue.length + (tab.stagedInput ? 1 : 0) >= P.limits.pendingInputFrames) return pauseInput(tab);
      try { socket.send(encoded); } catch {
        detach(tab, "Connection closed. Input will not be resent.");
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
        connectionText(tab, "Input is too large to send. Paste a smaller amount.");
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
          detach(tab, "Output could not be rendered. Choose Replay recent output to recover.");
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
      if (!runtimeReady()) { detach(tab, readinessMessage()); return; }
      detach(tab, "Connecting…", true);
      tab.wanted = true;
      const attempt = tab.attempt;
      const identityEpoch = epoch;
      // Old write callbacks still advance this retained presentation. Complete
      // them before choosing the reconnect cursor; never ACK them on a new WS.
      let timer;
      const drained = await Promise.race([tab.writes.then(() => true), new Promise((resolve) => { timer = setTimeout(() => resolve(false), 5000); })]);
      clearTimeout(timer);
      if (tab.disposed || tab.renderFailed || suspended || document.hidden || !authorized || !runtimeReady() || epoch !== identityEpoch || attempt !== tab.attempt) return;
      if (!drained) { detach(tab, "Output is still rendering. Replay output before reconnecting."); return; }
      tab.received = tab.rendered;
      let socket;
      try { socket = new WebSocket(websocketUrl(tab), [P.protocol]); } catch {
        detach(tab, "The terminal connection is unavailable."); return;
      }
      tab.socket = socket;
      let finalStatus = false;
      let finalText;
      tab.root.dataset.terminalSettled = "false";
      socket.addEventListener("open", () => {
        if (tab.socket !== socket || suspended || !authorized) { socket.close(); return; }
        if (socket.protocol !== P.protocol) { detach(tab, "The terminal protocol is unavailable."); return; }
        tab.toggle.textContent = "Disconnect";
        connectionText(tab, live(tab.state) ? "Connected" : tab.state);
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
            const text = `${frame.state}${frame.exitCode === undefined ? "" : ` (${frame.exitCode})`}`;
            if (finalStatus) {
              finalText = text;
              finalAfterRender(tab, text);
            } else connectionText(tab, text);
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
        } catch { detach(tab, "Connection closed because terminal output could not be verified."); }
      });
      socket.addEventListener("error", () => {
        if (tab.socket === socket) detach(tab, "Connection closed. Reconnect to resume this terminal.");
      });
      socket.addEventListener("close", (event) => {
        if (tab.socket !== socket) return;
        if (finalStatus && event.code === 1000) {
          detach(tab, "Rendering terminal output…");
          finalAfterRender(tab, finalText);
        } else if (finalStatus) {
          detach(tab, "Connection closed before terminal output could be confirmed.");
        } else detach(tab, "Disconnected. Reconnect to resume this terminal.");
      });
    }
    function presentation(tab) {
      tab.root.replaceChildren();
      tab.presentation = globalThis.CodewireTerminalPresentation.open(tab.root, styleNonce, {
        onResize: ({ cols, rows }) => { if (tab.socket && live(tab.state)) send(tab, tab.socket, { type: "resize", columns: cols, rows }); },
      });
      tab.input = tab.presentation.terminal.onData((data) => {
        if (tab.socket && live(tab.state)) queueInput(tab, tab.socket, data);
      });
      tab.presentation.terminal.options.disableStdin = true;
    }
    function dispose(tab) {
      detach(tab);
      tab.disposed = true;
      tab.renderEpoch += 1;
      tab.renderAbort.abort();
      tab.input.dispose();
      tab.presentation.dispose();
      tab.panel.remove();
      tab.item.remove();
      tabs.delete(tab.id);
    }
    function clearPresentations() {
      for (const tab of tabs.values()) dispose(tab);
      active = null;
      dialog.close();
      closeTarget = null;
    }
    function add(session) {
      if (tabs.has(session.sessionId) || tabs.size >= maxTabs) return tabs.get(session.sessionId);
      number += 1;
      const panel = template.content.firstElementChild.cloneNode(true);
      panel.id = `terminal-panel-${number}`;
      panel.dataset.terminalSessionId = session.sessionId;
      panel.querySelector("h2").textContent = `Terminal ${number}`;
      const item = document.createElement("li");
      item.setAttribute("role", "presentation");
      const button = document.createElement("button");
      button.type = "button";
      button.id = `terminal-tab-${number}`;
      button.setAttribute("role", "tab");
      button.setAttribute("aria-controls", panel.id);
      button.textContent = `Terminal ${number}`;
      panel.setAttribute("aria-labelledby", button.id);
      item.append(button);
      tabList.append(item);
      panels.append(panel);
      const tab = { id: session.sessionId, state: session.state, item, button, panel,
        root: panel.querySelector("[data-terminal-root]"), connection: panel.querySelector("[data-terminal-connection]"),
        historyGap: panel.querySelector("[data-terminal-history-gap]"),
        toggle: panel.querySelector("[data-terminal-toggle]"), reset: panel.querySelector("[data-terminal-replay]"),
        close: panel.querySelector("[data-terminal-close-session]"), remove: panel.querySelector("[data-terminal-remove-tab]"),
        socket: null, attempt: 0, renderEpoch: 0, renderAbort: new AbortController(), renderFailed: false,
        rendered: 0n, received: 0n, pendingBytes: 0, pendingFrames: 0, writes: Promise.resolve(),
        sendQueue: [], queuedBytes: 0, sendTimer: null, stagedInput: null, inputTimer: null,
        wanted: true, available: true, disposed: false };
      presentation(tab);
      tabs.set(tab.id, tab);
      button.addEventListener("click", () => choose(tab.id));
      tab.toggle.addEventListener("click", () => {
        if (tab.socket) detach(tab);
        else void refresh(tab.id);
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
      panels.hidden = true;
      for (const tab of tabs.values()) detach(tab, "Checking account…", true);
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
          for (const id of selected) if (available.has(id)) add(available.get(id));
          active = saved?.activeSessionId ?? null;
        }
        for (const tab of tabs.values()) {
          const session = available.get(tab.id);
          tab.available = !!session;
          if (session) tab.state = session.state;
          else { missing = true; detach(tab, "This terminal is no longer available."); }
          if (tab.id === reconnectId && tab.available) tab.wanted = true;
        }
        panels.hidden = false;
        choose(tabs.has(active) ? active : tabs.keys().next().value);
        store();
        announce(missing ? "A saved terminal is no longer available. Choose an existing terminal or start a new one." : "");
        for (const tab of tabs.values()) if (tab.available && tab.wanted) void connect(tab);
      } catch (error) {
        if (current !== epoch || suspended) return;
        if (error.authorization) { clearReferences(); clearPresentations(); account = null; }
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
          if (tab) dispose(tab);
          inventory = inventory.filter((item) => item.sessionId !== id);
          choose(tabs.keys().next().value);
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
        } else {
          uncertain = true;
          announce("The terminal change could not be confirmed. Refresh sessions to inspect the result before another change.");
        }
      } finally {
        if (current === epoch) {
          pending = false;
          showInventory();
          if (foregroundCheck && !document.hidden) void refresh();
        }
      }
    }
    newButton.addEventListener("click", () => { void mutate("launch"); });
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
        announce("This terminal is no longer live. Use Remove tab to clear it from this browser.");
        return;
      }
      void mutate("stop", id);
    });
    dialog.addEventListener("close", () => { const tab = tabs.get(closeTarget); closeTarget = null; tab?.close.focus(); });
    tabList.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      const ids = [...tabs.keys()];
      if (!ids.length) return;
      event.preventDefault();
      const index = ids.indexOf(active);
      const next = event.key === "Home" ? 0 : event.key === "End" ? ids.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + ids.length) % ids.length;
      choose(ids[next], true);
    });
    window.addEventListener("pagehide", () => {
      suspended = true;
      epoch += 1;
      requestController?.abort();
      pending = false;
      authorized = false;
      panels.hidden = true;
      for (const tab of tabs.values()) detach(tab, "Disconnected", true);
      dialog.close();
    });
    window.addEventListener("pageshow", (event) => {
      if (!event.persisted) return;
      suspended = false;
      void refresh();
    });
    function foreground() {
      if (suspended) return;
      authorized = false;
      panels.hidden = true;
      foregroundCheck = true;
      for (const tab of tabs.values()) detach(tab, "Checking account…", true);
      updateControls();
      if (!document.hidden && !pending) void refresh();
    }
    document.addEventListener("visibilitychange", foreground);
    window.addEventListener("focus", foreground);
    document.addEventListener("codewire:sandbox-status", (event) => {
      const status = event.detail;
      if (!status || status.environmentId !== environment || typeof status.running !== "boolean"
        || typeof status.available !== "boolean" || typeof status.setupComplete !== "boolean") return;
      const wasReady = runtimeReady();
      runtimeAvailable = status.available;
      runtimeRunning = status.running;
      setupComplete = status.setupComplete;
      root.dataset.terminalAvailable = String(runtimeAvailable);
      root.dataset.terminalRunning = String(runtimeRunning);
      for (const tab of tabs.values()) {
        if (!runtimeReady()) detach(tab, readinessMessage());
        else if (!wasReady && !tab.socket) connectionText(tab, "Disconnected. Reconnect to resume this terminal.");
      }
      root.querySelector("[data-terminal-empty]").textContent = !runtimeReady() ? readinessMessage()
        : "Choose New terminal to start a shell. Leaving this page disconnects the browser; the shell keeps running until you close it or stop the Sandbox.";
      updateControls();
      if (runtimeControlReady() && !initialStatusReceived && !pending && !suspended && !document.hidden) {
        initialStatusReceived = true;
        // Restore references only after the first fresh status. Later readiness
        // transitions require explicit Reconnect; they must never start shells.
        void refresh();
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
    if (!P.uuid.test(org || "") || !P.uuid.test(environment || "") || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug || "") || !csrf) {
      announce("Terminal settings are unavailable. Reload this page.");
      return;
    }
    announce("Checking Sandbox status before restoring terminals…");
    updateControls();
  }

  if (P && globalThis.CodewireTerminalPresentation) {
    for (const root of document.querySelectorAll("[data-durable-terminal]")) mount(root);
  }
})();
