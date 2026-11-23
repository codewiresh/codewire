(() => {
  "use strict";

  // The Desktop panel (docs/dev/SANDBOX-DESKTOP.md, "The dashboard viewer"):
  // Start, Stop and the vendored noVNC viewer on orchestration's desktop
  // stream. It reads the desktop's state when the page loads, after its own
  // Start and Stop, and after a stream closes; it polls nothing. The
  // clipboard moves only on the two buttons.
  const protocol = "codewire.desktop-stream.v1";
  const drainRetryMs = 2000;
  const messages = {
    loading: "Checking the desktop…",
    unavailable: "This Sandbox's image has no desktop. Create the Sandbox again to use one.",
    stopped: "The desktop is not running.",
    starting: "Starting the desktop…",
    stopping: "Stopping the desktop…",
    connecting: "Connecting to the desktop…",
    connected: "",
    lost: "The connection to the desktop was lost.",
    ended: "The desktop ended.",
    refused: "The desktop could not start. Check that the Sandbox is running.",
    unknown: "The desktop's state is unknown. Reload this page to check it.",
    sandbox: "Start the Sandbox to use its desktop.",
    noClipboard: "This browser did not allow the clipboard.",
    copied: "Copied from the desktop.",
    pasted: "Pasted to the desktop.",
  };

  function boot(panel) {
    const document = panel.ownerDocument;
    const body = document.body;
    const slug = panel.dataset.desktopOrgSlug;
    const orgId = panel.dataset.desktopOrgId;
    const environmentId = panel.dataset.desktopEnvironmentId;
    const csrf = document.querySelector('input[name="_csrf"]')?.value || "";
    const status = panel.querySelector("[data-desktop-status]");
    const note = panel.querySelector("[data-desktop-note]");
    const screen = panel.querySelector("[data-desktop-screen]");
    const buttons = {
      start: panel.querySelector("[data-desktop-start]"),
      stop: panel.querySelector("[data-desktop-stop]"),
      reconnect: panel.querySelector("[data-desktop-reconnect]"),
      paste: panel.querySelector("[data-desktop-paste]"),
      copy: panel.querySelector("[data-desktop-copy]"),
      release: panel.querySelector("[data-desktop-release]"),
    };
    let accountId = "";
    let password = "";
    let rfb = null;
    let desktopText = "";
    let busy = false;
    let retry = null;

    const base = `/${encodeURIComponent(slug)}/${encodeURIComponent(environmentId)}`;
    const visible = () => !panel.hidden && document.visibilityState === "visible";
    // As the page rendered it, then as the Sandbox's readiness reports it.
    let sandboxRunning = panel.dataset.desktopSandboxRunning === "true";

    function enable() {
      for (const button of [buttons.start, buttons.stop, buttons.reconnect]) button.disabled = busy;
      buttons.copy.disabled = busy || desktopText === "";
    }

    function show(state, text = messages[state] ?? "") {
      panel.dataset.desktopState = state;
      status.textContent = text;
      status.hidden = text === "";
      const connected = state === "connected";
      buttons.start.hidden = !["stopped", "ended"].includes(state);
      buttons.stop.hidden = !["connecting", "connected", "lost"].includes(state);
      buttons.reconnect.hidden = state !== "lost";
      buttons.paste.hidden = !connected;
      buttons.copy.hidden = !connected;
      buttons.release.hidden = !connected;
      screen.hidden = !["connecting", "connected"].includes(state);
      enable();
    }

    function say(text) {
      note.textContent = text;
      note.hidden = text === "";
    }

    async function call(path, method) {
      const init = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
      if (method === "POST") {
        init.headers["Content-Type"] = "application/x-www-form-urlencoded";
        init.body = new URLSearchParams({ _csrf: csrf, account_id: accountId }).toString();
      }
      const response = await fetch(`${base}${path}`, init);
      const value = await response.json().catch(() => ({}));
      if (!response.ok) throw Object.assign(new Error(value.error || "desktop-unavailable"), { code: value.error });
      if (typeof value.accountId !== "string" || typeof value.state !== "string") throw new Error("desktop-unavailable");
      return value;
    }

    // What an answer from the desktop service means for the panel.
    function apply(value) {
      accountId = value.accountId;
      // An answer that arrives after the Sandbox stopped is not shown over it.
      if (!sandboxRunning) {
        password = "";
        return show("sandbox");
      }
      password = value.state === "running" && typeof value.password === "string" ? value.password : "";
      if (value.state === "running") {
        if (visible()) connect();
        else show("connecting", "");
      } else {
        disconnect();
        show(value.state);
      }
    }

    async function read() {
      if (!sandboxRunning) return show("sandbox");
      try {
        apply(await call("/_fragments/desktop", "GET"));
      } catch {
        show("unknown");
      }
    }

    async function act(path, pending) {
      busy = true;
      show(pending);
      try {
        apply(await call(path, "POST"));
      } catch (error) {
        show(error.code === "desktop-refused" ? "refused" : "unknown");
      } finally {
        busy = false;
        enable();
      }
    }

    function viewerReady() {
      if (globalThis.CodewireNoVNC?.RFB) return Promise.resolve(globalThis.CodewireNoVNC.RFB);
      return new Promise((resolve) => globalThis.addEventListener(
        "codewire:novnc-ready", () => resolve(globalThis.CodewireNoVNC.RFB), { once: true }));
    }

    function streamUrl() {
      const origin = new URL(body.dataset.terminalWebsocketOrigin || location.origin.replace(/^http/, "ws"));
      if (!["ws:", "wss:"].includes(origin.protocol) || origin.hostname !== location.hostname
          || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash) {
        throw new Error("invalid desktop stream origin");
      }
      const url = new URL(
        `/api/v1/organizations/${encodeURIComponent(orgId)}/environments/${encodeURIComponent(environmentId)}/desktop-stream`,
        origin);
      url.searchParams.set("account_id", accountId);
      return url.toString();
    }

    async function connect() {
      if (rfb || !password) return;
      clearTimeout(retry);
      show("connecting");
      const RFB = await viewerReady();
      // The Sandbox may have stopped, or Stop been pressed, while the viewer loaded.
      if (rfb || !password || !sandboxRunning || !visible()) return;
      let socket;
      try {
        socket = new WebSocket(streamUrl(), protocol);
      } catch {
        return show("unknown");
      }
      socket.binaryType = "arraybuffer";
      let closed = null;
      socket.addEventListener("close", (event) => { closed = event; });
      let viewer;
      try {
        viewer = new RFB(screen, socket, { credentials: { password } });
      } catch {
        // A viewer that refuses its socket would leave it open and the panel
        // connecting; close it and say the state is unknown.
        socket.close();
        return show("unknown");
      }
      viewer.scaleViewport = true;
      viewer.focusOnClick = true;
      viewer.addEventListener("connect", () => {
        if (rfb === viewer) show("connected");
      });
      viewer.addEventListener("clipboard", (event) => {
        desktopText = typeof event.detail?.text === "string" ? event.detail.text : "";
        enable();
      });
      viewer.addEventListener("disconnect", () => {
        if (rfb !== viewer) return;
        rfb = null;
        ended(closed);
      });
      rfb = viewer;
    }

    function disconnect() {
      const viewer = rfb;
      rfb = null;
      viewer?.disconnect();
    }

    // A stream that closed: the server's reason, then the desktop's state.
    async function ended(event) {
      if (event?.code === 1012) {
        show("connecting");
        retry = setTimeout(() => read(), drainRetryMs);
        return;
      }
      const reason = event?.reason || "";
      try {
        const value = await call("/_fragments/desktop", "GET");
        accountId = value.accountId;
        password = value.state === "running" ? value.password || "" : "";
        if (value.state === "running") show("lost", reason ? `${reason[0].toUpperCase()}${reason.slice(1)}.` : messages.lost);
        else show(value.state === "stopped" ? "ended" : value.state);
      } catch {
        // A Sandbox that stopped under the stream is refused here; its status
        // may already have said so.
        show(sandboxRunning ? "unknown" : "sandbox");
      }
    }

    buttons.start.addEventListener("click", () => act("/_actions/desktop/start", "starting"));
    buttons.stop.addEventListener("click", () => {
      disconnect();
      act("/_actions/desktop/stop", "stopping");
    });
    buttons.reconnect.addEventListener("click", () => read());
    buttons.release.addEventListener("click", () => {
      rfb?.blur();
      buttons.release.focus();
    });
    buttons.copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(desktopText);
        say(messages.copied);
      } catch {
        say(messages.noClipboard);
      }
    });
    buttons.paste.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        rfb?.clipboardPasteFrom(text);
        say(messages.pasted);
      } catch {
        say(messages.noClipboard);
      }
    });
    // Readiness pauses the viewer as it pauses the terminals: a Sandbox that
    // stops ends the stream, and one that runs again reads its desktop. An
    // unknown status changes nothing.
    document.addEventListener("codewire:sandbox-status", (event) => {
      const status = event.detail;
      if (!status || status.environmentId !== environmentId || status.available !== true
        || typeof status.running !== "boolean" || status.running === sandboxRunning) return;
      sandboxRunning = status.running;
      if (sandboxRunning) return read();
      clearTimeout(retry);
      password = "";
      disconnect();
      show("sandbox");
    });
    // A tab shown again connects to a desktop that runs: a Start or a retry
    // answered while the tab was hidden left no stream.
    document.addEventListener("visibilitychange", () => {
      if (visible() && password && !rfb) connect();
    });
    // Shown again: connect to a desktop that runs. Hidden: let the stream go,
    // so a hidden panel holds none of the desktop's viewer places.
    const shown = new MutationObserver(() => {
      if (panel.hidden) {
        disconnect();
        if (password) show("connecting", "");
      } else if (password && !rfb) {
        connect();
      }
    });
    shown.observe(panel, { attributes: true, attributeFilter: ["hidden"] });

    show("loading");
    read();
  }

  // The workspace shows its terminals or its desktop. The terminal's own
  // `hidden` belongs to its readiness check (a Sandbox being deleted), so the
  // view is marked on the workspace and the stylesheet hides the terminal.
  function switcher(control) {
    const workspace = document.querySelector(".cw-workspace-main");
    const desktop = document.querySelector("[data-desktop-panel]");
    const buttons = control.querySelectorAll("[data-workspace-view]");
    for (const button of buttons) {
      button.addEventListener("click", () => {
        const view = button.dataset.workspaceView;
        for (const other of buttons) other.setAttribute("aria-pressed", String(other === button));
        if (workspace) workspace.dataset.workspaceShowing = view;
        if (desktop) desktop.hidden = view !== "desktop";
      });
    }
  }

  for (const panel of document.querySelectorAll("[data-desktop-panel]")) boot(panel);
  for (const control of document.querySelectorAll("[data-workspace-views]")) switcher(control);
})();
