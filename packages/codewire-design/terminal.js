(() => {
  "use strict";

  const MSG_STDIN = 0x00;
  const MSG_RESIZE = 0x01;
  const DEFAULT_COLS = 120;
  const DEFAULT_ROWS = 32;
  const styleNonce = document.currentScript?.nonce || "";
  let activeSession = null;

  function setStatus(root, message, tone) {
    let status = root.querySelector("[data-terminal-status]");
    if (!status) {
      status = document.createElement("p");
      status.className = "cw-terminal-status";
      status.dataset.terminalStatus = "";
      root.prepend(status);
    }
    status.textContent = message;
    status.dataset.tone = tone;
    status.hidden = message.length === 0;
  }

  function terminalUrl(root) {
    const origin = document.body.dataset.terminalWebsocketOrigin || "";
    const url = new URL(origin);
    if (!(["ws:", "wss:"].includes(url.protocol))) {
      throw new Error("Unsupported terminal endpoint protocol");
    }
    if (url.hostname !== window.location.hostname) {
      throw new Error("Terminal endpoint must use the dashboard hostname");
    }
    if (url.username || url.password || url.search || url.hash || !["", "/"].includes(url.pathname)) {
      throw new Error("Terminal endpoint must be an origin");
    }
    const orgId = root.dataset.terminalOrgId || "";
    const environmentId = root.dataset.terminalEnvironmentId || "";
    if (!orgId || !environmentId) throw new Error("Terminal target is missing");
    url.pathname = `/api/v1/organizations/${encodeURIComponent(orgId)}/environments/${encodeURIComponent(environmentId)}/terminal`;
    return url.toString();
  }

  function resizeFrame(cols, rows) {
    const frame = new Uint8Array(5);
    const safeCols = cols > 0 ? cols : DEFAULT_COLS;
    const safeRows = rows > 0 ? rows : DEFAULT_ROWS;
    frame[0] = MSG_RESIZE;
    frame[1] = (safeCols >> 8) & 0xff;
    frame[2] = safeCols & 0xff;
    frame[3] = (safeRows >> 8) & 0xff;
    frame[4] = safeRows & 0xff;
    return frame;
  }

  function openTerminal(root) {
    if (root.dataset.terminalRunning !== "true") {
      setStatus(root, "Environment is not running", "muted");
      return null;
    }
    if (!globalThis.CodewireTerminalPresentation) {
      setStatus(root, "Terminal assets could not be loaded", "danger");
      return null;
    }

    root.dataset.terminalSettled = "false";
    setStatus(root, "Connecting…", "muted");
    let socket;
    let presentation;
    try {
      presentation = globalThis.CodewireTerminalPresentation.open(root, styleNonce, {
        onResize: ({ cols, rows }) => {
          if (socket?.readyState === WebSocket.OPEN) socket.send(resizeFrame(cols, rows));
        },
      });
    } catch {
      root.dataset.terminalSettled = "true";
      setStatus(root, "Terminal rendering is unavailable. Reload the page or use the CLI terminal.", "danger");
      return null;
    }

    const { terminal, fit, fitAndResize } = presentation;
    let disposed = false;
    let settled = false;
    const settlementWaiters = [];
    const settle = () => {
      if (settled) return;
      settled = true;
      root.dataset.terminalSettled = "true";
      for (const resolve of settlementWaiters.splice(0)) resolve();
    };
    try {
      socket = new WebSocket(terminalUrl(root), ["terminal"]);
    } catch {
      setStatus(root, "Terminal endpoint is unavailable", "danger");
      settle();
      presentation.dispose();
      return null;
    }
    socket.binaryType = "arraybuffer";
    socket.addEventListener("open", () => {
      setStatus(root, "", "success");
      fitAndResize();
      requestAnimationFrame(fitAndResize);
    });
    socket.addEventListener("message", (event) => {
      if (event.data instanceof ArrayBuffer) terminal.write(new Uint8Array(event.data));
    });
    socket.addEventListener("error", () => {
      if (!disposed) setStatus(root, "Connection closed", "danger");
    });
    socket.addEventListener("close", () => {
      if (!disposed) setStatus(root, "Connection closed", "muted");
      settle();
    });

    const input = terminal.onData((data) => {
      if (socket.readyState !== WebSocket.OPEN) return;
      const encoded = new TextEncoder().encode(data);
      const frame = new Uint8Array(encoded.length + 1);
      frame[0] = MSG_STDIN;
      frame.set(encoded, 1);
      socket.send(frame);
    });
    return {
      root,
      terminal,
      fit,
      socket,
      async close() {
        if (disposed) return;
        if (!settled && socket.readyState !== WebSocket.CLOSED) {
          const settlement = new Promise((resolve) => settlementWaiters.push(resolve));
          if ([WebSocket.CONNECTING, WebSocket.OPEN].includes(socket.readyState)) {
            socket.close(1000, "terminal closed");
          }
          await settlement;
        } else {
          settle();
        }
        disposed = true;
        input.dispose();
        presentation.dispose();
      },
    };
  }

  async function closeActive() {
    const session = activeSession;
    activeSession = null;
    if (session) await session.close();
  }

  async function openDrawer(link) {
    const drawer = document.querySelector("[data-terminal-drawer]");
    const root = drawer?.querySelector("[data-terminal-root]");
    if (!drawer || !root) return;
    await closeActive();
    root.replaceChildren();
    root.dataset.terminalOrgId = link.dataset.terminalOrgId || "";
    root.dataset.terminalEnvironmentId = link.dataset.terminalEnvironmentId || "";
    root.dataset.terminalRunning = link.dataset.terminalEnvironmentState === "running" ? "true" : "false";
    const title = drawer.querySelector("[data-terminal-title]");
    const state = drawer.querySelector("[data-terminal-state]");
    const fullscreen = drawer.querySelector("[data-terminal-fullscreen]");
    if (title) title.textContent = link.dataset.terminalEnvironmentName || "Terminal";
    if (state) state.textContent = link.dataset.terminalEnvironmentState || "unknown";
    if (fullscreen) fullscreen.href = link.href;
    drawer.hidden = false;
    activeSession = openTerminal(root);
  }

  async function closeDrawer() {
    const drawer = document.querySelector("[data-terminal-drawer]");
    await closeActive();
    if (drawer) drawer.hidden = true;
  }

  document.addEventListener("click", (event) => {
    const open = event.target.closest?.("[data-terminal-open]");
    if (open && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.button === 0) {
      event.preventDefault();
      void openDrawer(open);
      return;
    }
    if (event.target.closest?.("[data-terminal-close]")) {
      event.preventDefault();
      void closeDrawer();
      return;
    }
    if (event.target.closest?.("[data-terminal-disconnect]")) {
      event.preventDefault();
      const root = document.querySelector(".cw-terminal-page [data-terminal-root]");
      void closeActive().then(() => {
        if (root) setStatus(root, "Disconnected", "muted");
      });
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !document.querySelector("[data-terminal-drawer]")?.hidden) {
      event.preventDefault();
      void closeDrawer();
    }
  });

  window.addEventListener("beforeunload", () => {
    activeSession?.socket.close(1000, "page closed");
  });

  const standalone = document.querySelector(".cw-terminal-page [data-terminal-root]");
  if (standalone) activeSession = openTerminal(standalone);
})();
