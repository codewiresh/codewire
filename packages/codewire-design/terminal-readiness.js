(() => {
  "use strict";
  const P = globalThis.CodewireTerminalProtocol;

  function mount(root) {
    const environmentId = root.dataset.terminalEnvironmentId;
    const slug = root.dataset.terminalOrgSlug;
    if (!P.uuid.test(environmentId || "") || !/^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug || "") || slug.length < 3 || slug.length > 48) return;
    const url = `/${encodeURIComponent(slug)}/${environmentId}/_fragments/terminal-readiness`;
    const button = root.querySelector("[data-terminal-readiness-refresh]");
    let epoch = 0;
    let pending = null;
    let timer = null;
    let paused = document.hidden;
    let lastRequest = -Infinity;
    const report = (available, value) => document.dispatchEvent(new CustomEvent("codewire:sandbox-status", {
      detail: { environmentId, available, running: value?.running === true,
        setupComplete: value?.setupComplete === true },
    }));
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
        if (!P.closed(value, ["environmentId", "running", "setupComplete"])
          || value.environmentId !== environmentId || typeof value.running !== "boolean"
          || typeof value.setupComplete !== "boolean") throw new Error("Invalid readiness");
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
      if (event.persisted) { paused = document.hidden; void refresh(); }
    });
    window.addEventListener("focus", () => {
      if (!paused && Date.now() - lastRequest >= 1000) void refresh();
    });
    controls();
    void refresh();
  }
  document.querySelectorAll("[data-terminal-readiness]").forEach(mount);
})();
