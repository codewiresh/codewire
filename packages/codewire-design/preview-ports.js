(() => {
  document.addEventListener("click", async (event) => {
    const button = event.target instanceof Element && event.target.closest("[data-copy-preview]");
    if (!(button instanceof HTMLButtonElement) || button.disabled || button.getAttribute("aria-disabled") === "true") return;
    const row = button.closest(".cw-port-row");
    const link = row?.querySelector(".cw-port-preview-url");
    const status = row?.querySelector("[data-preview-copy-status]");
    if (!(link instanceof HTMLAnchorElement) || !status) return;
    const url = link.getAttribute("href");
    if (!url || !url.startsWith("https://")) return;
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return;
    }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash) return;
    // aria-disabled, not disabled: a disabled button drops keyboard focus (#4533).
    button.setAttribute("aria-disabled", "true");
    try {
      await navigator.clipboard.writeText(url);
      if (row.isConnected) status.textContent = "Preview URL copied.";
    } catch {
      if (row.isConnected) status.textContent = "Could not copy. Select and copy the preview URL above.";
    } finally {
      button.removeAttribute("aria-disabled");
    }
  });
})();
