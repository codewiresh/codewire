(() => {
  // A successfully created personal key is only a one-time response. Clear
  // that exact presentation before a document can be retained by BFCache.
  // Ordinary inventories and public invitation/copy values are unaffected.
  window.addEventListener("pagehide", () => {
    document.querySelectorAll("[data-one-time-api-key]").forEach((value) => {
      value.textContent = "Key hidden. Return to API keys to view its metadata.";
      const copy = value.closest("[data-api-key-reveal]")?.querySelector("[data-copy-api-key]");
      if (copy instanceof HTMLButtonElement) copy.disabled = true;
    });
  });
  document.addEventListener("click", async (event) => {
    if (!(event.target instanceof Element)) return;
    const button = event.target.closest("[data-copy-api-key], [data-copy-public-value]");
    if (!button) return;
    const target = button.getAttribute("data-copy-target");
    const value = target
      ? document.getElementById(target)?.textContent?.trim()
      : button
          .closest("[data-api-key-reveal]")
          ?.querySelector('[data-secret-kind="api-key"]')
          ?.textContent?.trim();
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "Copied";
    } catch {
      button.textContent = button.hasAttribute("data-copy-api-key")
        ? "Select and copy the key"
        : "Select and copy";
    }
  });
})();
