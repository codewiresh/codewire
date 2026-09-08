(() => {
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
