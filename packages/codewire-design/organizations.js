(() => {
  document.addEventListener("click", async (event) => {
    if (!(event.target instanceof Element)) return;
    const button = event.target.closest("[data-copy-api-key]");
    if (!button) return;
    const secret = button
      .closest("[data-api-key-reveal]")
      ?.querySelector('[data-secret-kind="api-key"]')
      ?.textContent?.trim();
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Select and copy the key";
    }
  });
})();
