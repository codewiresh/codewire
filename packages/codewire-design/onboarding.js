(function () {
  "use strict";

  // Step 1: auto-populate organization slug from name until the user edits it.
  const nameInput = document.querySelector("[data-onboarding-org-name]");
  const slugInput = document.querySelector("[data-onboarding-org-slug]");
  if (nameInput && slugInput) {
    let manualSlug = slugInput.value.trim().length > 0 && nameInput.value.trim().length > 0;
    slugInput.addEventListener("input", () => {
      manualSlug = slugInput.value.trim().length > 0;
    });
    nameInput.addEventListener("input", () => {
      if (manualSlug) return;
      slugInput.value = nameInput.value
        .toLowerCase()
        .trim()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 48);
    });
  }

  // Step 3: reveal/hide masked TOTP setup key and copy with green check feedback.
  const secretEl = document.querySelector("[data-totp-secret-display]");
  const eyeBtn = document.querySelector("[data-totp-eye]");
  const copyBtn = document.querySelector("[data-totp-copy]");
  const codeInput = document.querySelector("[data-totp-code]");
  const submitBtn = document.querySelector("[data-totp-submit]");

  if (codeInput && submitBtn) {
    const syncSubmit = () => {
      submitBtn.disabled = codeInput.value.trim().length < 6;
    };
    codeInput.addEventListener("input", syncSubmit);
    syncSubmit();
  }

  if (secretEl && eyeBtn) {
    const maskedText = secretEl.dataset.maskedText || "";
    const fullText = secretEl.dataset.fullText || "";
    const iconsHref = eyeBtn.dataset.iconsHref || "/assets/codewire/icons-v2.svg";
    eyeBtn.addEventListener("click", () => {
      const revealing = secretEl.dataset.masked !== "false";
      secretEl.dataset.masked = revealing ? "false" : "true";
      secretEl.textContent = revealing ? fullText : maskedText;
      eyeBtn.setAttribute("aria-pressed", String(revealing));
      eyeBtn.setAttribute("aria-label", revealing ? "Hide setup key" : "Show setup key");
      const use = eyeBtn.querySelector("use");
      if (use) {
        use.setAttribute("href", `${iconsHref}#${revealing ? "icon-eye-off" : "icon-eye"}`);
      }
    });
  }

  if (secretEl && copyBtn) {
    let resetTimer = null;
    const rawSecret = secretEl.dataset.rawSecret || "";
    const iconsHref = copyBtn.dataset.iconsHref || "/assets/codewire/icons-v2.svg";
    copyBtn.addEventListener("click", () => {
      if (navigator.clipboard && rawSecret) {
        navigator.clipboard.writeText(rawSecret).catch(() => {});
      }
      copyBtn.setAttribute("aria-label", "Copied");
      copyBtn.classList.add("cw-onboarding-copy-done");
      const use = copyBtn.querySelector("use");
      if (use) {
        use.setAttribute("href", `${iconsHref}#icon-check`);
      }
      if (resetTimer) window.clearTimeout(resetTimer);
      resetTimer = window.setTimeout(() => {
        copyBtn.setAttribute("aria-label", "Copy setup key");
        copyBtn.classList.remove("cw-onboarding-copy-done");
        if (use) {
          use.setAttribute("href", `${iconsHref}#icon-copy`);
        }
      }, 1800);
    });
  }
})();
