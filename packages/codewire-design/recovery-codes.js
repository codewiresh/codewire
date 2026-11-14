// Copy codes on the recovery codes page (#4558): every code, one per line, in
// the order shown. The button says it worked for a moment; where the clipboard
// is unavailable or refused, the codes are selected so the keyboard can copy
// them, and the status line says so. Without this script the button stays
// hidden and the codes are shown as before.
(() => {
  "use strict";
  const button = document.querySelector("[data-copy-codes]");
  const list = document.querySelector("[data-recovery-codes]");
  const status = document.querySelector("[data-copy-codes-status]");
  if (!(button instanceof HTMLButtonElement) || !list) return;
  const label = button.querySelector("span");
  const use = button.querySelector("use");
  const icon = (name) => use?.setAttribute("href", use.getAttribute("href").replace(/#icon-[a-z-]+$/, `#icon-${name}`));
  const say = (text) => { if (status) status.textContent = text; };
  let timer = 0;
  button.hidden = false;
  button.addEventListener("click", async () => {
    const codes = Array.from(list.querySelectorAll("code"), (code) => code.textContent.trim()).filter(Boolean);
    if (codes.length === 0) return;
    window.clearTimeout(timer);
    try {
      if (!navigator.clipboard || !window.isSecureContext) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(codes.join("\n"));
    } catch {
      const range = document.createRange();
      range.selectNodeContents(list);
      window.getSelection()?.removeAllRanges();
      window.getSelection()?.addRange(range);
      say("Copying was blocked, so the codes are selected. Press Ctrl+C, or ⌘C on a Mac, to copy them.");
      return;
    }
    if (label) label.textContent = "Copied";
    icon("check");
    say("Recovery codes copied, one per line.");
    timer = window.setTimeout(() => {
      if (label) label.textContent = "Copy codes";
      icon("copy");
    }, 1600);
  });
})();
