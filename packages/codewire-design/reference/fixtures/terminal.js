(() => {
  "use strict";
  const root = document.querySelector("[data-terminal-root]");
  const presentation = CodewireTerminalPresentation.open(root, document.currentScript.nonce);
  presentation.terminal.options.disableStdin = true;
  root.querySelector("[data-terminal-status]").hidden = true;
  presentation.terminal.write([
    "Codewire · terminal preview",
    "",
    "\x1b[31mANSI red\x1b[0m  \x1b[38;5;196m256 red\x1b[0m  \x1b[38;2;12;160;240mRGB blue\x1b[0m",
    "\x1b[48;5;196m256 background\x1b[0m  \x1b[48;2;12;160;240mRGB background\x1b[0m",
    "\x1b[1mBold\x1b[0m  \x1b[3mItalic\x1b[0m  \x1b[4mUnderline\x1b[0m",
    "",
    "codewire-terminal-copy-234",
    "",
    "Select output, then choose Copy selection.",
    "Keyboard: Ctrl+Shift+C on Linux/Windows; ⌘C on macOS.",
  ].join("\r\n"));
  window.addEventListener("pagehide", () => presentation.dispose(), { once: true });
})();
