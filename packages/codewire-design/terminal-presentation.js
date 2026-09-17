(() => {
  "use strict";

  function open(root, styleNonce, { onResize } = {}) {
    if (onResize !== undefined && typeof onResize !== "function") {
      throw new TypeError("Terminal onResize must be a function");
    }
    if (!globalThis.CodewireTerminalRenderer?.open || !globalThis.FitAddon?.FitAddon
      || !globalThis.WebLinksAddon?.WebLinksAddon) {
      throw new Error("Terminal presentation assets are unavailable");
    }

    const document = root.ownerDocument;
    const view = document.defaultView;
    const section = root.closest("[data-terminal-tab-panel]") || root.closest(".cw-sandbox-terminal");
    const copyButton = section?.querySelector("[data-terminal-copy]");
    const feedback = section?.querySelector("[data-terminal-copy-status]");
    const fontFamily = view.getComputedStyle(root).getPropertyValue("--font-mono").trim() || "monospace";
    const fit = new globalThis.FitAddon.FitAddon();
    const terminal = globalThis.CodewireTerminalRenderer.open(root, {
      cursorBlink: true,
      fontSize: 13,
      fontFamily,
      fontWeight: 400,
      fontWeightBold: 600,
      theme: {
        background: "#0a0a0a",
        foreground: "#e4e4e7",
        cursor: "#e4e4e7",
        selectionBackground: "#3f3f46",
      },
    }, styleNonce, (instance) => {
      instance.loadAddon(fit);
      instance.loadAddon(new globalThis.WebLinksAddon.WebLinksAddon());
    });

    let disposed = false;
    let fontReady = false;
    let fitting = false;
    let pendingFit = null;
    let copyRevision = 0;

    const copyFeedback = (message) => {
      if (!disposed && feedback) feedback.textContent = message;
    };
    const copySelection = async () => {
      if (disposed) return;
      const revision = ++copyRevision;
      const selection = terminal.getSelection();
      if (!selection) {
        copyFeedback("Select terminal output to copy.");
        return;
      }
      try {
        // Copy only follows the user's explicit button/shortcut action. Never
        // read the clipboard or persist terminal output in browser storage.
        await view.navigator.clipboard.writeText(selection);
        if (revision === copyRevision) copyFeedback("Selection copied.");
      } catch {
        if (revision === copyRevision) {
          copyFeedback("Clipboard access was denied. Use your browser’s Copy command on the selection.");
        }
      }
    };
    const copyClick = (event) => {
      event.preventDefault();
      void copySelection();
    };
    const mac = /Mac|iPhone|iPad/.test(view.navigator.platform);
    if (copyButton) {
      copyButton.disabled = !terminal.hasSelection();
      copyButton.title = mac ? "Copy selection (⌘C)" : "Copy selection (Ctrl+Shift+C)";
      copyButton.setAttribute("aria-keyshortcuts", mac ? "Meta+C" : "Control+Shift+C");
      copyButton.addEventListener("click", copyClick);
    }
    copyFeedback("");
    const selectionSubscription = terminal.onSelectionChange(() => {
      copyRevision += 1;
      if (copyButton) copyButton.disabled = !terminal.hasSelection();
      copyFeedback("");
    });
    terminal.attachCustomKeyEventHandler((event) => {
      const copyShortcut = event.key.toLowerCase() === "c" && !event.altKey
        && (mac ? event.metaKey && !event.ctrlKey && !event.shiftKey
          : event.ctrlKey && event.shiftKey && !event.metaKey);
      if (!copyShortcut || disposed) return true;
      if (event.type === "keydown") void copySelection();
      event.preventDefault();
      return false;
    });

    const resizeSubscription = terminal.onResize((size) => {
      if (!disposed && !fitting) onResize?.(size);
    });
    const fitAndResize = () => {
      if (disposed || !fontReady || !root.isConnected) return;
      const bounds = root.getBoundingClientRect();
      if (bounds.width <= 0 || bounds.height <= 0) return;
      fitting = true;
      try {
        fit.fit();
      } finally {
        fitting = false;
      }
      // A caller may need the current size when its transport opens, even when
      // the fit did not change dimensions. Suppress only the duplicate event
      // emitted by xterm during this fit, not subsequent external resizes.
      onResize?.({ cols: terminal.cols, rows: terminal.rows });
    };
    const scheduleFit = () => {
      if (disposed || pendingFit !== null) return;
      pendingFit = view.requestAnimationFrame(() => {
        pendingFit = null;
        fitAndResize();
      });
    };
    const observer = new view.ResizeObserver(scheduleFit);
    observer.observe(root);

    // fonts.ready can resolve before xterm first requests its face. Load both
    // shipped weights explicitly, then fit against their settled metrics.
    void Promise.all([
      document.fonts.load(`400 13px ${fontFamily}`),
      document.fonts.load(`600 13px ${fontFamily}`),
    ]).catch(() => {
      if (disposed) return;
      terminal.options.fontFamily = "monospace";
      copyFeedback("The terminal font could not be loaded; using a system monospace font.");
    }).then(() => {
      if (disposed) return;
      fontReady = true;
      scheduleFit();
    });

    const dispose = () => {
      if (disposed) return;
      disposed = true;
      copyRevision += 1;
      observer.disconnect();
      if (pendingFit !== null) view.cancelAnimationFrame(pendingFit);
      selectionSubscription.dispose();
      resizeSubscription.dispose();
      if (copyButton) {
        copyButton.removeEventListener("click", copyClick);
        copyButton.disabled = true;
      }
      if (feedback) feedback.textContent = "";
      terminal.dispose();
    };

    return { terminal, fit, fitAndResize, dispose, copySelection };
  }

  globalThis.CodewireTerminalPresentation = Object.freeze({ open });
})();
