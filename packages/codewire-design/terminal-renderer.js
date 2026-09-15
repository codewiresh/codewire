(() => {
  "use strict";

  const failureMessage = "Terminal rendering is unavailable. Reload this page to try again.";
  const htmlNamespace = "http://www.w3.org/1999/xhtml";

  function showFailure(root) {
    let status = root.querySelector("[data-terminal-status]");
    if (!status) {
      status = root.ownerDocument.createElement("p");
      status.className = "cw-terminal-status";
      status.dataset.terminalStatus = "";
      root.prepend(status);
    }
    status.textContent = failureMessage;
    status.dataset.tone = "danger";
    status.hidden = false;
  }

  function requireSupported(condition) {
    if (!condition) throw new Error("Unsupported xterm 6.0.0 renderer integration");
  }

  function isColor(value) {
    if (/^#(?:[\da-f]{3,4}|[\da-f]{6}|[\da-f]{8})$/i.test(value)) return true;
    const match = /^(rgb|rgba)\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*(\d+(?:\.\d+)?|\.\d+))?\s*\)$/i.exec(value);
    if (!match || match.slice(2, 5).some((channel) => Number(channel) > 255)) return false;
    return match[1].toLowerCase() === "rgb"
      ? match[5] === undefined
      : match[5] !== undefined && Number(match[5]) >= 0 && Number(match[5]) <= 1;
  }

  function colorWriter(document, root) {
    return (element, declaration) => {
      try {
        requireSupported(element?.ownerDocument === document
          && element.namespaceURI === htmlNamespace && element.localName === "span");
        requireSupported(typeof declaration === "string" && declaration.length <= 128);
        const match = /^(color|background-color):\s*(.*?)\s*$/.exec(declaration);
        requireSupported(match && isColor(match[2]));
        // These assignments intentionally use CSSOM properties, never cssText or
        // setAttribute("style", ...). The latter is forbidden by the page CSP.
        if (match[1] === "color") element.style.color = match[2];
        else element.style.backgroundColor = match[2];
      } catch (error) {
        showFailure(root);
        throw error;
      }
    };
  }

  function nonceDocument(document, nonce, styles) {
    const methods = new Map();
    const createElement = (name, options) => {
      const element = document.createElement(name, options);
      if (element.namespaceURI === htmlNamespace && element.localName === "style") {
        element.nonce = nonce;
        styles.add(element);
      }
      return element;
    };
    // This proxy is passed only to this xterm instance. The actual Document,
    // its methods, and all browser prototypes remain untouched.
    return new Proxy(document, {
      get(target, key) {
        if (key === "createElement") return createElement;
        const value = Reflect.get(target, key, target);
        if (typeof value !== "function") return value;
        if (!methods.has(key)) methods.set(key, value.bind(target));
        return methods.get(key);
      },
    });
  }

  function open(root, options, styleNonce, configure) {
    let terminal;
    let subscription;
    try {
      requireSupported(root?.isConnected && root.ownerDocument?.defaultView);
      requireSupported(typeof styleNonce === "string"
        && /^[A-Za-z0-9+/_-]{22,128}={0,2}$/.test(styleNonce));
      requireSupported(typeof globalThis.Terminal === "function");
      requireSupported(configure === undefined || typeof configure === "function");
      const document = root.ownerDocument;
      const styles = new Set();
      const scopedDocument = nonceDocument(document, styleNonce, styles);
      terminal = new globalThis.Terminal({ ...options, documentOverride: scopedDocument });

      // Deliberately pinned to the unmodified, SRI-verified xterm 6.0.0 asset.
      // Its public documentOverride covers DomRenderer's styles, but two private
      // integration points are necessary: CoreBrowserService ignores that
      // override, and DomRendererRowFactory uses setAttribute for RGB colors.
      // Re-review these assertions and the strict-CSP browser regression whenever
      // upgrading xterm. Do not fall back to inline-style permission on failure.
      const core = terminal._core;
      requireSupported(core && typeof core.onWillOpen === "function");
      let openingError;
      let openingCount = 0;
      subscription = core.onWillOpen(() => {
        openingCount += 1;
        try {
          requireSupported(openingCount === 1 && core._document === scopedDocument);
          requireSupported(core._coreBrowserService?.mainDocument === document);
          // onWillOpen runs before the Viewport creates its owned stylesheet.
          core._coreBrowserService.mainDocument = scopedDocument;
        } catch (error) {
          // xterm catches exceptions from onWillOpen. Retain this error and
          // reject below instead of allowing a partially configured terminal.
          openingError = error;
        }
      });
      requireSupported(subscription && typeof subscription.dispose === "function");
      if (configure) configure(terminal);
      requireSupported(terminal.options.documentOverride === scopedDocument && !terminal.element);
      terminal.open(root);
      if (openingError) throw openingError;
      requireSupported(openingCount === 1);

      const renderer = core._renderService?._renderer?.value;
      const rowFactory = renderer?._rowFactory;
      requireSupported(rowFactory && typeof rowFactory.createRow === "function"
        && typeof rowFactory._addStyle === "function" && rowFactory._document === document);
      const ownedStyles = [
        renderer._themeStyleElement,
        renderer._dimensionsStyleElement,
        core._viewport?._styleElement,
      ];
      requireSupported(styles.size === ownedStyles.length && new Set(ownedStyles).size === ownedStyles.length);
      requireSupported(ownedStyles.every((style) => styles.has(style)
        && style.ownerDocument === document && style.nonce === styleNonce
        && style.localName === "style" && root.contains(style)));
      // Override only this instance's color writer. Terminal output can select
      // numeric colors, never arbitrary properties, URLs, selectors, or CSS text.
      Object.defineProperty(rowFactory, "_addStyle", {
        value: colorWriter(document, root),
        configurable: true,
      });
      return terminal;
    } catch (error) {
      terminal?.dispose();
      if (root?.ownerDocument) showFailure(root);
      throw error;
    } finally {
      subscription?.dispose();
    }
  }

  globalThis.CodewireTerminalRenderer = Object.freeze({ open });
})();
