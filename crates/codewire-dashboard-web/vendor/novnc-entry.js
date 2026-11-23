// Codewire's entry into the vendored noVNC: its RFB client, as one global for
// the dashboard's Desktop panel (docs/dev/SANDBOX-DESKTOP.md). noVNC's own
// top-level await can let later scripts run first, so the panel waits for
// the event.
import RFB from "./novnc-1.7.0/core/rfb.js";

globalThis.CodewireNoVNC = Object.freeze({ RFB });
globalThis.dispatchEvent(new Event("codewire:novnc-ready"));
