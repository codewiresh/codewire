// The page's one live stream (#4762; private-docs designs/live-updates.md
// §2.4, §3a). It relays /_events/live as DOM events on <body>:
// codewire:live:sandbox, :resize and :credit carry ids in `detail`
// ({organization, environment}); codewire:live:resync means "refresh
// everything shown". Regions subscribe and re-fetch through routes that
// re-authorize; this script never fetches page content itself.
//
// The stream is closed while the tab is hidden, and showing the tab opens it
// again; orchestration's first event is always resync, so the page catches up
// once. A resync from the stream waits a random moment of up to a second, so
// the pages a restart or a listener gap resyncs together don't all re-fetch at
// the same instant. When the stream answers busy, or keeps failing, the page falls back
// to a resync on focus and on show, and once a minute while visible: the one
// timer for server state the live-state rule allows.
(() => {
  if (typeof window.EventSource !== "function") return;
  const KINDS = ["sandbox", "resize", "credit", "resync"];
  const FALLBACK_MS = 60_000;
  // EventSource retries a dropped stream by itself; this many failures in a
  // row without an event means it isn't coming back soon.
  const MAX_FAILURES = 3;
  const RESYNC_SPREAD_MS = 1_000;

  let source = null;
  let failures = 0;
  let fallback = null;
  let resyncPending = false;

  const emit = (kind, detail) => {
    document.body.dispatchEvent(new CustomEvent(`codewire:live:${kind}`, { detail }));
  };

  // Resyncs that arrive while one waits are one resync.
  const resyncSoon = () => {
    if (resyncPending) return;
    resyncPending = true;
    window.setTimeout(() => {
      resyncPending = false;
      emit("resync", {});
    }, Math.random() * RESYNC_SPREAD_MS);
  };

  const startFallback = () => {
    if (fallback) return;
    close();
    fallback = window.setInterval(() => {
      if (document.visibilityState === "visible") emit("resync", {});
    }, FALLBACK_MS);
    emit("resync", {});
  };

  const close = () => {
    source?.close();
    source = null;
  };

  const open = () => {
    if (source || fallback || document.visibilityState !== "visible") return;
    source = new EventSource("/_events/live");
    for (const kind of KINDS) {
      source.addEventListener(kind, (event) => {
        failures = 0;
        let detail = {};
        try {
          detail = JSON.parse(event.data || "{}");
        } catch {
          return;
        }
        if (kind === "resync") resyncSoon();
        else emit(kind, detail);
      });
    }
    source.addEventListener("busy", startFallback);
    source.addEventListener("error", () => {
      // A refusal (401, 403) closes the source for good; so do repeated
      // failures. Either way the page keeps working on the fallback.
      failures += 1;
      if (source?.readyState === EventSource.CLOSED || failures >= MAX_FAILURES) startFallback();
    });
  };

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      if (fallback) emit("resync", {});
      else open();
    } else {
      close();
    }
  });
  window.addEventListener("focus", () => {
    if (fallback) emit("resync", {});
  });
  // A page restored from the back-forward cache reopens its stream, and the
  // stream's first resync brings it up to date.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) open();
  });
  window.addEventListener("pagehide", close);
  open();
})();
