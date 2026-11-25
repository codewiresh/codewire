// The public pages' analytics hook (infra#2677). Umami's tracker, loaded right after this with
// data-before-send="codewireAnalyticsBeforeSend", calls it with every event before sending it.
// A referrer from this host or a subdomain of it, on any scheme or port, is dropped, so no Codewire
// path reaches Umami from a previous page, such as a sign-in link or invitation that carried a token
// in its path. The tracker's data-exclude-search has already removed any query.
(() => {
  window.codewireAnalyticsBeforeSend = (type, payload) => {
    if (payload && payload.referrer) {
      let host = null;
      try { host = new URL(payload.referrer, location.href).hostname; } catch (e) {}
      const own = location.hostname;
      if (host === null || host === own || host.endsWith('.' + own)) payload.referrer = '';
    }
    return payload;
  };
})();
