// Every page's analytics hook (infra#2677). Umami's tracker, loaded right after this with
// data-before-send="codewireAnalyticsBeforeSend", calls it with every event before sending it.
// A referrer from this host or a subdomain of it, on any scheme or port, is dropped, so no Codewire
// path reaches Umami from a previous page, such as a sign-in link or invitation that carried a token
// in its path. The tracker's data-exclude-search has already removed any query.
// A page inside the account names only its kind: the server marks the hook's script with the page's
// route pattern, such as /:slug/:environment_id/, and every event carries that and a fixed title in
// place of the page's own address and title, which hold organization and Sandbox names and IDs.
(() => {
  const route = () => {
    const script = typeof document === 'undefined' ? null : document.querySelector('script[data-analytics-route]');
    return script ? script.dataset.analyticsRoute : null;
  };
  window.codewireAnalyticsBeforeSend = (type, payload) => {
    const pattern = route();
    if (payload && pattern) {
      payload.url = location.origin + pattern;
      payload.title = 'Codewire';
    }
    if (payload && payload.referrer) {
      let host = null;
      try { host = new URL(payload.referrer, location.href).hostname; } catch (e) {}
      const own = location.hostname;
      if (host === null || host === own || host.endsWith('.' + own)) payload.referrer = '';
    }
    return payload;
  };
})();
