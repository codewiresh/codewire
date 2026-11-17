// The invitation link (#3840) carries its token in the fragment,
// /accept-invite#t=<token>, which no request line, edge log or Referer ever
// holds. This script takes it out of the address bar and history first, then
// posts it once in a form body; the server keeps it in a cookie scoped to
// /accept-invite. It never writes the token anywhere else. Every invitation
// page carries it, so a new link replaces an invitation already open.
(() => {
  const form = document.querySelector("[data-invitation-open]");
  if (!form) return;
  const token = new URLSearchParams(window.location.hash.slice(1)).get("t");
  if (token) {
    window.history.replaceState(null, "", "/accept-invite");
    form.elements.namedItem("t").value = token;
    form.submit();
    return;
  }
  const opening = document.querySelector("[data-invitation-opening]");
  if (!opening) return;
  // Back from signing in with a provider: that redirect chain began on
  // another site, so the strict cookie stayed behind. One same-site load of
  // the page carries it; after that, there is no invitation to open.
  if (!new URLSearchParams(window.location.search).has("resume")) {
    window.location.replace("/accept-invite?resume");
    return;
  }
  const missing = document.querySelector("[data-invitation-missing]");
  if (missing) missing.hidden = false;
  opening.hidden = true;
})();
