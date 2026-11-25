# Web analytics

Cookie-free page counts on the public pages, with Codewire's own copy of Umami's tracker (infra#2677). The contract is [docs/CONFIGURATION.md, Web analytics](../CONFIGURATION.md#web-analytics). The format is in [README.md](README.md). Identifying a visitor who says Yes to the cookie banner comes later, with the banner itself. Written first; not yet observed.

## `analytics-counts-public-pages`: a public page view is counted, and nothing else is sent

- **Entry points:** `/`, `/pricing`, `/privacy`, `/terms`, `/updates` and a docs page such as `/docs/quickstart` in a browser, signed out and signed in; any other page, such as `/login`, `/reset-password` or the console.
- **States to exercise:** signed out; signed in; arriving from a sign-in or invitation link; a deployment without `CODEWIRE_ANALYTICS_ORIGIN` and `CODEWIRE_ANALYTICS_WEBSITE_ID`.
- **Driving it:**
  1. In a fresh private window, signed out, open `/pricing?utm_source=walk#plans`. In the browser's network log, see one `POST` to the analytics origin's `/api/send`. Its body's `url` is `/pricing`, with no query or fragment, and its `referrer` is empty. The page sets no cookie.
  2. Open `/` from a link on another site. See its `/api/send` carry that site's address as `referrer`.
  3. Sign in, then open `/pricing`, `/privacy`, `/terms` and `/updates`. See no request to the analytics origin and no tracker script. Open `/` and `/docs/quickstart`. See one `/api/send` for each: the homepage and the docs are the same cached page for every visitor, so they are tagged signed in too.
  4. Open `/login`, `/signup`, `/forgot-password`, a `/reset-password` link and the console. See no tracker script and no request to the analytics origin.
  5. Follow an emailed sign-in link to `/login/link`, then click through to `/pricing`. See `/pricing`'s `/api/send` with an empty `referrer`.
  6. In Umami's dashboard, open the website. See the views from steps 1, 2 and 3 under their paths, with no query string.
  7. On a deployment without the two values, open `/` and `/docs/quickstart`. See no tracker script, and a `Content-Security-Policy` whose `connect-src` is `'self'`, in the header and in the docs page's own meta tag.
- **Proof:** the request bodies in the network log (the `url`, the empty `referrer` in steps 1 and 5); the counts and paths in Umami's dashboard; the policy header and the docs page's meta policy in step 7.
- **Gotchas:** Dev and Kind have no analytics settings, so this walk runs on Production. A browser's tracking protection or an extension can block the tracker; walk in a profile with none. The homepage is cached at the edge for five minutes, so a change to the tag can take that long to show there.
- **Observed:**
  - Not yet observed.
