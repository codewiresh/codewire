# Web analytics

Cookie-free page counts on every page, signed in or not, with Codewire's own copy of Umami's tracker (infra#2677). The contract is [docs/CONFIGURATION.md, Web analytics](../CONFIGURATION.md#web-analytics). The format is in [README.md](README.md). Written first; not yet observed.

## `analytics-counts-public-pages`: every page view is counted, and nothing else is sent

- **Entry points:** any page in a browser, signed out and signed in: `/`, `/pricing`, a docs page such as `/docs/quickstart`, `/login`, a `/reset-password` link, an invitation link and the console.
- **States to exercise:** signed out; signed in; arriving from a sign-in or invitation link; a deployment without `CODEWIRE_ANALYTICS_ORIGIN` and `CODEWIRE_ANALYTICS_WEBSITE_ID`.
- **Driving it:**
  1. In a fresh private window, signed out, open `/pricing?utm_source=walk#plans`. In the browser's network log, see one `POST` to the analytics origin's `/api/send`. Its body's `url` is `/pricing`, with no query or fragment, and its `referrer` is empty. The page sets no cookie.
  2. Open `/` from a link on another site. See its `/api/send` carry that site's address as `referrer`.
  3. Sign in, then open `/pricing`, `/docs/quickstart`, the console and a Sandbox's page. See one `/api/send` for each. `/pricing` and the docs page send their path with no query. The console and the Sandbox's page send only their route pattern, such as `/:slug/:environment_id/`, and the title `Codewire`, with no organization or Sandbox name or ID.
  4. Signed out, open `/login`, `/signup`, a `/reset-password?token=…` link and an invitation link (`/accept-invite#t=…`). See one `/api/send` for each, its `url` `/reset-password` or `/accept-invite` and its title `Codewire`: no token is sent.
  5. Follow an emailed sign-in link to `/login/link`, then click through to `/pricing`. See `/pricing`'s `/api/send` with an empty `referrer`.
  6. In Umami's dashboard, open the website. See the views from steps 1 to 4 under their paths, with no query string or token.
  7. On a deployment without the two values, open `/` and `/docs/quickstart`. See no tracker script, and a `Content-Security-Policy` whose `connect-src` is `'self'`, in the header and in the docs page's own meta tag.
- **Proof:** the request bodies in the network log (the `url` with no query or token in steps 1 and 4, the empty `referrer` in steps 1 and 5); the counts and paths in Umami's dashboard; the policy header and the docs page's meta policy in step 7.
- **Gotchas:** Dev and Kind have no analytics settings, so this walk runs on Production. A browser's tracking protection or an extension can block the tracker; walk in a profile with none. The homepage is cached at the edge for five minutes, so a change to the tag can take that long to show there.
- **Observed:**
  - Not yet observed.
