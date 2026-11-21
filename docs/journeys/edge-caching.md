# Caching at the edge

This walk proves that no cache in front of Codewire keeps one caller's
response and serves it to another (#5054, with #5123 and #5072). The rule is
in `docs/CONFIGURATION.md`, "Caching at the edge": every response that can
depend on its caller is `no-store`, and anything cached says so in its own
`Cache-Control` through a reviewed exception. The format is in
[README.md](README.md).

## `edge-never-caches-per-caller`: per-caller responses are never stored at the edge

Issues: #5054, #5123, #5072. Code: `keep_responses_private` and
`HOME_CACHE_CONTROL` in `crates/codewire-dashboard-web/src/security.rs`; the
route walker in `crates/codewire-dashboard-web/src/routes/cache_policy_tests.rs`.

- **Entry points:** the dashboard origin through Dev's real edge, as a
  browser reaches it; the Connect API and the browser API on the same edge.
- **States to exercise:** each request signed out, then signed in, each sent
  twice in a row. The cookie requests sign in as the e2e acceptance account,
  because the Dev smoke identity has only an API key. The bearer requests use
  the smoke identity.
- **Driving it:** set `ORIGIN` to Dev's public dashboard origin, `SLUG` to one
  of the e2e account's organizations' slug, and `ORG` and `ENV` to one of the
  smoke identity's organizations and one of its running Sandboxes. Credentials never go on a command line: each
  is a header in a file only you can read, deleted by its path afterwards.
  Export `ROUTE` set to each path below in turn (and `ORIGIN`, which the
  bearer step's child reads) and run each request twice.
  - Signed out:

    ```sh
    curl -sS -o /dev/null -D - "$ORIGIN$ROUTE" | grep -i -E '^(cache-control|cf-cache-status):'
    ```

  - Signed in to the dashboard and the IdP: sign in as the e2e account
    itself, never through the owner's browser. Use its password and second
    factor from `apps/codewire/dev/ci-browser-auth`, read and posted to
    `/api/auth/sign-in` and `/api/auth/two-factor/validate` as `sign_in` in
    `scripts/docs/record-readme-walkthrough.sh` does, never printed. Write its
    session cookie as one header line, `Cookie: codewire.session_token=…`, to
    a file made with `umask 077`:

    ```sh
    curl -sS -o /dev/null -D - -H @"$COOKIE_FILE" "$ORIGIN$ROUTE" | grep -i -E '^(cache-control|cf-cache-status):'
    ```

    After the last signed-in request, sign the session out
    (`POST /api/auth/sign-out`), check that `get-session` with the old cookie
    answers `null`, and delete the file by its path: `rm -- "$COOKIE_FILE"`.

  - Signed in to Mesh and the SSH proxy check, which take a bearer, not the
    cookie: run under `scripts/runtime/dev/with-dev-smoke-auth.sh`, which
    hands the child the smoke identity's API key as
    `CODEWIRE_DEV_SMOKE_API_KEY`, and write the header to a file inside it:

    ```sh
    scripts/runtime/dev/with-dev-smoke-auth.sh sh -c '
      umask 077; auth="$(mktemp)"
      printf "Authorization: Bearer %s\n" "$CODEWIRE_DEV_SMOKE_API_KEY" >"$auth"
      curl -sS -o /dev/null -D - -H @"$auth" "$ORIGIN$ROUTE" | grep -i -E "^(HTTP|cache-control|cf-cache-status)"
      rm -- "$auth"'
    ```

  The paths:
  - a dashboard page: `/$SLUG/`;
  - a fragment: `/$SLUG/_fragments/sandboxes`;
  - a redirect: `/dashboard/` signed out, which sends the caller to sign in;
  - the 404: `/no-such-page/`. Without the slash it answers 308 to it, and
    signed out it redirects to sign-in like any page;
  - the anonymous homepage: `/`;
  - a Connect method behind the shared auth layer (#5317), with the cookie:
    `/codewire.v1.OrganizationService/ListOrganizations?encoding=json&message=%7B%7D`;
  - Mesh's list as a Connect GET (#5123), with the bearer:
    `/codewire.v1.MeshNetworkService/ListMeshNetworks?encoding=json&message=%7B%22orgId%22%3A%22$ORG%22%7D`;
  - the SSH proxy check (#5123), with the bearer:
    `/api/v1/organizations/$ORG/environments/$ENV/ssh-proxy/check`;
  - the session (#5072), with the cookie: `/api/auth/get-session`.
- **Proof:**
  - Every response but one carries `Cache-Control` with `no-store`, signed
    out and signed in, the redirects and the 404 included. The dashboard's
    signed-in pages, fragments and 404 carry `no-store, private`. Its
    redirects to sign-in carry `no-store`. The bearer requests to Mesh and the SSH
    proxy check answer 200, so the signed-in pair is really signed in.
  - The one reviewed exception is the homepage `/`. It reads no session, so
    every caller gets the same page: `public, max-age=0, s-maxage=300`
    (`HOME_CACHE_CONTROL`) and no `Set-Cookie`, signed out and signed in.
    `keep_responses_private` replaces that policy with `no-store, private`
    only on a response that sets a cookie. The edge stores it only for a
    request that carries no cookie: signed in it answers `DYNAMIC`.
  - `cf-cache-status` is never `HIT` on the second request of any pair
    except the signed-out `/`.
  - Signed out, `get-session` returns `null` on both requests, never another
    caller's session.
- **Gotchas:** a request with a stale cookie is answered as signed out; check
  the signed-in pairs return the signed-in caller's data (`get-session`'s
  user is the e2e account; the Mesh and SSH proxy checks answer 200). Only Dev's real edge
  proves this; Kind has no shared cache in front of it.
- **Observed:** 2026-11-21 on Dev, source 649362300, which carries #5226 and
  #5317. Every pair matched the proof:
  - Signed out, these answered `no-store` and `DYNAMIC` both times: the
    dashboard page, the fragment, `/dashboard/` and `/no-such-page/` (each a
    303 to sign-in), `ListOrganizations` (401, `no-store, private`) and
    `get-session` (`no-store, private`, body `null` both times).
    `/no-such-page` answered 308, `no-store, private`. `/` answered
    `public, max-age=0, s-maxage=300`, `EXPIRED` then `HIT`.
  - Signed in as the e2e account: the page and fragment (200), the 404 (404),
    `ListOrganizations` (200) and `get-session` (200, the e2e account's user)
    all answered `private, no-store` or `no-store, private`, and `DYNAMIC`
    both times. `/` answered the public policy, no `Set-Cookie`, `DYNAMIC`
    both times, with the same body as the anonymous page.
  - With the smoke identity's bearer: `ListMeshNetworks` and the SSH proxy
    check answered 200, `no-store, private`, `DYNAMIC` both times.
  - Afterwards the session was signed out, and `get-session` with its old
    cookie answered `null`.
