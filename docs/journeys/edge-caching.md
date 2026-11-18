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
- **States to exercise:** each request signed out, then signed in as the
  Dev smoke identity, each sent twice in a row.
- **Driving it:** set `ORIGIN` to Dev's public dashboard origin, `SLUG` and
  `ORG` to one of the Dev smoke identity's organizations' slug and id, and
  `ENV` to one of its Sandboxes. Credentials never go on a command line: each
  is a header in a file only you can read, deleted by its path afterwards.
  Export `ROUTE` set to each path below in turn (and `ORIGIN`, which the
  bearer step's child reads) and run each request twice.
  - Signed out:

    ```sh
    curl -sS -o /dev/null -D - "$ORIGIN$ROUTE" | grep -i -E '^(cache-control|cf-cache-status):'
    ```

  - Signed in to the dashboard and the IdP: sign in as the smoke identity
    itself, never through the owner's browser, and write its session cookie
    as one header line, `Cookie: codewire.session_token=…`, to a file made
    with `umask 077`:

    ```sh
    curl -sS -o /dev/null -D - -H @"$COOKIE_FILE" "$ORIGIN$ROUTE" | grep -i -E '^(cache-control|cf-cache-status):'
    rm -- "$COOKIE_FILE"
    ```

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
  - the 404: `/no-such-page`;
  - the anonymous homepage: `/`;
  - Mesh's list as a Connect GET (#5123), with the bearer:
    `/codewire.v1.MeshNetworkService/ListMeshNetworks?encoding=json&message=%7B%22orgId%22%3A%22$ORG%22%7D`;
  - the SSH proxy check (#5123), with the bearer:
    `/api/v1/organizations/$ORG/environments/$ENV/ssh-proxy/check`;
  - the session (#5072), with the cookie: `/api/auth/get-session`.
- **Proof:**
  - Every response but one carries `Cache-Control` with `no-store`, and the
    dashboard's with `no-store, private`, signed out and signed in, the
    redirect and the 404 included. The bearer requests to Mesh and the SSH
    proxy check answer 200, so the signed-in pair is really signed in.
  - The one reviewed exception is the anonymous `/`: signed out it carries
    `public, max-age=0, s-maxage=300` (`HOME_CACHE_CONTROL`) and no
    `Set-Cookie`; signed in it is `no-store, private`.
  - `cf-cache-status` is never `HIT` on the second request of any pair
    except the signed-out `/`.
  - Signed out, `get-session` returns `null` on both requests, never another
    caller's session.
- **Gotchas:** a request with a stale cookie is answered as signed out; check
  the signed-in pairs return the smoke identity's data. Only Dev's real edge
  proves this; Kind has no shared cache in front of it.
- **Observed:** not yet observed.
