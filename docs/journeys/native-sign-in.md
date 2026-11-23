# Staying signed in

`cw`, the desktop app and the iOS app stay signed in across their 1-hour
access token's expiry without asking the user to sign in again, and a sign-in
ends only when its refresh token does (#6145). The rules are in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Native sign-in
lifetimes". This journey was written before the code. The format is in
[README.md](README.md).

## Where it stands

Updated 2026-11-23.

| ID | Dev | Production |
| --- | --- | --- |
| `native-lifetime` | not yet observed | not yet observed |
| `native-refresh-ahead` | not yet observed | not yet observed |
| `native-refresh-on-401` | not yet observed | Dev only: it revokes tokens |
| `native-stream-past-expiry` | not yet observed | not yet observed |
| `native-apps` | not yet observed | not yet observed (the expiry state only) |

On Dev every step runs as a test account in its own `HOME`, never the
owner's sign-in. Production has no test account that can sign in: the smoke
identity holds only an API key. There, `native-lifetime`'s database read is
read-only, and the other steps are observed only through the owner's own
sign-in and the IdP's refresh counter (#4786). Nothing on Production revokes
or deletes a token without the owner's yes on #6145. `$H` is that `HOME`, and `cw` stores its sign-in in
`$H/.codewire/credentials.json`. No step prints a token. Commands that read
one pipe it straight into the next command.

## `native-lifetime`: a new sign-in gets a 1-hour access token

- **Entry points:** `cw login`; the desktop app's and the iOS app's sign-in.
- **States to exercise:**
  - a new `cw login`: the access token expires in 1 hour;
  - a refresh: the new access token expires in 1 hour, and the new refresh
    token in 90 days;
  - a sign-in made before the release: it keeps the expiry it was issued
    with.
- **Driving it:**
  1. `HOME=$H cw login`, approve it in the browser, then
     `jq '.expires_at_unix - now | floor' $H/.codewire/credentials.json`.
  2. Read the registered lifetimes from the IdP's database, read-only:
     `SELECT id, access_token_lifetime, refresh_token_lifetime FROM oidc_clients WHERE id IN ('codewire-cli','codewire-desktop','codewire-ios')`.
- **Proof:** step 1 prints a number between 3500 and 3600. Step 2 shows
  `01:00:00` and `2160:00:00` for each of the three clients.
- **Gotchas:** the IdP registers the clients when it starts, so read step 2
  after the release's IdP Pods are Ready.

## `native-refresh-ahead`: `cw` refreshes in the last 10 minutes

- **Entry points:** any `cw` command that calls the API, such as `cw org list`.
- **States to exercise:**
  - more than 10 minutes left: no refresh;
  - less than 10 minutes left: one refresh, then the command;
  - two commands at once, both inside the window: one refresh between them,
    and both succeed (#4428);
  - an expired access token: one refresh, then the command.
- **Driving it:** from `native-lifetime`'s sign-in:
  1. `HOME=$H cw org list`, noting the saved `expires_at_unix`.
  2. Move the saved expiry 9 minutes ahead:
     `jq '.expires_at_unix = (now + 540 | floor)' $H/.codewire/credentials.json > $H/c.json && mv $H/c.json $H/.codewire/credentials.json`,
     then `HOME=$H cw org list`.
  3. The same with 0 instead of 540, then two `HOME=$H cw org list` started at
     once.
- **Proof:** in step 1 the saved expiry is unchanged. In steps 2 and 3 each
  command exits 0 and the saved expiry moves to about an hour from now. On
  the IdP, `codewire_idp_refresh_grants_total{client="codewire-cli"}` gains
  one `rotated` for each refresh and nothing under `replayed` or `revoked`.
- **Gotchas:** `mv` gives the file the mode `jq` wrote it with, so
  `chmod 600 $H/.codewire/credentials.json` after each edit: it holds the
  sign-in.

## `native-refresh-on-401`: a refused token is refreshed once

- **Entry points:** any unary `cw` command.
- **States to exercise:**
  - the access token revoked while its saved expiry is still an hour away:
    the command refreshes once and succeeds;
  - the refresh token revoked too: the command fails once, saying `not
    signed in` with `→ cw login`, and makes no second refresh;
  - an `Unauthenticated` from a handler, without `BEARER_REFUSED`: returned
    as it is, sent once and with no refresh. Only a test can make one on
    purpose; it is `codewire-client`'s test that counts the sends.
- **Driving it:** from a fresh sign-in, with `$ISSUER` the IdP's origin:
  1. Revoke only the access token:
     `jq -r .access_token $H/.codewire/credentials.json | curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$ISSUER/api/oauth/revoke" --data-urlencode token@- -d client_id=codewire-cli`,
     then `HOME=$H cw org list`.
  2. Revoke both, the refresh token the same way with `.refresh_token`, then
     `HOME=$H cw org list`.
- **Proof:** the revocation answers `200`. `RUST_LOG=codewire_client=debug`
  shows the first answer's reason, `BEARER_REFUSED`. In step 1 the command exits 0, the
  saved access token changed and the counter gains one `rotated`. In step 2
  the command exits non-zero with the sign-in message and the counter gains
  nothing.
- **Gotchas:** a `cw` from before #6145 fails step 1 with the sign-in
  message. That is the behaviour this step replaces, so check the version
  first.

## `native-stream-past-expiry`: a stream outlives its access token

- **Entry points:** `cw logs --follow`, `cw shell`.
- **States to exercise:** a stream opened inside the access token's last
  minutes keeps running after the token expires (#3827).
- **Driving it:** a running Sandbox of the test account. Move the saved
  expiry 11 minutes ahead, so no refresh runs, then open
  `HOME=$H cw logs --follow <sandbox>` and leave it past the expiry while the
  Sandbox writes a line a minute.
- **Proof:** lines written after the expiry still arrive, and the stream
  ends only when it is closed.
- **Gotchas:** the moved expiry only stops `cw` refreshing. The server still
  holds the real one, so wait an hour from the sign-in, not from the edit.

## `native-apps`: the desktop and iOS apps stay signed in

- **Entry points:** the desktop app; the iOS app.
- **States to exercise:**
  - the app left open past its access token's expiry, then used: it works
    with no sign-in screen;
  - its access token revoked on the IdP, then used: it refreshes once and
    works;
  - its refresh token revoked too: it asks the user to sign in again.
- **Driving it:** sign in as the test account, leave the app open for more
  than an hour, then list environments. The app's tokens aren't in a file,
  so revoke them on Dev's IdP database by the test account and client (Dev
  only; on Production this is a data write):
  `DELETE FROM oidc_access_tokens WHERE user_id = $1 AND client_id = $2`,
  then the same on `oidc_refresh_tokens`.
- **Proof:** the environment list loads each time, the counter gains a
  `rotated` for `codewire-desktop` or `codewire-ios` each time, and the
  sign-in screen appears only after both tokens are revoked. On Production
  only the first state is walked, with the owner's own app.
- **Gotchas:** an iOS app sent to the background may be suspended. Bring it
  to the front before the hour ends as well as after.
