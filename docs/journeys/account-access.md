# Account access

What an account can still reach once it loses authority: after a sign-out, a
disable or a revoked credential (#3586). The rules are in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Account access
revocation" and "Product protocols". The design is `private-docs:
designs/stream-revocation.md`.
The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-24.

| ID | Dev | Production |
| --- | --- | --- |
| `access-ticket` | not yet observed | not yet observed |
| `access-streams` | not yet observed | not yet observed |
| `access-websockets` | the SSH proxy's API-key leg observed on Dev 2026-11-21, source 6ef416acfb; its `cw logout` leg not yet observed; the terminal half observed on Kind only (2026-11-20, main 6557aa7e83), and its revoked wording (#5660) on Kind 2026-11-22, main 253add63cd, and since #5946 the line holds until the page reaches sign-in (Kind 2026-11-23, main 4b20950d80); the terminal's sign-out leg and its revoked wording observed on Dev 2026-11-24, source 3e020c3405 | not yet observed |
| `access-org-deleting` | partly observed on Kind 2026-11-20, #5674's source (the owner only), and the dashboard's terminal area (#5677) on Kind 2026-11-22, main 253add63cd and an open terminal's Refresh sessions, reconnect check and return to the page (#5944) on Kind 2026-11-23, main 4b20950d80 (the preview pages not walkable on Kind); not on Dev | not yet observed |
| `access-org-removal` | not yet observed | not yet observed |
| `access-tailnet` | partly observed 2026-11-20, source adc886de2 (an API key; a sign-out and a disable on Kind, not on Dev) | not yet observed |
| `access-key-org-create` | the key half observed 2026-11-22, source ba20ac0df; the signed-in half by its database test | not yet observed |

## `access-ticket`: a terminal ticket from a session that has ended

Issue: #3586, its first step (cw-security, 2026-11-16).

- **Entry points:** the dashboard's terminal. Its WebSocket handshake carries
  a 30-second ticket from `IssueTerminalTicket`, minted for the browser's
  session.
- **States to exercise:**
  - a ticket from a live session opens the terminal;
  - a ticket minted, then the session signed out before it is used: refused;
  - a ticket minted, then the account disabled before it is used: refused;
  - a ticket asked for with an API key or an OAuth token: refused at once.
    Those clients send their own credential with the handshake.
- **Driving it:** a running Sandbox of the walk account, the account's
  session cookie, and, for the disable, an administrator on Admin → Account
  Access. Each case runs inside the ticket's 30 seconds:
  1. Ask for a ticket with the cookie:
     `curl -sS -X POST "$CODEWIRE_ORIGIN/codewire.console.v1.EnvironmentSetupService/IssueTerminalTicket" -H 'Content-Type: application/json' -H "Cookie: codewire.session_token=$SESSION" -d '{}'`.
  2. Open the handshake with it:
     `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" "$CODEWIRE_ORIGIN/api/v1/organizations/$ORG/environments/$SANDBOX/terminal?ticket=$TICKET"`
     answers `101`.
  3. Mint a ticket, sign the session out (`POST /api/auth/sign-out` with the
     cookie), then open the handshake: `401`, "invalid or expired ticket".
  4. Sign in again, mint a ticket, disable the account, then open the
     handshake: `401`. Enable the account afterwards.
  5. Ask for a ticket with an API key in `Authorization`: `permission_denied`.
- **Proof:** the handshake's status, `101` against `401`. A refused
  redemption still uses up the ticket.
- **Gotchas:** the ticket lives 30 seconds, so mint it last. The handshake is
  refused before the Sandbox is looked up, so a `401` says nothing about the
  Sandbox.
- **Observed:** on the local Kind cluster, 2026-11-17, with main fd786c437's
  orchestration (#3586, comment 111346), in a browser signed in as a seeded
  account. Each ticket was used from the page that minted it, with a plain
  `GET`, so an accepted ticket answers the upgrade error that follows the
  ticket check:
  - a live session's ticket was accepted;
  - the same ticket again, and a made-up one, answered `401`;
  - a ticket minted, then the session signed out, answered `401`;
  - a ticket minted, then the account disabled on Admin → Accounts,
    answered `401`;
  - asking with an API key answered `permission_denied`.

  On 2026-11-18, on a Kind cluster brought up from main 4199fd0f6 with a
  running Sandbox, a live session's ticket opened the terminal WebSocket
  (`101`), and the same ticket used again was refused.

## `access-streams`: a stream already open when its authority is lost

Issue: #3586, its second step (cw-security, 2026-11-16). The dashboard's
terminal and the SSH proxy are `access-websockets`.

- **Entry points:** streams through the API, signed in with an OAuth token
  from `cw login` or an API key: `cw shell` with
  `CW_SSH_TRANSPORT=websocket`, which skips the tailnet and attaches through
  the API's `AttachSession` stream, and `StreamExec`, the API's exec, as an
  SDK calls it. By default `cw shell` and `cw exec` reach a hosted Sandbox
  over its tailnet instead, which this step does not fence (see Gotchas).
- **States to exercise:**
  - the OAuth token behind a shell is revoked: that shell ends, and a shell
    signed in on another machine keeps running;
  - the API key behind an exec is disabled: that exec ends;
  - the account is disabled: every stream of the account ends;
  - a credential that only expires: its stream keeps running.
- **Driving it:** a running Sandbox of the walk account, and an
  administrator on Admin → Accounts for the disable. Two throwaway `HOME`s,
  A and B, stand for two machines.
  1. In A and in B, run `cw login`, then
     `CW_SSH_TRANSPORT=websocket cw shell <sandbox>`; its first line says
     "via API". With an API key from Settings as the bearer token, call
     `POST /codewire.v1.ExecService/StreamExec` (Connect, server streaming)
     with the organization, the Sandbox and the command `sleep 600`.
  2. In a second terminal on A, run `cw logout`. It revokes A's token, and
     A's shell ends within seconds with "Access revoked". B's shell and the
     exec keep running.
  3. In Settings, disable the API key: the exec's stream ends with
     `permission_denied`, "access revoked".
  4. Disable the account: B's shell ends within seconds. Enable the account
     afterwards; a new `cw login` and `cw shell` work at once.
- **Proof:** each ending within 30 seconds of its revocation, and a
  `stream.revoked` audit event for it naming the kind of loss and the
  surface. The streams that should survive are still running at the end of
  their step. The expiry case and the browser-session case are the database
  tests', since a walk can't wait out a credential's lifetime.
- **Gotchas:**
  - Mesh sessions aren't covered yet, so they outlive every case here; the
    dashboard's terminal and the SSH proxy are `access-websockets`;
  - plain `cw shell` and `cw exec` on a hosted Sandbox run over its tailnet,
    which the coordinator's `Coordinate` session carries; `access-tailnet`
    covers them. On 2026-11-18 a tailnet `cw shell` kept running 35 s after
    `cw logout`, and a tailnet `cw exec` 30 s after its key was disabled.
    A new one can't start: with a signed-out token or a disabled key,
    `cw shell` and `cw exec` stop at their first call, and the tailnet's own
    first call, `GetEnvironmentHostKey`, answers `401`;
  - disabling an account revokes its sessions, tokens and the user in one
    transaction, so a stream's audit event can name the token it was
    admitted with rather than `user`. `admin.account.disabled` is beside it.
- **Observed:** on a local Kind cluster brought up from main 4199fd0f6
  (with #5201), 2026-11-18, as the seeded `e2e-owner`, with `e2e-admin` for
  the disable, every stream on the API path:
  - `cw logout` on A at 19:41:36.882: A's shell ended at 19:41:36.907 with
    "Access revoked" (`stream.revoked`, surface `attach`, `oauth_token`);
    B's shell and the exec kept running;
  - the key disabled at 19:44:10.3: the exec ended at 19:44:10.538 with
    `permission_denied` "access revoked" (`stream.revoked`, `exec`,
    `api_key`); B's shell kept running;
  - the account disabled at 19:44:57.4: B's shell ended at 19:44:57.460
    (`stream.revoked`, `attach`, `oauth_token`, beside
    `admin.account.disabled`);
  - enabled again: the old browser session had ended, and a new `cw login`
    and shell worked at once.

## `access-websockets`: the dashboard's terminal and the SSH proxy when their authority is lost

Issue: #3586, after its tailnet steps. The terminal half is observed on
Kind, and its sign-out leg on Dev; the SSH proxy is not yet observed.

- **Entry points:** the dashboard's terminal on a Sandbox page, which is
  durable and opened from a browser session; and the SSH proxy's WebSocket, which
  `cw shell --stdio` (OpenSSH's `ProxyCommand` after `cw setup ssh`) uses
  with `CW_SSH_TRANSPORT=websocket`, or when the tailnet cannot connect,
  signed in with an OAuth token from `cw login` or an API key.
- **States to exercise:**
  - the browser session behind a terminal signs out, from that browser or
    from Settings → Sessions: that terminal's socket closes with "access
    revoked", and a terminal opened from another browser keeps running;
  - the OAuth token behind an SSH-proxy session is revoked by `cw logout`,
    and the API key behind another is disabled: each ends;
  - the account is disabled: every terminal and SSH-proxy session of the
    account ends;
  - a credential that only expires: its socket keeps running.
- **Driving it:** a running Sandbox of the walk account, two browsers (or a
  browser and a private window) signed in as it, and throwaway `HOME`s for
  `cw`.
  1. In the first browser open the Sandbox page's terminal, which is
     durable and admitted by the session cookie. In the second browser open
     the Sandbox page and start a new terminal beside it. Run
     `while :; do date -u +%T.%N; sleep 0.2; done` in each. No dashboard
     page opens the one-off terminal admitted by a terminal ticket any more;
     that path is still served and fenced, and its database tests cover it
     (`access-ticket`).
  2. In a `HOME` signed in with `cw login`, run `cw setup ssh`, then
     `CW_SSH_TRANSPORT=websocket ssh cw-<sandbox>` and the same loop. With
     an API key in `CODEWIRE_API_KEY`, open a second one the same way.
  3. Sign the first browser out: its terminal stops printing, shows
     "Access revoked. Sign in again to continue." with no Reconnect, and the
     page moves to sign-in within about five seconds; the second browser's
     terminal keeps printing.
     Sign the first browser in again and open the Sandbox page's terminal:
     the durable shell's loop is still running, and its lines resume.
  4. Run `cw logout` in the `HOME`: its `ssh` ends. Disable the API key in
     Settings: the other `ssh` ends.
  5. Disable the account: the second browser's terminal closes. Enable it
     afterwards; a new sign-in and terminal work at once.
- **Proof:** the last line each socket printed lies within 30 seconds of
  its revocation; the socket closes with code 1008, "access revoked"; the
  browser's terminal shows "Access revoked. Sign in again to continue."
  with no Reconnect (#5660; any other close keeps
  "Disconnected.") and its page moves to sign-in within about five seconds; and a `stream.revoked` audit event names the
  key that matched and the surface, `terminal` or `ssh_proxy`. The
  surviving terminal is still printing at the end of its step, and the
  durable terminal's loop was still running when a fresh sign-in attached
  to it. The expiry case and a
  ticket whose session signs out before it is redeemed are the database
  tests' (`access-ticket` covers redemption).
- **Gotchas:**
  - with the tailnet up, `cw shell --stdio` takes the tailnet, which
    `access-tailnet` covers; set `CW_SSH_TRANSPORT=websocket` to walk this
    one;
  - the close code is not on the page: read it from the socket, as a
    walk's browser tooling can, and the time from the audit event;
  - a disable writes the account's row and its sessions' rows in one
    transaction, so its events usually name `session`.
- **Observed:** the terminal half, on a local Kind cluster, 2026-11-20, main
  6557aa7e83 (orchestration cfc126636f92, dashboard 20bc5f61426e), in
  Chromium, as the seeded `e2e-owner`, with two browser contexts and the
  socket closes recorded by the walk's browser tooling; recorded on #3586.
  Signed out at 18:11:38.527Z, the first browser's socket closed with 1008
  "access revoked" at 18:11:39.052, the event (`session`, `terminal`) is at
  18:11:39.015, and the page moved to sign-in about five seconds later. The
  second browser kept printing through it. Signed in again, the first
  browser reattached to its durable terminal, whose loop had kept running.
  An admin's Disable at 18:12:53.035 closed both of the second browser's
  sockets with 1008 "access revoked" at 18:12:53.553, its last line at
  18:12:53.0, and wrote two events naming `session`; after Enable a new
  sign-in's terminal ran at once.

  The SSH proxy's API-key leg, on Dev, 2026-11-21, source 6ef416acfb, as the
  Dev smoke identity, with a scratch API key and a test Sandbox both removed
  by exact id afterwards. Two `CW_SSH_TRANSPORT=websocket cw shell` sessions
  ("via API"), one admitted by the scratch key and one by the smoke key,
  printed a line a second. The scratch key was deleted with
  `cw api-keys delete` at 13:01:54.940Z: its shell's last line was 13:01:55
  and it ended with "Access revoked"; the smoke key's shell kept printing for
  the 60 seconds read after. Not yet observed: the `cw logout` leg (step 4's
  first half), which waits on a sign-in to a Dev account, the account
  disable for the SSH proxy, and the terminal half on Dev.

  The revoked terminal's words (#5660), on a local Kind cluster, 2026-11-22,
  main 253add63cd, in Chromium, as a scratch owner, twice; recorded on #3586.
  Signed out in a second tab, the terminal's socket closed with 1008 "access
  revoked" at 11:07:45.228Z, and 0.29 s later its footer said "Access
  revoked. Sign in again to continue." with no Reconnect. About a second
  after the sign-out the page's Sandbox status feed failed too, and its
  "Sandbox status is unavailable. Terminal controls are paused." with a
  Reconnect link replaced that line until the page reached sign-in, 7 s and
  36 s later on the two runs.

  Since #5946 that line holds, on a local Kind cluster, 2026-11-23, main
  4b20950d80, in Chromium, as a scratch owner; recorded on #3586. Signed out
  in a second tab at 05:44:10.844Z, the terminal's socket closed with 1008
  "access revoked", and within 0.1 s its footer said "Access revoked. Sign in
  again to continue." with no Reconnect. Read every 0.2 s, nothing replaced it
  until the page reached sign-in 8.8 s after the sign-out, later than the
  proof's about five seconds.

  The terminal's sign-out leg (step 3's first half), on Dev, 2026-11-24,
  Dev's desired source 3e020c3405, in headless Chromium, as the Dev
  personal-walk identity with one browser session from
  `with-dev-personal-walk.sh --browser-sessions 1`, a test Sandbox removed by
  name afterwards, and the socket closes recorded by the walk's browser
  tooling; twice; recorded on #5660. On the second run the Sandbox page's
  terminal printed the loop, a second tab of the same browser signed out from
  Settings, answered 303 at 17:47:52.160Z, and the terminal's socket closed
  with 1008 "access revoked" at 17:47:53.114; 0.13 s later its footer said
  "Access revoked. Sign in again to continue." with no Reconnect. Read every
  0.2 s, nothing replaced it. The page moved to sign-in 6 s after the
  sign-out on the first run, and on the second it was still on the Sandbox
  page when the 60 s read ended, later than the proof's about five seconds.
  The helper signed every session out afterwards
  (`browser_sessions_ended=1`). Not walked here: the second browser that
  keeps printing, the reattach after a fresh sign-in, and the account disable.

## `access-org-deleting`: no new stream into an organization being deleted

Issue: #3586, ahead of the `membership` step (cw-security, 2026-11-20,
comment 123530). Not yet observed.

- **Entry points:** `cw exec`, `cw shell` (tailnet and
  `CW_SSH_TRANSPORT=websocket`), the dashboard's terminal and `cw logs
  --follow`, into an environment of an organization whose deletion has
  started.
- **States to exercise:**
  - a member signed in with a browser session or `cw login`, and the
    organization's owner, after `cw org delete` has started and before it
    finishes: each new stream is refused;
  - the same streams into another organization of the same user: they open;
  - someone who is not a member: refused as today (`organization not found`
    or `environment not found`), never told the organization is being
    deleted;
  - a deletion that failed: new streams stay refused, with the same words,
    until it is retried to the end;
  - streams opened before the deletion started, by the owner and by the
    member: a tailnet `cw shell`, a `CW_SSH_TRANSPORT=websocket` shell, a
    browser terminal, the desktop viewer and `cw logs --follow`; each ends
    when the deletion starts (the `organization` kind);
  - a public port's preview, opened by anyone, and a new Mesh Dial into the
    organization's networks: refused.
- **Driving it:** a walk organization with one running Sandbox and two
  members. Open a tailnet `cw shell` and a `CW_SSH_TRANSPORT=websocket cw
  shell` as the second member, then start `cw org delete` as the owner, and at once try a new `cw exec`, `cw shell`, terminal and
  `cw logs --follow` as each.
  On Dev the walk organization is a throwaway `w3586-del-N` that the
  synthetic invitee creates and owns (`with-dev-personal-walk.sh --identity
  invitee`), with the personal-walk identity as its plain member. Before its
  Sandbox is made, `grant-dev-walk-org-credit.sh --org-slug w3586-del-N`,
  through scoped kube-access, bounds it: top-up off, one Sandbox of the
  default shape and exactly EUR 2 of credit, never the unlimited card.
  After the deletion, check that the organization, its Sandbox and both
  memberships are gone.
- **Proof:** every new stream is refused with a message that the
  organization is being deleted, and none reaches the Sandbox; every stream
  opened before ends within 30 seconds and says the organization is being
  deleted (`cw shell --stdio`: `the connection ended: organization is being
  deleted`), with a `stream.revoked` audit event of kind `organization`; a
  public preview shows its unavailable page and a new Mesh Dial is refused;
  another organization's streams are unaffected. In the dashboard (#5677), the
  Sandbox page's terminal area says "This organization is being deleted, so
  its Sandboxes can't open terminals." with no Retry; an open terminal
  stops within 30 seconds, its socket closed with 1008 "organization is being
  deleted", and shows the same line with no Reconnect and stops
  reconnecting, as Refresh sessions, a dropped socket's check at every third
  retry or a return to the page also do; once the deletion
  stops the Sandbox the page says "This Sandbox is being deleted." and shows
  no terminal, as for any Sandbox being deleted (#5944); a member opening a
  shared
  preview sees "Preview unavailable" and "This organization is being
  deleted, so its Sandboxes' previews can't open."; a non-member still sees
  "Preview access denied".
- **Gotchas:** a small organization's deletion can run to its end in
  seconds, which leaves nothing to refuse, so try the new streams at once. A
  deletion that failed holds still for the walk: it stays refused until it is
  retried. `cw org delete` waits for the deletion to end, so start it in the
  background and try the new streams a second later.
- **Observed:** partly, on a local Kind cluster, 2026-11-20, with
  orchestration and the coordinator at #5674's source (3c91fabd47), as the
  seeded `e2e-owner` alone, through `cw login` and a browser session, in
  four throwaway organizations of one running Sandbox each; recorded on
  #3586. Inside a deletion (20:38:09.285 to 20:38:30.223Z, tried 1.2 s in):
  `cw logs --follow` said "Follow environment logs: organization is being
  deleted" while a bounded backfill still read; a new `cw shell`, over the
  tailnet and with `CW_SSH_TRANSPORT=websocket`, said "Organization is being
  deleted"; `cw exec` said the same with #5679's CLI (20:59:56Z), where the
  CLI before it printed the transport steps. A new browser tab 0.65 s into
  a deletion was refused, but its terminal said "This Sandbox can't list its
  terminals right now. Retry, or restart the Sandbox." (#5677). Streams
  opened before, a tailnet shell, a WebSocket shell and a browser terminal,
  printed until the deletion stopped the Sandbox 3 to 6 s in; the WebSocket
  shell's reconnect was refused with "Organization is being deleted", and
  the tailnet shell's, once the organization was gone, with "Organization
  not found". Not walked in the product: a second member, a non-member, and
  another organization's streams during a deletion; the database tests hold
  those. Dev is not yet observed.

  The dashboard's terminal (#5677), on a local Kind cluster, 2026-11-22, main
  253add63cd, in Chromium, as a scratch owner, in two scratch organizations of
  one running Sandbox each; recorded on #3586. New tabs of the Sandbox page
  0.3 to 0.6 s into a deletion said "This organization is being deleted, so
  its Sandboxes can't open terminals." with no Retry and opened no terminal
  socket. A terminal opened before the deletion printed until the deletion
  stopped the Sandbox (11:16:19.231Z, 1008 "terminal detached", 12 s in),
  showed "Disconnected. Reconnecting…" for about half a second, then the
  Sandbox's own "Deleting… This Sandbox is being deleted" with no terminal,
  and stopped reconnecting. The proof first said it would show the
  organization line; that held only for Refresh sessions while the Sandbox
  still runs, and a reconnect's check and a return to the page now say it
  too (#5944).
  The three, on a local Kind cluster, 2026-11-23, main 4b20950d80, in
  Chromium, as a scratch owner, in three scratch organizations of one running
  Sandbox each, each deleted with `cw org delete`; recorded on #3586. Refresh
  sessions 0.36 s into a deletion showed the organization line 0.57 s in and
  opened no new socket; the Sandbox reached "This Sandbox is being deleted" 23
  s in. A socket dropped 0.31 s in was refused twice on reconnect, and the
  third retry's check showed the line 7.5 s in, opening no socket; the Sandbox
  was being deleted 0.9 s later. A focus event, as a return to the page sends,
  0.31 s in showed the line 0.53 s in, closed the socket and opened none; the
  Sandbox was being deleted 5.9 s in. After Refresh sessions the terminal list
  emptied and offered no Reconnect, but after the reconnect check and the
  return the terminal kept its tab and output and offered Reconnect beside the
  line, which cannot succeed; the proof now says there is none.
  With the change's first commit, the branch's `durable-terminal.js` served in
  place of the cluster's otherwise identical copy, the same three on the same
  cluster (05:58 to 05:59Z, three more scratch organizations) showed the line
  with no Reconnect 0.62 s, 7.5 s and 0.54 s into each deletion, and opened no
  new socket. The line held for 7.9 s, 10.7 s and 10.3 s, read every 0.2 s; in
  the same reading in which the page said "This Sandbox is being deleted", the
  terminal's status line had become "Start this Sandbox to use its
  terminals.", the readiness line that replaced it. The second commit keeps
  the organization line and its missing Reconnect through such a status
  change, as for a revoked terminal; a design fixture proves it, and it was
  not walked on Kind.
  The preview pages were not walked: the preview proxy builds them only for an
  https dashboard origin and Kind's is http, so a preview navigation gets 503
  "preview authorization unavailable"; their database tests and fixtures hold
  them. An organization API key read the preview before the deletion and got
  401 during it, so a Bearer request never reached the deleting check.

## `access-org-removal`: a member removed from an organization

Issue: #3586, the `membership` kind. Not yet observed.

- **Entry points:** `cw org member rm USER --org ORG` and the dashboard's
  Members page, as an owner; `cw org leave`, as the member.
- **States to exercise:**
  - a member signed in with a browser session and with `cw login`, with
    streams open into the organization's Sandbox: a browser terminal, the
    desktop viewer, a `CW_SSH_TRANSPORT=websocket` `cw shell`, a tailnet
    `cw shell`, a `cw exec` that prints every second and `cw logs
    --follow`; then the owner removes them, and in a second run they leave;
  - the same member's streams into another organization: they keep running;
  - another member's streams into the same organization: they keep running;
  - the member invited back: new streams open at once.
- **Driving it:** a walk organization with one running Sandbox, its owner
  and a second member, both test accounts. Open the streams as the member,
  remove them as the owner, and time when each stream ends.
- **Proof:** every stream of the removed member into the organization ends
  within 30 seconds: a WebSocket closes with 1008 "access revoked", the
  dashboard's terminal shows its revoked line, and a Connect stream ends
  `permission_denied`, "access revoked". A `stream.revoked` audit event
  names the member, the kind `membership`, the surface and the environment.
  The other member's streams and the member's other organization keep
  running. After the member is invited back, new streams open.
- **Gotchas:** a stream opened with one of the organization's API keys ended
  before this kind, because a removal disables the member's keys for that
  organization; walk with a browser session and `cw login` to see the new
  kind.

## `access-tailnet`: a tailnet shell or exec when its authority is lost

Issue: #3586, its third step (cw-security, 2026-11-18). A launch item (owner,
2026-11-18).

- **Entry points:** plain `cw shell` and `cw exec` on a hosted Sandbox, which
  run over its tailnet, signed in with an OAuth token from `cw login` or an
  API key in `CODEWIRE_API_KEY`.
- **States to exercise:**
  - the OAuth token behind a tailnet shell is revoked: that shell ends with
    "Access revoked", and a tailnet shell signed in on another machine keeps
    running;
  - the API key behind a tailnet exec is disabled: that exec ends;
  - the account is disabled: every tailnet connection of the account ends;
  - a new `cw shell` with the revoked credential is refused, in words that
    name the credential (#5559): with a saved sign-in (not yet observed),
    `Not signed in: your saved sign-in is no longer accepted`, then
    `→ cw login`; with `CODEWIRE_API_KEY` set (observed on Dev,
    2026-11-20, below), `The API key in CODEWIRE_API_KEY is no longer
    accepted`, then `→ set CODEWIRE_API_KEY to a current key, or unset it
    and run cw login`. No internal step (such as `list orgs`) is named, and
    `cw ls` shows that step in place of a retry;
  - a credential that only expires: its connection keeps running;
  - **on the Sandbox, the removed client's SSH connection closes at once**
    (#3586, after its third step): its shell's processes end when the peer
    is removed, not when SSH's keepalive gives up, and the other machine's
    shell keeps running. Not yet observed.
- **Driving it:** a running Sandbox of the walk account, and an administrator
  on Admin → Accounts for the disable. Two throwaway `HOME`s, A and B, stand
  for two machines.
  1. In A and in B, run `cw login`, then `cw shell <sandbox>`; its first line
     says "via" the tailnet path, not "via API". In each shell run
     `while :; do date -u +%T.%N; sleep 0.2; done`, so the last line that
     arrives shows when packets stopped. With an API key from Settings in
     `CODEWIRE_API_KEY`, run `cw exec <sandbox> -- sh -c 'while :; do date -u
     +%T.%N; sleep 0.2; done'`.
  2. In a second terminal on A, copy A's saved sign-in aside, then run
     `cw logout`; it revokes the token A's shell holds. A's lines stop and its
     shell ends with "Access revoked". B's shell and the exec keep printing.
     On the Sandbox (from B's shell, in a second window),
     `pgrep -fc 'while :; do date'` counts the three loops (A, B and the
     exec) before, and two within about 20 seconds of the sign-out (not
     yet observed).
  3. In Settings, disable the API key: the exec's lines stop and it ends with
     "Access revoked".
  4. Disable the account: B's lines stop and its shell ends. Enable the
     account afterwards; a new `cw login` and `cw shell` work at once.
  5. With the copy of A's revoked sign-in, run `cw shell <sandbox>`: refused,
     with `Not signed in: your saved sign-in is no longer accepted`. With the
     disabled key in `CODEWIRE_API_KEY`, `cw exec <sandbox> -- true`: refused,
     naming the key (both not yet observed).
- **Proof:** the last line each stream printed lies within 30 seconds of its
  revocation, a `stream.revoked` audit event with the surface `tailnet` for
  each, and the surviving streams still printing at the end of their step.
  The expiry case, the dropped NATS remove and a rejoin refused at the hello
  are the coordinator's tests, as are a client's address checks (#5561): a
  node with another address shape, or the environment's own address, ends
  its session, and a second client announcing a held address is not
  forwarded while the first keeps working. A walk cannot drive them, since
  `cw` announces only its own address.
- **Gotchas:**
  - the two coordinator replicas matter in Production, not on a one-replica
    Kind cluster; the dropped-publish case is a test, not a walk;
  - before the daemon closes a removed peer's connections, A's loop on the
    Sandbox outlives the sign-out by up to 60 seconds (SSH's keepalive),
    though no packet reaches A.
- **Observed:** on the local Kind cluster before merge, 2026-11-18, main
  4199fd0f6 with this step's coordinator and `cw` (#3586), plain `cw shell`
  and `cw exec` running "via DERP":
  - `cw logout` on A at 22:12:39.648: A's last line 22:12:39.53, then
    "Access revoked" at 22:12:39.965; B's shell and the exec kept printing;
  - the key disabled at 22:13:07.320: the exec's last line 22:13:07.30,
    "Access revoked" at 22:13:08.346; B's shell kept printing;
  - the account disabled at 22:13:37.386: B's last line 22:13:37.29,
    "Access revoked" at 22:13:37.664;
  - each wrote `stream.revoked` with the surface `tailnet`; the revoked
    token's new `cw shell` and `cw exec` were refused; after the account was
    enabled again, a new sign-in and shell worked at once.

  Partly observed on Dev, 2026-11-20, source adc886de2 (the
  `promote-dev` that rolled out; the coordinator's image matched its
  `release.json`), with a `cw` built from main 911a51f01, as the Dev smoke
  identity (`scripts/runtime/dev/with-dev-smoke-auth.sh`) and a second
  API key it created for the walk, on a Sandbox made for the walk:
  - a plain `cw exec` signed in with the second key, and one with the
    smoke identity's own key, each printing the time every 0.2 s;
  - the second key deleted at 09:07:18.458: its exec's last line arrived
    within a second, it ended with "Access revoked" at 09:07:19.760, and
    the coordinator logged that client's session ending at 09:07:19.161
    with `CredentialRevoked(ApiKey)`. The other exec kept printing;
  - a new `cw exec` with the deleted key was refused at its first call;
    one with the smoke identity's key worked.

  A sign-out (`cw logout`) and an account disable are observed on Kind
  (2026-11-18, above), not on Dev: they need a person's own sign-in rather
  than the smoke identity's key. Not yet observed on Dev: the
  `stream.revoked` audit event, read here only as the coordinator's log
  line. The deleted key's refusal read `List orgs:
  session expired or invalid`, which named an internal call. With a `cw`
  built with #5559's change (2026-11-20, the same Dev source, the smoke
  identity's deleted test key), `cw exec` printed `x The API key in
  CODEWIRE_API_KEY is no longer accepted` and `-> set CODEWIRE_API_KEY to a
  current key, or unset it and run cw login`, and `cw ls` printed `! Cloud
  environments could not be listed: the API key in CODEWIRE_API_KEY is no
  longer accepted` with the same step and no retry.

## `access-key-org-create`: an API key can't create an organization

Issue: #5863. The rule: [`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md),
"Credential rules".

- **Entry points:** `cw org create` and `CreateOrganization`, with an API key
  in `CODEWIRE_API_KEY`; the same after `cw login`.
- **States to exercise:** an organization-scoped API key; a sign-in.
- **Driving it:** on Dev, as the Dev smoke identity (its credential is an API
  key), `cw org create "Scratch NAME" --slug SCRATCH`. Then the same
  signed in with `cw login` as a test account, and remove that organization
  with `cw org delete SCRATCH --yes`.
- **Proof:**
  - with the key, `cw org create` fails at once with "organizations are made
    from a sign-in", exits non-zero, and no organization with that slug
    exists;
  - signed in, the create succeeds and the organization is listed.
- **Observed:** the key half on Dev, 2026-11-22, source `ba20ac0df`, as the
  Dev smoke identity, with `cw` built from `253add63c`. At 04:30:56Z,
  `cw org create "Scratch cwt-5863" --slug cwt-5863-key` failed at once with
  "✗ Create org: organizations are made from a sign-in, not with an API
  key", exited 1 and printed nothing on stdout. Dev's database (read-only)
  has no organization with that slug. The signed-in half isn't walked live,
  since Dev's test identities sign in with API keys only.
  `db_an_api_key_cannot_create_an_organization_and_a_sign_in_can` covers
  both halves against the database.

