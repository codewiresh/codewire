# Account access

What an account can still reach once it loses authority: after a sign-out, a
disable or a revoked credential (#3586). The rules are in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Account access
revocation" and "Product protocols". The design is `private-docs:
designs/stream-revocation.md`.
The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-18.

| ID | Dev | Production |
| --- | --- | --- |
| `access-ticket` | not yet observed | not yet observed |
| `access-streams` | not yet observed | not yet observed |
| `access-tailnet` | not yet observed | not yet observed |

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
terminal and the SSH proxy follow in the next step.

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
  - the dashboard's terminal, the SSH proxy and Mesh sessions aren't covered
    yet, so they outlive every case here;
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
  - a new `cw shell` with the revoked credential is refused;
  - a credential that only expires: its connection keeps running.
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
  3. In Settings, disable the API key: the exec's lines stop and it ends with
     "Access revoked".
  4. Disable the account: B's lines stop and its shell ends. Enable the
     account afterwards; a new `cw login` and `cw shell` work at once.
  5. With the copy of A's revoked sign-in, run `cw shell <sandbox>`: refused.
- **Proof:** the last line each stream printed lies within 30 seconds of its
  revocation, a `stream.revoked` audit event with the surface `tailnet` for
  each, and the surviving streams still printing at the end of their step.
  The expiry case, the dropped NATS remove and a rejoin refused at the hello
  are the coordinator's tests.
- **Gotchas:**
  - the two coordinator replicas matter in Production, not on a one-replica
    Kind cluster; the dropped-publish case is a test, not a walk;
  - on the Sandbox's side an SSH connection from a removed peer ends only
    when it times out, until the next step closes it at once.
- **Observed:** not yet observed.
