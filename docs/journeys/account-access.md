# Account access

What an account can still reach once it loses authority: after a sign-out, a
disable or a revoked credential (#3586). The rules are in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Account access
revocation" and "Product protocols". The design is `private-docs:
designs/stream-revocation.md`.
The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-17.

| ID | Dev | Production |
| --- | --- | --- |
| `access-ticket` | not yet observed | not yet observed |
| `access-streams` | not yet observed | not yet observed |

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

  The `101` of a full handshake is not yet observed: that cluster's
  manifests were older than main's and ran no Sandbox.

## `access-streams`: a stream already open when its authority is lost

Issue: #3586, its second step (cw-security, 2026-11-16). The dashboard's
terminal and the SSH proxy follow in the next step.

- **Entry points:** `cw shell` (an attached session) and `cw exec`, signed in
  with an OAuth token from `cw login` or an API key in `CODEWIRE_API_KEY`.
- **States to exercise:**
  - the OAuth token behind a `cw shell` is revoked: that shell ends, and a
    `cw shell` signed in on another machine keeps running;
  - the API key behind a `cw exec` is disabled: that exec ends;
  - the account is disabled: every stream of the account ends;
  - a credential that only expires: its stream keeps running.
- **Driving it:** a running Sandbox of the walk account, and an
  administrator on Admin → Account Access for the disable. Two throwaway
  `HOME`s, A and B, stand for two machines.
  1. In A and in B, run `cw login`, then `cw shell <sandbox>`. With an API
     key from Settings in `CODEWIRE_API_KEY`, run
     `cw exec <sandbox> -- sleep 600`.
  2. In a second terminal on A, run `cw logout`. It revokes A's token, and
     A's shell ends within seconds with "access revoked". B's shell and the
     exec keep running.
  3. In Settings, disable the API key: the exec ends with "access revoked".
  4. Disable the account: B's shell ends within seconds. Enable the account
     afterwards; a new `cw login` and `cw shell` work at once.
- **Proof:** each ending within 30 seconds of its revocation, and a
  `stream.revoked` audit event for it naming the kind of loss and the
  surface. The streams that should survive are still running at the end of
  their step. The expiry case and the browser-session case are the database
  tests', since a walk can't wait out a credential's lifetime.
- **Gotchas:** the dashboard's terminal, the SSH proxy, and the coordinator's
  and Mesh sessions aren't covered yet, so they outlive every case here.
- **Observed:** not yet observed.
