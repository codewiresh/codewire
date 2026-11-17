# Account access

What an account can still reach once it loses authority: after a sign-out, a
disable or a revoked credential (#3586). The rules are in
[`docs/dev/AUTH-POLICY.md`](../dev/AUTH-POLICY.md), "Account access
revocation" and "Product protocols". The design is `private-docs:
designs/stream-revocation.md`; its later steps add the streams already open.
The format is in [README.md](README.md).

## Where it stands

Updated 2026-11-16.

| ID | Dev | Production |
| --- | --- | --- |
| `access-ticket` | not yet observed | not yet observed |

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
     `curl -sS -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" "$CODEWIRE_ORIGIN/api/v1/orgs/$ORG/environments/$SANDBOX/terminal?ticket=$TICKET"`
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
- **Observed:** not yet observed.
