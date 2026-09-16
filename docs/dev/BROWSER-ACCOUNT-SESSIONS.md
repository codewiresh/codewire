# Browser account session controls

The IdP exposes cookie-only session inventory and revocation for the Account
screen. These routes never accept API keys, OAuth tokens, or bearer session
tokens. The actor must be an enabled account with two-factor authentication
enabled. They do not change the existing factor enrollment flow.
These two exact routes are registered in the permanent raw identity policy.
The dashboard calls the internal IdP origin; this change adds no public ingress
path or wildcard raw control-plane exception.

`GET /api/auth/sessions?account_id=<expected-account>&cursor=<optional-id>`
returns `account_id`, `current_session` (`id`, `expires_at`), `sessions`
(`id`, nullable `created_at`, `expires_at`), and nullable `next_cursor`.
Pages contain at most 50 active sessions, ordered by session ID. Follow every
cursor to enumerate the inventory; the current session is reported separately
even if it is outside the current page. The inventory can change between pages.
Session IDs identify rows; they are not authentication capabilities.

`POST /api/auth/sessions/revoke` accepts exactly `account_id` and `session_id`.
It requires exactly one Origin equal to the configured public frontend origin.
A dashboard BFF must validate its browser Origin and CSRF token, then forward
that validated Origin deliberately. A successful committed deletion returns
`revoked: true` and `current_session_revoked`; revoking the current session also
clears its HttpOnly cookie. Foreign, absent, and expired targets return the same
404. Account mismatch returns 403 without deleting anything.

Both routes require exactly one session cookie, reject mixed bearer authority,
return no-store responses, have a five-second HTTP operation budget, and serialize
no token, digest, user agent or IP address. Revocation locks the account before
revalidating and locking the exact actor session, using wall-clock expiry after
lock waits, and deletes only rows owned by that account. Database or timeout
failures are errors, never best-effort success. Server-side statement and idle
transaction timeouts are capped at four seconds without increasing stricter
configured limits; HTTP cancellation alone is not treated as database cleanup.

Revocation denies subsequent cookie authentication. It does not claim to close
already-established streams, stop sandbox shells, revoke OAuth grants or revoke
API keys. These are distinct lifetimes and controls.

Focused proof is `cargo test -p codewire-idp --lib session_inventory` and the
six synthetic PostgreSQL tests in `tests/session_inventory.rs`. The checked-in
service verification requires all six tests and rejects missing-database skips.

## Dashboard Account screen

`/settings/` contains account details, security, and paginated active sessions.
The legacy Security and Sessions URLs authenticate and validate selected
organization membership before redirecting to the matching Account section.
Personal navigation has only Account and Credentials, including organization
settings pages. Git commit attribution lives separately on Credentials; the
legacy Git identity POST uses the same mutation handler, not a POST redirect.

The dashboard session adapter has a six-second request budget, disables
redirects, and enforces a streamed64 KiB response limit. It accepts only closed,
account-bound metadata with at most50 rows per page and advancing keyset cursors.
It rejects bearer or duplicate-cookie authority before cookie normalization.
The native confirmation form carries expected account/session IDs and CSRF;
the BFF checks exact Origin, fresh identity, factor state and organization
membership before forwarding the canonical cookie and validated public Origin.
Only a validated committed acknowledgement yields success. Cookie clearing is
driven by the server's current-session acknowledgement, never a browser flag.
Unknown outcomes require refreshed inventory rather than an optimistic retry.

Account identity and sign-out remain available when session controls are
unavailable. A synthetic dashboard factor-setup exemption does not waive the
IdP's actual enabled-factor requirement. This screen promises neither password
reset delivery nor closure of established streams or Sandbox shells.

Focused UI proof includes dashboard library tests (closed DTOs, cumulative
stream bounds, redirect rejection, acknowledgement projection and signed-out
`get-session:null`), desktop/mobile native-dialog fixture tests, and the managed
`ssr-dashboard.account-sessions.ssr.ts` journey. The managed journey enumerates
53 synthetic sessions across pages, checks auth/CSRF/Origin/account/foreign
scope rejection, and proves other/current-session revocation separately.
Fixture request interception proves only presentation/submit shape; it does
not substitute for the real IdP/database journey.

Account management goldens use an isolated synthetic owner with exactly two
sessions, fixed creation/expiry dates, and the byte-lowest session as the current
browser. The owner joins the selected organization only after its Members
visual test. Screenshots mask only per-run public session IDs and the unique
test email; metadata, row ordering, native actions and organization context
remain real assertions. The Git attribution journey restores its original
values in `finally` through the retained legacy POST and verifies that the
Credentials feedback preserves the selected organization.
