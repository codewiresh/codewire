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
Pages contain at most 50 active sessions, ordered by session ID using bytewise
`COLLATE "C"` in both the cursor predicate and ordering. The ordering is
independent of the database or column's default collation. Follow every
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
seven synthetic PostgreSQL tests in `tests/session_inventory.rs`. The checked-in
service verification requires all seven tests and rejects missing-database skips.
The collation regression uses a test-owned copy of the migrated session table
with ICU collation and60 mixed-case/punctuation IDs across the50-row boundary;
public/migrated tables are unchanged. Its old query fails byte-order equality,
and the explicit C-collation query preserves both ordering and cursor progress.
