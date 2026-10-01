# Sandbox previews

A preview is an HTTPS URL that forwards HTTP requests to an application's
internal Sandbox port. It is not a public TCP port mapping, and there is no
separate external port number to choose.

The creation page reads the deployment's public `preview_base_domain` from
`GetEnvironmentCreateOptions`. Before creation it shows a non-clickable pattern:
`https://{label}-{sandbox-id-prefix}-{organization-slug}.{preview_base_domain}`.
The five-character Sandbox ID prefix is assigned during creation. The Ports
dialog uses the exact URL returned by the API; Open and Copy share the same
validated HTTPS root address. Missing or malformed public configuration is
shown as unavailable, never replaced with a guessed deployment domain.

Preview access can be the Sandbox creator, organization members with Sandbox
access, or anyone with the URL. Creator-only access still exposes an
authenticated preview URL. Confidential policy can require authentication even
for a public preview. These settings do not determine whether an application
is listening inside the Sandbox.

The creation page explicitly submits its preview choice. Removing every row
sends `omit_application_previews: true` on `CreateEnvironmentRequest`, suppressing
preview defaults from both presets and repository configuration. That flag
requires an empty `project_spec.application_ports` list. Prepare preserves it
in returned drafts. Older clients omit the flag and retain default inheritance.
The flag controls creation-time defaults, not generic local-VM port bindings.

Internal ports must be distinct, in `1..65535`, and not runtime-reserved ports
`2222` or `2223`. Labels must be distinct and contain 2–22 lowercase letters,
digits or hyphens, with a letter or digit at either end. Empty access retains
the platform's creator-only default. Effective inherited previews are checked
before platform setup; database uniqueness remains the concurrency safeguard.

An empty preview list, or removing an existing entry, disables this HTTPS
preview mechanism only. It is not complete network isolation. Clipboard denial
does not report success: the dialog leaves the URL available for manual copying.

## Private preview browser authorization

Opening a private preview as a top-level HTTPS navigation returns to the
configured Codewire frontend. Signed-out users complete normal sign-in and
2FA before returning to the requested preview; signed-in authorized users
continue automatically, without a separate consent step. An encrypted,
five-minute continuation binds the preview host,
the full environment and port identities, the return path and a preview-host
nonce. Every start mints a fresh nonce in a cookie named for its challenge and
never adopts one the browser offers, because a preview page can write cookies
for its own host; concurrent tabs keep separate nonces. Starting this flow does
not allocate anonymous database rows.

The frontend's raw `/api/v1/preview-auth/authorize` transport keeps GET
read-only and auto-submits a same-origin POST using the normal host-only
account session, exact Origin and session-bound CSRF checks. A
one-use, 60-second code is posted in the body to the preview host's reserved
`/.codewire/preview-auth/callback`; it is never a query parameter. The callback
names its challenge, requires that challenge's host-only nonce, clears it, and
issues a separate Secure, HttpOnly
preview session cookie. Its authority lasts only while the originating account
session and current preview policy allow it; there is no independent one-hour
expiry. Preview traffic does not slide the account session. Consumed
authorization IDs remain until expiry, preventing a replay from minting another
code.

Each preview request checks the parent session, enabled account, exact target
and current audience/confidential-access policy. Logout or session expiry
invalidates preview access; deleting and recreating a port does not reuse its
old grant. Policy is checked again on use: callback issuance is not an atomic
transaction over every organization-membership or access-policy change.
Every preview host shares one site, so `SameSite` cannot stop another preview
from sending this browser's grant with its own scripts, images, frames or
credentialed fetches. A grant therefore authenticates only requests whose
`Sec-Fetch-Site` is `same-origin` or `none`, and top-level document
navigations; a browser without Fetch Metadata must send no Origin or this
preview's exact Origin. Unsafe cookie-authenticated requests also require the
exact preview Origin. In browsers with Fetch Metadata, a private preview cannot
be framed by another preview or called cross-origin with its grant; use a
public preview or a bearer credential for that. Older browsers without it
(Safari before 16.4) send no Origin on image, script or frame loads, so there
a grant still accompanies those. Private previews refuse service-worker
scripts: a worker could read the sign-in callback's one-use code. Non-navigation unauthenticated requests fail rather than entering
sign-in.

Codewire cookies and reserved Codewire headers never reach the application.
The proxy removes the Bearer credential it authenticated a request with, and
every Codewire API key (`Bearer cw_…`), including on public previews. Other
`Authorization` values belong to the application and are forwarded: Basic
authentication, and a bearer sent to a public preview or alongside a preview
grant. Do not send a Codewire session or OIDC token to a public preview; the
proxy cannot tell it from the application's own bearer without authenticating
every public request. Ordinary application cookies remain available. The
proxy drops `Set-Cookie` responses for Codewire-reserved names or for sibling
preview domains, and drops `Clear-Site-Data`, whose `cookies` directive would
clear every preview's cookies. Page script can still write site-wide cookies
through `document.cookie`; cookie lookup ignores unrelated pairs it cannot
parse, and only a duplicate of the exact grant or nonce name is rejected. A
very large planted Cookie header can still exceed the server's header limit
until those cookies expire. Listing the preview domains on the Public Suffix
List would make each preview its own site and remove these shared-site limits.
Private/confidential responses force non-cacheable browser and shared-cache
policy even if the application requests public caching. Public-preview caching
is otherwise unchanged. WebSocket upgrade support is not added by this flow.
Application redirects are returned to the browser unchanged; the proxy never
follows them into a different target on the application's behalf.

Storage is bounded per authenticated user/session and distinct preview scope.
Starting a challenge needs no account, so steering a signed-in browser through
eight challenges for previews it can open fills that session's quota for up to
five minutes; sign-in then reports `429` until they expire.
Repeated authorization of the same session and preview reissues the same
purpose-separated scoped capability, so browser restarts and out-of-order tab
responses cannot consume new grant slots. Authenticated requests also remove
bounded batches of expired challenges and grants whose parent sessions expired;
this is opportunistic cleanup, not a wall-clock deletion guarantee during
inactivity. Deleting a session or preview target cascades its grants.
Database digests replace raw codes, cookies and nonces. The short-lived callback
record still contains the application return path, including its query.
