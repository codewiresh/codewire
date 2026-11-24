# Sandbox identity: groups, audiences and minting

A hosted Sandbox can ask for a short-lived token that proves which
organization's Sandbox it is and which identity groups it is in, for one
verifier the organization registered: a Kubernetes cluster, an OpenBao or
Vault server, or a cloud's workload-identity federation. This page is the
contract for groups, audiences and minting (#4663, #4664). It was written
before the code. The issuer that publishes each organization's keys is in
[CONFIGURATION.md](../CONFIGURATION.md#sandbox-identity), and the journey is
[`docs/journeys/sandbox-identity.md`](../journeys/sandbox-identity.md).
Hosted Sandboxes only; local VMs and hosts come later, by a separate design.

**Status: target, not shipped.** Nothing below is built yet; each part's
journey step reads "not yet observed" until it has run on Dev.

## The token

A compact JWS, ES256, signed by the environment's OpenBao transit key:

- **Header:** `alg: ES256`, `kid: sandbox-identity-<version>`, `typ: JWT`, and
  nothing else: never `jku`, `x5u`, `jwk` or `x5c`.
- **`iss`:** `{issuer base}/orgs/<org id>`, the Sandbox's own organization.
- **`sub`:** `spiffe://<trust domain>/org/<org id>/sandbox/<environment id>`.
  The trust domain is `sandboxes.<deployment domain>`.
- **`aud`:** one string, the registered audience in its canonical form.
- **`iat`, `nbf`, `exp`:** `exp` is at most the registration's lifetime, and
  never more than 10 minutes, after `iat`.
- **`jti`:** 128 random bits, base64url.
- **`groups`:** `<org id>:all`, then `<org id>:<group>` for each of the
  Sandbox's groups the registration may see, sorted.
- **`codewire.sh`:** `org_id` and `sandbox_id`. `created_by` and
  `environment_name` only when the registration opts in to them. `created_by`
  is the creator's stable user ID, never an email address or a name.

No `nonce`, `auth_time`, `acr`, `amr`, `azp`, email or name. These are
workload identity tokens, not RFC 9068 access tokens.

## Groups

- **Who sets them:** an organization admin (`can_admin`) only. Nothing in a
  create request, `codewire.yaml` or the Sandbox sets them.
- **Names:** lowercase `[a-z0-9-]`, 1 to 63 characters, at most 32 on a
  Sandbox. Stored bare; the org ID is prefixed only in a token. `all` is
  reserved.
- **What a group means.** Everyone who can run code in the Sandbox can use its
  groups: its creator, members granted `operator` or `owner`, and every
  process inside it. Setting a group delegates the admin's trust to all of
  them, and `cw identity groups set` says so.
- **Gates:**
  - Presets can't carry groups yet; a preset with groups is refused.
  - A fork, duplicate or restore keeps the source's groups only when the actor
    is an admin of the organization. Otherwise it starts with none.
  - Moving a Sandbox to another organization clears its groups.
  - Hosted Sandboxes have no duplicate, restore or move between organizations
    today; a fork is a create from a snapshot. Each of those, when it is built,
    keeps groups only under the rule above, and is not built yet.
  - Granting `operator` or `owner` on a Sandbox that has groups needs an admin.
- **Effect:** a change applies to the next mint. Tokens already issued expire
  within their lifetime, at most 10 minutes.
- **CLI:** `cw identity groups NAME` lists a Sandbox's groups.
  `cw identity groups set NAME GROUP...` replaces them, and `--clear` removes
  them all.

## Audiences

An audience is a verifier the organization registered. A Sandbox can only get
a token for a registered audience.

- **Form:** an absolute `https` URI with no userinfo, query or fragment.
- **Canonical form:**
  - the scheme and host are lowercased, with the host as IDNA A-labels;
  - a default `:443` is dropped;
  - the path is kept exactly as written, trailing slash included.
  Registration stores it. A mint's `resource` is canonicalised the same way
  and must match exactly.
- **Refused at registration:**
  - any host equal to or under a domain the deployment serves: the hosts of
    `FRONTEND_URL` and `CODEWIRE_IDENTITY_ISSUER_BASE`, and
    `PREVIEW_BASE_DOMAIN`;
  - `kubernetes`, `kubernetes.default` and anything under
    `kubernetes.default.svc`;
  - IP literals, `localhost`, and link-local or private-address hosts.
- **Each registration carries:**
  - the groups the audience may see: all of them, or a named list;
  - a lifetime, 1 to 10 minutes, 10 by default;
  - the opt-in claims `created_by` and `environment_name`;
  - optionally a file name, for "project to file" (below).
- **Uniqueness:** an audience is registered at most once per organization.
  Two organizations may register the same one, because each token's `iss`
  names its own organization.
- **CLI, for org admins:**
  - `cw identity audience add URI [--groups G,...] [--lifetime 10m]
    [--claim created_by|environment_name] [--file NAME]`
  - `cw identity audience list`
  - `cw identity audience remove URI`

## Kill switches

- **One Sandbox, or a whole organization:** an org admin, or a platform
  operator, stops minting with `cw identity stop NAME` or `cw identity stop
  --org`, and resumes it with `cw identity resume`. Orchestration checks it
  before its cache, so a stopped Sandbox gets no new or cached token from the
  RPC. Inside the Sandbox, the daemon's socket cache and its `--file` files
  keep serving a token issued before the stop until half its lifetime.
- **Global circuit breaker:** `CODEWIRE_IDENTITY_MINTING=off` in
  orchestration's environment stops every mint with `unavailable`. It also
  trips by itself for 60 seconds after 20 consecutive signing failures.
- Tokens already issued stay valid until they expire, at most 10 minutes.
  This is not revocation.

## Minting

`WorkspaceBindingService.IssueIdentityToken(resource)`, on the binding
listener (8087), authenticated exactly as every binding call is: a TokenReview
of the Pod-bound token, and the caller's address matching the bound Pod's. Any
process in the Sandbox can read that token and call it, so every rule below is
enforced here, never in the daemon.

- **Response:** the token and its `expires_at`. Never logged.
- **Refusals:**
  - `invalid_argument`, `invalid_target`: the resource isn't an `https` URI,
    or isn't registered for the organization. One answer covers both, so a
    Sandbox can't probe which audiences another organization registered;
  - `failed_precondition`, `not_running`: the Sandbox isn't running;
  - `permission_denied`, `identity_stopped`: the organization is suspended or
    being deleted (its deletion state is anything but active, a failed
    deletion included), or the Sandbox's access is suspended: its creator's
    account is suspended. Like the kill switches, this is checked before the
    cache;
  - `permission_denied`, `identity_stopped`: a kill switch is on for the
    Sandbox or its organization;
  - `resource_exhausted`, `resource_exhausted`: a limit below;
  - `unavailable`, `identity_unavailable`: the circuit breaker is open,
    identity is off, or OpenBao can't sign;
  - `unavailable`, `key_not_yet_published`: no key version has been published
    for 24 hours yet. A new key signs nothing for a day, and minting never falls
    back to a younger version.
- **Limits**, separate from the binding's, so minting can't starve binding
  renewals:
  - per Sandbox: 30 a minute, burst 10, keyed by the caller's address, which
    authentication requires to be the bound Pod's;
  - per replica: 500 a second, burst 500;
  - a TokenReview semaphore of 16 of its own;
  - per organization: 3,000 a minute, burst 1,000.

  The per-Sandbox and per-replica limits, and the semaphore, refuse excess
  requests before any TokenReview. The organization is known only once the
  caller is authenticated, so its limit applies after the review and before
  the cache.
- **Cache:** keyed by Sandbox, canonical audience, the Sandbox's groups
  version and the registration's version. A cached token is returned until half
  its lifetime, so a repeat costs a TokenReview but no signature. A change to
  groups or to the registration misses the cache.
- **Signing:** the request to OpenBao names `key_version` from the newest
  version created at least 24 hours ago, and `marshaling_algorithm=jws`.
  OpenBao's own policy refuses a sign without `key_version`.
- **Mint log:** every mint, but not a cache hit, appends a row to
  `identity_mints`: environment, organization, audience, `jti`, `kid`, groups
  version and time. Never the token. Rows are deleted 30 days after the mint,
  and with their organization.

## In the Sandbox

- **The socket:** the daemon serves `/codewire/run/identity.sock`, mode 0600,
  as a platform socket that SSH socket forwards refuse. `GET
  /token?resource=URI` answers the token as `text/plain`. A refusal is a status
  with the refusal's name as the body: 400 for `invalid_target`, 403 for
  `identity_stopped`, 429 for a limit, and 503 for `identity_unavailable`,
  `key_not_yet_published` or `not_running`. It caches one token per audience
  until half its lifetime.
- **`cw identity token --resource URI`** prints the token on stdout with no
  newline. A refusal goes to stderr with its name and exits non-zero. Outside a
  cloud Sandbox, it says so and exits 2.
- **Files:** for an audience registered with `--file NAME`, the daemon keeps
  `/codewire/run/identity/NAME.jwt` current, renewed at half its lifetime. The
  directory is a tmpfs mounted at boot, mode 0700, with files at 0600. It is
  excluded from snapshots, VM checkpoints, environment projections, the files
  API, `cw cp` and sync, and previews, and a test holds each exclusion.
- **The shared uid isn't a boundary.** The workload runs as the daemon's user,
  so every process can read the files and call the socket. The limits and the
  groups rules above are what hold.
- **Logs** name the audience, never the token.

## Audit

Each of these writes an `audit_logs` row in the same transaction as the
change, with the organization's ID in its metadata:

- `identity.groups.changed`: the actor, the Sandbox, and the groups before and
  after;
- `identity.audience.registered` and `identity.audience.removed`;
- `identity.stopped` and `identity.resumed`;
- `environment.access.granted` on a Sandbox that has groups.

Mints are in `identity_mints`, not `audit_logs`. An organization's own view of
these records is not built yet (#4663).
