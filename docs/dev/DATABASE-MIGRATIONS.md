# Database Migrations

Codewire has two intentionally separate PostgreSQL schema histories:

| Database | Canonical migration history | Runtime owner |
|---|---|---|
| Primary application database | `crates/codewire-server-core/migrations` | Rust control-plane services through `codewire_server_core::migrate::ensure_schema` |
| Mesh database | `crates/codewire-mesh/migrations` | `codewire-mesh` through its own SQLx migrator |

The two histories must not be combined. Mesh table names and migration versions
are scoped to the Mesh database; they are not additions to the primary
application schema.

Hosted dev and production Mesh releases reference `codewire-mesh-db-app`, while
primary control-plane deployments reference `codewire-db-app`. Those distinct
Secret names record the intended wiring, but they do **not** prove that the live
Secret values resolve to separate databases. Verify the live boundary read-only
before the first Mesh rollout into a new database as described below.

### Hosted Database Topology

| Environment | CNPG Cluster | Namespace | App Secret | Instances |
|---|---|---|---|---|
| Dev | `codewire-mesh-db` | `dev` | `codewire-mesh-db-app` | 1 |
| Production | `codewire-mesh-db` | `prod` | `codewire-mesh-db-app` | 2 |

Infra owns both CNPG clusters and their Flux reconciliation. Source-owned Mesh
release inputs reference only the controller-generated Secret name and `uri`
key; rendered private desired state carries that reference without copying any
credential value. Dev is disposable at the environment level, but its database
keeps Mesh state durable across pod replacements and ordinary main deployments.
The separate Mesh PVC remains deliberately retained through the WS18
convergence work; it is not a substitute for the PostgreSQL store. Do not
remove or recreate it merely because the retired native Mesh SSH relay no
longer writes a host key there.

## Primary Application Database

`crates/codewire-server-core/migrations` is the only application-schema
authority. The first file is the reviewed pre-launch `0001_baseline.sql`;
every later schema change is a new immutable migration in the same directory.

### Runtime

Rust control-plane services run the SQLx native migrator on startup through
`codewire_server_core::migrate::ensure_schema`.

The entrypoint is intentionally a thin call to SQLx. It uses:

- one `sqlx::migrate!` owned by `codewire-server-core` over its `migrations` directory;
- SQLx's standard `_sqlx_migrations` table;
- SQLx checksum validation;
- SQLx Postgres advisory locking;
- SQLx dirty-migration detection.

Services run that same entrypoint on startup, and local/CI/Kind bootstrap may
invoke the `codewire-db-migrate` binary from the services image. Do not load a
schema snapshot, hand-edit `_sqlx_migrations`, infer an existing schema shape,
ignore missing history, or add another migration implementation. If migrations
become unsuitable for service startup, design a checked-in deploy phase
explicitly and keep the same SQLx history and engine.

### Adding a Primary Application Migration

1. Add a new immutable `NNNN_description.sql` file under
   `crates/codewire-server-core/migrations`.
2. Run it forward through standard SQLx; never edit an already-applied file.
3. Add or extend DB-backed tests for the new and immediately preceding shape.
4. Do not create a parallel full-schema snapshot or non-SQLx runner.
5. Run the bounded database verification:

   ```sh
   DATABASE_URL='postgres://...?sslmode=disable' \
     DATABASE_URL_RUST='postgres://...' \
     scripts/ci/verify/run-integration-verification.sh database
   # Focused iteration before the full database mode:
   TEST_DATABASE_URL='postgres://...' \
     cargo test -p codewire-server-core --lib migrate:: -- --ignored --nocapture
   ```

The database gate creates throwaway databases, requires explicit nonzero test
counts, proves fresh apply and a second no-op run, and keeps checksum, dirty
ledger, missing-history, concurrent-startup, and accepted-schema fingerprint
failures mechanical.

### Canonical ProjectSpec cutover

Migration `0016_canonical_project_spec.sql` is a deliberate pre-launch clean
break. Before changing any table, it requires `environment_presets`,
`environments`, `repo_configs`, `user_login_keys`, `user_ssh_keys`,
`user_git_credentials`, `github_oauth_states`, and `user_github_tokens` to
contain no rows. It also rejects the exact legacy SSH and Git credential keys
if their metadata is already absent. It does not translate those products or
retain a second runtime representation. The migration locks all checked tables
before the preflight, then versions the surviving `tenant_secrets` rows so an
old writer queued behind the lock cannot recreate retired material. Current
writers explicitly write storage contract version 1; an omitted version fails
closed. Once the preflight succeeds, the migration removes the retired
project-intent columns and their foreign keys, adds one non-null `project_spec`
JSONB column to each environment-intent table, removes the raw
`environments.auth_token` credential column, and drops all five retired account
credential metadata tables.
It also removes `sandbox_template_config.warm_pool_size`; the applied baseline
remains byte-for-byte unchanged so SQLx can validate existing migration history
before applying this clean break. Shared warm starts remain unsupported.
Auto-created image presets receive a nullable internal image identity with a
partial organization-scoped unique index. The API writes that identity, the
canonical preset, and its runtime template projection in one transaction, so
concurrent image resolution converges on one preset and a projection failure
cannot leave divergent state.

The lock and writer-version fence make rolling overlap safe from silent data
loss, but an old process can return errors for secret mutations after migration
16 commits. An older binary is not supported against a ledger containing
migration 16. If rollback is required, do not create an in-place down migration:
recreate only the disposable application `public` schema and activate the
selected prior source release so its embedded migration history is applied from
empty state. The PostgreSQL cluster, other databases, credentials, and external
secret material remain outside this rollback boundary.

### Typed platform credential storage

Migration `0018_platform_credentials.sql` adds two tables without translating
or importing another credential representation:

- `platform_credentials` contains typed, non-secret metadata. Each row belongs
  to exactly one existing user or organization. Display names are unique,
  ignoring case, within that owner. Authentication kind, status, expiry and
  positive revocation/material versions are constrained by the database.
- `platform_credential_material` contains one protected envelope per
  credential, using only the OpenBao Transit KEK provider. The ciphertext,
  nonce, wrapped DEK and format/version fields have explicit size and range
  constraints. A composite foreign key requires its material version to match
  the metadata row. Metadata contains no protected reference or plaintext.

The placement library prepares the new envelope before acquiring database
locks. Replacement then deletes the old material, updates the owner-fenced
metadata version and inserts the matching envelope in one transaction. The
foreign key is immediate, not deferred; mixed versions cannot be committed.
Deleting a credential, user or organization cascades to its protected material.
This does not delete the shared OpenBao key or generic workload-secret DEKs.
Storing credentials does not select how a workload receives access to them.

The migration tests pin the accepted versions 1–17 from canonical
`b794652d12ed1732215f0dc93b69a87dd87ffe46` and the accepted version-17 schema
fingerprint. This proves deployment-history integrity, not compatibility with
retired runtime models. Fresh apply and 17→18 upgrade use the standard SQLx
migrator; upgrade retains unrelated current user/organization rows, creates
empty credential tables, and preserves the exact prior ledger. A second run
must leave both the ledger and synthetic credential rows unchanged. Constraint
proof covers owner/name isolation, envelope bounds, generation mismatch,
transaction rollback and owner deletion cascades.

There is no in-place down migration. For a rollback to version 17, stop the
new credential writers and use the selected prior source release with an
empty, disposable application `public` schema. Resetting that schema discards
its credential records; it does not retain or translate their material.
The rollback test proves that replay ends at the accepted version-17 ledger
and schema and leaves a separate schema untouched. PostgreSQL clusters, other
databases/schemas, credentials and external OpenBao key material are outside
this reset boundary. This documents the boundary; it does not authorize a live
database reset or a migration-ledger rewrite.

### Platform access profiles and OAuth refresh coordination

Migrations `0019_platform_access_profiles.sql` and
`0020_platform_credential_refresh_attempts.sql` extend version 18 without
changing its accepted bytes or translating any previous access model.

Profiles contain only credential identities and explicit capability slots.
Editing a profile creates a new immutable revision; an environment retains
its selected revision until explicitly rebound. Binding admission uses the
existing environment operation generation, not a new secret generation.
The profile store checks exact authorized user/organization scope and locks
the owner, environment and selected credential rows through publication.
Only current profiles and bound revisions prevent credential deletion; unused
history can retain a non-secret identity. Owner and environment teardown
cascades are covered by database tests.

OAuth rotation has one durable attempt per credential. A reservation expires
after 60 database-clock seconds only if the provider request has not started.
Starting consumes a non-cloneable permit and sets a 90-second database-clock
execution deadline. Only that permit can report failure before the deadline;
another replica may fail an unstaged attempt closed after the deadline. Staging
rechecks the deadline after SQL waits, so a late writer cannot win against
abandonment. This is a write fence, not process-death detection. A possibly
started request is never reassigned or replayed after timeout. An uncertain
result marks the credential
refresh-failed until explicit owner replacement. A fresh wrapped DEK is
prepared before request start; encryption and durable result staging need no
further OpenBao call. Recovery authenticates the staged envelope outside DB
locks, then rechecks exact owner, versions, hard deadline and envelope bytes
before atomic promotion. An OpenBao outage retains staging for later recovery.
Neither staging nor a publication receipt authorizes a workload request.
Metadata-only discovery lets a new replica find the exact saved attempt without
knowing its UUID in advance. Staged and published outcomes remain recoverable
after the execution deadline; recovery never creates a new send permit.
This coordinates provider operations; it cannot make an external OAuth server
and PostgreSQL one atomic transaction or guarantee exactly-once delivery.

The upgrade fixture pins the complete accepted versions 1–18 from canonical
`69ee44b90badf36ddfb39751ced2f95aa78e4d62` and its schema fingerprint. It proves
18→20 retains existing metadata and encrypted material, creates empty access
tables and leaves a second startup unchanged. There is no down migration or
legacy writer. Rollback to version 18 requires stopping new writers and
recreating only the disposable application `public` schema using that prior
source's immutable history. It discards new records and leaves other schemas,
databases and external OpenBao keys outside the reset boundary. This is a
documented/tested recovery boundary, not authorization to reset live data.

### Restricted broker lock authority

Migration `0021_platform_broker_lock_authority.sql` adds exactly three
fixed-query functions: `codewire_platform_lock_owner(text,text)`,
`codewire_platform_lock_environment(text,text,text)`, and
`codewire_platform_lock_profile(text,text,text)`. They take SHARE locks on the
exact authorized metadata rows. PostgreSQL row locking normally needs UPDATE
privilege; these helpers let the broker keep the lifecycle fence without
permission to edit users, organizations, environments or profiles.
The helpers lock the scope supplied by the caller; they do not authenticate it.
The calling service must authorize that scope before using the store.

The canonical migration owner owns these SECURITY DEFINER functions. Every
object reference is schema-qualified, the search path is fixed to
`pg_catalog, pg_temp`, and PUBLIC execution is revoked in the same migration
transaction. No roles are created and no table privileges are granted here.
Deployment must separately grant only these exact EXECUTE signatures to the
restricted broker/enrollment login. That login must not own the functions or
be able to assume the migration owner's role. Profile management remains an
orchestration responsibility; credential CRUD and durable refresh transactions
retain their own ordinary table privileges. At this schema step application
secrets are not part of the broker role; migration 24 below adds a narrowly
granted encrypted projection reader.
A non-owner orchestration/profile-management login also needs the relevant
helper EXECUTE grants, since management operations retain these same owner and
metadata fences. Its existing management DML rights are not granted to the broker.

The 20→21 fixture independently pins migration bytes from the frozen
`14806fb3acb3566c19c95d2be0a293579cec165c` dependency, retaining the existing
canonical versions 1–18 pin. It checks unchanged history, credential rows,
envelopes and table schema, plus exact installed function signatures, bodies,
definer ownership, search path and ACLs. The existing table-schema fingerprint
does not include functions and is not used as their security proof. Separate
tests connect as real restricted PostgreSQL logins and exercise both permitted
operations and denied DML/DDL/role/function access, including concurrent locks.

There is no in-place downgrade. After stopping the new writers, rollback to
version 20 uses that prior source release with only the disposable application
`public` schema recreated. The fixture proves the three helpers and credential
records are removed while another schema survives. Cluster roles, other
databases and external OpenBao key material are outside this reset boundary.
These tests and instructions do not authorize live database access or reset.

### Personal binding consent and material-free profile locks

Migration `0022_platform_binding_consent.sql` adds nullable
`personal_owner_confirmed_by` to the existing environment binding row. It does
not populate consent from existing rows, credentials or membership. The profile
store writes the confirmed actor in the same transaction as the exact
environment/profile/revision selection. The actor must match the authenticated
environment creator and personal profile owner; a supplied ID is not identity
proof. Rebind replaces the choice instead of retaining it, and clear deletes
the row. Organization selections have no personal confirmation. Runtime checks
both the saved confirmation and current personal-credential policy. Metadata
inspection remains possible without confirmation, but does not grant access.
The existing environment operation generation remains the only lifecycle fence.

The same migration adds
`codewire_platform_lock_credential(text,text,text)`. This fixed SHARE helper
returns only credential metadata scoped by exact credential ID and owner.
Its canonical migration-owner identity, qualified relations, fixed
`pg_catalog, pg_temp` search path and same-transaction PUBLIC revocation match
the existing three lock helpers. Restricted profile-management and broker
logins need its exact EXECUTE grant. Profile management no longer needs any
credential UPDATE privilege just to fence metadata. Material reads and
credential lifecycle mutations remain broker/enrollment responsibilities;
broker roles still cannot edit owner, environment, profile or binding records.

The 21→22 proof pins accepted migration 21 from canonical
`c0921baf2cfeffbc627991b97fc3fcbb9f254bfb`, retaining the independent pins for
versions 1–20. It checks the unchanged prior ledger and protected bytes,
unconfirmed existing bindings, fresh schema, second-startup no-op, and exact
helper signature/body/definer/search-path/ACL authority. Real restricted-login
tests cover permitted profile management, forbidden credential lifecycle and
material access, hostile search paths, personal-policy denial, rebind/clear,
and atomic metadata observation behind environment locks.

There is no in-place downgrade or old-writer support. After stopping the new
writers, rollback to version 21 replays that source's history into only the
disposable application `public` schema. The test discards bindings and their
consent, removes the new helper, and retains a separate schema. This boundary
excludes other databases, cluster roles and OpenBao material and does not
authorize any live reset.

### Original OAuth authority through enrollment publication

Migration `0023_oauth_publication_authority.sql` adds one fixed
`codewire_lock_oauth_bearer_authority(text,text,text,timestamptz)` function and
does not change tables, token formats or existing rows. Long-running enrollment
retains the original OAuth token's digest, user, client and exact expiry. It
does not keep the raw bearer or substitute a newer token at publication.

The helper locks the exact user, enabled client and access-token rows in that
order with SHARE, then checks the original expiry using `clock_timestamp()`.
Transaction-start `NOW()` cannot prove freshness after a lock wait. The token
must retain its original identity/expiry and current `codewire.api` scope.
Prepare the protected envelope before taking these locks. Keep the original
authority fence and credential publication in one transaction; recheck expiry
after awaited work before commit. A lost commit acknowledgement is an unknown
outcome, not permission to revoke possibly stored credentials.

The migration owner owns the helper; its qualified queries, fixed
`pg_catalog, pg_temp` search path and immediate PUBLIC revocation match the
existing restricted lock boundary. Only the isolated enrollment login needs
the exact EXECUTE grant. It receives no user/client/token UPDATE authority and
no sessions, API-key bookkeeping, refresh-token, client-secret or signing-key
access. Migration creates no login or deployment grant.

The 22→23 fixture pins the previously qualified frozen migration22 bytes and
retains independent canonical history pins for versions1–21. It checks exact
prior ledger/credential/binding bytes, unchanged table fingerprint, the helper's
installed signature/body/owner/search path/ACL, and a second no-op startup.
Restricted-login tests cover original-token denial and publication/revocation
ordering. No pre-launch compatibility path or in-place downgrade is added.
Rollback requires stopping new writers and replaying version22 source into
only the disposable application `public` schema; its test preserves another
schema. Cluster roles, other databases and external OpenBao keys remain outside
this boundary. This is not authority for a live reset.

### Account-access revocation

Migration `0024_account_access.sql` adds `users.enabled` and an optional
operator-facing access reason. Existing users default to enabled. Changing an
enabled account to disabled atomically revokes browser sessions, authorization
codes, opaque OAuth access/refresh tokens, bound device grants, and pending
2FA challenges; it retires API keys. New capability inserts and subject-binding
application paths take the user lock before they write. The six corresponding
`user_id` indexes keep each revocation predicate bounded to the account being
disabled. A rolling predecessor transition may already hold its capability row,
so its database guard uses a non-waiting user lock and returns a retriable
lock-conflict result when disablement owns the account row. That avoids a
capability-to-user cycle while preserving the rule that an issuer which wins
first is purged and an issuer that arrives after disablement cannot issue
access.

The version-24 ledger is not compatible with starting a version-23 service.
SQLx must reject missing migration history; the trigger fence is only for
writers already participating during a rolling deployment, not executable
same-database source rollback. There is no in-place downgrade. After stopping
the new writers, rollback to version 23 recreates only the disposable
application `public` schema and replays the selected prior source's embedded
history. The rollback fixture proves that the account-access columns, triggers,
indexes, and version-24 helper replacement disappear while a separate schema
survives. The upgrade matrix pins version-23 bytes and proves index inventory,
both-order predecessor transitions, current device/2FA completion ordering, and
the no-resurrection boundary. It does not authorize a live reset,
migration-ledger rewrite, cluster change, or credential operation.

Before publication, the product branch's staged migrations 24–27 moved to
25–28 to preserve canonical account-access migration 24. The existing
projection, SSH and owner-source byte pins remain evidence for those unchanged
SQL sources at their new versions. Session migration 28 was composed with the
new enabled-account fence and has its own final bytes. None of these fixtures
describes an applied old-number ledger.

### Platform application environment projection

Migration `0025_platform_environment_projection.sql` is function-only and
retains the accepted versions 1–24. Its metadata helper exposes exact canonical
application-source/profile selectors and ordinary configuration key names,
never full `project_spec` or configured values. Its second helper takes SHARE
locks on the exact creator, active organization, membership, running environment,
backend, optional profile/binding and selected organization-owned project.
The helpers have fixed qualified queries, migration-owner SECURITY DEFINER
ownership, fixed `pg_catalog, pg_temp` search paths, and immediate PUBLIC
execution revocation. They are not authentication: the isolated service must
still verify exact live gateway/workspace Pod identities, their original
expiry, lineage, positive operation generation and current canonical selection.

Deployment grants only the two exact EXECUTE signatures and the encrypted
reader column lists in `tests/e2e/kind/credential-broker.sql`. No application
secret writes, full configuration reads, generic plaintext getter or new store
are granted. The existing OpenBao workload identity additionally needs the
corresponding tenant-scope unwrap authority; synthetic Kind proof does not
establish Dev provisioning. The application reader holds the existing tenant
scope advisory locks while selecting bounded key inventories and winning
envelopes, decrypts outside SQL locks, then revalidates authority and exact
inventory/envelope/DEK bytes under the same locks before recipient-bound sealing.
The existing environment operation is the only generation.

Upgrade fixtures independently pin migration 24 from accepted canonical
`7dfd53dfd93ed56f7564111a4eba9fc0a730cef3`, retain the existing pins for 1–23,
and check exact prior ledger and protected bytes, installed function bodies,
owner/search-path/ACL, unchanged table fingerprint and second-startup no-op.
A deliberate function collision proves failed application rolls back both DDL
and migration ledger changes. There is no in-place downgrade. Stop new readers
and replay version-24 source into only the disposable application `public`
schema to roll back; the fixture preserves a separate schema. Other databases,
cluster roles and external OpenBao keys are outside this boundary. These
instructions do not authorize live resets or imply runtime delivery is enabled.

### Typed SSH credential enrollment

Migration `0026_platform_ssh_credentials.sql` adds the fresh `ssh_key`
authentication kind and nullable `ssh_public_key`/`ssh_fingerprint` public
metadata columns. The pair is required exactly for provider `ssh` and kind
`ssh_key`; other credentials retain NULL in both columns. Shape/size checks
reject partial pairs, comments, control bytes and unsupported public-key
prefixes. The isolated authority derives and cryptographically verifies the
public identity from the explicit key import or Ed25519 generation before
wrapping it with the existing credential envelope. It publishes public
metadata and protected material in one existing transaction. No previous key
representation is imported, and storage does not enable an SSH runtime grant.

Generic opaque creation/replacement rejects SSH. The dedicated prepared type
cannot be constructed from caller-asserted metadata. OAuth-authorized requests
retain their original deadline and authority through the existing publication
lock/COMMIT boundary. Cancellation never detaches a blocking crypto worker;
the tracked driver retains its capacity until that worker joins, discards late
results, and drains publication. Cleanup may exceed the original operation
deadline but cannot renew authorization. An uncertain COMMIT acknowledgement
requires owner-scoped metadata reconciliation, not automatic generation retry.

The existing restricted credential INSERT and public metadata SELECT grants
suffice. No public-key UPDATE, protected-material access for metadata readers,
new SECURITY DEFINER function, or change to the applied credential-lock
function is required. Profile metadata loading holds that exact existing SHARE
lock before its additional public-column read in the same transaction.

The 25→26 fixture is a **staged branch upgrade**, not a claim that version25
was deployed or merged. It pins the accepted projection component's version25
bytes (SHA-256 `12de82cd0afc166e15fa3d4dbcb18111ae2ef2b19fdf5c8bd9a4e9476414c975`,
PostgreSQL component proof session46208), while versions1–24 retain their
independent accepted history pins. It preserves all prior credential/envelope
bytes and function authority, proves the new fields remain NULL on old rows,
and checks second-startup no-op. Fresh-schema constraints, real restricted-role
publication/read/denial and a forced failure after additive DDL are separate
proofs. The current schema fingerprint must be measured from real disposable
PostgreSQL before acceptance; a pending marker is not successful proof.

There is no in-place downgrade. Stop new writers and replay the selected
version25 source into only an empty, disposable application `public` schema.
That rollback discards credential records rather than retaining or translating
SSH material. The test preserves another schema; cluster roles, other databases
and external OpenBao material remain outside the reset boundary. These
instructions do not authorize any live reset or direct credential access.

### Owner-authenticated source authority

Migration `0027_owner_source_authority.sql` adds only
`codewire_platform_lock_owner_source_authority(text,text,text)`. It takes SHARE
locks in the fixed order exact user, active organization, current nonempty-role
membership, then optional exact organization-owned secret project. A NULL
project means no selected project, not a wildcard. SHARE fences both deletion
and non-key authority changes. The function returns only a boolean and neither
reads secret values nor requires, creates or impersonates a platform environment
or Pod.

This helper is **not authentication**. The trusted caller must first retain
`OAuthBearerAuthority::lock_for_publication` for the original user/client/token
in the same transaction, then acquire this owner/source fence. Retain the
original cancellation/expiry deadline and recheck it after awaited work before
publication or release; acquiring locks cannot renew authorization. Application
source inventory/envelope locks and profile/credential revalidation remain
separate existing responsibilities. This schema step does not enable delegation
or grant a general material-read API.

The function has migration-owner SECURITY DEFINER ownership, fixed
`pg_catalog, pg_temp` search path, schema-qualified fixed queries and immediate
PUBLIC execution revocation in the SQLx migration transaction. It creates no
role and grants no table privileges. Provisioning must separately grant only
its exact EXECUTE signature to the trusted restricted authority login; that
login must not own the function or assume its owner's role. Existing helpers
and migration bytes 1–26 remain unchanged.

The 26→27 proof is a **staged branch upgrade**, not deployed or merged history.
It independently pins version26 from the accepted SSH PostgreSQL component
proof: SHA-256 `0359fcfeeccffe93be57dcbafedb98a3f37ae7123bfddcc284de4f49b62d2483`,
SHA-384 `a1fa99436ba0690f41f8e90f2152dcec9253c263e73086104b7de23efd12d0a09a7b6d9d93d87c299658f817bb311edf`.
Versions1–25 retain their previous independent pins. The fixtures check fresh
apply, exact prior ledger/rows/envelopes and function definitions, the existing
unchanged table fingerprint, and second-startup no-op. Separate real restricted
login checks cover allowed/denied scope, absence of direct table authority,
function ownership/ACLs, hostile temporary objects/search paths, and observed
concurrent row-lock ordering for revocation and project deletion. A synthetic
disposable-database event trigger forces failure after function creation to
prove DDL and ledger rollback before a successful retry. Test execution requires
the existing isolated database fixture administrator with role/event-trigger
creation authority; authored tests are not database acceptance evidence.

There is no in-place downgrade. After stopping new callers, rollback replays
the selected version26 source into only an empty, disposable application
`public` schema. The test proves removal of the new helper and credential rows,
restoration of the prior schema/functions, and preservation of another schema.
Other databases, cluster roles and external OpenBao keys are outside this reset
boundary. These instructions authorize no live reset or direct credential use.

### Browser-session credential-mutation authority

Migration `0028_credential_session_mutation_authority.sql` adds two fixed
SECURITY DEFINER helpers. `codewire_authenticate_credential_session(text)`
performs the existing digest-only, enabled-account live-session validation and eight-hour
sliding update while returning only the exact row identity, user, administrator
flag and post-slide expiry. `codewire_lock_credential_session_authority(...)`
locks user then exact session in the credential publication transaction.

The isolated credential login receives only exact EXECUTE grants, never direct
session-table SELECT or UPDATE. The process retains the row ID, digest, user
and captured expiry, not the cookie. Later authentication may extend the stored
expiry, so publication accepts a current expiry at least as late as the
captured value, while both wall and monotonic operation deadlines remain fixed.
Deletion by logout makes the publication lock fail; deletion racing an already
held SHARE lock serializes after that publication. Existing OAuth publication
and OAuth-only delegation are unchanged.

This staged 27→28 change adds no tables or credential formats and does not
rewrite versions 1–27. Its upgrade fixture independently pins migration 27's
SHA-384 from accepted canonical
`f0340e08f72d0bb9066e6f3c2ef1529beee4c911`; that is a staged predecessor-byte
boundary, not a claim that version 27 alone was deployed. The fixture preserves
the exact prior ledger, representative session and protected application-secret
and credential rows, and every prior `codewire_` helper definition. It requires
the second startup to be a no-op. Fresh-schema proof checks helper
inventory/search-path/ACL, fixed-expiry, sliding-session and logout behavior; the
restricted deployment proof separately grants only the two exact EXECUTE
signatures. A disposable-database event trigger fails only after both new
helpers have been created, proving that SQLx rolls back both helpers and the
ledger before a successful retry.

There is no in-place downgrade. After stopping new credential-mutation callers,
rollback replays the selected version-27 source into only an empty, disposable
application `public` schema. The fixture proves both session helpers are absent,
the exact prior helper definitions and ledger are restored, credential records
are discarded, and a separate schema survives. Other schemas, databases, cluster
roles and external OpenBao key material remain outside this boundary. These tests
and instructions authorize no live reset;
authored fixtures are not acceptance evidence until executed against the
checked-in disposable PostgreSQL topology.

### GitHub singleton included in every personal profile

Migration `0029_github_singleton_profiles.sql` makes GitHub one account-level
connection. Each user has at most one active GitHub App OAuth credential, and
every personal access profile includes it. A profile never stores a GitHub
credential ID. Launch authority resolves the user's current active, unexpired
connection at use time. When none exists, GitHub is omitted rather than
fabricated and the product shows it as missing; a later reconnect restores it
for every profile without a new revision. Organization profiles cannot hold a
GitHub connection.

The migration runs in one transaction:

1. It fails closed with SQLSTATE `23514` when any user has more than one active
   GitHub OAuth credential. It never chooses a winner, and nothing is rewritten.
2. It deletes every `github` profile entry on current and historical revisions
   and adds a check constraint so no future entry can use the `github` slot.
   No revision is created.
3. It deletes obsolete non-active GitHub OAuth credentials. Their protected
   material and refresh rows go through the existing `ON DELETE CASCADE`
   foreign keys. Profile entries carry no credential foreign key, and none
   remain for GitHub.
4. It adds the partial unique index
   `platform_credentials_user_github_singleton_key` on active user-owned GitHub
   OAuth credentials.

No new column or grant is required: the restricted reader already selects the
`platform_credentials` provider and authentication columns.

This staged 28→29 change does not rewrite versions 1–28. Its upgrade fixture
independently pins migration 28's SHA-384 from accepted canonical
`01c315c18bd48dd4a0b80226f32d904ee311cfab`; that is a staged predecessor-byte
boundary, not a claim that version 28 alone was deployed. The fixture seeds
legacy `github` entries on current and historical revisions, one revoked and one
active GitHub credential, and an unrelated Codex entry. It proves that only the
non-GitHub entries remain, that no revision is created, that the revoked row is
removed and the active one kept, that a new `github` entry and a second active
connection are both rejected, and that the second startup is a no-op. A separate
fixture seeds two active connections for one user and proves the migration
fails, leaves the ledger, entries and credentials unchanged, and succeeds once
the ambiguity is resolved.

There is no in-place downgrade. After stopping new profile and credential
writers, rollback replays the selected version-28 source into only an empty,
disposable application `public` schema. The fixture proves the ledger and
migration 28 checksum are restored, the singleton index is absent, credential
records are discarded, and a separate schema survives. Replaying version 28
restores the pre-0029 table fingerprint pinned as
`ACCEPTED_PRE_GITHUB_SINGLETON_SCHEMA_FINGERPRINT`. Other schemas, databases,
cluster roles and external OpenBao key material remain outside this boundary.
These tests and instructions authorize no live reset.

### Per-session two-factor setup skip

Migration `0030_two_factor_setup_skip.sql` adds one nullable
`sessions.two_factor_setup_skipped_at` timestamp. It records that one browser
session chose **Set up later** (first labelled **Skip for now**) on the two-factor setup page. The choice ends
with that session: sign-out, revocation, expiry and account disablement delete
the row, and every newly created session starts with the column unset.
Enabling a factor clears it for all of the account's sessions. The IdP reports
`skip_2fa_setup` only for the current session of an account without an enabled
factor, and the terminal attach and session-control checks accept the same
session marker. An enrolled factor is never skipped at sign-in.

The upgrade fixture pins migration 29 at W1 branch head
`5991eabfdafb350c14c3e66960b507cfaf7fc8f6` as `ACCEPTED_STAGED29`, applies
versions 1–29, and proves the pre-0030 table fingerprint
`ACCEPTED_PRE_TWO_FACTOR_SKIP_SCHEMA_FINGERPRINT`. Upgrading keeps existing
sessions with the column unset, records the new application fingerprint, and a
second startup is a no-op. Services run the migrator at startup, so a version-29
binary cannot restart against a version-30 ledger.

There is no in-place downgrade. Rollback replays the selected version-29
source into only an empty, disposable application `public` schema. The fixture
proves the ledger and migration 29 checksum are restored, the column is absent,
session records are discarded, the pre-0030 fingerprint returns, and a
separate schema survives. These tests and instructions authorize no live reset.

### Preview browser authorization

Migration `0031_preview_browser_authorization.sql` adds two tables without
changing versions 1–30, previous rows, credential formats or existing helpers.
`preview_auth_challenges` stores bounded short-lived handoffs, with digests for
the nonce, client binding and optional one-use authorization code. Anonymous
starts use an encrypted stateless continuation; the application allocates a row
only after authenticated automatic handoff. Consumption retains the ID and
`consumed_at` tombstone until expiry, preventing the same continuation from
allocating a replacement code. A consumed row requires a bound code and cannot
record consumption after its challenge expiry.

`preview_browser_grants` stores only the digest of the preview capability,
bound to the exact session, organization, environment, port and host. Neither
table stores raw session cookies, authorization codes or preview tokens.

The database constrains lowercase SHA-256 digest shapes, host/path lengths,
the five-minute challenge ceiling, the complete optional session/code/expiry
tuple and one grant per originating session and exact preview scope. Grants
have no independent expiry; every use requires a live parent session and
current policy. Immediate foreign keys cascade after
session, port, environment or organization deletion; existing account
disablement removes sessions and therefore their preview capabilities. Exact
cross-resource ownership, canonical host/path validation, current audience and
membership, atomic code consumption and earlier runtime expiry remain the
application's responsibility; foreign-key existence alone is not authorization.
Challenge-expiry and parent/client indexes support bounded lookup and
retirement. This
migration grants no new role, privilege, provider material access or public
preview audience.

The 30→31 fixture independently pins the complete prior history and migration30
from accepted canonical `3ac1cfcb3b840aef5d96af55246897d552a094dd`.
The accepted version30 schema fingerprint remains separately pinned as
`ACCEPTED_PRE_PREVIEW_SCHEMA_FINGERPRINT`. Fixtures
cover fresh apply, retained sessions and protected application/credential rows,
unchanged prior helper definitions and ledger, second-startup no-op with saved
preview capabilities and consumed tombstones, constraints/indexes and all owner
cascades. A disposable database event trigger fails after both new tables exist,
proving SQLx rolls
back their DDL and ledger before a successful retry. These are database proof,
not evidence of deployed browser authorization or audience enforcement.

Because 0031 only adds two tables, it has an in-place rollback that keeps
every other row: stop the version-31 binaries, then in one transaction drop
`preview_browser_grants` and `preview_auth_challenges` and delete ledger
version 31 from `_sqlx_migrations`, then start the version-30 binaries. Open
preview grants are lost and are re-earned by opening the preview again. The
fixture `preview_down_restores30_in_place_and_keeps_every_other_row` runs that
exact statement and proves the accepted version-30 fingerprint, unchanged
rows, helpers and ledger, and a clean roll-forward. A full recovery remains
available: stop preview authorization writers, then replay
the selected version30 source into only an empty, disposable application
`public` schema. The rollback fixture proves removal of preview capabilities,
restoration of prior ledger/schema/helpers, discarded credential/session rows,
and preservation of a separate schema. Other databases, schemas, cluster roles,
and external OpenBao material remain outside this boundary. This documents a
recovery boundary and authorizes no live reset or direct credential access.

### Authenticator replacement

Migration `0032_two_factor_replacements.sql` is additive. It changes no
existing row, helper, credential format or earlier migration.

`two_factor_replacements` holds at most one pending replacement per account.
Each row belongs to the one browser session that proved the account, with a
foreign key to that session and to the user, and both cascade. It stores only
the encrypted pending secret, in the same base64 AES-256-GCM layout as
`two_factor.secret`; the database rejects a value too short to hold a nonce
and tag, or one outside the base64 alphabet. The database also enforces:

- a lowercase 32-hex identifier;
- a lifetime of at most ten minutes;
- between zero and five recorded confirmation attempts.

The existing `codewire_require_enabled_account()` trigger refuses an insert
for a disabled account. Account disablement deletes sessions, so it also
removes any pending replacement. The enrolled factor stays in `two_factor`
and keeps working until a code from the new authenticator verifies; the IdP
then swaps the secret and recovery codes in place in one transaction.

`two_factor.last_totp_step` is a nullable, non-negative `bigint`. It records
the newest TOTP time step that sign-in or a fresh proof accepted. A fresh
proof must use a later step, so a code already used to sign in cannot be
replayed to replace the authenticator or regenerate recovery codes. Upgrade
leaves the column NULL for existing factors.

**Compatibility.** Running version-31 pods ignore both changes: they never
read the new table or column. Old IdP pods answer the new routes with 404,
and the dashboard reports the controls as unavailable. As with every
migration, a version-31 binary cannot restart against a version-32 ledger.

**Fixtures.** The 31→32 fixture pins the staged history and migration 31's
SHA-384 from preview-login branch head
`da7bf6a031e98ffdf1df62bb8299d4947a13cdce`. Like the preview fixture, this is
a staged predecessor boundary, not a claim that version 31 alone was
deployed. The version-31 fingerprint stays pinned as
`ACCEPTED_PRE_TWO_FACTOR_REPLACEMENT_SCHEMA_FINGERPRINT`. The fixtures prove:

- fresh apply, every constraint, the trigger, the indexes and the one row per
  account;
- upgrade from version 31, with factors, sessions, challenges, credentials and
  secrets unchanged, no step invented, and a second startup that is a no-op;
- cascades on session deletion, account deletion and account disablement,
  each of which leaves the enrolled factor in place;
- a forced failure on the last statement, which rolls back the table, the
  column and the ledger, followed by a clean retry.

**Rollback.** Because 0032 only adds a table, its trigger and one nullable
column, it has an in-place rollback that keeps every other row:

1. Stop the version-32 binaries.
2. In one transaction, drop `two_factor_replacements`, drop
   `two_factor.last_totp_step`, and delete ledger version 32 from
   `_sqlx_migrations`.
3. Start the version-31 binaries.

Pending replacements are lost; their accounts keep the authenticator they
already had. The fixture
`two_factor_replacement_down_restores31_in_place_and_keeps_every_other_row`
runs that exact statement. It proves the version-31 fingerprint, unchanged
rows, helpers and ledger, and a clean roll-forward. The full recovery also
remains available: replay the selected version-31 source into only an empty,
disposable application `public` schema. Its fixture proves the ledger and
migration 31 checksum are restored, records are discarded, and a separate
schema survives. Other databases, schemas, cluster roles and external key
material remain outside this boundary. These tests and instructions
authorize no live reset.

### Runtime-dispatch lease environment scope

Migration `0033_runtime_dispatch_environment_scope.sql` adds one nullable,
opaque `organization_mutation_leases.environment_id`. It changes no existing
row, helper, index or earlier migration. A check allows a value only on an
`environment_runtime_dispatch` lease and rejects an empty one. There is no
foreign key: leases stay as evidence after their environment and
organization rows are removed.

Environment-scoped runtime admissions (terminal, SSH proxy, daemon session
mutations and repair, ports, sources, resize, start, stop and delete) record
their target environment. Environment creation and every lease admitted before version 33
stay NULL, which keeps the original organization-wide meaning. External
cleanup of one environment (issue #2347):

- waits for an active lease scoped to it or NULL;
- waits for an ambiguous (`resolution_required`) lease scoped to it or NULL
  that settled after the current destroy attempt began proving runtime
  absence, so the next attempt proves absence again;
- resolves, in the same statement as its marker, its own ambiguous leases that
  settled before that proof began;
- ignores leases scoped to other environments, and leaves NULL-scoped
  ambiguity unresolved for organization deletion.

Organization deletion still refuses every active or unresolved lease,
whatever its scope. Lease expiry is never treated as absence.

**Compatibility.** Running version-32 pods insert NULL and ignore the column,
so their leases block like before and their cleanup keeps the stricter
organization-wide check. As with every migration, a version-32 binary cannot
restart against a version-33 ledger.

**Fixtures.** The 32→33 fixture pins migration 32 and the history through it
from accepted canonical `219a16e228ddb03697c2794ab43f58f44a9b1e9f`. The
version-32 fingerprint stays pinned as
`ACCEPTED_PRE_RUNTIME_DISPATCH_SCOPE_SCHEMA_FINGERPRINT`. The fixtures prove:

- fresh apply, the column type and nullability, and the check;
- upgrade from version 32 with every lease unchanged and unscoped, and a
  second startup that is a no-op;
- a forced failure after the column and check exist, which rolls back both and
  the ledger, followed by a clean retry.

**Rollback.** Because 0033 only adds one nullable column and its check, it has
an in-place rollback that keeps every lease:

1. Stop the version-33 binaries.
2. In one transaction, drop `organization_mutation_leases_environment_scope_check`,
   drop `organization_mutation_leases.environment_id`, and delete ledger
   version 33 from `_sqlx_migrations`.
3. Start the version-32 binaries.

Scoped leases become organization-wide again, which only makes version-32
cleanup wait for more of them; resolved leases stay resolved. The fixture
`runtime_dispatch_scope_down_restores32_in_place_and_keeps_every_lease` runs
that exact statement and proves the version-32 fingerprint, unchanged leases,
helpers and ledger, and a clean roll-forward that does not invent scope. The
full recovery also remains available: replay the selected version-32 source
into only an empty, disposable application `public` schema. Its fixture
proves the ledger and migration 32 checksum are restored, records are
discarded, and a separate schema survives. These tests and instructions
authorize no live reset.

### Workspace claim-time binding

Migration `0034_workspace_claim_time_binding.sql` is additive. It changes no
existing row, helper or earlier migration. It implements section 6 of the
[claim-time binding design](../plans/2026-09-30-workspace-claim-time-binding.md)
for Program #2238 (slice B1).

`sandbox_workspace_bindings` records which environment one exact workspace Pod
serves. The Pod UID is the primary key, so a Pod is bound to at most one
environment, ever. Each row also records the namespace and Pod name, the
SandboxClaim and Sandbox UIDs, the workspace PVC UID (NULL for a volume-less
workspace), the operation generation, the projection digest, the managed
credential clients, the credential scope (`environment` or `pod`), `bound_at`
and `released_at`. A partial unique index allows one live binding
(`released_at IS NULL`) per environment; released history may accumulate.
Rows cascade with their environment.

`sandbox_environment_backend` gains three nullable columns: `pod_uid`,
`bound_at` and `workspace_pvc_uid`. The composite foreign key
`sandbox_environment_backend_binding_fkey` lets `(environment_id, pod_uid)`
name only a binding of the same environment, and
`chk_sandbox_backend_binding_coherent` sets `pod_uid` and `bound_at` together.
No binding can be deleted directly (see the cascade-only trigger below).

Beyond the reviewed section 6 SQL, the migration also enforces:

- lowercase Kubernetes UID syntax for the claim, Sandbox and PVC UIDs in both
  tables (the backend `pod_uid` is covered by the foreign key);
- `released_at >= bound_at`;
- the `codewire_workspace_binding_immutable` trigger, which makes a binding
  insert-only except `released_at`. A release may be recorded once and never
  cleared or moved, so Pod UID → environment is immutable in the database and
  not only in orchestration code;
- the `codewire_workspace_binding_cascade_only` trigger on the same function,
  which refuses a direct `DELETE`. A row leaves only through the cascade from
  its environment, which runs inside the foreign key's referential action and
  so reaches the trigger at `pg_trigger_depth() > 1`.

The function is a plain invoker function with a fixed search path, and
`PUBLIC` cannot execute it.

There is no backfill. Orchestration's recorder and its bounded backfill loop
write bindings and PVC UIDs later, under the operation-generation fence.

**Compatibility.** Running version-33 pods never read the new table or
columns, and their backend writes never name them. Existing backend rows keep
NULL pointers, which the `MATCH SIMPLE` foreign key ignores, and the existing
backend indexes are unchanged. The projection lock in migration 25 already
takes the backend row `FOR SHARE`, so a later pointer move is fenced against
in-flight projection. As with every migration, a version-33 binary cannot
restart against a version-34 ledger, so a code rollback is a forward revert
that keeps this migration.

**Fixtures.** The 33→34 fixtures pin migration 33's SHA-384 and the history
1–33 from accepted canonical main `761f9e9bdbdc35bb2210c514fa923ad9d432aefc`.
The version-33 fingerprint stays pinned as
`ACCEPTED_PRE_WORKSPACE_BINDING_SCHEMA_FINGERPRINT`. Earlier fixtures that
compare every `codewire_` helper exclude the new trigger function, which has
its own proof and replaces no prior helper. The fixtures prove:

- fresh apply, with every constraint and its SQLSTATE: 23505 for a second
  environment on one Pod UID and for a second live binding per environment,
  23503 for a backend pointer to another environment's binding, 23514 for the
  UID, digest, scope, release-ordering and coherence checks, and 23502 for
  each required column;
- existing backend rows staying valid and writable with NULL pointers;
- the update trigger, which rejects each in-place change and accepts one
  release, and the delete trigger, which refuses a direct delete of a live,
  pointed-at or released binding;
- a restart-style pointer move inside one environment, and the cascade that
  removes an environment's backend row and all its bindings while leaving
  another environment intact;
- upgrade from version 33 with rows and helpers unchanged, no binding invented,
  and a second startup that is a no-op;
- a forced failure on the last statement, which rolls back the table, trigger,
  function, columns and ledger, followed by a clean retry.

**Rollback.** Because 0034 only adds a table with its trigger and function,
and three nullable backend columns with their constraints, it has an in-place
rollback that keeps every other row:

1. Stop the version-34 binaries.
2. In one transaction, drop the three backend constraints and columns, drop
   `sandbox_workspace_bindings` (which removes both of its triggers) and
   `codewire_workspace_binding_immutable()`,
   and delete ledger version 34 from `_sqlx_migrations`.
3. Start the version-33 binaries.

Recorded bindings are lost; a later roll-forward records them again. The
fixture `workspace_binding_down_restores33_in_place_and_keeps_every_other_row`
runs that exact statement. It proves the version-33 fingerprint, unchanged
rows, helpers and ledger, and a clean roll-forward. The full recovery also
remains available: replay the selected version-33 source into only an empty,
disposable application `public` schema. Its fixture proves the ledger and
migration 33 checksum are restored, records are discarded, and a separate
schema survives. Other databases, schemas, cluster roles and external key
material remain outside this boundary. These tests and instructions authorize
no live reset.

### Authority stamp

Migration `0035_platform_authority_stamp.sql` is additive. It changes no
existing row, helper, column or earlier migration. It is phase 12b of the
credential plan's authority stamp: every write to a row that runtime
credential authority reads advances a generation for that row's own scope, in
the writer's transaction. A broker can later read the generations of the
scopes behind one decision before and after it, and reuse the decision while
they are unchanged. Nothing reads the stamp yet; phase 12c adds that reader
behind a flag.

**Objects.**

- `platform_authority_generations(scope_kind, scope_id, generation)`, keyed by
  `(scope_kind, scope_id)`, and the sequence
  `platform_authority_generation_seq`. An absent row reads as 0.
- `codewire_platform_authority_row_changed()`, the SECURITY DEFINER trigger
  function. It keys only on the written row's own columns: no join, no
  fan-out. A bump is an upsert with a fresh sequence value
  (`ON CONFLICT DO UPDATE SET generation = nextval(...)`), not an append-log
  row, because sequence order is not commit order. An UPDATE that moves a row
  to another scope bumps the old and the new scope, in sorted order.
- `codewire_platform_authority_stamp(text[], text[])`, the SECURITY DEFINER
  reader. It returns the generations in request order, 0 for a scope never
  bumped, and `clock_timestamp()`. Malformed input returns no row: unequal or
  empty arrays, more than 16 scopes, a NULL, or any (kind, id) pair the
  generation table's scope CHECK would reject (an unknown kind, an empty id,
  a `global` id that is not empty, a `creds` id without its `user:` or
  `organization:` owner prefix). A wrongly built key is refused instead of
  reading a generation of 0 that never changes. A well-formed key of the wrong
  scope cannot be told apart by shape; 12c's end-to-end test covers that.
- `codewire_platform_authority_generation_retained()`, a plain invoker
  function behind BEFORE DELETE and BEFORE TRUNCATE triggers on the
  generation table. Rows are never deleted, so no scope can read 0 again
  after a bump.

Every function has a fixed `pg_catalog, pg_temp` search path and no PUBLIC
EXECUTE. Writers need no grant on the table or sequence. Only the credential
broker is granted EXECUTE on the reader: `tests/e2e/kind/credential-broker.sql`
here, and infra's `scripts/sql/codewire-dev-credential-database-grants.sql`
with its audit allowlist and preflight pins. That infra grant can apply only
after this migration has run in the target database.

**Scopes.** The trigger inventory is `STAMPED_TABLES` in
`codewire_server_core::authority_stamp`:

| Table | Scope bumped |
|---|---|
| `environments` | `env(id)` |
| `sandbox_environment_backend`, `sandbox_workspace_bindings`, `platform_environment_access_bindings` | `env(environment_id)` |
| `users` | `user(id)` |
| `org_members` | `user(user_id)` |
| `organizations` | `org(id)` |
| `secret_projects` | `org(org_id)` |
| `platform_access_profiles` | `profile(id)` |
| `platform_access_profile_revisions`, `platform_access_profile_entries` | `profile(profile_id)` |
| `platform_credentials` | `creds(user:<user_id>)` or `creds(organization:<organization_id>)` |
| TRUNCATE of any of them | `global` |

Each table has three triggers: `codewire_stamp_authority_row` (AFTER INSERT
OR DELETE), `codewire_stamp_authority_update` (AFTER UPDATE, only when a
column changed) and `codewire_stamp_authority_truncate` (statement level).
An UPDATE that changes no column bumps nothing. On `environments`, an UPDATE
that changes only billing's `last_billing_event_at` and
`total_running_seconds` bumps nothing either. That is a deny-list: any other
column, including one added later, bumps.

**Inventory guard.** The credential-service test
`every_relation_runtime_authority_reads_is_stamped` captures every statement
of a real resolve, `evaluate_grants` and the credential record read at the
wire, with and without a profile. It plans each with
`EXPLAIN (GENERIC_PLAN, VERBOSE)`, follows SQL-language SECURITY DEFINER bodies,
and pins PL/pgSQL helpers (`codewire_platform_lock_owner`) by source digest and
a reviewed relation list. It requires the relations read to equal
`STAMPED_TABLES` exactly, and no plan to name a billing column or read a whole
`environments` row. A new table or helper on that path fails it until the
stamp covers it.

**Lock order.** The triggers are AFTER triggers named to sort after every
other AFTER trigger on their tables, so for each row the generation row is the
last lock its triggers take. That holds per row, not per statement: a
statement that writes several rows bumps for each row as its events fire, and
holds each generation row while it goes on to lock later rows. Writers that keep the program-wide order (environment row,
then its backend and binding rows) already hold the environment row before any
`env` bump. The orchestration fixture
`db_stamp_triggers_never_deadlock_the_bind_transaction` runs the claim-time
bind transaction (`write_binding` under the recorder's fence) against
generation bumps, state-then-backend writes, backend-only writes, billing
updates and another user's credential and profile writes. It forces both lock
orders and runs 100 staggered concurrent iterations of each.
`db_stamp_triggers_add_under_a_millisecond_to_the_bind_transaction` bounds what
the three bumps per bind add.

**Compatibility.** Version-34 binaries never read the new objects, and their
writes fire the triggers without new grants. As with every migration, a
version-34 binary cannot restart against a version-35 ledger.

**Deploying.** The migration sets `lock_timeout` to 5 s, so it fails instead of
queueing every writer of a stamped table behind it while it waits for a long
transaction; the next service start retries it. It then takes every stamped
table's trigger lock in one `LOCK TABLE`, one table at a time in the
application's lock order (users, organizations, memberships, environments,
backends, bindings, environment profile bindings, profiles, revisions,
entries, credentials, projects), and creates the triggers in that order, so a
version-34 writer that keeps that order cannot deadlock with it.

**Fixtures.** The 34→35 fixtures pin migration 34's SHA-384 and the history
1–34 from accepted canonical main `a4d598aca65c1ffcfffa57cdae775df29e99473a`.
The version-34 fingerprint stays pinned as
`ACCEPTED_PRE_AUTHORITY_STAMP_SCHEMA_FINGERPRINT`. Earlier fixtures that compare
every `codewire_` helper or a table's triggers exclude this migration's
functions and triggers, which have their own proof. The fixtures prove:

- fresh apply, every trigger's exact definition and enabled state, function
  ownership, search path and ACL, the reader's order, zeros and malformed
  input, the retained-row guards, and that a missing key column fails the
  write;
- that every input row and column change, insert and delete advances exactly
  its own scope and nothing else, that a billing-only or no-op update advances
  nothing, and that TRUNCATE advances only `global`;
- that a restricted writer needs no grant, cannot read or write the
  generations, and that the startup probe reports a missing EXECUTE grant, a
  disabled trigger, and a login that could write the table or use the
  sequence;
- that the reader accepts exactly the (kind, id) pairs the table's CHECK
  accepts;
- upgrade from version 34 with rows, helpers and triggers unchanged, no scope
  backfilled, and a second startup that is a no-op;
- a forced failure after the last trigger, which rolls back every object and
  the ledger, followed by a clean retry.

**Startup probe.** `codewire_server_core::authority_stamp::verify_authority_stamp_schema`
reads only the catalog. It checks that the reader and trigger functions exist,
are SECURITY DEFINER with a pinned search path and have the exact source
migration 35 installed (SHA-256 of `prosrc`), that the calling login may
execute the reader but cannot write the generation table or use, read or set
its sequence, and that every expected trigger is present, enabled (`O` or
`A`) and has the exact definition `pg_get_triggerdef` gives with
`search_path = pg_catalog`. A PostgreSQL version that deparses a trigger
differently fails it closed until the expected text is reviewed. The broker
will call it before relying on a stamp (12c). It cannot detect writes made
while triggers were bypassed. The broker's audit (infra's
`codewire-dev-credential-database-audit.sql`) and the Kind ACL guard also deny
the broker every privilege on every `public` sequence: a broker that could
`setval` the generation sequence backwards could make a changed scope read an
old value again.

**When triggers were bypassed.** These writes do not bump: writes under
`session_replication_role = replica`, writes while a stamp trigger was
disabled with `ALTER TABLE ... DISABLE TRIGGER`, and a restore of the data
(including restores that disable triggers). Treat a point-in-time recovery and
a CloudNativePG asynchronous failover promotion as a restore: the promoted
replica can lack commits, and generation values, that a broker already saw.
A later migration that rewrites stamped data through DDL (a table rewrite, a
column default backfilled without row triggers) or that disables triggers must
bump the global scope in the same migration; phase 12d's AGENTS invariant
should say so. After such a write, either restart
every credential broker, which drops every cached decision, or, as the
migration owner, bump the global scope once the last such write has committed.
Every stamp includes the global scope. After a restore, first move the
sequence past every value it may have issued since the backup:

```sql
-- Only after a restore: values issued after the backup were lost with it.
SELECT pg_catalog.setval('public.platform_authority_generation_seq',
    GREATEST((SELECT last_value FROM public.platform_authority_generation_seq),
             (pg_catalog.date_part('epoch', pg_catalog.clock_timestamp()) * 1000000)::bigint));
-- Then, and after any bypassed write:
INSERT INTO public.platform_authority_generations (scope_kind, scope_id, generation)
VALUES ('global', '', pg_catalog.nextval('public.platform_authority_generation_seq'))
ON CONFLICT (scope_kind, scope_id) DO UPDATE
SET generation = pg_catalog.nextval('public.platform_authority_generation_seq');
```

Then confirm the triggers with the startup probe. The migration starts the
sequence at the database clock in microseconds, and bumps are far rarer than
microseconds, so the clock stays ahead of every issued value.

**For phase 12c.** These fixtures prove that every mutation changes the
generation of its own scope. 12c must also run each of the mutation fixture's
cases through its own tuple builder, for the environment whose decision it
caches, and assert that the built tuple changes, end to end, so a key built
for the wrong scope is caught.

**Rollback.** The migration adds only derived state, so it has an in-place
rollback that keeps every other row:

1. Stop the version-35 binaries.
2. In one transaction, drop the 36 `codewire_stamp_authority_*` triggers, the
   generation table (which removes its two guards), the three functions and
   the sequence, and delete ledger version 35 from `_sqlx_migrations`.
3. Start the version-34 binaries.

The fixture `authority_stamp_down_restores34_in_place_and_keeps_every_other_row`
runs that exact statement (`AUTHORITY_STAMP_DOWN`). It proves the version-34
fingerprint, unchanged rows, helpers, triggers and ledger, that version-34
writers keep working, and a clean roll-forward. Rolling forward starts the
sequence at the clock again and bumps the global scope at installation, so
every tuple read after it differs from every tuple read before the rollback,
although writes in between were not stamped. A broker reading the stamp must
fail closed while the reader is missing. Rolling forward recreates the reader
without the broker's EXECUTE grant, so run the infra grant reconcile again
afterwards; the startup probe reports the missing grant until then. The full recovery also remains
available: replay the selected version-34 source into only an empty,
disposable application `public` schema. Its fixture proves the ledger and
migration 34 checksum are restored, records are discarded, and a separate
schema survives. These tests and instructions authorize no live reset.

## Mesh Database

Issue #823 was implemented by PR #835. Mesh uses:

- `sqlx::migrate!` over `crates/codewire-mesh/migrations`;
- the Mesh database's own standard `_sqlx_migrations` table;
- SQLx checksum validation and dirty-migration detection;
- SQLx's Postgres migration advisory lock; and
- `codewire_server_core::db::connect` for the Mesh runtime pool.

The standard ledger name is safe because the Mesh history belongs to a
separate database. Do not introduce a custom ledger table or advisory-lock key
to make two unrelated histories coexist in one database. If the Mesh
connection reaches a database whose `_sqlx_migrations` rows belong to another
history, checksum/version validation must stop startup. The service must not
overwrite, relabel, ignore, or fall back to raw schema execution around that
conflict.

### Existing Mesh Baseline

`crates/codewire-mesh/migrations/001_initial_schema.sql` is already idempotent:
its tables and indexes use `IF NOT EXISTS`. The ledgered implementation uses
that file as migration version 1 for both supported starting shapes:

- On a fresh Mesh database, SQLx executes `001_initial_schema.sql`, creates the
  schema, and records the successful version and checksum.
- On an existing pre-ledger Mesh database, SQLx executes the same idempotent
  file. Existing objects are preserved, missing objects are repaired, and SQLx
  records the successful version and checksum only after execution succeeds.

Do not hand-insert a baseline row. Once the implementation starts recording
version 1, `001_initial_schema.sql` is immutable; every later Mesh schema change
gets a new forward-only migration in the same directory.

### Migration Verification

The DB-backed Mesh tests fail rather than silently skip and prove all of the
following:

1. A fresh throwaway Mesh database applies every registered migration and has
   the expected successful ledger count.
2. A database initialized with the current pre-ledger `001` schema gains the
   ledger without losing representative existing data.
3. Repeated startup is a no-op with the same migration count and checksum.
4. Concurrent Mesh startups serialize and converge on one successful ledger.
5. The registered migration versions are unique and ordered, and the expected
   migration count increases when a new migration is added.

Run those tests with `TEST_DATABASE_URL` against a dedicated throwaway database
and record the executed test count. Wire them into
`scripts/ci/verify/run-integration-verification.sh database`, then run that mode
locally. CI confirms the result; it is not the first integration environment.

### Network deletion

Mesh migration `007_network_deletion.sql` adds immediate foreign keys from
every remaining network-owned table. Registered nodes restrict deletion;
memberships, invitations, enrollments, groups, group policies/members, KV,
access grants and task events cascade with their network. Existing orphan rows
make the migration fail transactionally; it neither guesses ownership nor
discards data to satisfy the constraints.

Owner-authorized deletion locks the exact network, rechecks its organization
and owner membership, and refuses any registered node, including an offline
node. It then inserts a durable `retired_network_names` record and deletes the
network in the same transaction. Deleted names cannot be reused: existing
capabilities and coordinate streams identify a network by name, so admitting
a replacement would grant old authority access to new state. Creation checks
retirement after its insert has waited for any concurrent deletion. Enrollment
redemption and invitation joining lock their parent before child rows; the
foreign keys fence late writes across all server processes. Coordinate
sessions on the deleting process are closed, including delayed registration.

The upgrade fixture independently pins accepted versions 1–6 from canonical
`9a22ecb46f1f22fbefc83c1bcf7b7dd3fe296df3`. It proves retained rows and the
unchanged prior ledger, fresh apply, no-op restart, orphan rejection, metadata
cascades, nonempty refusal, name retirement, failure/cancellation rollback,
and concurrent enrollment/deletion/creation ordering using database locks.

There is no in-place downgrade or old-writer compatibility. Stop new writers
and replay the selected version-6 source into only an empty disposable Mesh
`public` schema to roll back. The fixture proves the old ledger is restored,
new records are discarded, and a separate schema survives. Cluster resources,
other databases/schemas and external credentials are outside this boundary;
this documentation authorizes no live reset.

### Hosted Rollout Preflight

Before the first Mesh rollout into a new hosted database, use the environment
kubeconfig for a strictly read-only check:

1. Resolve the `uri` values referenced by `codewire-mesh-db-app` and the
   primary application's `codewire-db-app` without printing credentials.
2. Compare only the database host/cluster identity and database name, and
   confirm that Mesh resolves to a database separate from the primary
   application history.
3. On the Mesh database, inspect whether `_sqlx_migrations` exists. If it does,
   record its versions, descriptions, success state, and checksums and prove
   that they belong to the Mesh history before rollout.
4. Confirm that the expected pre-ledger Mesh tables exist and that the database
   identity matches the checked-in deployment intent.

Do not create or modify a Secret, database, schema, table, or ledger row during
this preflight. If database separation cannot be proven, or an existing ledger
conflicts with the Mesh history, stop the rollout and correct the documented
topology before implementation proceeds.

Record the exact infra revision, deploy revision, source SHA, and Mesh image
digest with the preflight and post-rollout evidence. A rollback may disable the
workload connection, but it must retain the CNPG Cluster and PVC until the
database is explicitly retired through a separate reviewed operation.
