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
retain their own ordinary table privileges. Generic workload secrets are not
part of the broker role.
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
