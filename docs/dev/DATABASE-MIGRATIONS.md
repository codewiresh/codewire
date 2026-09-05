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
