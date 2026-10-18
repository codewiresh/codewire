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
authority. The first file is the reviewed squashed `0001_baseline.sql` (see
"The baseline" below); every later schema change is a new immutable migration in
the same directory.

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

### The baseline

The pre-launch history of 41 migrations was squashed into the single
`0001_baseline.sql` (schema fingerprint
`6a6a17eb52120fa37b56eef07bff233eed562ddd5f9dc755191381bbf77e3401`, measured
before and after the squash). It holds the complete application schema,
including the privileges that keep the `codewire_*` authority helpers private,
and the billing catalog reference rows. It was generated from the old history
with `pg_dump --schema-only` plus the three seeded catalog tables, applied to
an empty database, and checked for the same fingerprint, the same privileges and
the same table, function and constraint definitions.

No database that applied the earlier history can run this source: the ledger
would name versions that no longer exist and `ensure_schema` fails closed. Hosted
and local databases were disposable at the squash and were recreated from empty
state; to reset one, recreate only the application `public` schema and run
`codewire-db-migrate`. The PostgreSQL cluster, other databases and external
secret material stay outside that boundary. Every later change is a new
immutable migration after the baseline, with its own focused database proof.

Database-backed tests live in `crates/codewire-server-core/src/migrate.rs` and
its `migrate/tests` modules: the baseline checksum pin, fresh apply with the
accepted fingerprint and a no-op second run, concurrent startup, checksum-drift
and dirty-ledger refusal, and the constraint, trigger, privilege and concurrency
behavior of the schema. A migration that changes behavior adds its upgrade test
next to the migration, from the shape before it.

## Mesh Database

Mesh uses:

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
That mode runs its suites in four lanes (`core`, `credential-service`,
`credential-broker`, `orchestration`), each in order against its own
PostgreSQL. Add a suite to the lane of the crate it tests, and its harness to
`build_database_suites`. Against one explicit database the lanes run one after
another.

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
