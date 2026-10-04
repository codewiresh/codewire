//! Environment scope on runtime-dispatch leases: accepted prior history and
//! disposable database proof.

use super::*;

const VERSION: i64 = 33;
// Measured from accepted canonical 219a16e228ddb03697c2794ab43f58f44a9b1e9f,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL32))
// and SHA384(SQL32).
const PRIOR_HISTORY32: &str = "3829827d665329b75541c536eeb3ed6b466a7ac8ce382584bad984f1e366727bf15749081aefa30b342d371d8e43d69f";
const PRIOR32: &str = "47d4b64c2ee4873bb656e8b1f094ddb22faa7da2289a062e6573a3e5e0d09119e8f3f9e0ee47f5c55c01c8f1a68310b9";

pub(super) fn assert_accepted_prior32() -> anyhow::Result<()> {
    two_factor_replacements::assert_accepted_staged31()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 32);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY32,
        "migration1..32 differs from accepted canonical 219a16e22"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[31].sql.as_bytes())) == PRIOR32,
        "migration32 differs from accepted canonical 219a16e22"
    );
    Ok(())
}

#[test]
fn runtime_dispatch_scope_upgrade_pins_the_accepted32_history() -> anyhow::Result<()> {
    assert_accepted_prior32()
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Every helper except migration34's workspace-binding trigger function and
/// migration35's authority-stamp functions, which have their own proof and
/// replace no prior helper.
async fn helpers(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n \
        ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
        AND p.proname <> 'codewire_workspace_binding_immutable' \
        AND NOT starts_with(p.proname,'codewire_platform_authority_') \
        ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)",
    )
    .fetch_all(pool)
    .await?)
}

/// Every pre-existing row this migration could touch. Leases are compared
/// without the new column, which upgrade leaves NULL.
async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for (table, projection) in [
        ("users", "to_jsonb(t)"),
        ("organizations", "to_jsonb(t)"),
        (
            "organization_mutation_leases",
            "to_jsonb(t) - 'environment_id'",
        ),
    ] {
        result.push(
            sqlx::query_scalar(&format!(
                "SELECT COALESCE(jsonb_agg({projection} ORDER BY ({projection})::text),'[]'::jsonb)::text \
                 FROM public.{table} t"
            ))
            .fetch_one(pool)
            .await?,
        );
    }
    Ok(result)
}

/// One lease in each state, across classes, as version 32 wrote them.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO users(id,email) VALUES ('lease-scope-user','lease-scope@example.test')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO organizations(id,name,slug,created_by) \
         VALUES ('lease-scope-org','Lease scope','lease-scope-org','lease-scope-user')",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO organization_mutation_leases \
           (id,organization_id,mutation_class,state,deadline_at,released_at, \
            resolution_required_at,resolved_at,recovery_code) VALUES \
         ('lease-scope-active','lease-scope-org','environment_runtime_dispatch','active', \
          NOW()+interval '60 seconds',NULL,NULL,NULL,NULL), \
         ('lease-scope-released','lease-scope-org','control_plane_database','released', \
          NOW()+interval '30 seconds',NOW(),NULL,NULL,NULL), \
         ('lease-scope-ambiguous','lease-scope-org','environment_runtime_dispatch','resolution_required', \
          NOW()+interval '60 seconds',NULL,NOW(),NULL,'environment_runtime_dispatch_ambiguous'), \
         ('lease-scope-resolved','lease-scope-org','billing_provider','resolved', \
          NOW()+interval '30 seconds',NULL,NOW(),NOW(),'billing_provider_ambiguous')",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn scoped_leases(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM public.organization_mutation_leases WHERE environment_id IS NOT NULL",
    )
    .fetch_one(pool)
    .await?)
}

async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' \
         AND table_name='organization_mutation_leases' AND column_name='environment_id') \
         AND NOT EXISTS (SELECT 1 FROM pg_constraint \
         WHERE conname='organization_mutation_leases_environment_scope_check')",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn runtime_dispatch_scope_fresh_schema_constrains_scope_to_runtime_dispatch()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(embedded_max_version()? >= VERSION);
        seed(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "runtime dispatch scope measured fingerprint: {measured}"
        );
        let column: (String, String) = sqlx::query_as(
            "SELECT data_type, is_nullable FROM information_schema.columns \
             WHERE table_schema='public' AND table_name='organization_mutation_leases' \
             AND column_name='environment_id'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(column == ("text".into(), "YES".into()), "{column:?}");
        // Each failure uses a separate transaction: one rejected statement must
        // not hide another assertion behind PostgreSQL's aborted-transaction state.
        for (lease, environment) in [
            ("lease-scope-released", "env-a"),
            ("lease-scope-resolved", "env-a"),
            ("lease-scope-active", ""),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(
                "UPDATE organization_mutation_leases SET environment_id=$2 WHERE id=$1",
            )
            .bind(lease)
            .bind(environment)
            .execute(&mut *tx)
            .await
            .expect_err("invalid lease environment scope accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23514"),
                "{lease}/{environment}: {error}"
            );
            tx.rollback().await?;
        }
        // Runtime dispatch leases in every state may name their environment,
        // which need not exist: leases outlive environment rows as evidence.
        sqlx::query(
            "UPDATE organization_mutation_leases SET environment_id='env-removed' \
             WHERE mutation_class='environment_runtime_dispatch'",
        )
        .execute(&pool)
        .await?;
        anyhow::ensure!(scoped_leases(&pool).await? == 2);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn runtime_dispatch_scope_upgrade_keeps32_leases_organization_wide_and_second_startup()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 32 && before[31].0 == 32);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_RUNTIME_DISPATCH_SCOPE_SCHEMA_FINGERPRINT
        );
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(
            after.len() == MIGRATOR.iter().count()
                && after[..32] == before
                && after[32].0 == VERSION
        );
        // Existing leases keep every value and gain no scope: their target is
        // unknown, so each stays organization-wide.
        anyhow::ensure!(rows(&pool).await? == original && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(scoped_leases(&pool).await? == 0);
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "runtime dispatch scope measured fingerprint: {measured}"
        );
        pool.close().await;

        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(rows(&pool).await? == original && scoped_leases(&pool).await? == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL with event-trigger creation"]
async fn runtime_dispatch_scope_failed_forward_rolls_back_column_and_ledger_then_retries()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        seed(&pool).await?;
        let original = rows(&pool).await?;
        // Fail after the column and its constraint exist.
        sqlx::raw_sql(
            "CREATE SCHEMA migration_failure; CREATE FUNCTION migration_failure.reject_scope() RETURNS event_trigger LANGUAGE plpgsql AS $$ \
             BEGIN IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname='organization_mutation_leases_environment_scope_check') \
             THEN RAISE EXCEPTION 'synthetic failure after lease environment scope'; END IF; END; $$; \
             CREATE EVENT TRIGGER lease_scope_failure ON ddl_command_end WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION migration_failure.reject_scope();",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        let error = ensure_schema(&db.url)
            .await
            .err()
            .context("forced migration33 failure accepted")?;
        anyhow::ensure!(format!("{error:#}").contains("synthetic failure after lease environment scope"));
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            absent(&pool).await?
                && applied_migrations(&pool).await? == before
                && rows(&pool).await? == original
        );
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_RUNTIME_DISPATCH_SCOPE_SCHEMA_FINGERPRINT
        );
        sqlx::raw_sql("DROP EVENT TRIGGER lease_scope_failure; DROP SCHEMA migration_failure CASCADE;")
            .execute(&pool)
            .await?;
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(
            !absent(&pool).await?
                && applied_migrations(&pool).await?.len() == MIGRATOR.iter().count()
                && rows(&pool).await? == original
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The documented in-place rollback: the migration only adds one nullable
/// column and its check, so removing them and the ledger row restores version
/// 32 without touching any lease. Scoped leases become organization-wide
/// again, which only makes version-32 cleanup wait for more of them.
const RUNTIME_DISPATCH_SCOPE_DOWN: &str = "BEGIN; \
    ALTER TABLE public.organization_mutation_leases \
        DROP CONSTRAINT organization_mutation_leases_environment_scope_check, \
        DROP COLUMN environment_id; \
    DELETE FROM public._sqlx_migrations WHERE version = 33; \
    COMMIT;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn runtime_dispatch_scope_down_restores32_in_place_and_keeps_every_lease()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        seed(&pool).await?;
        sqlx::query(
            "UPDATE organization_mutation_leases SET environment_id='env-scoped' \
             WHERE mutation_class='environment_runtime_dispatch'",
        )
        .execute(&pool)
        .await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 33 && ledger[32].0 == VERSION);
        sqlx::raw_sql(RUNTIME_DISPATCH_SCOPE_DOWN)
            .execute(&pool)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..32]);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_RUNTIME_DISPATCH_SCOPE_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(rows(&pool).await? == original);
        pool.close().await;
        // Rolling forward again applies 33 cleanly; the lost scope is not
        // invented back, so those leases stay organization-wide.
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        anyhow::ensure!(applied_migrations(&pool).await?.len() == MIGRATOR.iter().count());
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool).await? == original && scoped_leases(&pool).await? == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn runtime_dispatch_scope_rollback_replays32_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..32]);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=32 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == PRIOR32);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_RUNTIME_DISPATCH_SCOPE_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>(
                "SELECT NOT EXISTS(SELECT 1 FROM organization_mutation_leases) \
                 AND NOT EXISTS(SELECT 1 FROM organizations)"
            )
            .fetch_one(&pool)
            .await?
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, i32>("SELECT id FROM rollback_boundary.keep")
                .fetch_one(&pool)
                .await?
                == 1
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
