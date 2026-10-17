//! Environment scope on runtime-dispatch leases: disposable database proof.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
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
