//! The owner of a runtime lease (0049, #4523): leases record the incarnation
//! of the process that admitted them, and each process keeps one heartbeat
//! row. Leases from before the upgrade carry none, and only an environment
//! runtime dispatch may carry one.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

fn through(version: i64) -> sqlx::migrate::Migrator {
    sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(
            MIGRATOR
                .iter()
                .filter(|migration| migration.version <= version)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    }
}

async fn lease(
    pool: &PgPool,
    id: &str,
    class: &str,
    owner: Option<i64>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO organization_mutation_leases \
           (id,organization_id,mutation_class,deadline_at,owner_incarnation) \
         VALUES ($1,'lease-owner-org',$2,NOW() + interval '60 seconds',$3)",
    )
    .bind(id)
    .bind(class)
    .bind(owner)
    .execute(pool)
    .await
    .map(|_| ())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn lease_owner_incarnation_upgrade_keeps_old_leases_unowned_and_scopes_owners()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(48).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        sqlx::query(
            "INSERT INTO users(id,email) VALUES ('lease-owner-user','lease-owner@example.test')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO organizations(id,name,slug,created_by) \
             VALUES ('lease-owner-org','Lease owner','lease-owner-org','lease-owner-user')",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO organization_mutation_leases \
               (id,organization_id,mutation_class,deadline_at) \
             VALUES ('lease-before','lease-owner-org','environment_runtime_dispatch', \
                     NOW() + interval '60 seconds')",
        )
        .execute(&pool)
        .await?;
        let previous = fingerprint(&pool).await?;
        through(49).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        let before: Option<i64> = sqlx::query_scalar(
            "SELECT owner_incarnation FROM organization_mutation_leases WHERE id='lease-before'",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(before.is_none(), "an old lease gained an owner");
        lease(
            &pool,
            "lease-owned",
            "environment_runtime_dispatch",
            Some(7),
        )
        .await?;
        let refused = lease(&pool, "lease-database", "control_plane_database", Some(7))
            .await
            .expect_err("an owner on another class was accepted");
        anyhow::ensure!(
            refused
                .as_database_error()
                .and_then(|error| error.constraint())
                == Some("organization_mutation_leases_owner_incarnation_check"),
            "{refused}"
        );
        lease(&pool, "lease-database", "control_plane_database", None).await?;
        // One heartbeat row per incarnation.
        sqlx::query("INSERT INTO lease_owner_heartbeats VALUES (7, LOCALTIMESTAMP)")
            .execute(&pool)
            .await?;
        let twice = sqlx::query("INSERT INTO lease_owner_heartbeats VALUES (7, LOCALTIMESTAMP)")
            .execute(&pool)
            .await
            .expect_err("a second heartbeat row for one incarnation");
        anyhow::ensure!(
            twice
                .as_database_error()
                .and_then(|error| error.code())
                .as_deref()
                == Some("23505"),
            "{twice}"
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
