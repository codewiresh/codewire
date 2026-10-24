//! Environment Mesh attachment (0002): an upgrade from the baseline keeps
//! existing environments and adds empty tables whose constraints admit only
//! digests, bounded lifetimes and the closed status set, and that cascade
//! with their environment.

use super::*;

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

const ENV: &str = "mesh-env";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";

async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    sqlx::raw_sql(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('mesh-preset',\
         'credential-org-a','Mesh','mesh','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,name,state,desired_state,environment_operation_generation,project_spec) \
         VALUES('mesh-env','credential-org-a','credential-user-a','sandbox','mesh-preset','app-1','running','started',3,\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb);",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn environment_mesh_upgrade_keeps_environments_and_constrains_attachments()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        // The shape before 0002: the baseline alone, with an environment.
        let baseline = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(vec![
                MIGRATOR.iter().next().expect("baseline").clone(),
            ]),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        let mut connection = PgConnection::connect(&db.url).await?;
        baseline.run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new().max_connections(1).connect(&db.url).await?;
        seed(&pool).await?;
        let absent: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.environment_mesh_attachments') IS NULL",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(absent);

        ensure_schema(&db.url).await?;
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        let (environments, attachments): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM environments), \
                    (SELECT count(*) FROM environment_mesh_attachments)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!((environments, attachments) == (1, 0));

        sqlx::raw_sql(&format!(
            "INSERT INTO environment_mesh_attachments(environment_id,org_id,network_id,node_name,attached_by_user_id) \
             VALUES('{ENV}','credential-org-a','work','app-1','credential-user-a'); \
             INSERT INTO environment_mesh_enrollments(code_sha256,environment_id,pod_uid,operation_generation,org_id,network_id,node_name,expires_at) \
             VALUES(repeat('a',64),'{ENV}','{POD}',3,'credential-org-a','work','app-1',now()+interval '60 seconds');"
        ))
        .execute(&pool)
        .await?;
        // Each refusal in its own transaction.
        for (table, assignment, code) in [
            ("environment_mesh_attachments", "network_id='a b'", "23514"),
            ("environment_mesh_attachments", "network_id=repeat('n',129)", "23514"),
            ("environment_mesh_attachments", "node_name='-app'", "23514"),
            ("environment_mesh_attachments", "node_name=repeat('n',64)", "23514"),
            ("environment_mesh_attachments", "status='other'", "23514"),
            ("environment_mesh_attachments", "status='failed'", "23514"),
            ("environment_mesh_attachments", "failure='refused'", "23514"),
            (
                "environment_mesh_attachments",
                "status='failed',failure='other',status_pod_uid='7e7b20f6-0bd2-4f11-8b16-9c239851eb52',status_changed_at=now()",
                "23514",
            ),
            ("environment_mesh_attachments", "status='attached'", "23514"),
            (
                "environment_mesh_attachments",
                "status='attached',status_pod_uid='not-a-uid',status_changed_at=now()",
                "23514",
            ),
            ("environment_mesh_attachments", "environment_id='missing'", "23503"),
            ("environment_mesh_enrollments", "code_sha256='raw-code'", "23514"),
            ("environment_mesh_enrollments", "code_sha256=repeat('A',64)", "23514"),
            ("environment_mesh_enrollments", "pod_uid='pod'", "23514"),
            ("environment_mesh_enrollments", "operation_generation=0", "23514"),
            ("environment_mesh_enrollments", "expires_at=issued_at", "23514"),
            (
                "environment_mesh_enrollments",
                "expires_at=issued_at+interval '61 seconds'",
                "23514",
            ),
            (
                "environment_mesh_enrollments",
                "consumed_at=expires_at+interval '1 second'",
                "23514",
            ),
            ("environment_mesh_enrollments", "environment_id='missing'", "23503"),
        ] {
            let mut tx = pool.begin().await?;
            let error = sqlx::query(&format!("UPDATE {table} SET {assignment}"))
                .execute(&mut *tx)
                .await
                .expect_err("invalid Mesh attachment state accepted");
            anyhow::ensure!(
                error.as_database_error().and_then(|e| e.code()).as_deref() == Some(code),
                "{table}/{assignment}: {error}"
            );
            tx.rollback().await?;
        }
        sqlx::query(
            "UPDATE environment_mesh_attachments SET status='failed',failure='not_a_member', \
             status_pod_uid=$1,status_changed_at=now()",
        )
        .bind(POD)
        .execute(&pool)
        .await?;

        // Both go with their environment.
        sqlx::query("DELETE FROM environments WHERE id = $1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        let left: i64 = sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM environment_mesh_attachments) + \
                    (SELECT count(*) FROM environment_mesh_enrollments)",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(left == 0);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
