//! Resolving an unknown cw runtime request (0028, #4518): a later request may
//! add, once, what it observed in the Store, and a resolved request no longer
//! holds its environment's one unresolved slot. The upgrade keeps an unknown
//! request written by version 22 blocking until it is resolved.

use super::*;

const ENV: &str = "550e8400-e29b-41d4-a716-446655440023";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb23";

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

/// The SQLSTATE of a refused statement, or `None` when it succeeded. Each
/// runs alone, so one refusal cannot abort a later statement.
async fn refused(pool: &PgPool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(sqlx::Error::Database(error)) => Some(error.code().unwrap_or_default().into_owned()),
        Err(error) => Some(error.to_string()),
    }
}

/// One request row of `phase`, as the journal writes it.
async fn insert(pool: &PgPool, request: &str, phase: &str) -> Result<(), sqlx::Error> {
    let (checkpoint, effect, terminal, code) = match phase {
        "unknown" => (
            1,
            Some("staging"),
            true,
            Some("cw_runtime_dispatch_unknown"),
        ),
        _ => (0, None, false, None),
    };
    sqlx::query(
        "INSERT INTO environment_cw_runtime_requests \
           (request_id,organization_id,environment_id,actor_user_id,via_api_key,pod_uid, \
            fingerprint,request_json,binding_json,expected_store_generation,owner_id, \
            mutation_lease_id,phase,checkpoint,effect,error_code,issued_at,terminal_at) \
         VALUES ($1::uuid,'resolution-org',$2,'resolution-user',false,$3::uuid,repeat('a',64), \
            '{\"expected_store_generation\":\"1\"}'::jsonb, \
            jsonb_build_object('organization_id','resolution-org','environment_id',$2::text, \
                               'pod_uid',$3::text), \
            '1',gen_random_uuid(),'lease-'||$1,$4,$5,$6,$7, \
            CASE WHEN $5>0 THEN NOW() END,CASE WHEN $8 THEN NOW() END)",
    )
    .bind(request)
    .bind(ENV)
    .bind(POD)
    .bind(phase)
    .bind(checkpoint)
    .bind(effect)
    .bind(code)
    .bind(terminal)
    .execute(pool)
    .await
    .map(|_| ())
}

const UNKNOWN: &str = "00000000-0000-4000-8000-000000000001";
const NEXT: &str = "00000000-0000-4000-8000-000000000002";

fn resolve(request: &str, resolution: &str, by: &str) -> String {
    format!(
        "UPDATE environment_cw_runtime_requests SET resolved_at=NOW(),resolution='{resolution}',\
         resolved_by_request_id='{by}',resolution_selection='{{\"generation\":1}}' \
         WHERE request_id='{request}'"
    )
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn cw_runtime_resolution_upgrade_frees_a_resolved_unknown_request_once() -> anyhow::Result<()>
{
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        let mut connection = PgConnection::connect(&db.url).await?;
        through(22).run(&mut connection).await?;
        connection.close().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db.url)
            .await?;
        insert(&pool, UNKNOWN, "unknown").await?;
        let previous = fingerprint(&pool).await?;
        through(28).run(&pool).await?;
        anyhow::ensure!(fingerprint(&pool).await? != previous);

        // The unknown request written before the upgrade still holds its slot.
        let held = insert(&pool, NEXT, "admitted")
            .await
            .expect_err("slot held");
        anyhow::ensure!(
            held.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505"),
            "{held}"
        );
        // A resolution changes nothing else, and never names its own request.
        for (label, sql) in [
            (
                "with another change",
                format!(
                    "UPDATE environment_cw_runtime_requests SET resolved_at=NOW(),\
                     resolution='unchanged',resolved_by_request_id='{NEXT}',\
                     resolution_selection='{{}}',error_code='other' WHERE request_id='{UNKNOWN}'"
                ),
            ),
            ("by itself", resolve(UNKNOWN, "unchanged", UNKNOWN)),
            ("with an unknown outcome", resolve(UNKNOWN, "maybe", NEXT)),
            (
                "partly",
                format!(
                    "UPDATE environment_cw_runtime_requests SET resolution='unchanged' \
                     WHERE request_id='{UNKNOWN}'"
                ),
            ),
        ] {
            anyhow::ensure!(
                refused(&pool, &sql).await.as_deref() == Some("23514"),
                "a resolution {label} was accepted"
            );
        }

        anyhow::ensure!(
            refused(&pool, &resolve(UNKNOWN, "unchanged", NEXT))
                .await
                .is_none()
        );
        anyhow::ensure!(
            refused(&pool, &resolve(UNKNOWN, "applied", NEXT))
                .await
                .as_deref()
                == Some("23514"),
            "a resolution was replaced"
        );
        anyhow::ensure!(
            refused(
                &pool,
                &format!(
                    "DELETE FROM environment_cw_runtime_requests WHERE request_id='{UNKNOWN}'"
                )
            )
            .await
            .as_deref()
                == Some("23514"),
            "resolved evidence was deleted"
        );
        // The slot is free, and only an unknown request takes a resolution.
        insert(&pool, NEXT, "admitted").await?;
        anyhow::ensure!(
            refused(&pool, &resolve(NEXT, "unchanged", UNKNOWN))
                .await
                .as_deref()
                == Some("23514"),
            "an admitted request was resolved"
        );
        let resolved: (String, Option<String>) = sqlx::query_as(
            "SELECT resolution, resolved_by_request_id::text FROM environment_cw_runtime_requests \
             WHERE request_id=$1::uuid",
        )
        .bind(UNKNOWN)
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(
            resolved == ("unchanged".into(), Some(NEXT.into())),
            "{resolved:?}"
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
