//! SSH host keys: disposable database proof for the host-key table, write-once
//! per bound Pod, its constraints and its cascade.

use super::*;

const ENV: &str = "host-key-env";
const OTHER_ENV: &str = "host-key-env-other";
const POD: &str = "7e7b20f6-0bd2-4f11-8b16-9c239851eb52";
// A Pod that replaces POD within the same generation, and the other
// environment's Pod.
const NEXT_POD: &str = "a1560db3-8899-40c9-b521-500f223b04fb";
const OTHER_POD: &str = "0b3c5d7e-1f2a-4b6c-8d9e-0f1a2b3c4d5e";
const FRESH_POD: &str = "c2d4e6f8-0a1b-4c3d-9e5f-6a7b8c9d0e1f";
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoVDsBGpvXjHq1Mc3BJ6ANWjUtpnGxFp1yfCaeHRu3T";

async fn connect(url: &str) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(1).connect(url).await?)
}

async fn fingerprint(pool: &PgPool) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(include_str!(
        "../../../tests/data/application_schema_fingerprint.sql"
    ))
    .fetch_one(pool)
    .await?)
}

/// Two running sandboxes written by version-36 code.
async fn seed(pool: &PgPool) -> anyhow::Result<()> {
    seed_platform_credential_owners(pool).await?;
    sqlx::raw_sql(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) VALUES('host-key-preset',\
         'credential-org-a','Host key','host-key','{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
         INSERT INTO environments(id,org_id,created_by,type,preset_id,state,desired_state,environment_operation_generation,project_spec) \
         VALUES('host-key-env','credential-org-a','credential-user-a','sandbox','host-key-preset','running','started',3,\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb), \
         ('host-key-env-other','credential-org-a','credential-user-a','sandbox','host-key-preset','running','started',1,\
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb); \
         INSERT INTO sandbox_environment_backend(environment_id,namespace,sandbox_claim_name,pod_name,pod_ip,\
         sandbox_claim_uid,setup_phase,setup_complete) VALUES \
         ('host-key-env','codewire-sandboxes','sandbox-host-key-env','sandbox-host-key-env','10.0.0.10',\
         '6f2d8c1a-0e4b-4f7a-9c3d-5b8e2a1f0c41',4,true);",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert one host key the way orchestration's only writer does.
async fn record(
    pool: &PgPool,
    environment_id: &str,
    generation: i64,
    pod_uid: &str,
    public_key: &str,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "INSERT INTO public.sandbox_ssh_host_keys \
             (environment_id, operation_generation, pod_uid, public_key) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (pod_uid) DO NOTHING",
    )
    .bind(environment_id)
    .bind(generation)
    .bind(pod_uid)
    .bind(public_key)
    .execute(pool)
    .await?
    .rows_affected())
}

async fn keys(pool: &PgPool) -> anyhow::Result<Vec<(String, String, i64, String)>> {
    Ok(sqlx::query_as(
        "SELECT pod_uid, environment_id, operation_generation, public_key \
         FROM public.sandbox_ssh_host_keys ORDER BY 1",
    )
    .fetch_all(pool)
    .await?)
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|code| code.into_owned())
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_host_keys_fresh_schema_is_write_once_per_pod_constrained_and_cascades()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT,
            "ssh host keys measured fingerprint: {measured}"
        );

        anyhow::ensure!(record(&pool, ENV, 3, POD, KEY).await? == 1);
        // A Pod never takes a second key, even the same one, nor records for
        // another environment or generation.
        anyhow::ensure!(record(&pool, ENV, 3, POD, OTHER_KEY).await? == 0);
        anyhow::ensure!(record(&pool, ENV, 3, POD, KEY).await? == 0);
        anyhow::ensure!(record(&pool, ENV, 4, POD, OTHER_KEY).await? == 0);
        anyhow::ensure!(record(&pool, OTHER_ENV, 1, POD, KEY).await? == 0);
        let duplicate = sqlx::query(
            "INSERT INTO public.sandbox_ssh_host_keys \
             (environment_id, operation_generation, pod_uid, public_key) VALUES ($1, 3, $2, $3)",
        )
        .bind(ENV)
        .bind(POD)
        .bind(OTHER_KEY)
        .execute(&pool)
        .await
        .err()
        .context("a second key for one Pod was accepted")?;
        anyhow::ensure!(sqlstate(&duplicate).as_deref() == Some("23505"));
        // A Pod replacing another within the same generation, and another
        // environment's Pod, record their own.
        anyhow::ensure!(record(&pool, ENV, 3, NEXT_POD, OTHER_KEY).await? == 1);
        anyhow::ensure!(record(&pool, OTHER_ENV, 1, OTHER_POD, KEY).await? == 1);
        anyhow::ensure!(
            keys(&pool).await?
                == vec![
                    (
                        OTHER_POD.to_owned(),
                        OTHER_ENV.to_owned(),
                        1,
                        KEY.to_owned()
                    ),
                    (POD.to_owned(), ENV.to_owned(), 3, KEY.to_owned()),
                    (NEXT_POD.to_owned(), ENV.to_owned(), 3, OTHER_KEY.to_owned()),
                ]
        );

        let with_comment = format!("{KEY} user@host");
        let with_newline = format!("{KEY}\n");
        let short = &KEY[..KEY.len() - 1];
        let uppercase_pod = FRESH_POD.to_ascii_uppercase();
        for (generation, pod_uid, public_key, code) in [
            (0, FRESH_POD, KEY, "23514"),
            (-1, FRESH_POD, KEY, "23514"),
            (9, "not-a-uid", KEY, "23514"),
            (9, uppercase_pod.as_str(), KEY, "23514"),
            (9, FRESH_POD, with_comment.as_str(), "23514"),
            (9, FRESH_POD, with_newline.as_str(), "23514"),
            (9, FRESH_POD, short, "23514"),
            (
                9,
                FRESH_POD,
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0ssh-ed25519-padding-padding-padd",
                "23514",
            ),
            (9, FRESH_POD, "", "23514"),
        ] {
            let error = record(&pool, ENV, generation, pod_uid, public_key)
                .await
                .err()
                .with_context(|| format!("accepted {generation} {pod_uid:?} {public_key:?}"))?;
            anyhow::ensure!(
                sqlstate(&error).as_deref() == Some(code),
                "{generation} {pod_uid:?} {public_key:?}: {error}"
            );
        }
        let unknown = record(&pool, "no-such-environment", 1, FRESH_POD, KEY)
            .await
            .err()
            .context("a key for an unknown environment was accepted")?;
        anyhow::ensure!(sqlstate(&unknown).as_deref() == Some("23503"));

        // Keys go with their environment and only theirs.
        sqlx::query("DELETE FROM public.sandbox_environment_backend WHERE environment_id = $1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        sqlx::query("DELETE FROM public.environments WHERE id = $1")
            .bind(ENV)
            .execute(&pool)
            .await?;
        anyhow::ensure!(
            keys(&pool).await?
                == vec![(
                    OTHER_POD.to_owned(),
                    OTHER_ENV.to_owned(),
                    1,
                    KEY.to_owned()
                )]
        );
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}
