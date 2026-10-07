//! SSH host keys (migration 37): accepted prior history and disposable
//! database proof for the host-key table, write-once per bound Pod, its
//! constraints and its cascade, an upgrade that changes no existing row or
//! helper, the in-place down and the replay of version 36 into a disposable
//! application schema.

use super::*;

const VERSION: i64 = 37;
// Measured from accepted canonical main 6f2693256155b615af44f10ba47c9e53a9419b1b,
// not the edited branch: SHA384(concatenated binary SHA384(SQL1)..SHA384(SQL36))
// and SHA384(SQL36).
const PRIOR_HISTORY36: &str = "d93e9473a13019377f7cc71ae0327aa1bb0e7d1951d57dc45deeab0746e5a1d51e859523d963a0dde16059dbd8ce0383";
const PRIOR36: &str = "32b0848765fb6892efe547f652316061c530b60e68607d20bce9dbd23f4ab37cb0008095a5fe3a86f9cfcdd5ecebbb8d";

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

pub(super) fn assert_accepted_prior36() -> anyhow::Result<()> {
    authority_stamp_removal::assert_accepted_prior35()?;
    let mut digest = Sha384::new();
    let prior: Vec<_> = MIGRATOR.iter().filter(|m| m.version < VERSION).collect();
    anyhow::ensure!(prior.len() == 36);
    for (index, migration) in prior.iter().enumerate() {
        anyhow::ensure!(migration.version == index as i64 + 1);
        digest.update(Sha384::digest(migration.sql.as_bytes()));
    }
    anyhow::ensure!(
        format!("{:x}", digest.finalize()) == PRIOR_HISTORY36,
        "migration1..36 differs from accepted canonical 6f2693256"
    );
    anyhow::ensure!(
        format!("{:x}", Sha384::digest(prior[35].sql.as_bytes())) == PRIOR36,
        "migration36 differs from accepted canonical 6f2693256"
    );
    Ok(())
}

#[test]
fn ssh_host_keys_pins_the_accepted36_history() -> anyhow::Result<()> {
    assert_accepted_prior36()
}

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

/// Every `codewire_` helper with its definition. Migration 37 adds none.
async fn helpers(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n \
         ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'codewire_') \
         ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)",
    )
    .fetch_all(pool)
    .await?)
}

/// Every pre-existing row this migration could touch.
async fn rows(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    for table in [
        "users",
        "organizations",
        "environments",
        "sandbox_environment_backend",
        "sandbox_workspace_bindings",
    ] {
        result.push(
            sqlx::query_scalar(&format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb)::text \
                 FROM public.{table} t"
            ))
            .fetch_one(pool)
            .await?,
        );
    }
    Ok(result)
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

async fn absent(pool: &PgPool) -> anyhow::Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT to_regclass('public.sandbox_ssh_host_keys') IS NULL")
            .fetch_one(pool)
            .await?,
    )
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
        anyhow::ensure!(embedded_max_version()? >= VERSION);
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_host_keys_upgrade_preserves36_rows_helpers_and_second_startup() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        let before = applied_migrations(&pool).await?;
        anyhow::ensure!(before.len() == 36 && before[35].0 == 36);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_SSH_HOST_KEY_SCHEMA_FINGERPRINT);
        seed(&pool).await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        pool.close().await;

        // Prove SSH37 itself before the later CW journal adds its helper.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        let after = applied_migrations(&pool).await?;
        anyhow::ensure!(after.len() == 37 && after[..36] == before && after[36].0 == VERSION);
        // No backfill and no other change: no key exists until a daemon
        // records one.
        anyhow::ensure!(rows(&pool).await? == original);
        anyhow::ensure!(helpers(&pool).await? == old_helpers);
        anyhow::ensure!(keys(&pool).await?.is_empty());
        let measured = fingerprint(&pool).await?;
        anyhow::ensure!(
            measured == ACCEPTED_SSH_HOST_KEY_SCHEMA_FINGERPRINT,
            "ssh host keys measured fingerprint: {measured}"
        );
        record(&pool, ENV, 3, POD, KEY).await?;
        let recorded = keys(&pool).await?;
        pool.close().await;

        // A second version-37 startup changes nothing.
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == after);
        anyhow::ensure!(rows(&pool).await? == original && keys(&pool).await? == recorded);
        pool.close().await;

        // Ordinary current startup adds the later journals without changing
        // the accepted SSH ledger, rows or keys, and then is a no-op too.
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        let current = applied_migrations(&pool).await?;
        anyhow::ensure!(
            current.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
                && current[..37] == after
        );
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool).await? == original && keys(&pool).await? == recorded);
        pool.close().await;
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == current);
        anyhow::ensure!(rows(&pool).await? == original && keys(&pool).await? == recorded);
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

/// The documented in-place rollback: the migration only adds one table, so
/// dropping it and the ledger row restores version 36 without touching any
/// other row. Recorded keys are lost; daemons record them again after a
/// later roll-forward, at their next bind.
const SSH_HOST_KEYS_DOWN: &str = "BEGIN; \
    DROP TABLE public.sandbox_ssh_host_keys; \
    DELETE FROM public._sqlx_migrations WHERE version = 37; \
    COMMIT;";

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_host_keys_down_restores36_in_place_and_keeps_every_other_row() -> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        apply_migrations_before(&db.url, VERSION + 1).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        record(&pool, ENV, 3, POD, KEY).await?;
        let original = rows(&pool).await?;
        let old_helpers = helpers(&pool).await?;
        let ledger = applied_migrations(&pool).await?;
        anyhow::ensure!(ledger.len() == 37 && ledger[36].0 == VERSION);
        sqlx::raw_sql(SSH_HOST_KEYS_DOWN).execute(&pool).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..36]);
        anyhow::ensure!(absent(&pool).await? && helpers(&pool).await? == old_helpers);
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_PRE_SSH_HOST_KEY_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool).await? == original);
        pool.close().await;

        // Rolling forward again applies 37 cleanly with no keys.
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(
            applied_migrations(&pool).await?.len()
                == MIGRATOR
                    .iter()
                    .filter(|m| m.migration_type.is_up_migration())
                    .count()
        );
        anyhow::ensure!(fingerprint(&pool).await? == ACCEPTED_APPLICATION_SCHEMA_FINGERPRINT);
        anyhow::ensure!(rows(&pool).await? == original && keys(&pool).await?.is_empty());
        pool.close().await;
        Ok(())
    }
    .await;
    result.and(db.drop().await)
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn ssh_host_keys_rollback_replays36_only_in_disposable_application_schema()
-> anyhow::Result<()> {
    let db = TestDatabase::create(&std::env::var("TEST_DATABASE_URL")?).await?;
    let result = async {
        ensure_schema(&db.url).await?;
        let pool = connect(&db.url).await?;
        seed(&pool).await?;
        record(&pool, ENV, 3, POD, KEY).await?;
        let ledger = applied_migrations(&pool).await?;
        sqlx::raw_sql(
            "CREATE SCHEMA rollback_boundary; CREATE TABLE rollback_boundary.keep(id integer); \
             INSERT INTO rollback_boundary.keep VALUES(1); DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
        apply_migrations_before(&db.url, VERSION).await?;
        let pool = connect(&db.url).await?;
        anyhow::ensure!(applied_migrations(&pool).await? == ledger[..36]);
        let prior_checksum: String = sqlx::query_scalar(
            "SELECT encode(checksum,'hex') FROM public._sqlx_migrations WHERE version=36 AND success",
        )
        .fetch_one(&pool)
        .await?;
        anyhow::ensure!(prior_checksum == PRIOR36);
        anyhow::ensure!(absent(&pool).await?);
        anyhow::ensure!(
            fingerprint(&pool).await? == ACCEPTED_PRE_SSH_HOST_KEY_SCHEMA_FINGERPRINT
        );
        anyhow::ensure!(
            sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM environments)")
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
