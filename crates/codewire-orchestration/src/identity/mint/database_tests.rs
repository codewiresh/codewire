//! Disposable-PostgreSQL proof for the mint store against migration 0050:
//! the Sandbox's standing, groups and kill switches in one read, a
//! registration by its canonical audience, and the mint log. Only synthetic
//! rows in an isolated test database are used.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const CREATOR: &str = "identity-creator";
const ORG: &str = "identity-organization";
const OTHER_ORG: &str = "identity-other-organization";
const PRESET: &str = "identity-preset";
const ENV: &str = "7b1f2e3d-4c5b-4a69-8877-665544332211";
const OTHER_ENV: &str = "8c2a3f4e-5d6c-4b7a-9988-776655443322";
const AUDIENCE: &str = "https://k8s.walk.example";

async fn seed(db: &TestDatabase) -> Result<()> {
    db.user(CREATOR).await?;
    db.organization(ORG).await?;
    db.organization(OTHER_ORG).await?;
    sqlx::query(
        "INSERT INTO environment_presets(id,org_id,name,slug,project_spec) \
         VALUES ($1,$2,'Identity','identity','{\"schema_version\":1}'::jsonb)",
    )
    .bind(PRESET)
    .bind(ORG)
    .execute(&db.pool)
    .await?;
    for (id, name) in [(ENV, Some("app")), (OTHER_ENV, None)] {
        sqlx::query(
            "INSERT INTO environments \
             (id,org_id,created_by,preset_id,type,name,state,desired_state,project_spec) \
             VALUES ($1,$2,$3,$4,'sandbox',$5,'running','started','{\"schema_version\":1}'::jsonb)",
        )
        .bind(id)
        .bind(ORG)
        .bind(CREATOR)
        .bind(PRESET)
        .bind(name)
        .execute(&db.pool)
        .await?;
    }
    Ok(())
}

/// Every column of an `identity_mints` row: none of them holds a token.
#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct MintRow {
    jti: String,
    environment_id: String,
    org_id: String,
    audience: String,
    kid: String,
    groups_version: i64,
    audience_version: i64,
    minted_at: chrono::DateTime<chrono::Utc>,
}

async fn execute(db: &TestDatabase, statement: &str) -> Result<()> {
    sqlx::query(statement).execute(&db.pool).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_subject_reads_the_sandboxs_standing_groups_and_kill_switches() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let store = PgMintStore::from_pool(db.pool.clone());
        let subject = || store.subject(ENV);

        ensure!(store.subject("no-such-environment").await?.is_none());
        let fresh = subject().await?.ok_or_else(|| anyhow::anyhow!("no subject"))?;
        ensure!(
            fresh
                == MintSubject {
                    org_id: ORG.into(),
                    org: OrgStanding::Active,
                    running: true,
                    access_suspended: false,
                    stopped: false,
                    created_by: CREATOR.into(),
                    name: Some("app".into()),
                    groups: Vec::new(),
                    groups_version: 0,
                },
            "{fresh:?}"
        );

        execute(
            &db,
            &format!(
                "INSERT INTO environment_identity_groups (environment_id,groups,version,updated_by) \
                 VALUES ('{ENV}', ARRAY['data-readers','builders'], 3, '{CREATOR}')"
            ),
        )
        .await?;
        let grouped = subject().await?.ok_or_else(|| anyhow::anyhow!("no subject"))?;
        ensure!(grouped.groups == ["data-readers", "builders"] && grouped.groups_version == 3);

        // Another Sandbox's stop leaves this one minting; its own or its
        // organization's stops it.
        execute(
            &db,
            &format!(
                "INSERT INTO identity_minting_stops (org_id,environment_id,stopped_by) \
                 VALUES ('{ORG}','{OTHER_ENV}','{CREATOR}')"
            ),
        )
        .await?;
        ensure!(!subject().await?.is_some_and(|s| s.stopped));
        ensure!(store.subject(OTHER_ENV).await?.is_some_and(|s| s.stopped));
        execute(
            &db,
            &format!(
                "INSERT INTO identity_minting_stops (org_id,stopped_by) VALUES ('{OTHER_ORG}','{CREATOR}')"
            ),
        )
        .await?;
        ensure!(!subject().await?.is_some_and(|s| s.stopped));
        execute(
            &db,
            &format!("INSERT INTO identity_minting_stops (org_id,stopped_by) VALUES ('{ORG}','{CREATOR}')"),
        )
        .await?;
        ensure!(subject().await?.is_some_and(|s| s.stopped));
        execute(&db, "DELETE FROM identity_minting_stops").await?;

        execute(&db, &format!("UPDATE environments SET state = 'starting' WHERE id = '{ENV}'")).await?;
        ensure!(subject().await?.is_some_and(|s| !s.running));
        execute(&db, &format!("UPDATE environments SET state = 'running' WHERE id = '{ENV}'")).await?;

        execute(
            &db,
            &format!(
                "UPDATE users SET enabled = false, suspended_at = now(), suspended_by = 'fixture-admin' \
                 WHERE id = '{CREATOR}'"
            ),
        )
        .await?;
        ensure!(subject().await?.is_some_and(|s| s.access_suspended));
        execute(
            &db,
            &format!(
                "UPDATE organizations SET suspended_at = now(), suspended_by = 'fixture-admin', \
                 suspended_for = '{CREATOR}' WHERE id = '{ORG}'"
            ),
        )
        .await?;
        ensure!(subject().await?.is_some_and(|s| s.org == OrgStanding::Suspended));
        execute(
            &db,
            &format!(
                "UPDATE organizations SET deletion_state = 'deleting', deletion_generation = 1, \
                 deletion_operation_id = 'op', deletion_workflow_id = 'wf', \
                 deletion_requested_at = now(), deletion_phase = 'environments' WHERE id = '{ORG}'"
            ),
        )
        .await?;
        ensure!(subject().await?.is_some_and(|s| s.org == OrgStanding::Deleting));
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_registration_is_its_organizations_and_a_mint_row_holds_no_token() -> Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        seed(&db).await?;
        let store = PgMintStore::from_pool(db.pool.clone());
        ensure!(store.registration(ORG, AUDIENCE).await?.is_none());
        execute(
            &db,
            &format!(
                "INSERT INTO identity_audiences \
                 (org_id,audience,visible_groups,lifetime_seconds,claim_created_by,version,created_by) \
                 VALUES ('{OTHER_ORG}','{AUDIENCE}',NULL,600,false,1,'{CREATOR}'), \
                        ('{ORG}','{AUDIENCE}',ARRAY['data-readers'],120,true,4,'{CREATOR}')"
            ),
        )
        .await?;
        let registration = store.registration(ORG, AUDIENCE).await?;
        ensure!(
            registration
                == Some(Registration {
                    visible_groups: Some(vec!["data-readers".into()]),
                    lifetime_seconds: 120,
                    claim_created_by: true,
                    claim_environment_name: false,
                    version: 4,
                }),
            "{registration:?}"
        );
        ensure!(store.registration(ORG, "https://k8s.walk.example/").await?.is_none());

        let minted_at = chrono::DateTime::parse_from_rfc3339("2026-11-21T12:00:00Z")?.to_utc();
        let record = MintRecord {
            jti: "Rk0xMjM0NTY3ODkwYWJjZA".into(),
            environment_id: ENV.into(),
            org_id: ORG.into(),
            audience: AUDIENCE.into(),
            kid: "sandbox-identity-1".into(),
            groups_version: 3,
            audience_version: 4,
            minted_at,
        };
        store.record(&record).await?;
        ensure!(store.record(&record).await.is_err(), "a jti is logged once");
        let rows: Vec<MintRow> = sqlx::query_as(
            "SELECT jti, environment_id, org_id, audience, kid, groups_version, \
                    audience_version, minted_at FROM identity_mints",
        )
        .fetch_all(&db.pool)
        .await?;
        ensure!(
            rows == [MintRow {
                jti: record.jti.clone(),
                environment_id: ENV.into(),
                org_id: ORG.into(),
                audience: AUDIENCE.into(),
                kid: "sandbox-identity-1".into(),
                groups_version: 3,
                audience_version: 4,
                minted_at,
            }],
            "{rows:?}"
        );
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns \
              WHERE table_name = 'identity_mints' ORDER BY ordinal_position",
        )
        .fetch_all(&db.pool)
        .await?;
        ensure!(
            columns
                == [
                    "jti",
                    "environment_id",
                    "org_id",
                    "audience",
                    "kid",
                    "groups_version",
                    "audience_version",
                    "minted_at"
                ],
            "{columns:?}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
