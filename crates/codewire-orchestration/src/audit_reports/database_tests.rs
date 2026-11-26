//! Filing reported credential uses against PostgreSQL (#6189): a use is filed
//! under the environment of orchestration's own binding of the reported Pod,
//! released or not, named as the credential's owner stored it. A Pod with no
//! binding, a credential its owner does not hold and a provider that is not
//! the credential's write nothing.

use anyhow::{Result, ensure};

use super::*;
use crate::test_database_support::TestDatabase;

const ORG: &str = "org-credential-uses";
const OWNER: &str = "org-credential-uses-owner";
const ENV: &str = "env-credential-uses";
const POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a6189";
const UNBOUND_POD: &str = "0b8f6a52-0f6c-4a59-9f43-1b1f0c3a0000";
const OTHER_ORG: &str = "org-credential-uses-other";
const PROFILE: &str = "8d2e3f40-6189-4a6b-9c1d-0000000000a1";
/// The creator's two OpenAI credentials and one Anthropic one.
const PERSONAL: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000001";
const PERSONAL_SECOND: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000002";
const PERSONAL_ANTHROPIC: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000003";
/// The environment's organization's credential, and another organization's.
const ORGANIZATION: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000004";
const OTHER_ORGANIZATION: &str = "4c7a1f0e-6189-4a6b-9c1d-000000000005";

async fn bound_environment(db: &TestDatabase) -> Result<()> {
    db.organization(ORG).await?;
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(OWNER)
        .bind(format!("{OWNER}@example.test"))
        .execute(&db.pool)
        .await?;
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ($1, $2, 'Preset', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(format!("{ORG}-preset"))
    .bind(ORG)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
         VALUES ($1, $2, $3, $4, 'sandbox', $1, 'running', 'started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(ENV)
    .bind(ORG)
    .bind(OWNER)
    .bind(format!("{ORG}-preset"))
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO sandbox_workspace_bindings \
         (pod_uid,environment_id,namespace,pod_name,claim_uid,sandbox_uid, \
          operation_generation,managed_credential_clients,credential_scope) \
         VALUES ($1,$2,'dev-sandboxes','ws-0','c0ffee00-e29b-41d4-a716-446655440000', \
         '5a4db0c5-e29b-41d4-a716-446655440000',1,'','pod')",
    )
    .bind(POD)
    .bind(ENV)
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// One active credential, owned by a user or an organization.
async fn credential(
    db: &TestDatabase,
    id: &str,
    owner: (Option<&str>, Option<&str>),
    provider: &str,
    name: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO platform_credentials (id, user_id, organization_id, provider, \
         authentication_kind, display_name, status, revocation_generation, material_generation) \
         VALUES ($1, $2, $3, $4, 'api_key', $5, 'active', 1, 1)",
    )
    .bind(id)
    .bind(owner.0)
    .bind(owner.1)
    .bind(provider)
    .bind(name)
    .execute(&db.pool)
    .await?;
    Ok(())
}

async fn credentials(db: &TestDatabase) -> Result<()> {
    db.organization(OTHER_ORG).await?;
    credential(db, PERSONAL, (Some(OWNER), None), "openai", "Ana's OpenAI").await?;
    credential(
        db,
        PERSONAL_SECOND,
        (Some(OWNER), None),
        "openai",
        "Ana's spare",
    )
    .await?;
    credential(
        db,
        PERSONAL_ANTHROPIC,
        (Some(OWNER), None),
        "anthropic",
        "Ana's Claude",
    )
    .await?;
    credential(db, ORGANIZATION, (None, Some(ORG)), "openai", "Team OpenAI").await?;
    credential(
        db,
        OTHER_ORGANIZATION,
        (None, Some(OTHER_ORG)),
        "openai",
        "Their OpenAI",
    )
    .await
}

/// Binds the environment to an organization profile, so its Sandbox leases
/// the organization's credentials, not its creator's.
async fn organization_profile(db: &TestDatabase) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    sqlx::query(
        "INSERT INTO platform_access_profiles (id, organization_id, name, current_revision) \
         VALUES ($1, $2, 'Team', 1)",
    )
    .bind(PROFILE)
    .bind(ORG)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO platform_access_profile_revisions (profile_id, revision) VALUES ($1, 1)",
    )
    .bind(PROFILE)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO platform_environment_access_bindings (environment_id, profile_id, profile_revision) \
         VALUES ($1, $2, 1)",
    )
    .bind(ENV)
    .bind(PROFILE)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(sqlx::FromRow, Debug, PartialEq, Eq)]
struct Pending {
    org_id: String,
    environment_id: String,
    kind: String,
    action: String,
    count: i64,
    actor_type: String,
    detail: serde_json::Value,
}

async fn pending(db: &TestDatabase) -> Result<Vec<Pending>> {
    Ok(sqlx::query_as(
        "SELECT org_id, environment_id, kind, action, count, actor_type, detail \
         FROM sandbox_audit_pending ORDER BY subject",
    )
    .fetch_all(&db.pool)
    .await?)
}

async fn events(db: &TestDatabase) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM sandbox_audit_events")
            .fetch_one(&db.pool)
            .await?,
    )
}

fn reported(credential: &str, provider: &str, host: &str, count: u64) -> ReportedUse {
    let now = Utc::now();
    let ms = u64::try_from(now.timestamp_millis()).unwrap();
    let wire = CredentialUse {
        credential_id: credential.into(),
        provider: provider.into(),
        host: host.into(),
        first_unix_ms: ms,
        last_unix_ms: ms,
        count,
        ..Default::default()
    };
    parse_uses(&[wire], now).unwrap().remove(0)
}

async fn file(db: &TestDatabase, pod: &str, uses: &[ReportedUse]) -> Result<Filed> {
    let mut tx = db.pool.begin().await?;
    let filed = file_uses(&mut tx, pod, uses).await?;
    tx.commit().await?;
    Ok(filed)
}

fn detail(name: &str, host: &str) -> serde_json::Value {
    serde_json::json!({"provider": "openai", "name": name, "host": host})
}

macro_rules! database_case {
    ($name:ident, $db:ident, $body:block) => {
        #[tokio::test]
        #[ignore = "requires checked-in disposable TEST_DATABASE_URL"]
        async fn $name() -> Result<()> {
            let database = TestDatabase::create().await?;
            let result = async {
                bound_environment(&database).await?;
                credentials(&database).await?;
                let $db = &database;
                $body
                Ok(())
            }
            .await;
            database.finish(result).await
        }
    };
}

database_case!(
    db_a_use_is_filed_under_its_bindings_environment_and_stored_name,
    db,
    {
        let uses = [
            reported(PERSONAL, "openai", "api.openai.com", 3),
            reported(PERSONAL, "openai", "chatgpt.com", 1),
        ];
        ensure!(
            file(db, POD, &uses).await?
                == Filed::Uses {
                    written: 2,
                    foreign: 0
                }
        );
        // The next report of the same subject adds to its hour's fold.
        ensure!(
            file(db, POD, &uses[..1]).await?
                == Filed::Uses {
                    written: 1,
                    foreign: 0
                }
        );
        let rows = pending(db).await?;
        ensure!(rows.len() == 2, "{rows:?}");
        for row in &rows {
            ensure!(row.org_id == ORG && row.environment_id == ENV, "{row:?}");
            ensure!(row.kind == "credentials" && row.action == "used", "{row:?}");
            ensure!(row.actor_type == "sandbox", "{row:?}");
        }
        ensure!(rows[0].count == 6, "{rows:?}");
        ensure!(
            rows[0].detail == detail("Ana's OpenAI", "api.openai.com"),
            "{rows:?}"
        );
        ensure!(events(db).await? == 0);

        // A released binding still names its environment.
        sqlx::query("UPDATE sandbox_workspace_bindings SET released_at = now() WHERE pod_uid = $1")
            .bind(POD)
            .execute(&db.pool)
            .await?;
        ensure!(
            file(db, POD, &uses[1..]).await?
                == Filed::Uses {
                    written: 1,
                    foreign: 0
                }
        );
        ensure!(pending(db).await?[1].count == 2);
    }
);

database_case!(
    db_two_credentials_of_one_provider_at_one_host_stay_two_events,
    db,
    {
        let uses = [
            reported(PERSONAL, "openai", "api.openai.com", 2),
            reported(PERSONAL_SECOND, "openai", "api.openai.com", 5),
        ];
        ensure!(
            file(db, POD, &uses).await?
                == Filed::Uses {
                    written: 2,
                    foreign: 0
                }
        );
        let rows = pending(db).await?;
        ensure!(rows.len() == 2, "{rows:?}");
        let mut found: Vec<_> = rows
            .iter()
            .map(|row| (row.detail.clone(), row.count))
            .collect();
        found.sort_by_key(|(_, count)| *count);
        ensure!(
            found
                == [
                    (detail("Ana's OpenAI", "api.openai.com"), 2),
                    (detail("Ana's spare", "api.openai.com"), 5),
                ],
            "{rows:?}"
        );
    }
);

database_case!(
    db_a_credential_the_owner_does_not_hold_writes_nothing,
    db,
    {
        // Without a profile the Sandbox leases its creator's credentials: an
        // organization's, its own or another's, is not one of them.
        let foreign = [
            reported(OTHER_ORGANIZATION, "openai", "api.openai.com", 3),
            reported(ORGANIZATION, "openai", "api.openai.com", 2),
            reported(
                "4c7a1f0e-6189-4a6b-9c1d-0000000000ff",
                "openai",
                "api.openai.com",
                1,
            ),
        ];
        ensure!(
            file(db, POD, &foreign).await?
                == Filed::Uses {
                    written: 0,
                    foreign: 6
                }
        );
        ensure!(pending(db).await?.is_empty());

        // With an organization profile it leases the organization's credentials
        // only: the creator's own and another organization's write nothing.
        organization_profile(db).await?;
        let uses = [
            reported(ORGANIZATION, "openai", "api.openai.com", 4),
            reported(PERSONAL, "openai", "api.openai.com", 1),
            reported(OTHER_ORGANIZATION, "openai", "api.openai.com", 2),
        ];
        ensure!(
            file(db, POD, &uses).await?
                == Filed::Uses {
                    written: 1,
                    foreign: 3
                }
        );
        let rows = pending(db).await?;
        ensure!(rows.len() == 1, "{rows:?}");
        ensure!(
            rows[0].detail == detail("Team OpenAI", "api.openai.com"),
            "{rows:?}"
        );
        ensure!(rows[0].count == 4, "{rows:?}");
        ensure!(events(db).await? == 0);
    }
);

database_case!(
    db_a_provider_that_is_not_the_credentials_writes_nothing,
    db,
    {
        let uses = [
            reported(PERSONAL_ANTHROPIC, "openai", "api.openai.com", 3),
            reported(PERSONAL, "anthropic", "api.anthropic.com", 1),
        ];
        ensure!(
            file(db, POD, &uses).await?
                == Filed::Uses {
                    written: 0,
                    foreign: 4
                }
        );
        ensure!(pending(db).await?.is_empty());
        ensure!(events(db).await? == 0);
    }
);

database_case!(db_a_pod_with_no_binding_writes_nothing, db, {
    let uses = [reported(PERSONAL, "openai", "api.openai.com", 3)];
    ensure!(file(db, UNBOUND_POD, &uses).await? == Filed::Unbound);
    ensure!(pending(db).await?.is_empty());
    ensure!(events(db).await? == 0);
});
