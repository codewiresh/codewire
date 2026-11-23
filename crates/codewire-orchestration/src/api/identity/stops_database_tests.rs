//! What the kill switches promise (docs/dev/SANDBOX-IDENTITY.md, "Kill
//! switches"): an organization owner or admin, or a platform administrator,
//! stops and resumes minting for one Sandbox or the whole organization; each
//! change writes its audit row, and a repeat writes nothing.

use super::database_test_support::*;
use super::stops::{StopTarget, resume_minting, stop_minting};

/// The stops in place: `None` for the organization's, else the Sandbox's.
async fn stops(db: &TestDatabase, org_id: &str) -> anyhow::Result<Vec<Option<String>>> {
    Ok(sqlx::query_scalar(
        "SELECT environment_id FROM identity_minting_stops WHERE org_id = $1 \
         ORDER BY environment_id NULLS FIRST",
    )
    .bind(org_id)
    .fetch_all(&db.pool)
    .await?)
}

fn platform_administrator(user_id: &str) -> codewire_server_core::auth::AuthUser {
    let mut user = session(user_id);
    user.is_admin = true;
    user
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_admin_stops_and_resumes_a_sandbox_and_the_organization() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "is-org").await?;
        environment(&db, "is-env", "is-org", "is-org-alice").await?;
        let admin = session("is-org-admin");
        let sandbox = StopTarget::Environment("is-env");

        anyhow::ensure!(bounded(stop_minting(&db.pool, &admin, "is-org", sandbox)).await??);
        anyhow::ensure!(!bounded(stop_minting(&db.pool, &admin, "is-org", sandbox)).await??);
        anyhow::ensure!(stops(&db, "is-org").await? == [Some("is-env".to_owned())]);
        let owner = session("is-org-owner");
        anyhow::ensure!(
            bounded(stop_minting(
                &db.pool,
                &owner,
                "is-org",
                StopTarget::Organization
            ))
            .await??
        );
        anyhow::ensure!(stops(&db, "is-org").await? == [None, Some("is-env".to_owned())]);

        // Resuming the organization leaves the Sandbox's own stop.
        anyhow::ensure!(
            bounded(resume_minting(
                &db.pool,
                &admin,
                "is-org",
                StopTarget::Organization
            ))
            .await??
        );
        anyhow::ensure!(
            !bounded(resume_minting(
                &db.pool,
                &admin,
                "is-org",
                StopTarget::Organization
            ))
            .await??
        );
        anyhow::ensure!(stops(&db, "is-org").await? == [Some("is-env".to_owned())]);
        anyhow::ensure!(
            bounded(resume_minting(
                &db.pool,
                &session("is-org-super"),
                "is-org",
                sandbox
            ))
            .await??
        );
        anyhow::ensure!(!bounded(resume_minting(&db.pool, &admin, "is-org", sandbox)).await??);
        anyhow::ensure!(stops(&db, "is-org").await?.is_empty());

        let row = |actor: &str, environment: Option<&str>| AuditRow {
            user_id: Some(actor.to_owned()),
            metadata: Some(serde_json::json!({
                "org_id": "is-org",
                "environment_id": environment,
                "authority": "organization_admin",
            })),
        };
        anyhow::ensure!(
            audits(&db, "identity.stopped").await?
                == [
                    row("is-org-admin", Some("is-env")),
                    row("is-org-owner", None)
                ]
        );
        anyhow::ensure!(
            audits(&db, "identity.resumed").await?
                == [
                    row("is-org-admin", None),
                    row("is-org-super", Some("is-env"))
                ]
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_admins_and_platform_administrators_stop_minting() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "is-org").await?;
        organization(&db, "is-other").await?;
        environment(&db, "is-env", "is-org", "is-org-alice").await?;
        environment(&db, "is-other-env", "is-other", "is-other-alice").await?;
        user(&db, "platform-operator").await?;

        // The Sandbox's own creator is a member, not an admin.
        for (user, expected) in [
            (session("is-org-alice"), "not_identity_admin"),
            (session("is-other-owner"), "org_not_found"),
            (api_key("is-org-admin", "is-other"), "org_not_found"),
            // A platform administrator's API key carries no platform authority.
            (
                {
                    let mut key = api_key("platform-operator", "is-org");
                    key.is_admin = true;
                    key
                },
                "org_not_found",
            ),
        ] {
            for target in [StopTarget::Organization, StopTarget::Environment("is-env")] {
                let refused = bounded(stop_minting(&db.pool, &user, "is-org", target)).await?;
                anyhow::ensure!(
                    code(refused.unwrap_err()) == expected,
                    "{user:?} {target:?}"
                );
                let refused = bounded(resume_minting(&db.pool, &user, "is-org", target)).await?;
                anyhow::ensure!(
                    code(refused.unwrap_err()) == expected,
                    "{user:?} {target:?}"
                );
            }
        }
        // Another organization's Sandbox does not exist here.
        let refused = bounded(stop_minting(
            &db.pool,
            &session("is-org-admin"),
            "is-org",
            StopTarget::Environment("is-other-env"),
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "env_not_found");
        anyhow::ensure!(stops(&db, "is-org").await?.is_empty());
        anyhow::ensure!(stops(&db, "is-other").await?.is_empty());

        // A platform administrator acts on any organization, as one.
        let operator = platform_administrator("platform-operator");
        anyhow::ensure!(
            bounded(stop_minting(
                &db.pool,
                &operator,
                "is-org",
                StopTarget::Environment("is-env")
            ))
            .await??
        );
        anyhow::ensure!(
            bounded(stop_minting(
                &db.pool,
                &operator,
                "is-org",
                StopTarget::Organization
            ))
            .await??
        );
        let refused = bounded(stop_minting(
            &db.pool,
            &operator,
            "no-such-org",
            StopTarget::Organization,
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");
        anyhow::ensure!(
            bounded(resume_minting(
                &db.pool,
                &operator,
                "is-org",
                StopTarget::Organization
            ))
            .await??
        );
        let stopped = audits(&db, "identity.stopped").await?;
        anyhow::ensure!(stopped.len() == 2);
        for row in &stopped {
            anyhow::ensure!(row.user_id.as_deref() == Some("platform-operator"));
            anyhow::ensure!(
                row.metadata
                    .as_ref()
                    .map(|metadata| metadata["authority"].clone())
                    == Some("platform_administrator".into())
            );
        }
        Ok(())
    }
    .await;
    db.finish(result).await
}
