//! What a Sandbox's identity groups promise (docs/dev/SANDBOX-IDENTITY.md,
//! "Groups"): only an organization owner or admin sets them, each change
//! bumps the version and writes its audit row, the answer names who can run
//! code in the Sandbox, and a grant of `operator` or `owner` on a Sandbox
//! with groups needs an admin.

use super::database_test_support::*;
use super::groups::{CodeRunnerReason, get_groups, set_groups};
use crate::api::env_access::{GrantAccessBody, grant_environment_access_core};

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_each_change_of_groups_bumps_the_version_in_its_audited_transaction()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ig-org").await?;
        environment(&db, "ig-env", "ig-org", "ig-org-alice").await?;
        let admin = session("ig-org-admin");

        let never = bounded(get_groups(&db.pool, &admin, "ig-org", "ig-env")).await??;
        anyhow::ensure!(
            never.groups.is_empty() && never.version == 0 && never.updated_at.is_none()
        );

        let first = bounded(set_groups(
            &db.pool,
            &admin,
            "ig-org",
            "ig-env",
            &names(&["data-readers", "builders", "data-readers"]),
        ))
        .await??;
        anyhow::ensure!(first.changed && first.previous.is_empty());
        anyhow::ensure!(first.groups.groups == names(&["builders", "data-readers"]));
        anyhow::ensure!(first.groups.version == 1);

        // The same set again writes nothing.
        let same = bounded(set_groups(
            &db.pool,
            &admin,
            "ig-org",
            "ig-env",
            &names(&["builders", "data-readers"]),
        ))
        .await??;
        anyhow::ensure!(!same.changed && same.groups.version == 1);

        let second = bounded(set_groups(
            &db.pool,
            &admin,
            "ig-org",
            "ig-env",
            &names(&["deployers"]),
        ))
        .await??;
        anyhow::ensure!(second.changed && second.groups.version == 2);
        anyhow::ensure!(second.previous == names(&["builders", "data-readers"]));

        // Clearing keeps the row, so the next version is never one used before.
        let cleared = bounded(set_groups(&db.pool, &admin, "ig-org", "ig-env", &[])).await??;
        anyhow::ensure!(cleared.changed && cleared.groups.groups.is_empty());
        anyhow::ensure!(cleared.groups.version == 3);
        let read = bounded(get_groups(&db.pool, &admin, "ig-org", "ig-env")).await??;
        anyhow::ensure!(read.version == 3 && read.groups.is_empty());

        let rows = audits(&db, "identity.groups.changed").await?;
        anyhow::ensure!(rows.len() == 3, "one row per change: {rows:?}");
        anyhow::ensure!(rows[0].user_id.as_deref() == Some("ig-org-admin"));
        anyhow::ensure!(
            rows[0].metadata
                == Some(serde_json::json!({
                    "org_id": "ig-org",
                    "environment_id": "ig-env",
                    "before": [],
                    "after": ["builders", "data-readers"],
                    "version": 1,
                }))
        );
        anyhow::ensure!(
            rows[2]
                .metadata
                .as_ref()
                .map(|metadata| (metadata["before"].clone(), metadata["after"].clone()))
                == Some((serde_json::json!(["deployers"]), serde_json::json!([])))
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_an_owner_or_admin_sets_groups_and_names_are_checked() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ig-org").await?;
        organization(&db, "ig-other").await?;
        environment(&db, "ig-env", "ig-org", "ig-org-alice").await?;
        environment(&db, "ig-other-env", "ig-other", "ig-other-alice").await?;
        let one = names(&["data-readers"]);

        for owner_or_admin in ["ig-org-owner", "ig-org-admin", "ig-org-super"] {
            bounded(set_groups(
                &db.pool,
                &session(owner_or_admin),
                "ig-org",
                "ig-env",
                &names(&[owner_or_admin.trim_start_matches("ig-org-")]),
            ))
            .await??;
        }
        // The creator is a member, not an admin.
        let refused = bounded(set_groups(
            &db.pool,
            &session("ig-org-alice"),
            "ig-org",
            "ig-env",
            &one,
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "not_identity_admin");
        // A non-member, and an admin's key for another organization, see no
        // organization.
        for user in [
            session("ig-other-owner"),
            api_key("ig-org-admin", "ig-other"),
        ] {
            let refused = bounded(set_groups(&db.pool, &user, "ig-org", "ig-env", &one)).await?;
            anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found", "{user:?}");
        }
        // Another organization's Sandbox does not exist here.
        let refused = bounded(set_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "ig-other-env",
            &one,
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "env_not_found");

        let too_many: Vec<String> = (0..33).map(|index| format!("g{index}")).collect();
        for (bad, words) in [
            (names(&["all"]), "reserved"),
            (names(&["Data"]), "lowercase"),
            (names(&["data_readers"]), "lowercase"),
            (names(&[""]), "1 to 63"),
            (vec!["a".repeat(64)], "1 to 63"),
            (too_many, "at most 32"),
        ] {
            let error = bounded(set_groups(
                &db.pool,
                &session("ig-org-admin"),
                "ig-org",
                "ig-env",
                &bad,
            ))
            .await?
            .unwrap_err();
            let text = detail(&error);
            anyhow::ensure!(code(error) == "invalid_identity_group", "{bad:?}");
            anyhow::ensure!(text.contains(words), "{bad:?}: {text}");
        }
        let read = bounded(get_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "ig-env",
        ))
        .await??;
        anyhow::ensure!(read.groups == names(&["super"]) && read.version == 3);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_groups_are_read_by_admins_and_whoever_can_access_the_sandbox() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ig-org").await?;
        environment(&db, "ig-env", "ig-org", "ig-org-alice").await?;
        grant(&db, "ig-env", "ig-org-bob", "viewer").await?;
        member(&db, "ig-org-carol", "ig-org", "member").await?;
        bounded(set_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "ig-env",
            &names(&["data-readers"]),
        ))
        .await??;
        for reader in ["ig-org-admin", "ig-org-super", "ig-org-alice", "ig-org-bob"] {
            let read =
                bounded(get_groups(&db.pool, &session(reader), "ig-org", "ig-env")).await??;
            anyhow::ensure!(read.groups == names(&["data-readers"]), "{reader}");
        }
        let refused = bounded(get_groups(
            &db.pool,
            &session("ig-org-carol"),
            "ig-org",
            "ig-env",
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "access_denied");
        let refused = bounded(get_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "missing",
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "env_not_found");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_setting_groups_names_everyone_who_can_run_code_in_the_sandbox() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ig-org").await?;
        environment(&db, "ig-env", "ig-org", "ig-org-alice").await?;
        member(&db, "ig-org-carol", "ig-org", "member").await?;
        member(&db, "ig-org-dave", "ig-org", "member").await?;
        member(&db, "ig-org-erin", "ig-org", "member").await?;
        grant(&db, "ig-env", "ig-org-bob", "operator").await?;
        grant(&db, "ig-env", "ig-org-carol", "owner").await?;
        grant(&db, "ig-env", "ig-org-dave", "viewer").await?;
        // An admin with a grant is named once, for the grant.
        grant(&db, "ig-env", "ig-org-admin", "operator").await?;
        // A former member's grant no longer admits them.
        grant(&db, "ig-env", "ig-org-erin", "operator").await?;
        sqlx::query("DELETE FROM org_members WHERE user_id = 'ig-org-erin'")
            .execute(&db.pool)
            .await?;

        let outcome = bounded(set_groups(
            &db.pool,
            &session("ig-org-owner"),
            "ig-org",
            "ig-env",
            &names(&["data-readers"]),
        ))
        .await??;
        let runners: Vec<(String, CodeRunnerReason)> = outcome
            .can_run_code
            .iter()
            .map(|runner| (runner.email.clone(), runner.reason))
            .collect();
        let expected = [
            ("ig-org-alice@example.test", CodeRunnerReason::Creator),
            ("ig-org-carol@example.test", CodeRunnerReason::OwnerGrant),
            ("ig-org-admin@example.test", CodeRunnerReason::OperatorGrant),
            ("ig-org-bob@example.test", CodeRunnerReason::OperatorGrant),
            (
                "fixture-admin@example.test",
                CodeRunnerReason::OrganizationAdmin,
            ),
            (
                "ig-org-owner@example.test",
                CodeRunnerReason::OrganizationAdmin,
            ),
            // A member, but an admin by the super_admin assignment.
            (
                "ig-org-super@example.test",
                CodeRunnerReason::OrganizationAdmin,
            ),
        ]
        .map(|(email, reason)| (email.to_owned(), reason));
        anyhow::ensure!(runners == expected, "{runners:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}

fn grant_body(user_id: &str, permission: &str) -> GrantAccessBody {
    GrantAccessBody {
        user_id: user_id.to_owned(),
        permission: permission.to_owned(),
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_granting_operator_or_owner_on_a_grouped_sandbox_needs_an_admin() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ig-org").await?;
        environment(&db, "ig-env", "ig-org", "ig-org-alice").await?;
        environment(&db, "ig-plain", "ig-org", "ig-org-alice").await?;
        member(&db, "ig-org-carol", "ig-org", "member").await?;
        let state = crate::api::test_state::offline(db.pool.clone()).await;
        let alice = session("ig-org-alice");
        bounded(set_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "ig-env",
            &names(&["data-readers"]),
        ))
        .await??;

        // The creator owns the Sandbox but is no admin: viewer only.
        for permission in ["operator", "owner"] {
            let refused = bounded(grant_environment_access_core(
                &state,
                &alice,
                "ig-org",
                "ig-env",
                grant_body("ig-org-bob", permission),
            ))
            .await?;
            anyhow::ensure!(
                code(refused.unwrap_err()) == "identity_groups_need_admin",
                "{permission}"
            );
        }
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM environment_access WHERE environment_id = 'ig-env'",
        )
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(count == 0, "a refused grant writes nothing");
        bounded(grant_environment_access_core(
            &state,
            &alice,
            "ig-org",
            "ig-env",
            grant_body("ig-org-bob", "viewer"),
        ))
        .await??;
        // Raising that viewer grant is a grant of operator too.
        let refused = bounded(grant_environment_access_core(
            &state,
            &alice,
            "ig-org",
            "ig-env",
            grant_body("ig-org-bob", "operator"),
        ))
        .await?;
        anyhow::ensure!(code(refused.unwrap_err()) == "identity_groups_need_admin");
        bounded(grant_environment_access_core(
            &state,
            &session("ig-org-admin"),
            "ig-org",
            "ig-env",
            grant_body("ig-org-carol", "operator"),
        ))
        .await??;
        // Without groups, the creator grants as before.
        bounded(grant_environment_access_core(
            &state,
            &alice,
            "ig-org",
            "ig-plain",
            grant_body("ig-org-bob", "owner"),
        ))
        .await??;
        // And with its groups cleared again.
        bounded(set_groups(
            &db.pool,
            &session("ig-org-admin"),
            "ig-org",
            "ig-env",
            &[],
        ))
        .await??;
        bounded(grant_environment_access_core(
            &state,
            &alice,
            "ig-org",
            "ig-env",
            grant_body("ig-org-bob", "operator"),
        ))
        .await??;

        let rows = audits(&db, "environment.access.granted").await?;
        let grants: Vec<(Option<String>, serde_json::Value, serde_json::Value)> = rows
            .into_iter()
            .map(|row| {
                let metadata = row.metadata.unwrap_or_default();
                (
                    row.user_id,
                    metadata["environment_id"].clone(),
                    metadata["permission"].clone(),
                )
            })
            .collect();
        let expected = [
            ("ig-org-alice", "ig-env", "viewer"),
            ("ig-org-admin", "ig-env", "operator"),
            ("ig-org-alice", "ig-plain", "owner"),
            ("ig-org-alice", "ig-env", "operator"),
        ]
        .map(|(actor, environment, permission)| {
            (
                Some(actor.to_owned()),
                serde_json::json!(environment),
                serde_json::json!(permission),
            )
        });
        anyhow::ensure!(grants == expected, "one row per grant: {grants:?}");
        Ok(())
    }
    .await;
    db.finish(result).await
}
