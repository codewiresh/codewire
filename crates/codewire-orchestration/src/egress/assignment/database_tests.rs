//! The assignment query against the organization policy store (#4211): what
//! a hosted environment's sandbox is told to enforce.

use codewire_egress_policy::{BuiltinPolicy, HOSTED_DEFAULT_DIGEST, PolicyDigest};
use codewire_server_core::auth::AuthUser;

use super::*;
use crate::api::network_policies::{
    RuleInput, Selector, create_policy, select_for_environment, update_policy,
};
use crate::test_database_support::TestDatabase;

const ORG: &str = "org-egress";
const OWNER: &str = "org-egress-owner";
const ENVIRONMENT: &str = "env-egress";

fn owner() -> AuthUser {
    AuthUser {
        user_id: OWNER.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn fixture(db: &TestDatabase) -> anyhow::Result<()> {
    db.organization(ORG).await?;
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(OWNER)
        .bind(format!("{OWNER}@example.test"))
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'owner')")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(ORG)
        .bind(OWNER)
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
    .bind(ENVIRONMENT)
    .bind(ORG)
    .bind(OWNER)
    .bind(format!("{ORG}-preset"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

fn hex(policy: &AssignedPolicy) -> String {
    PolicyDigest::from_bytes(policy.digest).to_hex()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_sandbox_is_assigned_its_selections_current_revision() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        fixture(&db).await?;

        // Nothing selected: hosted-default, and no row.
        let none = environment_policy(&db.pool, ENVIRONMENT).await?;
        assert_eq!((none.name.as_str(), none.revision), ("hosted-default", 0));
        assert_eq!(hex(&none), HOSTED_DEFAULT_DIGEST);

        // A built-in.
        select_for_environment(&db.pool, &owner(), ORG, ENVIRONMENT, "locked")
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let locked = environment_policy(&db.pool, ENVIRONMENT).await?;
        assert_eq!(locked.name, "locked");
        assert_eq!(hex(&locked), BuiltinPolicy::Locked.digest_hex());

        // A stored policy, followed to its current revision.
        let rule = [RuleInput {
            target: "github.com",
            ports: &[443],
        }];
        let created = create_policy(&db.pool, &owner(), ORG, "web", None, &rule)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        select_for_environment(&db.pool, &owner(), ORG, ENVIRONMENT, "platform:web")
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let first = environment_policy(&db.pool, ENVIRONMENT).await?;
        assert_eq!((first.name.as_str(), first.revision), ("platform:web", 1));
        assert_eq!(hex(&first), created.digest);
        assert_eq!(
            CompiledPolicy::compile(serde_json::from_slice(&first.document)?)?
                .digest()
                .to_hex(),
            created.digest,
            "the document reproduces its digest"
        );

        let extra = [RuleInput {
            target: "crates.io",
            ports: &[443],
        }];
        let changed = update_policy(
            &db.pool,
            &owner(),
            ORG,
            Selector::Name("web"),
            &extra,
            &[],
            None,
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let second = environment_policy(&db.pool, ENVIRONMENT).await?;
        assert_eq!(second.revision, 2);
        assert_eq!(hex(&second), changed.digest);

        assert!(matches!(
            environment_policy(&db.pool, "no-such-environment").await,
            Err(AssignmentError::NoEnvironment)
        ));
        anyhow::Ok(())
    }
    .await;
    db.finish(result).await
}
