//! What `NetworkPolicyService` promises (#4000, item 1): who may read, change
//! and select an organization's policies; that every change is a new
//! revision with the same document and digest a local store writes; that a
//! selection follows the current revision; and that a selected policy cannot
//! be deleted.

use super::*;
use crate::test_database_support::TestDatabase;

fn session(user_id: &str) -> AuthUser {
    AuthUser {
        user_id: user_id.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

async fn member(db: &TestDatabase, user_id: &str, org_id: &str, role: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(user_id)
        .bind(format!("{user_id}@example.test"))
        .execute(&db.pool)
        .await?;
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, $4)")
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(org_id)
        .bind(user_id)
        .bind(role)
        .execute(&db.pool)
        .await?;
    Ok(())
}

/// One organization with an owner, an admin and a member.
async fn organization(db: &TestDatabase, org_id: &str) -> anyhow::Result<()> {
    db.organization(org_id).await?;
    member(db, &format!("{org_id}-owner"), org_id, "owner").await?;
    member(db, &format!("{org_id}-admin"), org_id, "admin").await?;
    member(db, &format!("{org_id}-alice"), org_id, "member").await?;
    Ok(())
}

/// A running hosted environment `created_by` made.
async fn environment(
    db: &TestDatabase,
    id: &str,
    org_id: &str,
    created_by: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO environment_presets (id, org_id, name, slug, project_spec) \
         VALUES ($1, $2, 'Preset', $1, '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(format!("{org_id}-preset"))
    .bind(org_id)
    .execute(&db.pool)
    .await?;
    sqlx::query(
        "INSERT INTO environments \
         (id, org_id, created_by, preset_id, type, name, state, desired_state, project_spec) \
         VALUES ($1, $2, $3, $4, 'sandbox', $1, 'running', 'started', \
         '{\"schema_version\":1,\"working_directory\":\"/workspace\"}'::jsonb)",
    )
    .bind(id)
    .bind(org_id)
    .bind(created_by)
    .bind(format!("{org_id}-preset"))
    .execute(&db.pool)
    .await?;
    Ok(())
}

/// The error's machine-readable code, or the variant's name.
fn code(error: AppError) -> String {
    match error {
        AppError::Coded { code, .. } => code.to_owned(),
        AppError::Precondition(detail) => format!("precondition {detail}"),
        AppError::BadRequest(detail) => format!("bad request {detail}"),
        other => format!("{other:?}"),
    }
}

fn rule<'a>(target: &'a str, ports: &'a [u32]) -> RuleInput<'a> {
    RuleInput { target, ports }
}

fn targets(view: &PolicyView) -> Vec<(String, Vec<u16>)> {
    view.policy
        .rules()
        .iter()
        .map(|rule| (rule.target().to_string(), rule.ports().to_vec()))
        .collect()
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_owners_and_admins_change_policies_and_members_read_them() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "np-org").await?;
        organization(&db, "np-other").await?;
        let owner = session("np-org-owner");

        let web = create_policy(
            &db.pool,
            &owner,
            "np-org",
            "web",
            None,
            &[rule("github.com", &[443])],
        )
        .await
        .unwrap();
        anyhow::ensure!(uuid::Uuid::parse_str(&web.id).is_ok());
        anyhow::ensure!((web.revision, web.current_revision) == (1, 1));
        anyhow::ensure!(targets(&web) == vec![("github.com".to_owned(), vec![443])]);
        anyhow::ensure!(web.created_by.as_deref() == Some("np-org-owner"));

        // A member reads but does not change; a non-member, an API key for
        // another organization and another organization's member see nothing.
        let alice = session("np-org-alice");
        anyhow::ensure!(
            list_policies(&db.pool, &alice, "np-org")
                .await
                .unwrap()
                .len()
                == 1
        );
        let refused = create_policy(&db.pool, &alice, "np-org", "mine", None, &[]).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "not_network_policy_manager");
        let refused = update_policy(
            &db.pool,
            &alice,
            "np-org",
            Selector::Name("web"),
            &[],
            &["github.com"],
            None,
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()) == "not_network_policy_manager");
        let refused = delete_policy(&db.pool, &alice, "np-org", Selector::Name("web")).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "not_network_policy_manager");
        let outsider = session("np-other-alice");
        let refused = list_policies(&db.pool, &outsider, "np-org").await;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");
        let api_key = AuthUser {
            org_id: Some("np-other".into()),
            via_api_key: true,
            ..session("np-org-owner")
        };
        let refused = get_policy(&db.pool, &api_key, "np-org", Selector::Name("web"), None).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");
        let refused = get_policy(
            &db.pool,
            &session("np-other-owner"),
            "np-other",
            Selector::Id(&web.id),
            None,
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()) == "network_policy_not_found");

        // An admin changes it: a new revision, the old one kept as it was.
        let admin = session("np-org-admin");
        let second = update_policy(
            &db.pool,
            &admin,
            "np-org",
            Selector::Id(&web.id),
            &[rule("github.com", &[22]), rule("pypi.org", &[443])],
            &[],
            Some(1),
        )
        .await
        .unwrap();
        anyhow::ensure!((second.revision, second.current_revision) == (2, 2));
        anyhow::ensure!(
            targets(&second)
                == vec![
                    ("github.com".to_owned(), vec![22, 443]),
                    ("pypi.org".to_owned(), vec![443])
                ]
        );
        anyhow::ensure!(second.digest != web.digest);
        let first = get_policy(&db.pool, &alice, "np-org", Selector::Name("web"), Some(1))
            .await
            .unwrap();
        anyhow::ensure!(
            first
                == PolicyView {
                    current_revision: 2,
                    ..web.clone()
                }
        );

        // A stale revision, a change that changes nothing and a missing rule
        // are refused.
        let refused = update_policy(
            &db.pool,
            &admin,
            "np-org",
            Selector::Name("web"),
            &[rule("crates.io", &[443])],
            &[],
            Some(1),
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("it is at revision 2"));
        let refused = update_policy(
            &db.pool,
            &admin,
            "np-org",
            Selector::Name("web"),
            &[rule("pypi.org", &[443])],
            &[],
            None,
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("already allows exactly that"));
        let refused = update_policy(
            &db.pool,
            &admin,
            "np-org",
            Selector::Name("web"),
            &[],
            &["crates.io"],
            None,
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("has no rule for crates.io"));

        // Names: taken once per organization, never a built-in's.
        let taken = create_policy(&db.pool, &owner, "np-org", "web", None, &[]).await;
        anyhow::ensure!(code(taken.unwrap_err()) == "network_policy_name_taken");
        create_policy(
            &db.pool,
            &session("np-other-owner"),
            "np-other",
            "web",
            None,
            &[],
        )
        .await
        .unwrap();
        for (reserved, expected) in [
            ("open", "reserved for the built-in policies"),
            ("locked", "reserved for the built-in policies"),
            ("hosted-default", "reserved for the hosted default"),
        ] {
            let refused = create_policy(&db.pool, &owner, "np-org", reserved, None, &[]).await;
            anyhow::ensure!(code(refused.unwrap_err()).contains(expected), "{reserved}");
        }

        // A copy starts from the other policy's current revision.
        let copy = create_policy(
            &db.pool,
            &owner,
            "np-org",
            "web-and-npm",
            Some(Selector::Name("web")),
            &[rule("registry.npmjs.org", &[443])],
        )
        .await
        .unwrap();
        anyhow::ensure!(copy.revision == 1 && copy.policy.rules().len() == 3);

        // Deleting returns what it deleted.
        let deleted = delete_policy(&db.pool, &owner, "np-org", Selector::Name("web-and-npm"))
            .await
            .unwrap();
        anyhow::ensure!(deleted == copy);
        let names: Vec<String> = list_policies(&db.pool, &owner, "np-org")
            .await
            .unwrap()
            .into_iter()
            .map(|view| view.name)
            .collect();
        anyhow::ensure!(names == ["web"]);
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// The canonical document a local VM's policy store writes for these rules
/// (crates/codewire-local-vmm, network_policy_store tests).
const SHARED_DOCUMENT: &str = r#"{"version":1,"default":"deny","rules":[{"id":"allow-5901884b7857ae99.tcp","action":"allow","protocols":["tcp"],"ports":[443],"cidrs":["93.184.216.0/24"],"destinations":[],"route_classes":["general"]},{"id":"allow-a6ad0e232c75e1ac.dns","action":"allow","protocols":["dns"],"ports":[53],"cidrs":[],"destinations":["github.com"],"route_classes":["general"]},{"id":"allow-a6ad0e232c75e1ac.tcp","action":"allow","protocols":["tcp"],"ports":[22,443],"cidrs":[],"destinations":["github.com"],"route_classes":["general"]}]}"#;
const SHARED_DIGEST: &str = "90edf3723213a00ccc8639cc0386f5261c9128c281f2a73dc3805a0bfef1df35";

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_revision_holds_the_document_and_digest_a_local_store_writes() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "np-bytes").await?;
        let view = create_policy(
            &db.pool,
            &session("np-bytes-owner"),
            "np-bytes",
            "shared",
            None,
            &[
                rule("github.com", &[443, 22]),
                rule("93.184.216.0/24", &[443]),
            ],
        )
        .await
        .unwrap();
        let (document, digest): (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT document, digest FROM platform_network_policy_revisions WHERE policy_id = $1",
        )
        .bind(&view.id)
        .fetch_one(&db.pool)
        .await?;
        let document = String::from_utf8(document)?;
        anyhow::ensure!(document == SHARED_DOCUMENT, "document: {document}");
        let digest = PolicyDigest::from_bytes(digest.as_slice().try_into()?).to_hex();
        anyhow::ensure!(
            digest == SHARED_DIGEST && view.digest == SHARED_DIGEST,
            "digest: {digest}"
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_environment_selects_a_policy_and_follows_its_current_revision() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "np-env").await?;
        organization(&db, "np-env-other").await?;
        let owner = session("np-env-owner");
        let alice = session("np-env-alice");
        environment(&db, "np-env-app", "np-env", "np-env-alice").await?;
        environment(&db, "np-env-owners", "np-env", "np-env-owner").await?;
        let web = create_policy(&db.pool, &owner, "np-env", "web", None, &[rule("github.com", &[443])])
            .await
            .unwrap();
        create_policy(
            &db.pool,
            &session("np-env-other-owner"),
            "np-env-other",
            "elsewhere",
            None,
            &[],
        )
        .await
        .unwrap();

        // No selection is hosted-default.
        let mut connection = db.pool.acquire().await?;
        let unselected = environment_policy_in(&mut connection, "np-env-app").await.unwrap();
        drop(connection);
        anyhow::ensure!(
            unselected == EnvironmentPolicyView {
                reference: "hosted-default".into(),
                name: "hosted-default".into(),
                revision: 0,
                digest: HOSTED_DEFAULT_DIGEST.into(),
            }
        );

        // A member selects by name, platform:NAME or platform:id:UUID.
        let exact = format!("platform:id:{}", web.id);
        for reference in ["web", "platform:web", exact.as_str()] {
            let view = select_for_environment(&db.pool, &alice, "np-env", "np-env-app", reference)
                .await
                .unwrap();
            anyhow::ensure!(
                view == EnvironmentPolicyView {
                    reference: format!("platform:id:{}", web.id),
                    name: "web".into(),
                    revision: 1,
                    digest: web.digest.clone(),
                },
                "{reference}"
            );
        }

        // The selection follows the policy's current revision.
        let second = update_policy(
            &db.pool,
            &owner,
            "np-env",
            Selector::Name("web"),
            &[rule("pypi.org", &[443])],
            &[],
            None,
        )
        .await
        .unwrap();
        let mut connection = db.pool.acquire().await?;
        let followed = environment_policy_in(&mut connection, "np-env-app").await.unwrap();
        drop(connection);
        anyhow::ensure!(followed.revision == 2 && followed.digest == second.digest);

        // A selected policy cannot be deleted; the refusal names who selects it.
        let refused = delete_policy(&db.pool, &owner, "np-env", Selector::Name("web")).await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("web is selected by np-env-app"));

        // Built-ins, then back to no selection.
        let locked = select_for_environment(&db.pool, &alice, "np-env", "np-env-app", "locked")
            .await
            .unwrap();
        anyhow::ensure!(
            (locked.reference.as_str(), locked.revision, locked.digest.as_str())
                == ("locked", 0, BuiltinPolicy::Locked.digest_hex())
        );
        let unselected =
            select_for_environment(&db.pool, &alice, "np-env", "np-env-app", "hosted-default")
                .await
                .unwrap();
        anyhow::ensure!(unselected.reference == "hosted-default");
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM platform_environment_network_policies WHERE environment_id = 'np-env-app'",
        )
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(rows == 0, "hosted-default stores no row");

        // Refused: a local policy, a qualified built-in, another organization's
        // policy, a policy that does not exist, another member's environment,
        // and an environment of an organization the caller is not in.
        for (reference, expected) in [
            ("local:web", "local-only"),
            ("platform:open", "built-in network policy"),
            ("elsewhere", "network_policy_not_found"),
            ("missing", "network_policy_not_found"),
        ] {
            let refused =
                select_for_environment(&db.pool, &alice, "np-env", "np-env-app", reference).await;
            anyhow::ensure!(code(refused.unwrap_err()).contains(expected), "{reference}");
        }
        let refused =
            select_for_environment(&db.pool, &alice, "np-env", "np-env-owners", "web").await;
        anyhow::ensure!(code(refused.unwrap_err()) == "environment_not_found");
        let refused = select_for_environment(
            &db.pool,
            &session("np-env-other-alice"),
            "np-env",
            "np-env-app",
            "web",
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");

        // Destroying the environment releases its selection, so the policy
        // can go.
        select_for_environment(&db.pool, &alice, "np-env", "np-env-app", "web")
            .await
            .unwrap();
        sqlx::query(
            "UPDATE environments SET desired_state = 'destroyed', state = 'destroying' \
             WHERE id = 'np-env-app'",
        )
        .execute(&db.pool)
        .await?;
        let proof = crate::lifecycle::RuntimeAbsenceProof::begin(&db.pool).await?;
        crate::lifecycle::Service::for_pool(db.pool.clone())
            .complete_destroy("np-env-app", proof)
            .await?;
        delete_policy(&db.pool, &owner, "np-env", Selector::Name("web"))
            .await
            .unwrap();
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_strangers_change_nothing_and_the_limits_hold() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "np-lim").await?;
        organization(&db, "np-lim-other").await?;
        let owner = session("np-lim-owner");
        environment(&db, "np-lim-app", "np-lim", "np-lim-owner").await?;
        let web = create_policy(
            &db.pool,
            &owner,
            "np-lim",
            "web",
            None,
            &[rule("github.com", &[443])],
        )
        .await
        .unwrap();

        // A non-member, and an API key scoped to another organization even
        // though its user is an owner here, are told the organization does
        // not exist, on every call.
        let outsider = session("np-lim-other-owner");
        let foreign_key = AuthUser {
            org_id: Some("np-lim-other".into()),
            via_api_key: true,
            ..session("np-lim-owner")
        };
        for caller in [&outsider, &foreign_key] {
            let refusals = [
                create_policy(&db.pool, caller, "np-lim", "theirs", None, &[])
                    .await
                    .map(|_| ()),
                get_policy(&db.pool, caller, "np-lim", Selector::Name("web"), None)
                    .await
                    .map(|_| ()),
                update_policy(
                    &db.pool,
                    caller,
                    "np-lim",
                    Selector::Name("web"),
                    &[rule("pypi.org", &[443])],
                    &[],
                    None,
                )
                .await
                .map(|_| ()),
                delete_policy(&db.pool, caller, "np-lim", Selector::Name("web"))
                    .await
                    .map(|_| ()),
                select_for_environment(&db.pool, caller, "np-lim", "np-lim-app", "web")
                    .await
                    .map(|_| ()),
                list_policies(&db.pool, caller, "np-lim").await.map(|_| ()),
            ];
            for (index, refused) in refusals.into_iter().enumerate() {
                anyhow::ensure!(
                    code(refused.unwrap_err()) == "org_not_found",
                    "{} call {index}",
                    caller.user_id
                );
            }
        }
        let unchanged = get_policy(&db.pool, &owner, "np-lim", Selector::Id(&web.id), None)
            .await
            .unwrap();
        anyhow::ensure!(unchanged == web, "nothing changed it");

        // 256 policies per organization: the 256th is made, the 257th refused.
        sqlx::query(
            "INSERT INTO platform_network_policies (org_id, name, current_revision) \
             SELECT 'np-lim', 'filler-' || n, 1 FROM generate_series(1, 254) AS n",
        )
        .execute(&db.pool)
        .await?;
        create_policy(&db.pool, &owner, "np-lim", "last", None, &[])
            .await
            .unwrap();
        let refused = create_policy(&db.pool, &owner, "np-lim", "one-more", None, &[]).await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("the most network policies"));

        // 10,000 revisions per policy: a policy at the last one takes no more.
        sqlx::query(
            "INSERT INTO platform_network_policy_revisions (policy_id, revision, document, digest) \
             SELECT policy_id, 10000, document, digest FROM platform_network_policy_revisions \
             WHERE policy_id = $1 AND revision = 1",
        )
        .bind(&web.id)
        .execute(&db.pool)
        .await?;
        sqlx::query("UPDATE platform_network_policies SET current_revision = 10000 WHERE id = $1")
            .bind(&web.id)
            .execute(&db.pool)
            .await?;
        let refused = update_policy(
            &db.pool,
            &owner,
            "np-lim",
            Selector::Id(&web.id),
            &[rule("pypi.org", &[443])],
            &[],
            None,
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()).contains("the most revisions"));
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// A selection that does not decode is logged and left out of the
/// environment read; it never fails the read, so it cannot take a whole
/// organization's environment list down. The constraints make such a row
/// impossible, so this throwaway database drops one to make it.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_a_selection_that_does_not_decode_never_fails_the_environment_read() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "np-bad").await?;
        environment(&db, "np-bad-app", "np-bad", "np-bad-owner").await?;
        let web = create_policy(
            &db.pool,
            &session("np-bad-owner"),
            "np-bad",
            "web",
            None,
            &[rule("github.com", &[443])],
        )
        .await
        .unwrap();
        select_for_environment(
            &db.pool,
            &session("np-bad-owner"),
            "np-bad",
            "np-bad-app",
            "web",
        )
        .await
        .unwrap();
        sqlx::raw_sql(
            "ALTER TABLE platform_network_policy_revisions \
               DROP CONSTRAINT platform_network_policy_revisions_digest_check; \
             ALTER TABLE platform_network_policy_revisions \
               DISABLE TRIGGER platform_network_policy_revisions_immutable;",
        )
        .execute(&db.pool)
        .await?;
        sqlx::query(
            "UPDATE platform_network_policy_revisions SET digest = '\\x00' WHERE policy_id = $1",
        )
        .bind(&web.id)
        .execute(&db.pool)
        .await?;
        let row = sqlx::query(&format!(
            "SELECT {} FROM environments e {} WHERE e.id = 'np-bad-app'",
            crate::api::environments::ENV_SELECT_COLS,
            crate::api::environments::ENV_SELECT_JOINS
        ))
        .fetch_one(&db.pool)
        .await?;
        let environment = crate::api::environments::scan_environment(&row)?;
        anyhow::ensure!(environment.id == "np-bad-app");
        anyhow::ensure!(environment.network_policy.is_none());
        Ok(())
    }
    .await;
    db.finish(result).await
}
