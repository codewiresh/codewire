//! What an organization's registered audiences promise
//! (docs/dev/SANDBOX-IDENTITY.md, "Audiences"): only an owner or admin
//! registers, lists and removes them; each is stored once, in its canonical
//! form, with its defaults; refusals name the rule; and each change writes
//! its audit row.

use std::time::Duration;

use super::audiences::{AudienceRequest, list_audiences, register_audience, remove_audience};
use super::database_test_support::*;
use crate::identity::audience::AudienceDenylist;

fn denylist() -> AudienceDenylist {
    AudienceDenylist::for_deployment(
        "https://codewire.example",
        "preview.example",
        Some("https://identity.codewire.example"),
    )
}

fn plain(audience: &str) -> AudienceRequest<'_> {
    AudienceRequest {
        audience,
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_an_audience_is_registered_once_in_its_canonical_form_and_audited() -> anyhow::Result<()>
{
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ia-org").await?;
        organization(&db, "ia-other").await?;
        let admin = session("ia-org-admin");
        let denylist = denylist();

        let registered = bounded(register_audience(
            &db.pool,
            &denylist,
            &admin,
            "ia-org",
            plain("HTTPS://K8S.WALK.EXAMPLE:443"),
        ))
        .await??;
        anyhow::ensure!(registered.audience == "https://k8s.walk.example");
        anyhow::ensure!(
            registered.visible_groups.is_none(),
            "every group by default"
        );
        anyhow::ensure!(registered.lifetime_seconds == 600, "ten minutes by default");
        anyhow::ensure!(!registered.claim_created_by && !registered.claim_environment_name);
        anyhow::ensure!(registered.file_name.is_none() && registered.version > 0);
        anyhow::ensure!(registered.created_by == "ia-org-admin");

        // Once per organization, in any spelling; another organization may
        // register it too.
        let again = bounded(register_audience(
            &db.pool,
            &denylist,
            &admin,
            "ia-org",
            plain("https://k8s.walk.example"),
        ))
        .await?;
        anyhow::ensure!(code(again.unwrap_err()) == "identity_audience_exists");
        bounded(register_audience(
            &db.pool,
            &denylist,
            &session("ia-other-owner"),
            "ia-other",
            plain("https://k8s.walk.example"),
        ))
        .await??;

        let groups = vec!["data-readers".to_owned(), "builders".to_owned()];
        let options = bounded(register_audience(
            &db.pool,
            &denylist,
            &session("ia-org-super"),
            "ia-org",
            AudienceRequest {
                audience: "https://vault.example.com:8200/v1/auth/jwt/",
                visible_groups: Some(&groups),
                lifetime: Some(Duration::from_secs(300)),
                claim_created_by: true,
                claim_environment_name: true,
                file_name: Some("vault"),
            },
        ))
        .await??;
        anyhow::ensure!(options.audience == "https://vault.example.com:8200/v1/auth/jwt/");
        anyhow::ensure!(
            options.visible_groups.as_deref()
                == Some(&["builders".to_owned(), "data-readers".to_owned()][..])
        );
        anyhow::ensure!(options.lifetime_seconds == 300);
        anyhow::ensure!(options.claim_created_by && options.claim_environment_name);
        anyhow::ensure!(options.file_name.as_deref() == Some("vault"));
        let none: Vec<String> = Vec::new();
        let sees_none = bounded(register_audience(
            &db.pool,
            &denylist,
            &admin,
            "ia-org",
            AudienceRequest {
                audience: "https://sees-none.example",
                visible_groups: Some(&none),
                ..Default::default()
            },
        ))
        .await??;
        anyhow::ensure!(sees_none.visible_groups == Some(Vec::new()));

        let taken = bounded(register_audience(
            &db.pool,
            &denylist,
            &admin,
            "ia-org",
            AudienceRequest {
                audience: "https://other.example",
                file_name: Some("vault"),
                ..Default::default()
            },
        ))
        .await?;
        anyhow::ensure!(code(taken.unwrap_err()) == "identity_file_name_in_use");

        let listed = bounded(list_audiences(&db.pool, &admin, "ia-org")).await??;
        let audiences: Vec<&str> = listed.iter().map(|view| view.audience.as_str()).collect();
        anyhow::ensure!(
            audiences
                == [
                    "https://k8s.walk.example",
                    "https://sees-none.example",
                    "https://vault.example.com:8200/v1/auth/jwt/",
                ],
            "{audiences:?}"
        );

        let rows = audits(&db, "identity.audience.registered").await?;
        anyhow::ensure!(rows.len() == 4, "one row per registration: {rows:?}");
        anyhow::ensure!(
            rows[0].metadata
                == Some(serde_json::json!({
                    "org_id": "ia-org",
                    "audience": "https://k8s.walk.example",
                    "visible_groups": null,
                    "lifetime_seconds": 600,
                    "claim_created_by": false,
                    "claim_environment_name": false,
                    "file_name": null,
                    "version": registered.version,
                })),
            "{:?}",
            rows[0]
        );
        anyhow::ensure!(
            rows[1].metadata.as_ref().map(|m| m["org_id"].clone()) == Some("ia-other".into())
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_removing_an_audience_is_audited_and_a_new_registration_has_a_new_version()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ia-org").await?;
        let admin = session("ia-org-admin");
        let first = bounded(register_audience(
            &db.pool,
            &denylist(),
            &admin,
            "ia-org",
            plain("https://k8s.walk.example"),
        ))
        .await??;
        let removed = bounded(remove_audience(
            &db.pool,
            &admin,
            "ia-org",
            "https://K8S.walk.example:443",
        ))
        .await??;
        anyhow::ensure!(removed == "https://k8s.walk.example");
        anyhow::ensure!(
            bounded(list_audiences(&db.pool, &admin, "ia-org"))
                .await??
                .is_empty()
        );
        for missing in ["https://k8s.walk.example", "not a uri"] {
            let refused = bounded(remove_audience(&db.pool, &admin, "ia-org", missing)).await?;
            anyhow::ensure!(
                code(refused.unwrap_err()) == "identity_audience_not_found",
                "{missing}"
            );
        }
        let second = bounded(register_audience(
            &db.pool,
            &denylist(),
            &admin,
            "ia-org",
            plain("https://k8s.walk.example"),
        ))
        .await??;
        anyhow::ensure!(
            second.version > first.version,
            "a registration never reuses a version: {} then {}",
            first.version,
            second.version
        );
        let rows = audits(&db, "identity.audience.removed").await?;
        anyhow::ensure!(
            rows.iter()
                .map(|row| (row.user_id.clone(), row.metadata.clone()))
                .collect::<Vec<_>>()
                == [(
                    Some("ia-org-admin".to_owned()),
                    Some(serde_json::json!({
                        "org_id": "ia-org",
                        "audience": "https://k8s.walk.example",
                        "version": first.version,
                    }))
                )]
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_an_owner_or_admin_manages_audiences_and_each_refusal_names_its_rule()
-> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "ia-org").await?;
        organization(&db, "ia-other").await?;
        let admin = session("ia-org-admin");
        let denylist = denylist();
        for user in [session("ia-org-alice"), session("ia-other-owner")] {
            let expected = if user.user_id == "ia-org-alice" {
                "not_identity_admin"
            } else {
                "org_not_found"
            };
            let refused = bounded(register_audience(
                &db.pool,
                &denylist,
                &user,
                "ia-org",
                plain("https://k8s.walk.example"),
            ))
            .await?;
            anyhow::ensure!(code(refused.unwrap_err()) == expected);
            let refused = bounded(list_audiences(&db.pool, &user, "ia-org")).await?;
            anyhow::ensure!(code(refused.unwrap_err()) == expected);
            let refused = bounded(remove_audience(
                &db.pool,
                &user,
                "ia-org",
                "https://k8s.walk.example",
            ))
            .await?;
            anyhow::ensure!(code(refused.unwrap_err()) == expected);
        }

        // The journey's step 3 refusals, each naming its rule.
        for (audience, words) in [
            ("https://api.codewire.example", "codewire.example"),
            ("https://x.codewire.example/", "deployment serves it"),
            ("https://x.preview.example", "preview.example"),
            ("https://kubernetes.default.svc", "Kubernetes"),
            ("https://10.0.0.1", "IP address"),
            ("http://k8s.walk.example", "https"),
            ("https://k8s.walk.example/?a=1", "query"),
            ("https://localhost", "localhost"),
        ] {
            let error = bounded(register_audience(
                &db.pool,
                &denylist,
                &admin,
                "ia-org",
                plain(audience),
            ))
            .await?
            .unwrap_err();
            let text = detail(&error);
            anyhow::ensure!(code(error) == "invalid_audience", "{audience}");
            anyhow::ensure!(text.contains(words), "{audience}: {text}");
        }
        let all = vec!["all".to_owned()];
        for (request, expected) in [
            (
                AudienceRequest {
                    audience: "https://a.example",
                    lifetime: Some(Duration::from_secs(59)),
                    ..Default::default()
                },
                "invalid_audience_lifetime",
            ),
            (
                AudienceRequest {
                    audience: "https://a.example",
                    lifetime: Some(Duration::from_secs(601)),
                    ..Default::default()
                },
                "invalid_audience_lifetime",
            ),
            (
                AudienceRequest {
                    audience: "https://a.example",
                    visible_groups: Some(&all),
                    ..Default::default()
                },
                "invalid_identity_group",
            ),
            (
                AudienceRequest {
                    audience: "https://a.example",
                    file_name: Some("../token"),
                    ..Default::default()
                },
                "invalid_identity_file_name",
            ),
        ] {
            let refused = bounded(register_audience(
                &db.pool, &denylist, &admin, "ia-org", request,
            ))
            .await?;
            anyhow::ensure!(code(refused.unwrap_err()) == expected, "{expected}");
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_audiences")
            .fetch_one(&db.pool)
            .await?;
        anyhow::ensure!(count == 0, "a refused registration writes nothing");
        anyhow::ensure!(
            audits(&db, "identity.audience.registered")
                .await?
                .is_empty()
        );
        Ok(())
    }
    .await;
    db.finish(result).await
}
