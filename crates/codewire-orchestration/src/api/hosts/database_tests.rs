//! What `HostService` promises (#3609, slice 1): who may enroll, read,
//! change, grant, revoke and remove a host; that enrolling grants nothing;
//! that names and keys cannot be taken twice; and the online, offline and
//! revoked states.

use ed25519_dalek::{Signer, SigningKey};

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

/// One organization with an owner, an admin and two members.
async fn organization(db: &TestDatabase, org_id: &str) -> anyhow::Result<()> {
    db.organization(org_id).await?;
    member(db, &format!("{org_id}-owner"), org_id, "owner").await?;
    member(db, &format!("{org_id}-admin"), org_id, "admin").await?;
    member(db, &format!("{org_id}-alice"), org_id, "member").await?;
    member(db, &format!("{org_id}-bob"), org_id, "member").await?;
    Ok(())
}

async fn enroll(
    db: &TestDatabase,
    user_id: &str,
    org_id: &str,
    name: &str,
    seed: u8,
) -> AppResult<HostView> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public = key.verifying_key().to_bytes();
    let signature = key
        .sign(&enrollment_statement(org_id, user_id, &public))
        .to_bytes();
    enroll_host(
        &db.pool,
        &session(user_id),
        org_id,
        &NewHost {
            name,
            platform: Some(HostPlatform::LinuxX86_64Kvm),
            capability_version: 1,
            public_key: &public,
            enrollment_signature: &signature,
        },
    )
    .await
}

/// The error's machine-readable code, or the variant's name.
fn code(error: AppError) -> String {
    match error {
        AppError::Coded { code, .. } => code.to_owned(),
        AppError::Validation { errors } => format!("validation {}", errors[0].path),
        AppError::Precondition(detail) => format!("precondition {detail}"),
        other => format!("{other:?}"),
    }
}

const LIMITS: HostLimits = HostLimits {
    max_vms: 2,
    max_vcpus: None,
    max_memory_mib: Some(8192),
    max_disk_gib: None,
};

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_enrolling_needs_membership_and_takes_no_name_or_key_twice() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        organization(&db, "hosts-other").await?;

        let host = enroll(&db, "hosts-org-alice", "hosts-org", "build-box", 1)
            .await
            .unwrap()
            .host;
        anyhow::ensure!(uuid::Uuid::parse_str(&host.id).is_ok());
        anyhow::ensure!(host.owner_user_id == "hosts-org-alice");
        anyhow::ensure!(host.platform == "linux-x86_64-kvm");
        // Enrolling grants nothing: not providing, no grants, never seen.
        anyhow::ensure!(!host.provide && !host.organization_grant && host.limits().is_none());
        anyhow::ensure!(host.state() == HostState::Offline && host.last_seen_at.is_none());

        // A non-member is told the organization does not exist.
        let refused = enroll(&db, "hosts-other-alice", "hosts-org", "theirs", 2).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");
        // So is an API key for another organization, though its user is a
        // member.
        let key = SigningKey::from_bytes(&[3; 32]);
        let public = key.verifying_key().to_bytes();
        let signature = key
            .sign(&enrollment_statement("hosts-org", "hosts-org-bob", &public))
            .to_bytes();
        let api_key = AuthUser {
            org_id: Some("hosts-other".into()),
            via_api_key: true,
            ..session("hosts-org-bob")
        };
        let refused = enroll_host(
            &db.pool,
            &api_key,
            "hosts-org",
            &NewHost {
                name: "bobs",
                platform: Some(HostPlatform::LinuxX86_64Kvm),
                capability_version: 1,
                public_key: &public,
                enrollment_signature: &signature,
            },
        )
        .await;
        anyhow::ensure!(code(refused.unwrap_err()) == "org_not_found");

        // A live name is taken in its organization only.
        let taken = enroll(&db, "hosts-org-bob", "hosts-org", "build-box", 4).await;
        anyhow::ensure!(code(taken.unwrap_err()) == "host_name_taken");
        enroll(&db, "hosts-other-bob", "hosts-other", "build-box", 5)
            .await
            .unwrap();
        // A key is enrolled once, anywhere, even with a fresh signature.
        let again = enroll(&db, "hosts-other-alice", "hosts-other", "again", 1).await;
        anyhow::ensure!(code(again.unwrap_err()) == "host_key_enrolled");

        // Revoking frees the name, but never the key.
        revoke_host(&db.pool, &session("hosts-org-alice"), "hosts-org", &host.id)
            .await
            .unwrap();
        enroll(&db, "hosts-org-bob", "hosts-org", "build-box", 6)
            .await
            .unwrap();
        let reused = enroll(&db, "hosts-org-alice", "hosts-org", "rebuilt", 1).await;
        anyhow::ensure!(code(reused.unwrap_err()) == "host_key_enrolled");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_members_read_their_organizations_hosts_with_live_state() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        organization(&db, "hosts-other").await?;
        let first = enroll(&db, "hosts-org-alice", "hosts-org", "first", 1)
            .await
            .unwrap()
            .host;
        let second = enroll(&db, "hosts-org-bob", "hosts-org", "second", 2)
            .await
            .unwrap()
            .host;
        let foreign = enroll(&db, "hosts-other-alice", "hosts-other", "foreign", 3)
            .await
            .unwrap()
            .host;

        // Any member lists every host of the organization, oldest first.
        let bob = session("hosts-org-bob");
        let ids: Vec<_> = list_hosts(&db.pool, &bob, "hosts-org", "")
            .await
            .unwrap()
            .into_iter()
            .map(|host| host.id)
            .collect();
        anyhow::ensure!(ids == [first.id.clone(), second.id.clone()]);
        let paged = list_hosts(&db.pool, &bob, "hosts-org", "next").await;
        anyhow::ensure!(code(paged.unwrap_err()) == "validation /page_token");
        let outsider = list_hosts(&db.pool, &session("hosts-other-bob"), "hosts-org", "").await;
        anyhow::ensure!(code(outsider.unwrap_err()) == "org_not_found");

        // Another organization's host, or a malformed ID, is no host.
        for id in [foreign.id.as_str(), "not-a-uuid"] {
            let missing = get_host(&db.pool, &bob, "hosts-org", id).await;
            anyhow::ensure!(code(missing.unwrap_err()) == "host_not_found");
        }

        // Online while heard from in the last 45 seconds, by the database's
        // clock; offline after; revoked over either.
        let state = |id: String| {
            let pool = db.pool.clone();
            let bob = bob.clone();
            async move {
                anyhow::Ok(
                    get_host(&pool, &bob, "hosts-org", &id)
                        .await
                        .unwrap()
                        .host
                        .state(),
                )
            }
        };
        let seen = |seconds_ago: i32| {
            sqlx::query(
                "UPDATE hosts SET last_seen_at = now() - make_interval(secs => $2) WHERE id = $1",
            )
            .bind(&first.id)
            .bind(seconds_ago)
            .execute(&db.pool)
        };
        seen(10).await?;
        anyhow::ensure!(state(first.id.clone()).await? == HostState::Online);
        seen(46).await?;
        anyhow::ensure!(state(first.id.clone()).await? == HostState::Offline);
        seen(0).await?;
        revoke_host(
            &db.pool,
            &session("hosts-org-admin"),
            "hosts-org",
            &first.id,
        )
        .await
        .unwrap();
        anyhow::ensure!(state(first.id.clone()).await? == HostState::Revoked);
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_only_the_owner_sets_what_a_host_provides() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        let id = enroll(&db, "hosts-org-alice", "hosts-org", "build-box", 1)
            .await
            .unwrap()
            .host
            .id;
        let alice = session("hosts-org-alice");

        let missing = update_provide(&db.pool, &alice, "hosts-org", &id, true, None).await;
        anyhow::ensure!(code(missing.unwrap_err()) == "validation /limits");
        let bad = HostLimits {
            max_vms: 0,
            ..LIMITS
        };
        let refused = update_provide(&db.pool, &alice, "hosts-org", &id, true, Some(bad)).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "validation /limits/max_vms");

        let host = update_provide(&db.pool, &alice, "hosts-org", &id, true, Some(LIMITS))
            .await
            .unwrap()
            .host;
        anyhow::ensure!(host.provide && host.limits() == Some(LIMITS));
        // Off keeps the limits for next time.
        let host = update_provide(&db.pool, &alice, "hosts-org", &id, false, None)
            .await
            .unwrap()
            .host;
        anyhow::ensure!(!host.provide && host.limits() == Some(LIMITS));

        // Not even an organization owner or admin changes another's host.
        for other in ["hosts-org-owner", "hosts-org-admin", "hosts-org-bob"] {
            let refused = update_provide(
                &db.pool,
                &session(other),
                "hosts-org",
                &id,
                true,
                Some(LIMITS),
            )
            .await;
            anyhow::ensure!(code(refused.unwrap_err()) == "not_host_owner", "{other}");
        }

        revoke_host(&db.pool, &alice, "hosts-org", &id)
            .await
            .unwrap();
        let refused = update_provide(&db.pool, &alice, "hosts-org", &id, true, Some(LIMITS)).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "precondition the host is revoked");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_owner_grants_members_or_the_organization_and_takes_it_back() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        organization(&db, "hosts-other").await?;
        let id = enroll(&db, "hosts-org-alice", "hosts-org", "build-box", 1)
            .await
            .unwrap()
            .host
            .id;
        let alice = session("hosts-org-alice");
        let bob = Grantee::User("hosts-org-bob");

        let host = grant_host(&db.pool, &alice, "hosts-org", &id, bob)
            .await
            .unwrap();
        anyhow::ensure!(host.granted_user_ids == ["hosts-org-bob"]);
        // Granting twice changes nothing.
        let host = grant_host(&db.pool, &alice, "hosts-org", &id, bob)
            .await
            .unwrap();
        anyhow::ensure!(host.granted_user_ids == ["hosts-org-bob"]);
        // Only members, and not the owner.
        let outsider = grant_host(
            &db.pool,
            &alice,
            "hosts-org",
            &id,
            Grantee::User("hosts-other-bob"),
        )
        .await;
        anyhow::ensure!(code(outsider.unwrap_err()) == "member_not_found");
        let owner = grant_host(
            &db.pool,
            &alice,
            "hosts-org",
            &id,
            Grantee::User("hosts-org-alice"),
        )
        .await;
        anyhow::ensure!(code(owner.unwrap_err()) == "validation /user_id");
        // Only the host's owner grants, even over an organization admin.
        for other in ["hosts-org-admin", "hosts-org-bob"] {
            let refused = grant_host(
                &db.pool,
                &session(other),
                "hosts-org",
                &id,
                Grantee::Organization,
            )
            .await;
            anyhow::ensure!(code(refused.unwrap_err()) == "not_host_owner", "{other}");
            let refused = revoke_grant(&db.pool, &session(other), "hosts-org", &id, bob).await;
            anyhow::ensure!(code(refused.unwrap_err()) == "not_host_owner", "{other}");
        }

        let host = grant_host(&db.pool, &alice, "hosts-org", &id, Grantee::Organization)
            .await
            .unwrap();
        anyhow::ensure!(host.host.organization_grant);
        let host = revoke_grant(&db.pool, &alice, "hosts-org", &id, Grantee::Organization)
            .await
            .unwrap();
        anyhow::ensure!(!host.host.organization_grant);
        let host = revoke_grant(&db.pool, &alice, "hosts-org", &id, bob)
            .await
            .unwrap();
        anyhow::ensure!(host.granted_user_ids.is_empty());

        // A revoked host takes no new grant.
        revoke_host(&db.pool, &alice, "hosts-org", &id)
            .await
            .unwrap();
        let refused = grant_host(&db.pool, &alice, "hosts-org", &id, bob).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "precondition the host is revoked");
        Ok(())
    }
    .await;
    db.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_the_owner_or_an_admin_revokes_and_only_the_owner_removes() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        let enrolled =
            |name: &'static str, seed: u8| enroll(&db, "hosts-org-alice", "hosts-org", name, seed);
        let first = enrolled("first", 1).await.unwrap().host.id;
        let second = enrolled("second", 2).await.unwrap().host.id;
        let third = enrolled("third", 3).await.unwrap().host.id;

        let refused = revoke_host(&db.pool, &session("hosts-org-bob"), "hosts-org", &first).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "not_host_owner_or_admin");
        for (revoker, id) in [
            ("hosts-org-alice", &first),
            ("hosts-org-admin", &second),
            ("hosts-org-owner", &third),
        ] {
            let host = revoke_host(&db.pool, &session(revoker), "hosts-org", id)
                .await
                .unwrap()
                .host;
            anyhow::ensure!(host.state() == HostState::Revoked, "{revoker}");
            let by: Option<String> =
                sqlx::query_scalar("SELECT revoked_by FROM hosts WHERE id = $1")
                    .bind(id)
                    .fetch_one(&db.pool)
                    .await?;
            anyhow::ensure!(by.as_deref() == Some(revoker));
        }
        // Revoking again keeps the first revocation.
        let at = get_host(&db.pool, &session("hosts-org-alice"), "hosts-org", &first)
            .await
            .unwrap()
            .host
            .revoked_at;
        let again = revoke_host(&db.pool, &session("hosts-org-admin"), "hosts-org", &first)
            .await
            .unwrap()
            .host;
        anyhow::ensure!(again.revoked_at == at);

        // Only the owner removes a host, and its grants go with it.
        grant_host(
            &db.pool,
            &session("hosts-org-alice"),
            "hosts-org",
            &enrolled("fourth", 4).await.unwrap().host.id,
            Grantee::User("hosts-org-bob"),
        )
        .await
        .unwrap();
        let fourth: String = sqlx::query_scalar("SELECT id FROM hosts WHERE name = 'fourth'")
            .fetch_one(&db.pool)
            .await?;
        for other in ["hosts-org-owner", "hosts-org-admin", "hosts-org-bob"] {
            let refused = leave_host(&db.pool, &session(other), "hosts-org", &fourth).await;
            anyhow::ensure!(code(refused.unwrap_err()) == "not_host_owner", "{other}");
        }
        leave_host(&db.pool, &session("hosts-org-alice"), "hosts-org", &fourth)
            .await
            .unwrap();
        let left: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM hosts WHERE id = $1),
                    (SELECT count(*) FROM host_grants WHERE host_id = $1)",
        )
        .bind(&fourth)
        .fetch_one(&db.pool)
        .await?;
        anyhow::ensure!(left == (0, 0));

        // A revoked host's record stays, even for its owner, so its key can
        // never enroll again and undo the revocation.
        let refused = leave_host(&db.pool, &session("hosts-org-alice"), "hosts-org", &first).await;
        anyhow::ensure!(
            code(refused.unwrap_err()) == "precondition the host is revoked; its record stays"
        );
        let reused = enrolled("first-again", 1).await;
        anyhow::ensure!(code(reused.unwrap_err()) == "host_key_enrolled");
        Ok(())
    }
    .await;
    db.finish(result).await
}

/// Adds `count` hosts owned by `owner` directly, with distinct keys from
/// `first_key` on, revoked or not.
async fn fill(
    db: &TestDatabase,
    owner: &str,
    first_key: i32,
    count: i64,
    revoked: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO hosts (org_id, owner_user_id, name, platform, capability_version, public_key,
                            revoked_at)
         SELECT 'hosts-org', $1, 'filled-' || n, 'linux-x86_64-kvm', 1,
                decode(lpad(to_hex(n), 64, '0'), 'hex'), CASE WHEN $4 THEN now() END
           FROM generate_series($2::int, $2::int + $3::int - 1) AS n",
    )
    .bind(owner)
    .bind(first_key)
    .bind(count as i32)
    .bind(revoked)
    .execute(&db.pool)
    .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn db_live_hosts_are_bounded_per_organization_and_records_per_member() -> anyhow::Result<()> {
    let db = TestDatabase::create().await?;
    let result = async {
        organization(&db, "hosts-org").await?;
        // One member fills every live place.
        fill(&db, "hosts-org-alice", 1000, MAX_LIVE_HOSTS_PER_ORG, false).await?;
        let refused = enroll(&db, "hosts-org-bob", "hosts-org", "one-more", 1).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "host_limit_reached");
        // An admin revoking one frees its place.
        let filled: String = sqlx::query_scalar("SELECT id FROM hosts WHERE name = 'filled-1000'")
            .fetch_one(&db.pool)
            .await?;
        revoke_host(&db.pool, &session("hosts-org-admin"), "hosts-org", &filled)
            .await
            .unwrap();
        enroll(&db, "hosts-org-bob", "hosts-org", "one-more", 1)
            .await
            .unwrap();

        // Revoked records stay, so they count toward their member's own
        // bound, and only theirs.
        sqlx::query("DELETE FROM hosts").execute(&db.pool).await?;
        fill(
            &db,
            "hosts-org-alice",
            2000,
            MAX_HOST_RECORDS_PER_OWNER,
            true,
        )
        .await?;
        let refused = enroll(&db, "hosts-org-alice", "hosts-org", "after-revokes", 2).await;
        anyhow::ensure!(code(refused.unwrap_err()) == "host_limit_reached");
        enroll(&db, "hosts-org-bob", "hosts-org", "bobs", 3)
            .await
            .unwrap();
        Ok(())
    }
    .await;
    db.finish(result).await
}
