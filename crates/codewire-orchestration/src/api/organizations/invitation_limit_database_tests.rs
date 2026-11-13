//! CreateInvitation's limits (#4457): an inviter must have a verified email;
//! one account creates at most 30 invitations an hour across organizations,
//! one organization at most 60 an hour and 200 pending. A refusal writes no
//! invitation, queues no email and uses up no count.

use codewire_server_core::connect_error::{ConnectCode, ConnectError};

use super::invitation_limits::{
    PENDING_PER_ORGANIZATION, PER_INVITER_PER_HOUR, PER_ORGANIZATION_PER_HOUR,
};
use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

/// The fixture's organization, a second one its owner also owns, and the
/// extra inviters of one test.
struct Limits<'a> {
    fixture: &'a LeaseFixture,
    second_org: String,
    users: Vec<String>,
}

impl<'a> Limits<'a> {
    async fn new(fixture: &'a LeaseFixture) -> Self {
        // Its id is also its slug, which may be at most 48 characters.
        let second_org = format!("{}-2nd", fixture.id);
        sqlx::query(
            "INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, 'Second', $1, $2)",
        )
        .bind(&second_org)
        .bind(&fixture.id)
        .execute(&fixture.pool)
        .await
        .unwrap();
        Self {
            fixture,
            second_org,
            users: Vec::new(),
        }
    }

    fn pool(&self) -> &sqlx::PgPool {
        &self.fixture.pool
    }

    fn owner(&self) -> String {
        self.fixture.id.clone()
    }

    fn org(&self) -> String {
        self.fixture.id.clone()
    }

    /// Inserts a verified user named `{fixture}-{name}` and returns its id.
    async fn user(&mut self, name: &str) -> String {
        let id = format!("{}-{name}", self.fixture.id);
        sqlx::query(
            "INSERT INTO users (id, email, name, email_verified) \
             VALUES ($1, $1 || '@example.test', $1, true)",
        )
        .bind(&id)
        .execute(self.pool())
        .await
        .unwrap();
        self.users.push(id.clone());
        id
    }

    /// Invites `{fixture}-{name}@example.test` to `org` as `inviter`.
    async fn invite(&self, inviter: &str, org: &str, name: &str) -> AppResult<CreatedInvitation> {
        create_invitation(
            self.pool(),
            &AuthUser {
                user_id: inviter.to_owned(),
                org_id: None,
                is_admin: false,
                via_api_key: false,
            },
            org,
            "owner",
            InviteMemberBody {
                email: format!("{}-{name}@example.test", self.fixture.id),
                role: "member".to_owned(),
                assignments: Vec::new(),
            },
        )
        .await
    }

    /// Invitations and queued emails to `{fixture}-{name}@example.test`.
    async fn written(&self, name: &str) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM org_invitations WHERE email = $1), \
                    (SELECT COUNT(*) FROM org_invitation_emails WHERE recipient = $1)",
        )
        .bind(format!("{}-{name}@example.test", self.fixture.id))
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    /// The count kept for `key`, if any.
    async fn count(&self, key: &str) -> Option<i32> {
        sqlx::query_scalar("SELECT count FROM rate_limit WHERE key = $1")
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .unwrap()
    }

    fn inviter_key(&self, user: &str) -> String {
        format!("org_invite_user:{user}")
    }

    fn org_key(&self, org: &str) -> String {
        format!("org_invite_org:{org}")
    }

    /// Sets `key`'s count and the start of its window, `ago_secs` before now.
    async fn set_count(&self, key: &str, count: i32, ago_secs: i64) {
        sqlx::query(
            "INSERT INTO rate_limit (id, key, count, last_request) VALUES ($1, $1, $2, $3) \
             ON CONFLICT (key) DO UPDATE SET count = $2, last_request = $3",
        )
        .bind(key)
        .bind(count)
        .bind(chrono::Utc::now().timestamp_millis() - ago_secs * 1000)
        .execute(self.pool())
        .await
        .unwrap();
    }

    async fn cleanup(self) {
        let mut keys = vec![
            self.org_key(&self.org()),
            self.org_key(&self.second_org),
            self.inviter_key(&self.owner()),
        ];
        keys.extend(self.users.iter().map(|user| self.inviter_key(user)));
        sqlx::query("DELETE FROM rate_limit WHERE key = ANY($1)")
            .bind(&keys)
            .execute(self.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM org_invitations WHERE org_id = ANY($1)")
            .bind([self.org(), self.second_org.clone()])
            .execute(self.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(&self.second_org)
            .execute(self.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(&self.users)
            .execute(self.pool())
            .await
            .unwrap();
    }
}

fn refusal<T: std::fmt::Debug>(result: AppResult<T>) -> ConnectError {
    ConnectError::from_app_error(&result.expect_err("must be refused"), None)
}

/// A refusal past a limit: resource_exhausted, naming the limit and when
/// to try again.
fn assert_limit<T: std::fmt::Debug>(result: AppResult<T>, names: &str) {
    let refused = refusal(result);
    assert_eq!(refused.code, ConnectCode::ResourceExhausted, "{refused:?}");
    assert!(refused.message.contains(names), "{}", refused.message);
    assert!(
        refused.message.contains("try again after ") || refused.message.contains("expires "),
        "{}",
        refused.message
    );
    assert!(refused.message.ends_with(" UTC") || refused.message.ends_with(" UTC)"));
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_unverified_inviter_is_refused_and_nothing_is_written() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-unverified").await;
    let t = Limits::new(&fixture).await;
    sqlx::query("UPDATE users SET email_verified = NULL WHERE id = $1")
        .bind(t.owner())
        .execute(t.pool())
        .await
        .unwrap();

    let refused = refusal(t.invite(&t.owner(), &t.org(), "a").await);
    assert_eq!(
        (refused.code, refused.message.as_str()),
        (
            ConnectCode::FailedPrecondition,
            "verify your email address before inviting members"
        )
    );
    assert_eq!(t.written("a").await, (0, 0));
    assert_eq!(t.count(&t.inviter_key(&t.owner())).await, None);
    assert_eq!(t.count(&t.org_key(&t.org())).await, None);

    sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
        .bind(t.owner())
        .execute(t.pool())
        .await
        .unwrap();
    t.invite(&t.owner(), &t.org(), "a").await.unwrap();
    assert_eq!(t.written("a").await, (1, 1));

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_inviter_cap_spans_organizations_and_outlives_their_invitations() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-inviter").await;
    let t = Limits::new(&fixture).await;
    let owner = t.owner();
    let half = PER_INVITER_PER_HOUR / 2;
    for i in 0..half {
        t.invite(&owner, &t.org(), &format!("first-{i}"))
            .await
            .unwrap();
    }
    for i in half..PER_INVITER_PER_HOUR {
        t.invite(&owner, &t.second_org, &format!("second-{i}"))
            .await
            .unwrap();
    }

    assert_limit(t.invite(&owner, &t.second_org, "over").await, "one account");
    assert_eq!(t.written("over").await, (0, 0));
    assert_eq!(
        t.count(&t.inviter_key(&owner)).await,
        Some(PER_INVITER_PER_HOUR)
    );

    // Deleting an organization deletes its invitations, not the count.
    sqlx::query("DELETE FROM org_invitations WHERE org_id = $1")
        .bind(t.org())
        .execute(t.pool())
        .await
        .unwrap();
    assert_limit(t.invite(&owner, &t.org(), "over").await, "one account");
    assert_eq!(t.written("over").await, (0, 0));

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_organization_cap_counts_every_inviter() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-organization").await;
    let mut t = Limits::new(&fixture).await;
    let mut sent = 0;
    for name in ["admin-a", "admin-b", "admin-c"] {
        let admin = t.user(name).await;
        while sent < PER_ORGANIZATION_PER_HOUR
            && t.count(&t.inviter_key(&admin)).await.unwrap_or(0) < PER_INVITER_PER_HOUR
        {
            t.invite(&admin, &t.org(), &format!("to-{sent}"))
                .await
                .unwrap();
            sent += 1;
        }
    }
    assert_eq!(sent, PER_ORGANIZATION_PER_HOUR);
    let fresh = t.user("admin-d").await;

    assert_limit(
        t.invite(&fresh, &t.org(), "over").await,
        "an organization can send",
    );
    assert_eq!(t.written("over").await, (0, 0));
    assert_eq!(t.count(&t.inviter_key(&fresh)).await, None);
    // The same inviter may still invite to another organization.
    t.invite(&fresh, &t.second_org, "elsewhere").await.unwrap();

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_the_pending_cap_frees_a_place_when_one_is_revoked() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-pending").await;
    let t = Limits::new(&fixture).await;
    sqlx::query(
        "INSERT INTO org_invitations \
             (id, org_id, email, role, invited_by, token_hash, status, expires_at) \
         SELECT $1 || '-held-' || n, $1, $1 || '-held-' || n || '@example.test', 'member', $1, \
                encode(sha256(($1 || n)::bytea), 'hex'), 'pending', \
                NOW() + make_interval(hours => n) \
           FROM generate_series(1, $2) AS n",
    )
    .bind(t.org())
    .bind(i32::try_from(PENDING_PER_ORGANIZATION).unwrap())
    .execute(t.pool())
    .await
    .unwrap();

    assert_limit(
        t.invite(&t.owner(), &t.org(), "over").await,
        "pending invitations",
    );
    assert_eq!(t.written("over").await, (0, 0));
    // The refusal took nothing from either hourly count.
    assert_eq!(t.count(&t.inviter_key(&t.owner())).await, None);
    assert_eq!(t.count(&t.org_key(&t.org())).await, None);

    sqlx::query("UPDATE org_invitations SET status = 'revoked' WHERE id = $1 || '-held-7'")
        .bind(t.org())
        .execute(t.pool())
        .await
        .unwrap();
    t.invite(&t.owner(), &t.org(), "over").await.unwrap();
    assert_eq!(t.written("over").await, (1, 1));

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_window_resets_an_hour_after_it_started() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-window").await;
    let t = Limits::new(&fixture).await;
    let key = t.inviter_key(&t.owner());

    t.set_count(&key, PER_INVITER_PER_HOUR, 59 * 60).await;
    assert_limit(t.invite(&t.owner(), &t.org(), "early").await, "one account");
    assert_eq!(t.count(&key).await, Some(PER_INVITER_PER_HOUR));

    t.set_count(&key, PER_INVITER_PER_HOUR, 60 * 60 + 1).await;
    t.invite(&t.owner(), &t.org(), "later").await.unwrap();
    assert_eq!(t.count(&key).await, Some(1));

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_concurrent_invitations_at_the_limit_do_not_overshoot() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-concurrent").await;
    let t = Limits::new(&fixture).await;
    let key = t.inviter_key(&t.owner());
    t.set_count(&key, PER_INVITER_PER_HOUR - 1, 0).await;

    // Across two organizations, so only the inviter's count stands between
    // them.
    let racing = &t;
    let results = futures::future::join_all((0..4).map(|i| {
        let org = if i % 2 == 0 {
            racing.org()
        } else {
            racing.second_org.clone()
        };
        let owner = racing.owner();
        async move { racing.invite(&owner, &org, &format!("racer-{i}")).await }
    }))
    .await;
    let created = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(created, 1, "{results:?}");
    for result in results.into_iter().filter(Result::is_err) {
        assert_limit(result, "one account");
    }
    assert_eq!(t.count(&key).await, Some(PER_INVITER_PER_HOUR));

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_a_refused_duplicate_uses_no_count() {
    let fixture = LeaseFixture::seed("synthetic-invitation-limits-duplicate").await;
    let t = Limits::new(&fixture).await;

    t.invite(&t.owner(), &t.org(), "twice").await.unwrap();
    let duplicate = refusal(t.invite(&t.owner(), &t.org(), "twice").await);
    assert_eq!(duplicate.code, ConnectCode::AlreadyExists);
    assert_eq!(t.count(&t.inviter_key(&t.owner())).await, Some(1));
    assert_eq!(t.count(&t.org_key(&t.org())).await, Some(1));

    t.cleanup().await;
    fixture.cleanup().await;
}
