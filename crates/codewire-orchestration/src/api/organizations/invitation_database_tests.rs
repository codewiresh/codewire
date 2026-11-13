//! Accepting an invitation needs an account credential and the caller's
//! verified email address equal to the invitation's, whether it is named by
//! its one-time token or by its id; a refusal leaves it pending. To a caller
//! at another address an invitation is not found, whatever its state.
//! ListMyInvitations shows a verified address its pending, unexpired
//! invitations and nothing else, matching addresses by the same rule (#3840).

use codewire_server_core::connect_error::{ConnectCode, ConnectError};

use super::*;
use crate::api::runtime_lease_test_support::LeaseFixture;

/// Users and invitations of one test, all in the fixture's organization.
struct Invitations<'a> {
    fixture: &'a LeaseFixture,
    users: Vec<String>,
}

impl<'a> Invitations<'a> {
    fn new(fixture: &'a LeaseFixture) -> Self {
        Self {
            fixture,
            users: Vec::new(),
        }
    }

    fn pool(&self) -> &sqlx::PgPool {
        &self.fixture.pool
    }

    /// Inserts a user named `{fixture}-{name}` with `email` and returns its id.
    async fn user(&mut self, name: &str, email: &str, verified: bool) -> String {
        let id = format!("{}-{name}", self.fixture.id);
        sqlx::query("INSERT INTO users (id, email, name, email_verified) VALUES ($1, $2, $1, $3)")
            .bind(&id)
            .bind(email)
            .bind(verified)
            .execute(self.pool())
            .await
            .unwrap();
        self.users.push(id.clone());
        id
    }

    /// An address unique to this test.
    fn email(&self, name: &str) -> String {
        format!("{}-{name}@example.test", self.fixture.id)
    }

    /// Inserts an invitation named `{fixture}-{name}` and returns its id and
    /// its one-time token. `expires` is an SQL interval from now.
    async fn invite(
        &self,
        name: &str,
        email: &str,
        status: &str,
        expires: &str,
    ) -> (String, String) {
        let id = format!("{}-{name}", self.fixture.id);
        let token = format!("synthetic-invitation-capability-{id}");
        sqlx::query(
            "INSERT INTO org_invitations \
             (id, org_id, email, role, invited_by, token_hash, status, expires_at, assignments) \
             VALUES ($1, $2, $3, 'admin', $2, $4, $5, NOW() + $6::interval, \
                     ARRAY['viewer', 'billing_admin'])",
        )
        .bind(&id)
        .bind(&self.fixture.id)
        .bind(email)
        .bind(hash_oauth_token(&token))
        .bind(status)
        .bind(expires)
        .execute(self.pool())
        .await
        .unwrap();
        (id, token)
    }

    async fn status(&self, invitation: &str) -> String {
        sqlx::query_scalar("SELECT status FROM org_invitations WHERE id = $1")
            .bind(invitation)
            .fetch_one(self.pool())
            .await
            .unwrap()
    }

    async fn is_member(&self, user: &str) -> bool {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)",
        )
        .bind(&self.fixture.id)
        .bind(user)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn verify(&self, user: &str) {
        sqlx::query("UPDATE users SET email_verified = true WHERE id = $1")
            .bind(user)
            .execute(self.pool())
            .await
            .unwrap();
    }

    async fn accept(
        &self,
        user: &str,
        by: AcceptInvitationBy,
    ) -> AppResult<AcceptInvitationResult> {
        accept_invitation(self.pool(), &caller(user), by).await
    }

    async fn cleanup(self) {
        for sql in [
            "DELETE FROM org_member_assignments WHERE org_member_id IN \
             (SELECT id FROM org_members WHERE org_id = $1 AND user_id <> $1)",
            "DELETE FROM org_members WHERE org_id = $1 AND user_id <> $1",
            "DELETE FROM org_invitations WHERE org_id = $1",
        ] {
            sqlx::query(sql)
                .bind(&self.fixture.id)
                .execute(self.pool())
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(&self.users)
            .execute(self.pool())
            .await
            .unwrap();
    }
}

fn caller(user: &str) -> AuthUser {
    AuthUser {
        user_id: user.to_owned(),
        org_id: None,
        is_admin: false,
        via_api_key: false,
    }
}

fn api_key_caller(user: &str, org: &str) -> AuthUser {
    AuthUser {
        user_id: user.to_owned(),
        org_id: Some(org.to_owned()),
        is_admin: false,
        via_api_key: true,
    }
}

fn refusal<T: std::fmt::Debug>(result: AppResult<T>) -> ConnectError {
    ConnectError::from_app_error(&result.expect_err("must be refused"), None)
}

fn code<T: std::fmt::Debug>(result: AppResult<T>) -> ConnectCode {
    refusal(result).code
}

/// The refusal an unknown id or token gets, and so a stranger's too.
fn assert_not_found<T: std::fmt::Debug>(result: AppResult<T>) {
    let refused = refusal(result);
    assert_eq!(
        (refused.code, refused.message.as_str()),
        (ConnectCode::NotFound, "invitation not found")
    );
}

/// The three callers of the security rule, by token or by id: a verified
/// matching address joins; an unverified one with the same address is asked
/// to verify and leaves the invitation pending, so it joins once verified; to
/// a verified caller at another address the invitation is not found, and it
/// stays pending.
async fn acceptance_requires_a_verified_matching_email(
    namespace: &str,
    by: impl Fn(&(String, String)) -> AcceptInvitationBy,
) {
    let fixture = LeaseFixture::seed(namespace).await;
    let mut t = Invitations::new(&fixture);
    let (verified_email, unverified_email, other_email) =
        (t.email("verified"), t.email("unverified"), t.email("other"));
    // The address is compared case-insensitively.
    let verified = t
        .user("verified", &verified_email.to_uppercase(), true)
        .await;
    let unverified = t.user("unverified", &unverified_email, false).await;
    let to_verified = t
        .invite("to-verified", &verified_email, "pending", "1 hour")
        .await;
    let to_unverified = t
        .invite("to-unverified", &unverified_email, "pending", "1 hour")
        .await;
    let to_other = t
        .invite("to-other", &other_email, "pending", "1 hour")
        .await;

    let refused = t.accept(&unverified, by(&to_unverified)).await;
    assert_eq!(code(refused), ConnectCode::FailedPrecondition);
    assert_eq!(t.status(&to_unverified.0).await, "pending");
    assert!(!t.is_member(&unverified).await);

    assert_not_found(t.accept(&verified, by(&to_other)).await);
    assert_eq!(t.status(&to_other.0).await, "pending");
    assert!(!t.is_member(&verified).await);

    let accepted = t.accept(&verified, by(&to_verified)).await.unwrap();
    assert_eq!(accepted.org_id, fixture.id);
    assert_eq!(t.status(&to_verified.0).await, "accepted");
    assert!(t.is_member(&verified).await);

    t.verify(&unverified).await;
    t.accept(&unverified, by(&to_unverified)).await.unwrap();
    assert_eq!(t.status(&to_unverified.0).await, "accepted");
    assert!(t.is_member(&unverified).await);

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_token_acceptance_requires_a_verified_matching_email() {
    acceptance_requires_a_verified_matching_email("synthetic-invitation-token", |(_, token)| {
        AcceptInvitationBy::Token(token.clone())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_id_acceptance_requires_a_verified_matching_email() {
    acceptance_requires_a_verified_matching_email("synthetic-invitation-id", |(id, _)| {
        AcceptInvitationBy::Id(id.clone())
    })
    .await;
}

/// A stranger learns nothing of someone else's invitation, by token or by id:
/// a lapsed one is not found and stays pending, since only its invitee's
/// attempt marks it expired, and a revoked one is not found rather than
/// revoked. The invitee still learns that the lapsed one has expired.
async fn a_strangers_invitation_is_not_found_in_any_state(
    namespace: &str,
    by: impl Fn(&(String, String)) -> AcceptInvitationBy,
) {
    let fixture = LeaseFixture::seed(namespace).await;
    let mut t = Invitations::new(&fixture);
    let (invitee_email, stranger_email) = (t.email("invitee"), t.email("stranger"));
    let invitee = t.user("invitee", &invitee_email, true).await;
    let stranger = t.user("stranger", &stranger_email, true).await;
    let lapsed = t
        .invite("lapsed", &invitee_email, "pending", "-1 day")
        .await;
    let revoked = t
        .invite("revoked", &invitee_email, "revoked", "1 hour")
        .await;

    assert_not_found(t.accept(&stranger, by(&lapsed)).await);
    assert_eq!(t.status(&lapsed.0).await, "pending");
    assert_not_found(t.accept(&stranger, by(&revoked)).await);
    assert_eq!(t.status(&revoked.0).await, "revoked");
    assert!(!t.is_member(&stranger).await);

    let expired = refusal(t.accept(&invitee, by(&lapsed)).await);
    assert_eq!(
        (expired.code, expired.message.as_str()),
        (ConnectCode::InvalidArgument, "invitation has expired")
    );
    assert_eq!(t.status(&lapsed.0).await, "expired");
    let revoked = refusal(t.accept(&invitee, by(&revoked)).await);
    assert_eq!(
        (revoked.code, revoked.message.as_str()),
        (ConnectCode::InvalidArgument, "invitation is revoked")
    );

    t.cleanup().await;
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_by_token_a_strangers_invitation_is_not_found_in_any_state() {
    a_strangers_invitation_is_not_found_in_any_state(
        "synthetic-invitation-token-stranger",
        |(_, token)| AcceptInvitationBy::Token(token.clone()),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_by_id_a_strangers_invitation_is_not_found_in_any_state() {
    a_strangers_invitation_is_not_found_in_any_state(
        "synthetic-invitation-id-stranger",
        |(id, _)| AcceptInvitationBy::Id(id.clone()),
    )
    .await;
}

/// Listing and accepting compare addresses by one rule, the database's
/// `lower()`, so an invitation listed for a caller is one the caller can
/// accept even where only a non-ASCII letter differs in case.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_listing_and_accepting_match_addresses_by_one_rule() {
    let fixture = LeaseFixture::seed("synthetic-invitation-case").await;
    let mut t = Invitations::new(&fixture);
    let folds: bool = sqlx::query_scalar("SELECT lower('É') = lower('é')")
        .fetch_one(t.pool())
        .await
        .unwrap();
    assert!(folds, "the test database's ctype must fold non-ASCII case");
    let invitee = t
        .user(
            "invitee",
            &format!("émile-{}@example.test", fixture.id),
            true,
        )
        .await;
    let (invitation, _) = t
        .invite(
            "accented",
            &format!("Émile-{}@example.test", fixture.id),
            "pending",
            "1 hour",
        )
        .await;

    let mine = list_my_invitations(t.pool(), &caller(&invitee))
        .await
        .unwrap();
    assert_eq!(
        mine.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
        [invitation.as_str()]
    );
    t.accept(&invitee, AcceptInvitationBy::Id(invitation.clone()))
        .await
        .unwrap();
    assert_eq!(t.status(&invitation).await, "accepted");
    assert!(t.is_member(&invitee).await);

    t.cleanup().await;
    fixture.cleanup().await;
}

/// By id, an invitation keeps the token form's claim semantics: an unknown id
/// is not found, a used or revoked one is refused, and an expired one is
/// marked expired. An organization API key cannot accept by id either.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_id_acceptance_keeps_the_claim_semantics() {
    let fixture = LeaseFixture::seed("synthetic-invitation-id-states").await;
    let mut t = Invitations::new(&fixture);
    let email = t.email("invitee");
    let invitee = t.user("invitee", &email, true).await;
    let (revoked, _) = t.invite("revoked", &email, "revoked", "1 hour").await;
    let (expired, _) = t.invite("expired", &email, "pending", "-1 day").await;
    let (pending, _) = t.invite("pending", &email, "pending", "1 hour").await;
    let by_id = |id: &str| AcceptInvitationBy::Id(id.to_owned());

    let unknown = format!("{}-unknown", fixture.id);
    assert_eq!(
        code(t.accept(&invitee, by_id(&unknown)).await),
        ConnectCode::NotFound
    );
    assert_eq!(
        code(t.accept(&invitee, by_id(&revoked)).await),
        ConnectCode::InvalidArgument
    );
    assert_eq!(
        code(t.accept(&invitee, by_id(&expired)).await),
        ConnectCode::InvalidArgument
    );
    assert_eq!(t.status(&expired).await, "expired");

    let key = api_key_caller(&invitee, &fixture.id);
    let refused = accept_invitation(t.pool(), &key, by_id(&pending)).await;
    assert_eq!(code(refused), ConnectCode::PermissionDenied);
    assert_eq!(t.status(&pending).await, "pending");

    t.accept(&invitee, by_id(&pending)).await.unwrap();
    let replay = t.accept(&invitee, by_id(&pending)).await;
    assert_eq!(code(replay), ConnectCode::InvalidArgument);

    t.cleanup().await;
    fixture.cleanup().await;
}

/// An organization API key cannot accept, even with the invitation's valid
/// token and the invitee's verified address; the invitation stays pending and
/// the same invitee's session then accepts it.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_an_api_key_cannot_accept_by_token() {
    let fixture = LeaseFixture::seed("synthetic-invitation-token-key").await;
    let mut t = Invitations::new(&fixture);
    let email = t.email("invitee");
    let invitee = t.user("invitee", &email, true).await;
    let (invitation, token) = t.invite("keyed", &email, "pending", "1 hour").await;

    let key = api_key_caller(&invitee, &fixture.id);
    let by_token = || AcceptInvitationBy::Token(token.clone());
    let refused = accept_invitation(t.pool(), &key, by_token()).await;
    assert_eq!(code(refused), ConnectCode::PermissionDenied);
    assert_eq!(t.status(&invitation).await, "pending");
    assert!(!t.is_member(&invitee).await);

    t.accept(&invitee, by_token()).await.unwrap();
    assert_eq!(t.status(&invitation).await, "accepted");

    t.cleanup().await;
    fixture.cleanup().await;
}

/// The token is stored only as its digest, and of two concurrent claims of
/// one invitation exactly one succeeds; a replay is refused.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_invitation_claim_is_digest_only_atomic_and_single_use() {
    let fixture = LeaseFixture::seed("synthetic-invitation-claim").await;
    let mut t = Invitations::new(&fixture);
    let email = t.email("invitee");
    let invitee = t.user("invitee", &email, true).await;
    let (invitation, token) = t.invite("claim", &email, "pending", "1 hour").await;
    let key = InvitationKey::TokenHash(hash_oauth_token(&token));

    let persisted: String =
        sqlx::query_scalar("SELECT token_hash FROM org_invitations WHERE id = $1")
            .bind(&invitation)
            .fetch_one(t.pool())
            .await
            .unwrap();
    assert_eq!(persisted, key.value());
    assert_ne!(persisted, token);

    let first = accept_invitation_transaction(t.pool(), &fixture.id, &key, &invitee);
    let second = accept_invitation_transaction(t.pool(), &fixture.id, &key, &invitee);
    let (first, second) = tokio::join!(first, second);
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second.is_ok()),
        1,
        "exactly one concurrent invitation claimant succeeds"
    );

    let (status, member_count, assignment_count): (String, i64, i64) = sqlx::query_as(
        "SELECT i.status, \
                (SELECT COUNT(*) FROM org_members m \
                 WHERE m.org_id = i.org_id AND m.user_id = $2), \
                (SELECT COUNT(*) FROM org_member_assignments a \
                 JOIN org_members m ON m.id = a.org_member_id \
                 WHERE m.org_id = i.org_id AND m.user_id = $2) \
         FROM org_invitations i WHERE i.id = $1",
    )
    .bind(&invitation)
    .bind(&invitee)
    .fetch_one(t.pool())
    .await
    .unwrap();
    assert_eq!(status, "accepted");
    assert_eq!(member_count, 1);
    assert_eq!(assignment_count, 2);
    assert!(
        accept_invitation_transaction(t.pool(), &fixture.id, &key, &invitee)
            .await
            .is_err(),
        "accepted invitation capability must reject replay"
    );

    t.cleanup().await;
    fixture.cleanup().await;
}

/// A verified caller sees only its own pending, unexpired invitations, its
/// address compared case-insensitively, with what accepting and showing one
/// needs. An unverified caller sees none, and an organization API key cannot
/// ask.
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run by the database capability gate"]
async fn db_my_invitations_are_the_pending_unexpired_ones_of_a_verified_address() {
    let fixture = LeaseFixture::seed("synthetic-invitation-mine").await;
    let mut t = Invitations::new(&fixture);
    let (email, unverified_email) = (t.email("invitee"), t.email("unverified"));
    let invitee = t.user("invitee", &email.to_uppercase(), true).await;
    let unverified = t.user("unverified", &unverified_email, false).await;
    let (pending, _) = t.invite("pending", &email, "pending", "1 hour").await;
    t.invite("accepted", &email, "accepted", "1 hour").await;
    t.invite("revoked", &email, "revoked", "1 hour").await;
    t.invite("expired", &email, "expired", "1 hour").await;
    t.invite("lapsed", &email, "pending", "-1 day").await;
    t.invite("other", &t.email("other"), "pending", "1 hour")
        .await;
    t.invite("to-unverified", &unverified_email, "pending", "1 hour")
        .await;

    let mine = list_my_invitations(t.pool(), &caller(&invitee))
        .await
        .unwrap();
    assert_eq!(
        mine.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
        [pending.as_str()]
    );
    let invitation = &mine[0];
    assert_eq!(invitation.org_id, fixture.id);
    assert_eq!(invitation.org_name, "Runtime lease owner test");
    assert_eq!(invitation.org_slug, fixture.id);
    assert_eq!(invitation.role, "admin");
    assert_eq!(invitation.status, "pending");
    assert_eq!(invitation.assignments, ["viewer", "billing_admin"]);

    let none = list_my_invitations(t.pool(), &caller(&unverified))
        .await
        .unwrap();
    assert!(none.is_empty(), "{none:?}");

    let key = list_my_invitations(t.pool(), &api_key_caller(&invitee, &fixture.id)).await;
    assert_eq!(code(key), ConnectCode::PermissionDenied);

    t.cleanup().await;
    fixture.cleanup().await;
}
