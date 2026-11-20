//! A terminal ticket admits only while the session that minted it is live and
//! its user is enabled (AUTH-POLICY "Product protocols", #3586;
//! `docs/journeys/account-access.md` `access-ticket`).

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use super::*;

const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// A user signed in with one live session.
struct SignedIn {
    pool: PgPool,
    user_id: String,
    session_id: String,
}

async fn signed_in(name: &str) -> SignedIn {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let user_id = format!("user_ticket_{name}_{suffix}");
    let session_id = format!("session_ticket_{name}_{suffix}");
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(format!("{user_id}@example.test"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
         VALUES ($1, $2, NOW() + interval '1 hour', $3)",
    )
    .bind(&session_id)
    .bind(&user_id)
    .bind(hex_lower(&Sha256::digest(session_id.as_bytes())))
    .execute(&pool)
    .await
    .unwrap();
    SignedIn {
        pool,
        user_id,
        session_id,
    }
}

impl SignedIn {
    fn ticket(&self) -> String {
        issue_ticket(SECRET, &self.user_id, &self.session_id).unwrap()
    }

    async fn admit(&self, ticket: &str) -> Result<AuthUser, TicketRefused> {
        admit_ticket(
            &self.pool,
            SECRET,
            &TerminalTicketReplayCache::default(),
            ticket,
        )
        .await
        .map(|(user, _)| user)
    }

    async fn remove(self) {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(&self.user_id)
            .execute(&self.pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_ticket_from_a_live_session_admits_its_user() {
    let signed_in = signed_in("live").await;
    let user = signed_in.admit(&signed_in.ticket()).await.unwrap();
    assert_eq!(user.user_id, signed_in.user_id);
    assert!(!user.is_admin && !user.via_api_key);
    signed_in.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_ticket_whose_session_signed_out_before_it_was_used_is_refused() {
    let signed_in = signed_in("signed_out").await;
    let ticket = signed_in.ticket();
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&signed_in.session_id)
        .execute(&signed_in.pool)
        .await
        .unwrap();
    assert_eq!(
        signed_in.admit(&ticket).await.unwrap_err(),
        TicketRefused::Invalid
    );
    signed_in.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_ticket_whose_user_was_disabled_before_it_was_used_is_refused() {
    let signed_in = signed_in("disabled").await;
    let ticket = signed_in.ticket();
    sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
        .bind(&signed_in.user_id)
        .execute(&signed_in.pool)
        .await
        .unwrap();
    assert_eq!(
        signed_in.admit(&ticket).await.unwrap_err(),
        TicketRefused::Invalid
    );
    signed_in.remove().await;
}
