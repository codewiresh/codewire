//! A terminal or SSH-proxy socket ends when the credential its handshake
//! carried is lost, and only that one (#3586; AUTH-POLICY.md, "Account
//! access revocation"; `docs/journeys/account-access.md`,
//! `access-websockets`).

use std::time::Duration;

use axum::http::header;
use codewire_server_core::auth::{
    SESSION_COOKIE_NAME, api_key_prefix, generate_api_key, hash_api_key, hash_session_token,
};
use sqlx::postgres::PgPoolOptions;

use super::*;

/// The revocation bound: within seconds normally, 30 s at most.
const REVOCATION_BOUND: Duration = Duration::from_secs(35);

/// A user in an organization with two live browser sessions and an API key.
struct Account {
    pool: PgPool,
    auth: AuthState,
    fence: Fence,
    listener: tokio::task::JoinHandle<()>,
    user_id: String,
    org_id: String,
    sessions: [(String, String); 2],
    api_key: String,
    api_key_id: String,
}

async fn account(name: &str) -> Account {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("ignored DB test requires TEST_DATABASE_URL");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .unwrap();
    let ns = uuid::Uuid::new_v4().simple().to_string();
    let user_id = format!("user_socket_{name}_{ns}");
    let org_id = format!("org_socket_{name}_{ns}");
    sqlx::query("INSERT INTO users (id, email, email_verified) VALUES ($1, $2, true)")
        .bind(&user_id)
        .bind(format!("{user_id}@socket-fence.test"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, name, slug, created_by) VALUES ($1, $1, $2, $3)")
        .bind(&org_id)
        .bind(format!("sf-{}", &ns[..16]))
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO org_members (id, org_id, user_id, role) VALUES ($1, $2, $3, 'owner')")
        .bind(format!("om_{org_id}"))
        .bind(&org_id)
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut sessions = Vec::new();
    for index in 0..2 {
        let session_id = format!("session_socket_{name}_{index}_{ns}");
        let token = format!("token_socket_{name}_{index}_{ns}");
        sqlx::query(
            "INSERT INTO sessions (id, user_id, expires_at, token_hash) \
             VALUES ($1, $2, NOW() + interval '1 hour', $3)",
        )
        .bind(&session_id)
        .bind(&user_id)
        .bind(hash_session_token(&token))
        .execute(&pool)
        .await
        .unwrap();
        sessions.push((session_id, token));
    }
    let api_key = generate_api_key();
    let api_key_id = format!("api_key_socket_{name}_{ns}");
    sqlx::query(
        "INSERT INTO api_keys (id, user_id, org_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&api_key_id)
    .bind(&user_id)
    .bind(&org_id)
    .bind(format!("socket fence {name}"))
    .bind(hash_api_key(&api_key))
    .bind(api_key_prefix(&api_key))
    .execute(&pool)
    .await
    .unwrap();
    let fence = Fence::new();
    let listener = fence.spawn_listener(pool.clone());
    Account {
        auth: AuthState { pool: pool.clone() },
        pool,
        fence,
        listener,
        user_id,
        org_id,
        sessions: sessions.try_into().unwrap(),
        api_key,
        api_key_id,
    }
}

impl Account {
    fn user(&self) -> AuthUser {
        AuthUser {
            user_id: self.user_id.clone(),
            org_id: None,
            is_admin: false,
            via_api_key: false,
        }
    }

    async fn fence(&self, admission: SocketAdmission, surface: &'static str) -> SocketRevoked {
        // The listener reads the log for the first time shortly after it
        // starts; a registration before that is still fenced.
        let (_, revoked) = admission
            .fence(
                &self.auth,
                &self.pool,
                &self.fence,
                &self.org_id,
                site(surface, "env-socket"),
            )
            .await
            .expect("admitted");
        revoked
    }

    async fn revoked_surface(&self) -> Option<String> {
        for _ in 0..50 {
            let surface: Option<Option<String>> = sqlx::query_scalar(
                "SELECT metadata->>'surface' FROM audit_logs \
                 WHERE action = 'stream.revoked' AND user_id = $1",
            )
            .bind(&self.user_id)
            .fetch_optional(&self.pool)
            .await
            .unwrap();
            if let Some(surface) = surface {
                return surface;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        None
    }

    async fn remove(self) {
        self.listener.abort();
        sqlx::query("DELETE FROM audit_logs WHERE user_id = $1")
            .bind(&self.user_id)
            .execute(&self.pool)
            .await
            .unwrap();
        for statement in [
            "DELETE FROM api_keys WHERE user_id = $1",
            "DELETE FROM org_members WHERE user_id = $1",
            "DELETE FROM organizations WHERE created_by = $1",
            "DELETE FROM users WHERE id = $1",
        ] {
            sqlx::query(statement)
                .bind(&self.user_id)
                .execute(&self.pool)
                .await
                .unwrap();
        }
    }
}

fn cookie(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{SESSION_COOKIE_NAME}={token}").parse().unwrap(),
    );
    headers
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_ticket_socket_ends_when_its_session_signs_out_and_records_it() {
    let account = account("ticket").await;
    let session_id = account.sessions[0].0.clone();
    let revoked = account
        .fence(
            SocketAdmission::ticket(account.user(), session_id.clone()),
            "terminal",
        )
        .await;

    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&session_id)
        .execute(&account.pool)
        .await
        .unwrap();
    tokio::time::timeout(REVOCATION_BOUND, revoked.into_future())
        .await
        .expect("the socket ends within the bound");
    assert_eq!(account.revoked_surface().await.as_deref(), Some("terminal"));
    account.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_ticket_whose_session_signed_out_before_it_registered_is_refused() {
    let account = account("ticket_late").await;
    let session_id = account.sessions[0].0.clone();
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&session_id)
        .execute(&account.pool)
        .await
        .unwrap();
    let refused = SocketAdmission::ticket(account.user(), session_id)
        .fence(
            &account.auth,
            &account.pool,
            &account.fence,
            &account.org_id,
            site("terminal", "env-socket"),
        )
        .await
        .err();
    assert_eq!(refused, Some(StatusCode::UNAUTHORIZED));
    account.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn an_api_key_socket_ends_when_the_key_is_disabled() {
    let account = account("api_key").await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", account.api_key).parse().unwrap(),
    );
    let admission = SocketAdmission::headers(&account.auth, &headers)
        .await
        .expect("the key authenticates");
    let revoked = account.fence(admission, "ssh_proxy").await;

    sqlx::query("UPDATE api_keys SET disabled_at = NOW() WHERE id = $1")
        .bind(&account.api_key_id)
        .execute(&account.pool)
        .await
        .unwrap();
    tokio::time::timeout(REVOCATION_BOUND, revoked.into_future())
        .await
        .expect("the socket ends within the bound");
    assert_eq!(
        account.revoked_surface().await.as_deref(),
        Some("ssh_proxy")
    );
    account.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_sign_out_ends_only_the_socket_its_own_session_admitted() {
    let account = account("cookie").await;
    let first = SocketAdmission::headers(&account.auth, &cookie(&account.sessions[0].1))
        .await
        .expect("the first session authenticates");
    let second = SocketAdmission::headers(&account.auth, &cookie(&account.sessions[1].1))
        .await
        .expect("the second session authenticates");
    let first = account.fence(first, "terminal").await;
    let mut second = account.fence(second, "terminal").await.into_future();

    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(&account.sessions[0].0)
        .execute(&account.pool)
        .await
        .unwrap();
    tokio::time::timeout(REVOCATION_BOUND, first.into_future())
        .await
        .expect("the signed-out session's socket ends");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), &mut second)
            .await
            .is_err(),
        "the other session's socket keeps running"
    );
    account.remove().await;
}

/// The stream.revoked audit event's kind of loss, once written.
async fn revoked_kind(account: &Account) -> Option<String> {
    for _ in 0..50 {
        let kind: Option<Option<String>> = sqlx::query_scalar(
            "SELECT metadata->>'revocation' FROM audit_logs \
             WHERE action = 'stream.revoked' AND user_id = $1",
        )
        .bind(&account.user_id)
        .fetch_optional(&account.pool)
        .await
        .unwrap();
        if let Some(kind) = kind {
            return kind;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_socket_ends_when_its_user_leaves_the_organization() {
    let account = account("membership").await;
    let revoked = account
        .fence(
            SocketAdmission::headers(&account.auth, &cookie(&account.sessions[0].1))
                .await
                .expect("the session authenticates"),
            "terminal",
        )
        .await;
    sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(&account.org_id)
        .bind(&account.user_id)
        .execute(&account.pool)
        .await
        .unwrap();
    let revocation = tokio::time::timeout(REVOCATION_BOUND, revoked.into_future())
        .await
        .expect("the socket ends within the bound");
    assert_eq!(revocation, Revocation::Membership);
    assert_eq!(revoked_close(revocation), access_revoked_close());
    assert_eq!(revoked_kind(&account).await.as_deref(), Some("membership"));
    account.remove().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn a_socket_ends_saying_why_when_its_organizations_deletion_starts() {
    let account = account("deletion").await;
    let revoked = account
        .fence(
            SocketAdmission::ticket(account.user(), account.sessions[0].0.clone()),
            "desktop",
        )
        .await;
    sqlx::query(
        "UPDATE organizations SET deletion_state = 'deleting', deletion_generation = 1, \
         deletion_operation_id = 'synthetic-operation', deletion_workflow_id = 'synthetic-workflow', \
         deletion_requested_at = NOW(), deletion_phase = 'synthetic_phase' WHERE id = $1",
    )
    .bind(&account.org_id)
    .execute(&account.pool)
    .await
    .unwrap();
    let revocation = tokio::time::timeout(REVOCATION_BOUND, revoked.into_future())
        .await
        .expect("the socket ends within the bound");
    assert_eq!(revocation, Revocation::Organization);
    assert_eq!(
        revoked_close(revocation),
        Message::Close(Some(CloseFrame {
            code: 1008,
            reason: "organization is being deleted".into(),
        }))
    );
    assert_eq!(
        revoked_kind(&account).await.as_deref(),
        Some("organization")
    );
    account.remove().await;
}
