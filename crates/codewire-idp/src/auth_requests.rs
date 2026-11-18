//! [`AuthorizationStore`] over the `oidc_auth_requests` table.
//!
//! Stores in-flight `/authorize` requests with a 10-minute expiry (matching
//! the Go provider). `update` records the resolved end-user (the Go
//! `CompleteAuthRequest`: sets `user_id`, `auth_time`, `done`).
//!
//! `prompt` and `max_age` are stored with the request, because login resumes
//! by re-driving `/authorize` from the stored request. On the way back
//! [`AuthorizationStore::get`] turns them into one bound: the session must be
//! no older than the original request (`prompt=login`) or than `max_age`
//! before it. That bound returns as `max_age` counted from now, and `login`
//! leaves `prompt`. A resumed request, and any later one in the same chain,
//! then accepts only a sign-in made after the original request, never an
//! older session presented at the callback directly.

use async_trait::async_trait;
use codewire_oidc::{
    AuthRequestId, AuthorizationRequest, AuthorizationStore, ResponseType, Scopes, StoreError,
    StoreResult, StoredAuthRequest, Subject,
};
use rand::RngCore;
use sqlx::PgPool;

/// Auth-request lifetime, matching the Go provider's 10 minutes.
const AUTH_REQUEST_TTL: &str = "10 minutes";

/// `AuthorizationStore` backed by the `oidc_auth_requests` table.
#[derive(Clone)]
pub struct PgAuthorizationStore {
    pool: PgPool,
}

impl PgAuthorizationStore {
    /// Wrap a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// 16 random bytes, lowercase hex (32 chars) — matching the Go `generateID`.
fn generate_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(sqlx::FromRow)]
struct AuthRequestRow {
    id: String,
    client_id: String,
    scopes: Vec<String>,
    redirect_uri: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    user_id: Option<String>,
    prompt: Option<String>,
    max_age: Option<i64>,
    /// Whole seconds since the request was stored, rounded up, so a sign-in
    /// moments after it is never refused for the rounding.
    age_secs: i64,
}

impl From<AuthRequestRow> for StoredAuthRequest {
    fn from(r: AuthRequestRow) -> Self {
        let forced_login = r
            .prompt
            .as_deref()
            .is_some_and(|prompt| prompt.split_whitespace().any(|value| value == "login"));
        // The newest sign-in this request accepts, as an age from now.
        let bound = if forced_login {
            Some(r.age_secs)
        } else {
            r.max_age.map(|max_age| r.age_secs.saturating_add(max_age))
        };
        let prompt = r.prompt.and_then(|prompt| {
            let rest: Vec<&str> = prompt
                .split_whitespace()
                .filter(|value| *value != "login")
                .collect();
            (!rest.is_empty()).then(|| rest.join(" "))
        });
        StoredAuthRequest {
            id: AuthRequestId(r.id),
            request: AuthorizationRequest {
                client_id: r.client_id,
                redirect_uri: r.redirect_uri,
                response_type: ResponseType::Code,
                scopes: Scopes(r.scopes),
                state: r.state,
                nonce: r.nonce,
                code_challenge: r.code_challenge,
                code_challenge_method: r.code_challenge_method,
                prompt,
                max_age: bound.map(|seconds| seconds.max(0).unsigned_abs()),
            },
            subject: r.user_id.map(Subject),
        }
    }
}

#[async_trait]
impl AuthorizationStore for PgAuthorizationStore {
    async fn create(&self, request: StoredAuthRequest) -> StoreResult<AuthRequestId> {
        crate::expired_rows::auth_requests(&self.pool)
            .await
            .map_err(StoreError::new)?;
        let id = generate_id();
        let req = &request.request;
        sqlx::query(
            r#"
            INSERT INTO oidc_auth_requests
                (id, client_id, scopes, redirect_uri, state, nonce,
                 response_type, code_challenge, code_challenge_method,
                 user_id, done, expires_at, prompt, max_age)
            VALUES ($1, $2, $3, $4, $5, $6, 'code', $7, $8, $9, false,
                    NOW() + $10::interval, $11, $12)
            "#,
        )
        .bind(&id)
        .bind(&req.client_id)
        .bind(&req.scopes.0)
        .bind(&req.redirect_uri)
        .bind(&req.state)
        .bind(&req.nonce)
        .bind(&req.code_challenge)
        .bind(&req.code_challenge_method)
        .bind(request.subject.as_ref().map(|s| &s.0))
        .bind(AUTH_REQUEST_TTL)
        .bind(&req.prompt)
        .bind(
            req.max_age
                .map(|seconds| i64::try_from(seconds).unwrap_or(i64::MAX)),
        )
        .execute(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(AuthRequestId(id))
    }

    async fn get(&self, id: &AuthRequestId) -> StoreResult<Option<StoredAuthRequest>> {
        // Expired requests resolve to None (the store owns expiry).
        // `age_secs` rounds up, so the bound also accepts a session signed in
        // under a second before the request, deliberately: rounding down
        // could refuse a sign-in made just after it and send the user round
        // again.
        let row: Option<AuthRequestRow> = sqlx::query_as(
            r#"
            SELECT id, client_id, scopes, redirect_uri, state, nonce,
                   code_challenge, code_challenge_method, user_id, prompt, max_age,
                   CEIL(EXTRACT(EPOCH FROM NOW() - created_at))::bigint AS age_secs
            FROM oidc_auth_requests
            WHERE id = $1 AND expires_at > NOW()
            "#,
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;
        Ok(row.map(StoredAuthRequest::from))
    }

    async fn update(&self, request: &StoredAuthRequest) -> StoreResult<()> {
        // Binding the subject is the Go `CompleteAuthRequest`: record the
        // user, the authentication time, and mark the request done.
        let subject = request.subject.as_ref().map(|subject| subject.0.as_str());
        let mut tx = self.pool.begin().await.map_err(StoreError::new)?;
        if let Some(subject) = subject {
            // Account disablement locks the account before deleting bound
            // requests. Take the same lock before this update takes the
            // pending-request row, so browser completion and disablement
            // serialize without a user/request lock cycle. The database
            // trigger remains the compatibility fence for older writers.
            let enabled_subject: Option<String> =
                sqlx::query_scalar("SELECT id FROM users WHERE id = $1 AND enabled FOR SHARE")
                    .bind(subject)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(StoreError::new)?;
            if enabled_subject.is_none() {
                tx.rollback().await.map_err(StoreError::new)?;
                return Err(StoreError::new(
                    "authorization request is expired or subject access is disabled",
                ));
            }
        }

        let updated = sqlx::query(
            r#"
            UPDATE oidc_auth_requests
            SET user_id = $1, auth_time = NOW(), done = ($1 IS NOT NULL)
            WHERE id = $2
            "#,
        )
        .bind(subject)
        .bind(&request.id.0)
        .execute(&mut *tx)
        .await
        .map_err(StoreError::new)?;
        if updated.rows_affected() != 1 {
            tx.rollback().await.map_err(StoreError::new)?;
            return Err(StoreError::new("authorization request is expired"));
        }
        tx.commit().await.map_err(StoreError::new)?;
        Ok(())
    }

    async fn delete(&self, id: &AuthRequestId) -> StoreResult<()> {
        sqlx::query("DELETE FROM oidc_auth_requests WHERE id = $1")
            .bind(&id.0)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_id_is_32_hex_chars() {
        let id = generate_id();
        assert_eq!(id.len(), 32);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(generate_id(), generate_id());
    }

    #[test]
    fn row_maps_to_stored_request() {
        let row = AuthRequestRow {
            id: "abc".into(),
            client_id: "pub".into(),
            scopes: vec!["openid".into(), "profile".into()],
            redirect_uri: "https://app/cb".into(),
            state: Some("xyz".into()),
            nonce: Some("n".into()),
            code_challenge: Some("chal".into()),
            code_challenge_method: Some("S256".into()),
            user_id: Some("user_1".into()),
            prompt: None,
            max_age: None,
            age_secs: 0,
        };
        let sr = StoredAuthRequest::from(row);
        assert_eq!(sr.id.0, "abc");
        assert_eq!(sr.request.client_id, "pub");
        assert_eq!(sr.request.scopes.0, vec!["openid", "profile"]);
        assert_eq!(sr.subject, Some(Subject("user_1".into())));
        assert!(matches!(sr.request.response_type, ResponseType::Code));
        assert_eq!(sr.request.prompt, None);
        assert_eq!(sr.request.max_age, None);
    }

    /// A resumed request carries `prompt=login` and `max_age` as one bound,
    /// counted from now, on the newest sign-in it accepts.
    #[test]
    fn a_resumed_request_bounds_the_sign_in_from_the_original_request() {
        let row = |prompt: Option<&str>, max_age: Option<i64>, age_secs: i64| AuthRequestRow {
            id: "abc".into(),
            client_id: "pub".into(),
            scopes: vec!["openid".into()],
            redirect_uri: "https://app/cb".into(),
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            user_id: None,
            prompt: prompt.map(str::to_string),
            max_age,
            age_secs,
        };
        let resumed = |prompt, max_age, age_secs| {
            let request = StoredAuthRequest::from(row(prompt, max_age, age_secs)).request;
            (request.prompt, request.max_age)
        };
        // prompt=login: a sign-in after the original request, so no older than its age.
        assert_eq!(resumed(Some("login"), None, 30), (None, Some(30)));
        // Other prompt values stay; only `login` becomes the bound.
        assert_eq!(
            resumed(Some("login consent"), None, 30),
            (Some("consent".into()), Some(30))
        );
        // max_age: no older than max_age before the original request.
        assert_eq!(resumed(None, Some(60), 30), (None, Some(90)));
        // Both: the fresh sign-in is the stricter bound.
        assert_eq!(resumed(Some("login"), Some(600), 30), (None, Some(30)));
        // Neither: no bound.
        assert_eq!(
            resumed(Some("consent"), None, 30),
            (Some("consent".into()), None)
        );
        assert_eq!(resumed(None, None, 30), (None, None));
    }
}
