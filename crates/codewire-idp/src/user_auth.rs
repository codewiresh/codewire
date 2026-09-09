//! [`UserAuthenticator`] — the bridge to Codewire's session + org model.
//!
//! Resolves the end-user from the `codewire.session_token` cookie and sends
//! unauthenticated user agents to the login page. Login resumes by returning
//! to the callback, which re-drives `/authorize` with the session now present.

use async_trait::async_trait;
use codewire_oidc::{
    AuthOutcome, RequestContext, StoreError, StoreResult, StoredAuthRequest, Subject,
    UserAuthenticator,
};
use codewire_server_core::auth::hash_session_token;
use sqlx::PgPool;

/// The session cookie name (matches the Go `auth.SessionCookieName`).
const SESSION_COOKIE: &str = "codewire.session_token";

/// `UserAuthenticator` backed by the Codewire `sessions` table.
#[derive(Clone)]
pub struct PgUserAuthenticator {
    pool: PgPool,
    /// Base URL of the login UI (the user agent is sent to `{frontend}/login`).
    frontend_url: String,
}

impl PgUserAuthenticator {
    /// Construct with the connection pool and the login UI base URL.
    pub fn new(pool: PgPool, frontend_url: impl Into<String>) -> Self {
        Self {
            pool,
            frontend_url: frontend_url.into(),
        }
    }

    fn login_url(&self, auth_request_id: &str) -> String {
        format!(
            "{}/login?authRequestID={}",
            self.frontend_url.trim_end_matches('/'),
            urlencode(auth_request_id)
        )
    }
}

#[async_trait]
impl UserAuthenticator for PgUserAuthenticator {
    async fn authenticate(
        &self,
        ctx: &RequestContext,
        request: &StoredAuthRequest,
    ) -> StoreResult<AuthOutcome> {
        let Some(token) = ctx
            .cookie
            .as_deref()
            .and_then(|c| cookie_value(c, SESSION_COOKIE))
        else {
            return Ok(AuthOutcome::NeedsLogin(self.login_url(&request.id.0)));
        };

        // Resolve a live session -> (user_id, login time).
        let token_hash = hash_session_token(&token);
        let row: Option<(String, chrono::NaiveDateTime)> = sqlx::query_as(
            r#"
            SELECT s.user_id, s.created_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = $1
              AND s.expires_at > NOW()
              AND u.enabled
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(StoreError::new)?;

        let Some((user_id, created_at)) = row else {
            return Ok(AuthOutcome::NeedsLogin(self.login_url(&request.id.0)));
        };

        Ok(AuthOutcome::Authenticated {
            subject: Subject(user_id),
            auth_time: Some(created_at.and_utc().timestamp()),
        })
    }
}

/// Extract a cookie value from a raw `Cookie` header.
fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

/// Minimal percent-encoding for the `authRequestID` query value.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_cookie_among_others() {
        let h = "foo=bar; codewire.session_token=abc123; baz=qux";
        assert_eq!(cookie_value(h, SESSION_COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie_value("other=1", SESSION_COOKIE), None);
        assert_eq!(
            cookie_value("codewire.session_token=tok", SESSION_COOKIE).as_deref(),
            Some("tok")
        );
    }

    #[tokio::test]
    async fn login_url_carries_request_id() {
        // connect_lazy never dials; it just needs a Tokio context.
        let pool = PgPool::connect_lazy("postgres://localhost/none").unwrap();
        let a = PgUserAuthenticator {
            pool,
            frontend_url: "https://app.test/".into(),
        };
        assert_eq!(a.login_url("r1"), "https://app.test/login?authRequestID=r1");
    }
}
