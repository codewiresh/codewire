//! Authentication helpers for the Rust mesh service.
//!
//! Preserves the hosted Mesh authentication contract after the Rust cutover.
//! Store-backed GitHub/OIDC session lookup matches the accepted relay behavior:
//! `sess_` tokens resolve OIDC sessions first, then GitHub sessions, before
//! falling back to the shared admin token for non-session tokens.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use subtle::ConstantTimeEq;

use crate::Config;
use crate::store::MeshStore;

pub const SESSION_COOKIE_NAME: &str = "cw_session";
pub const SESSION_TOKEN_PREFIX: &str = "sess_";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthIdentity {
    pub user_id: Option<i64>,
    pub sub: Option<String>,
    pub username: String,
    pub is_admin: bool,
}

impl AuthIdentity {
    fn admin() -> Self {
        Self {
            user_id: None,
            sub: None,
            username: String::new(),
            is_admin: true,
        }
    }
}

/// Resolves a request identity from headers without mutating request state.
pub async fn authenticate_headers(
    headers: &HeaderMap,
    config: &Config,
    store: &dyn MeshStore,
) -> Option<AuthIdentity> {
    if let Some(token) = bearer_token(headers)
        && let Some(identity) = resolve_token(token, config, store).await
    {
        return Some(identity);
    }

    for token in session_cookie_values(headers) {
        if let Some(identity) = resolve_token(token, config, store).await {
            return Some(identity);
        }
    }

    None
}

/// Extracts `Authorization: Bearer <token>` exactly like the Go relay.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

async fn resolve_token(
    token: &str,
    config: &Config,
    store: &dyn MeshStore,
) -> Option<AuthIdentity> {
    if token.starts_with(SESSION_TOKEN_PREFIX) {
        return store
            .session_identity(token)
            .await
            .ok()
            .flatten()
            .map(|identity| AuthIdentity {
                user_id: identity.user_id,
                sub: identity.sub,
                username: identity.username,
                is_admin: false,
            });
    }

    match config.auth_token.as_deref() {
        Some(admin_token)
            if !admin_token.is_empty()
                && bool::from(token.as_bytes().ct_eq(admin_token.as_bytes())) =>
        {
            Some(AuthIdentity::admin())
        }
        _ => None,
    }
}

fn session_cookie_values(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers.get_all(COOKIE).iter().flat_map(|value| {
        value
            .to_str()
            .ok()
            .into_iter()
            .flat_map(|raw| raw.split(';'))
            .filter_map(|cookie| {
                let cookie = cookie.trim();
                let value = cookie.strip_prefix(SESSION_COOKIE_NAME)?;
                let value = value.strip_prefix('=')?;
                (!value.is_empty()).then_some(value)
            })
    })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use chrono::{Duration, Utc};

    use super::*;
    use crate::AuthMode;
    use crate::MemoryStore;

    fn config(auth_token: Option<&str>) -> Config {
        Config {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ssh_bind_addr: "127.0.0.1:0".parse().unwrap(),
            ssh_host_key_path: String::new(),
            base_url: "https://mesh.codewire.sh".to_string(),
            auth_mode: AuthMode::Token,
            auth_token: auth_token.map(str::to_string),
            derp_url: None,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_allowed_groups: Vec::new(),
            database_url: None,
        }
    }

    #[tokio::test]
    async fn bearer_admin_token_authenticates() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer relay-admin"),
        );
        let store = MemoryStore::new();

        let identity = authenticate_headers(&headers, &config(Some("relay-admin")), &store)
            .await
            .unwrap();

        assert!(identity.is_admin);
        assert_eq!(identity.user_id, None);
        assert_eq!(identity.sub, None);
    }

    #[tokio::test]
    async fn bearer_admin_token_rejects_missing_and_mismatched_tokens() {
        let store = MemoryStore::new();
        let config = config(Some("relay-admin"));

        assert_eq!(
            authenticate_headers(&HeaderMap::new(), &config, &store).await,
            None
        );

        for token in [
            "Xelay-admin",
            "relay-Xdmin",
            "relay-admiX",
            "relay",
            "relay-admin-extra",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );

            assert_eq!(
                authenticate_headers(&headers, &config, &store).await,
                None,
                "unexpectedly accepted {token:?}"
            );
        }
    }

    #[tokio::test]
    async fn bearer_prefix_matches_go_case_sensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer relay-admin"),
        );
        let store = MemoryStore::new();

        assert_eq!(
            authenticate_headers(&headers, &config(Some("relay-admin")), &store).await,
            None
        );
    }

    #[tokio::test]
    async fn session_cookie_falls_back_to_admin_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("theme=dark; cw_session=relay-admin"),
        );
        let store = MemoryStore::new();

        let identity = authenticate_headers(&headers, &config(Some("relay-admin")), &store)
            .await
            .unwrap();

        assert!(identity.is_admin);
    }

    #[tokio::test]
    async fn bearer_session_token_resolves_github_identity() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sess_member"),
        );
        let store = MemoryStore::new();
        store
            .upsert_github_session(
                "sess_member",
                101,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;

        let identity = authenticate_headers(&headers, &config(Some("relay-admin")), &store)
            .await
            .unwrap();

        assert!(!identity.is_admin);
        assert_eq!(identity.user_id, Some(101));
        assert_eq!(identity.sub, None);
        assert_eq!(identity.username, "member");
    }

    #[tokio::test]
    async fn bearer_session_token_resolves_oidc_before_github() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer sess_shared"),
        );
        let store = MemoryStore::new();
        store
            .upsert_github_session(
                "sess_shared",
                101,
                "member",
                Utc::now() + Duration::hours(1),
            )
            .await;
        store
            .upsert_oidc_session(
                "sess_shared",
                "oidc-subject",
                "oidc-user",
                Utc::now() + Duration::hours(1),
            )
            .await;

        let identity = authenticate_headers(&headers, &config(Some("relay-admin")), &store)
            .await
            .unwrap();

        assert_eq!(identity.user_id, None);
        assert_eq!(identity.sub.as_deref(), Some("oidc-subject"));
        assert_eq!(identity.username, "oidc-user");
    }

    #[tokio::test]
    async fn expired_session_token_does_not_fall_back_to_admin_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer sess_user"));
        let store = MemoryStore::new();
        store
            .upsert_github_session(
                "sess_user",
                101,
                "member",
                Utc::now() - Duration::minutes(1),
            )
            .await;

        assert_eq!(
            authenticate_headers(&headers, &config(Some("sess_user")), &store).await,
            None
        );
    }
}
