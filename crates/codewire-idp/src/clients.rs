//! [`ClientStore`] over the `oidc_clients` table.

use async_trait::async_trait;
use codewire_oidc::{
    ApplicationType, AuthMethod, Client, ClientStore, GrantType, ResponseType, Scopes, StoreError,
    StoreResult,
};
use sqlx::PgPool;

/// `ClientStore` backed by the `oidc_clients` Postgres table.
#[derive(Clone)]
pub struct PgClientStore {
    pool: PgPool,
}

impl PgClientStore {
    /// Wrap a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Row shape from `oidc_clients`. Interval columns are projected to whole
/// seconds via `EXTRACT(EPOCH …)` so we never parse `PgInterval` by hand.
#[derive(sqlx::FromRow)]
struct ClientRow {
    id: String,
    name: Option<String>,
    application_type: String,
    auth_method: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Option<Vec<String>>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    scopes: Vec<String>,
    skip_consent: bool,
    access_token_lifetime_secs: i64,
    id_token_lifetime_secs: i64,
    refresh_token_lifetime_secs: Option<i64>,
    clock_skew_secs: i64,
    disabled: bool,
}

const SELECT_CLIENT: &str = r#"
    SELECT
        id, name, application_type, auth_method, redirect_uris,
        post_logout_redirect_uris, grant_types, response_types, scopes, skip_consent,
        EXTRACT(EPOCH FROM access_token_lifetime)::int8 AS access_token_lifetime_secs,
        EXTRACT(EPOCH FROM id_token_lifetime)::int8     AS id_token_lifetime_secs,
        EXTRACT(EPOCH FROM refresh_token_lifetime)::int8 AS refresh_token_lifetime_secs,
        EXTRACT(EPOCH FROM clock_skew)::int8            AS clock_skew_secs,
        disabled
    FROM oidc_clients
    WHERE id = $1
"#;

fn application_type(s: &str) -> ApplicationType {
    match s {
        "native" => ApplicationType::Native,
        "user_agent" => ApplicationType::UserAgent,
        _ => ApplicationType::Web,
    }
}

fn auth_method(s: &str) -> AuthMethod {
    match s {
        "none" => AuthMethod::None,
        "client_secret_post" => AuthMethod::ClientSecretPost,
        // private_key_jwt is unsupported (no client uses it); treat any other
        // value as the default confidential method.
        _ => AuthMethod::ClientSecretBasic,
    }
}

fn grant_types(raw: &[String]) -> Vec<GrantType> {
    raw.iter()
        .filter_map(|g| match g.as_str() {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "refresh_token" => Some(GrantType::RefreshToken),
            "urn:ietf:params:oauth:grant-type:device_code" => Some(GrantType::DeviceCode),
            _ => None,
        })
        .collect()
}

fn response_types(raw: &[String]) -> Vec<ResponseType> {
    raw.iter()
        .filter(|r| r.as_str() == "code")
        .map(|_| ResponseType::Code)
        .collect()
}

impl From<ClientRow> for Client {
    fn from(r: ClientRow) -> Self {
        Client {
            id: r.id.clone(),
            name: r.name.unwrap_or(r.id),
            application_type: application_type(&r.application_type),
            auth_method: auth_method(&r.auth_method),
            redirect_uris: r.redirect_uris,
            post_logout_redirect_uris: r.post_logout_redirect_uris.unwrap_or_default(),
            grant_types: grant_types(&r.grant_types),
            response_types: response_types(&r.response_types),
            scopes: Scopes(r.scopes),
            skip_consent: r.skip_consent,
            access_token_lifetime_secs: r.access_token_lifetime_secs.max(0) as u64,
            id_token_lifetime_secs: r.id_token_lifetime_secs.max(0) as u64,
            refresh_token_lifetime_secs: r.refresh_token_lifetime_secs.map(|s| s.max(0) as u64),
            clock_skew_secs: r.clock_skew_secs.max(0) as u64,
            disabled: r.disabled,
        }
    }
}

#[async_trait]
impl ClientStore for PgClientStore {
    async fn get(&self, client_id: &str) -> StoreResult<Option<Client>> {
        let row: Option<ClientRow> = sqlx::query_as(SELECT_CLIENT)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(row.map(Client::from))
    }

    async fn verify_secret(&self, client_id: &str, secret: &str) -> StoreResult<bool> {
        // Mirror the Go provider: compare against the bcrypt hash of an
        // enabled client only (a disabled client never authenticates).
        let hash: Option<Option<String>> =
            sqlx::query_scalar("SELECT secret FROM oidc_clients WHERE id = $1 AND NOT disabled")
                .bind(client_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::new)?;
        let Some(Some(hash)) = hash else {
            // Unknown/disabled client, or a public client with no secret.
            return Ok(false);
        };
        // bcrypt::verify is constant-time over the hash comparison.
        Ok(bcrypt::verify(secret, &hash).unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_grant_and_response_types() {
        assert_eq!(
            grant_types(&[
                "authorization_code".into(),
                "urn:ietf:params:oauth:grant-type:device_code".into(),
                "bogus".into(),
            ]),
            vec![GrantType::AuthorizationCode, GrantType::DeviceCode]
        );
        assert_eq!(
            response_types(&["code".into(), "token".into()]),
            vec![ResponseType::Code]
        );
    }

    #[test]
    fn maps_enums_with_defaults() {
        assert_eq!(application_type("native"), ApplicationType::Native);
        assert_eq!(application_type("web"), ApplicationType::Web);
        assert_eq!(application_type("weird"), ApplicationType::Web);
        assert_eq!(auth_method("none"), AuthMethod::None);
        assert_eq!(
            auth_method("client_secret_post"),
            AuthMethod::ClientSecretPost
        );
        assert_eq!(
            auth_method("private_key_jwt"),
            AuthMethod::ClientSecretBasic
        );
    }
}
