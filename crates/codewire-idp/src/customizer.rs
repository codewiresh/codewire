//! [`TokenCustomizer`] — the Codewire claim set for id_tokens and userinfo.
//!
//! Emits scope-gated standard claims (`email`/`email_verified` for `email`;
//! `name`/`picture` for `profile`). Retired relying-party integrations used
//! to receive implicit organization claims; new clients use explicit
//! product APIs for organization context.

use std::collections::BTreeMap;

use async_trait::async_trait;
use codewire_oidc::{Client, Scopes, StoreError, StoreResult, Subject, TokenCustomizer};
use serde_json::Value;
use sqlx::PgPool;

/// `TokenCustomizer` backed by the `users` table.
#[derive(Clone)]
pub struct PgTokenCustomizer {
    pool: PgPool,
}

impl PgTokenCustomizer {
    /// Wrap a connection pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenCustomizer for PgTokenCustomizer {
    async fn extra_claims(
        &self,
        subject: &Subject,
        scopes: &Scopes,
        _client: &Client,
    ) -> StoreResult<BTreeMap<String, Value>> {
        let mut claims = BTreeMap::new();

        // Standard profile/email claims, gated by scope.
        let profile: Option<(Option<String>, Option<String>, Option<String>, Option<bool>)> =
            sqlx::query_as("SELECT email, name, image, email_verified FROM users WHERE id = $1")
                .bind(&subject.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(StoreError::new)?;
        if let Some((email, name, image, email_verified)) = profile {
            if scopes.contains("email") {
                if let Some(email) = email {
                    claims.insert("email".into(), Value::String(email));
                }
                claims.insert(
                    "email_verified".into(),
                    Value::Bool(email_verified.unwrap_or(false)),
                );
            }
            if scopes.contains("profile") {
                if let Some(name) = name {
                    claims.insert("name".into(), Value::String(name));
                }
                if let Some(image) = image {
                    claims.insert("picture".into(), Value::String(image));
                }
            }
        }

        Ok(claims)
    }
}
