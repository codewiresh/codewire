use axum::http::{HeaderMap, StatusCode, header};
use serde::Deserialize;

use crate::{error::WebError, security::canonical_cookie, state::AppState};

#[derive(Debug, Deserialize)]
struct IdentityEnvelope {
    user: Option<IdentityUser>,
    #[serde(default)]
    skip_2fa_setup: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IdentityUser {
    pub(crate) id: String,
    email: String,
    name: Option<String>,
    #[serde(default)]
    pub(crate) is_admin: bool,
    #[serde(default)]
    two_factor_enabled: bool,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    created_at: String,
    #[serde(skip)]
    skip_2fa_setup: bool,
}

impl IdentityUser {
    pub(crate) fn display_name(&self) -> &str {
        self.name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.email)
    }

    pub(crate) fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn two_factor_enabled(&self) -> bool {
        self.two_factor_enabled
    }

    pub(crate) fn email_verified(&self) -> bool {
        self.email_verified
    }

    pub(crate) fn created_at(&self) -> &str {
        &self.created_at
    }
}

pub(crate) async fn authenticated_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<IdentityUser, WebError> {
    let cookie = canonical_cookie(headers).map_err(|()| WebError::Unauthorized)?;
    let response = state
        .http
        .get(format!(
            "{}/api/auth/get-session",
            state.identity_origin_string
        ))
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| WebError::IdentityUnavailable)?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(WebError::Unauthorized);
    }
    if !response.status().is_success() {
        return Err(WebError::IdentityUnavailable);
    }
    let envelope = response
        .json::<Option<IdentityEnvelope>>()
        .await
        .map_err(|_| WebError::IdentityUnavailable)?
        .ok_or(WebError::Unauthorized)?;
    let mut user = envelope.user.ok_or(WebError::Unauthorized)?;
    user.skip_2fa_setup = envelope.skip_2fa_setup;
    Ok(user)
}

pub(crate) fn enforce_two_factor(identity: &IdentityUser) -> Result<(), WebError> {
    if identity.two_factor_enabled || identity.skip_2fa_setup {
        Ok(())
    } else {
        Err(WebError::TwoFactorRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_storage_identity_uses_the_immutable_idp_id() {
        let user: IdentityUser = serde_json::from_value(serde_json::json!({
            "id": "immutable-account-id", "name": "Changeable name",
            "email": "changeable@example.test"
        }))
        .unwrap();
        assert_eq!(user.id, "immutable-account-id");
        assert!(
            serde_json::from_value::<IdentityUser>(serde_json::json!({
                "name": "Changeable name", "email": "changeable@example.test"
            }))
            .is_err()
        );
    }

    #[test]
    fn two_factor_gate_preserves_the_identity_opt_out() {
        let mut user = IdentityUser {
            id: "synthetic-account".into(),
            email: "user@example.test".into(),
            name: None,
            is_admin: false,
            two_factor_enabled: false,
            email_verified: false,
            created_at: String::new(),
            skip_2fa_setup: false,
        };
        assert!(matches!(
            enforce_two_factor(&user),
            Err(WebError::TwoFactorRequired)
        ));
        user.skip_2fa_setup = true;
        assert!(enforce_two_factor(&user).is_ok());
    }
}
