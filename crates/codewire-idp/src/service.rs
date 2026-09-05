//! Service assembly: build the [`Provider`] from the Postgres stores and the
//! Codewire glue, and serve it through the library's axum router plus the
//! Codewire resume-after-login callback.
//!
//! The public CLI uses the provider's RFC 8628 device grant. Its authenticated
//! browser approval route is assembled beside this standards-based router.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use codewire_oidc::{
    AuthRequestId, AuthorizeOutcome, EndpointPaths, Issuer, KeyStore, Provider, ProviderConfig,
    RawAuthorizeParams, RequestContext,
};
use sqlx::PgPool;

use crate::{
    PgAuthorizationStore, PgClientStore, PgDeviceAuthorizationStore, PgKeyStore, PgTokenCustomizer,
    PgTokenStore, PgUserAuthenticator, SigningKekKeyring, auth_session::SignupInvitePolicy,
};

/// Static configuration for the idp service.
#[derive(Clone)]
pub struct IdpConfig {
    /// The OIDC issuer URL (also the base for endpoint URLs).
    pub issuer: String,
    /// Base URL of the login UI (`{frontend}/login`).
    pub frontend_url: String,
    /// Resend API key for transactional auth emails. Empty disables delivery.
    pub resend_api_key: String,
    /// Signup invite policy. An absent/blank hash list explicitly leaves
    /// signup open; configured hashes require a matching invite code.
    pub signup_invite_policy: SignupInvitePolicy,
    /// Scopes advertised in discovery.
    pub scopes_supported: Vec<String>,
}

impl fmt::Debug for IdpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdpConfig")
            .field("issuer", &self.issuer)
            .field("frontend_url", &self.frontend_url)
            .field(
                "resend_api_key_configured",
                &!self.resend_api_key.is_empty(),
            )
            .field("signup_invite_policy", &self.signup_invite_policy)
            .field("scopes_supported", &self.scopes_supported)
            .finish()
    }
}

impl IdpConfig {
    /// Read from the environment, mirroring the Go issuer resolution:
    /// `PUBLIC_OIDC_ISSUER_URL` → `OIDC_ISSUER_URL` → `CODEWIRE_API_URL` →
    /// `FRONTEND_URL`.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_values(|k| std::env::var(k).ok())
    }

    fn from_values(mut value: impl FnMut(&str) -> Option<String>) -> anyhow::Result<Self> {
        fn pick(keys: &[&str], value: &mut impl FnMut(&str) -> Option<String>) -> Option<String> {
            keys.iter().find_map(|k| {
                value(k)
                    .map(|v| v.trim().to_string())
                    .filter(|v| !v.is_empty())
            })
        }

        let issuer = pick(
            &[
                "PUBLIC_OIDC_ISSUER_URL",
                "OIDC_ISSUER_URL",
                "CODEWIRE_API_URL",
                "FRONTEND_URL",
            ],
            &mut value,
        )
        .ok_or_else(|| {
            anyhow::anyhow!(
                "one of PUBLIC_OIDC_ISSUER_URL / OIDC_ISSUER_URL / CODEWIRE_API_URL / FRONTEND_URL is required"
            )
        })?;
        let frontend_url = pick(&["FRONTEND_URL", "CODEWIRE_API_URL"], &mut value)
            .unwrap_or_else(|| issuer.clone());
        let resend_api_key = pick(&["RESEND_API_KEY"], &mut value).unwrap_or_default();
        let signup_invite_policy = SignupInvitePolicy::from_sha256_hashes(
            value("IDP_SIGNUP_INVITE_CODE_HASHES").as_deref(),
        )?;
        Ok(Self {
            issuer,
            frontend_url,
            resend_api_key,
            signup_invite_policy,
            scopes_supported: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
                "groups".into(),
                "codewire.api".into(),
            ],
        })
    }
}

/// Assemble the [`Provider`] from a pool, config, and idp-only signing
/// keyring. `capability_hmac_secret` is the service's existing session secret;
/// it keys the purpose-bound lookup digest for low-entropy human device codes
/// and is never persisted. Every signing-capable envelope is authenticated and
/// the active signer is created or adopted before the replica can serve
/// readiness.
pub async fn build_provider(
    pool: PgPool,
    cfg: &IdpConfig,
    keyring: SigningKekKeyring,
    capability_hmac_secret: impl Into<String>,
) -> anyhow::Result<Provider> {
    let keys = PgKeyStore::new(pool.clone(), keyring);
    let validated = keys
        .validate_envelopes()
        .await
        .map_err(|error| anyhow::anyhow!(error.0))?;
    let signer = keys
        .active_signer()
        .await
        .map_err(|error| anyhow::anyhow!(error.0))?;
    tracing::info!(validated, kid = %signer.kid, "oidc signing-key envelopes ready");

    let device_store = PgDeviceAuthorizationStore::new(pool.clone(), capability_hmac_secret)?;

    Ok(Provider::builder(ProviderConfig {
        issuer: Issuer(cfg.issuer.clone()),
        paths: EndpointPaths::default(),
        scopes_supported: cfg.scopes_supported.clone(),
    })
    .auth_requests(Arc::new(PgAuthorizationStore::new(pool.clone())))
    .tokens(Arc::new(PgTokenStore::new(pool.clone())))
    .clients(Arc::new(PgClientStore::new(pool.clone())))
    .keys(Arc::new(keys))
    .device_store(Arc::new(device_store))
    .device_verification_uri(format!("{}/device", cfg.frontend_url.trim_end_matches('/')))
    .authenticator(Arc::new(PgUserAuthenticator::new(
        pool.clone(),
        cfg.frontend_url.clone(),
    )))
    .customizer(Arc::new(PgTokenCustomizer::new(pool)))
    .build()
    .expect("all required stores are provided"))
}

/// The full OIDC router: the library's endpoints plus the Codewire
/// resume-after-login callback (`/api/oidc/callback`).
pub fn router(provider: Provider) -> Router {
    let callback = Router::new()
        .route("/api/oidc/callback", get(callback).post(callback))
        .with_state(provider.clone());
    codewire_oidc::transport::router(provider).merge(callback)
}

/// Resume an authorization after the user has logged in.
///
/// The login UI redirects here with `?id=<authRequestID>`; the user now has a
/// session cookie. We reload the stored request, reconstruct the original
/// `/authorize` parameters, and re-drive [`Provider::authorize`] — which now
/// resolves the session and issues the code (redirecting back to the RP).
async fn callback(
    State(p): State<Provider>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let Some(id) = q.get("id") else {
        return (StatusCode::BAD_REQUEST, "missing id parameter").into_response();
    };
    let stored = match p.auth_requests().get(&AuthRequestId(id.clone())).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "invalid or expired auth request").into_response();
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let req = &stored.request;
    let params = RawAuthorizeParams {
        client_id: Some(req.client_id.clone()),
        redirect_uri: Some(req.redirect_uri.clone()),
        response_type: Some("code".into()),
        scope: Some(req.scopes.to_space_delimited()),
        state: req.state.clone(),
        nonce: req.nonce.clone(),
        code_challenge: req.code_challenge.clone(),
        code_challenge_method: req.code_challenge_method.clone(),
        prompt: None,
        max_age: None,
    };
    // The resumed authorize() creates its own request row; drop the original.
    let _ = p.auth_requests().delete(&stored.id).await;

    let ctx = RequestContext {
        cookie: headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    };
    match p.authorize(&ctx, params).await {
        Ok(AuthorizeOutcome::Redirect(url)) | Ok(AuthorizeOutcome::RedirectToLogin(url)) => {
            found(&url)
        }
        Ok(AuthorizeOutcome::Fail(e)) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn found(location: &str) -> Response {
    match header::HeaderValue::from_str(location) {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::{IdpConfig, SignupInvitePolicy};

    #[test]
    fn config_debug_redacts_resend_api_key() {
        let cfg = IdpConfig {
            issuer: "https://issuer.example".into(),
            frontend_url: "https://app.example".into(),
            resend_api_key: "resend-secret-marker".into(),
            signup_invite_policy: SignupInvitePolicy::open(),
            scopes_supported: vec!["openid".into()],
        };

        let diagnostic = format!("{cfg:?}");
        assert!(!diagnostic.contains("resend-secret-marker"));
        assert!(diagnostic.contains("resend_api_key_configured: true"));
    }

    #[test]
    fn issuer_prefers_public_oidc_issuer_url() {
        let values = [
            ("PUBLIC_OIDC_ISSUER_URL", " http://127.0.0.1:8080 "),
            ("OIDC_ISSUER_URL", "https://oidc.example"),
            ("CODEWIRE_API_URL", "http://codewire-server:8080"),
            ("FRONTEND_URL", "http://frontend.example"),
        ];

        let cfg = IdpConfig::from_values(|key| {
            values
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_string())
        })
        .expect("config resolves");

        assert_eq!(cfg.issuer, "http://127.0.0.1:8080");
        assert_eq!(cfg.frontend_url, "http://frontend.example");
        assert_eq!(cfg.resend_api_key, "");
        assert!(!cfg.signup_invite_policy.is_configured());
        assert!(
            cfg.scopes_supported
                .iter()
                .any(|scope| scope == "codewire.api")
        );
    }

    #[test]
    fn issuer_falls_back_to_codewire_api_url() {
        let values = [
            ("PUBLIC_OIDC_ISSUER_URL", " "),
            ("CODEWIRE_API_URL", " http://codewire-server:8080 "),
        ];

        let cfg = IdpConfig::from_values(|key| {
            values
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_string())
        })
        .expect("config resolves");

        assert_eq!(cfg.issuer, "http://codewire-server:8080");
        assert_eq!(cfg.frontend_url, "http://codewire-server:8080");
        assert_eq!(cfg.resend_api_key, "");
        assert!(!cfg.signup_invite_policy.is_configured());
    }

    #[test]
    fn signup_invite_hashes_are_owned_by_idp_configuration() {
        let values = [
            ("PUBLIC_OIDC_ISSUER_URL", "https://idp.example"),
            (
                "IDP_SIGNUP_INVITE_CODE_HASHES",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];

        let cfg = IdpConfig::from_values(|key| {
            values
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_string())
        })
        .expect("configured invite policy resolves");

        assert!(cfg.signup_invite_policy.is_configured());
    }

    #[test]
    fn malformed_signup_invite_hashes_fail_configuration() {
        let values = [
            ("PUBLIC_OIDC_ISSUER_URL", "https://idp.example"),
            ("IDP_SIGNUP_INVITE_CODE_HASHES", "plaintext-is-not-valid"),
        ];

        let error = IdpConfig::from_values(|key| {
            values
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| (*value).to_string())
        })
        .unwrap_err();

        assert!(error.to_string().contains("IDP_SIGNUP_INVITE_CODE_HASHES"));
        assert!(!error.to_string().contains("plaintext-is-not-valid"));
    }
}
