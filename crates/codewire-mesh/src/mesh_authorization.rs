//! Typed authorization boundary for the generated Mesh Connect services.
//!
//! Hosted Mesh forwards exactly one already-presented product credential to
//! the primary control plane through the private generated service. Standalone
//! Mesh verifies its explicit local identity into the same typed context. Raw
//! credentials never become a Mesh model, store value, log field, or response.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine as _;
use codewire_proto::codewire::internal::v1::{
    MeshAuthorizationContext, MeshAuthorizationCredentialKind, MeshAuthorizationPrincipalKind,
    MeshAuthorizationServiceClient, ResolveMeshAuthorizationRequest,
};
use codewire_proto::codewire::v1::OrgRole;
use codewire_server_core::auth::{SESSION_COOKIE_NAME, hash_api_key};
use codewire_server_core::internal_hmac::issue_internal_hmac_token;
use codewire_tls::ConnectOriginTransport;
use connectrpc::client::{CallOptions, ClientConfig};
use connectrpc::{ConnectError, ErrorCode};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::config::{LocalMeshAuthorizationConfig, MeshAuthorizationConfig};

pub const MESH_AUTHORIZATION_CALLER: &str = "codewire-mesh";
pub const MESH_AUTHORIZATION_METHOD: &str =
    "codewire.internal.v1.MeshAuthorizationService/ResolveMeshAuthorization";
pub const FORWARDED_SESSION_HEADER: &str = "codewire-forwarded-session-bin";
pub const FORWARDED_AUTHORIZATION_HEADER: &str = "codewire-forwarded-authorization-bin";

#[derive(Clone)]
pub struct MeshAuthorizationClient {
    url: String,
    hmac_secret: String,
    tls_roots: std::path::PathBuf,
}

impl fmt::Debug for MeshAuthorizationClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeshAuthorizationClient")
            .field("url", &self.url)
            .field("hmac_secret", &"[redacted]")
            .field("tls_roots", &self.tls_roots)
            .finish()
    }
}

#[derive(Clone)]
pub enum ForwardedMeshCredential {
    Session(String),
    Authorization(String),
}

impl fmt::Debug for ForwardedMeshCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(_) => formatter.write_str("ForwardedMeshCredential::Session([redacted])"),
            Self::Authorization(_) => {
                formatter.write_str("ForwardedMeshCredential::Authorization([redacted])")
            }
        }
    }
}

impl ForwardedMeshCredential {
    pub(crate) fn environment_enrollment_code(&self) -> Option<&str> {
        let Self::Authorization(value) = self else {
            return None;
        };
        value.strip_prefix("Bearer ").filter(|value| {
            value.starts_with(crate::environment_members::ENVIRONMENT_ENROLLMENT_PREFIX)
                && value.len() > crate::environment_members::ENVIRONMENT_ENROLLMENT_PREFIX.len()
        })
    }

    /// Return the setup-only node enrollment capability when the caller
    /// presented that exact bearer class. Callers must consume it locally and
    /// must not fall through to hosted authorization forwarding.
    pub(crate) fn node_enrollment_code(&self) -> Option<&str> {
        let Self::Authorization(value) = self else {
            return None;
        };
        value
            .strip_prefix("Bearer ")
            .filter(|value| value.starts_with("cw_enr_") && value.len() > "cw_enr_".len())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ForwardedMeshCredentialError {
    #[error("exactly one session cookie or Authorization header is required")]
    MissingOrAmbiguous,
    #[error("forwarded Authorization header is invalid")]
    InvalidAuthorization,
}

/// Extracts the one credential the caller already presented. Multiple cookie
/// values, multiple Authorization values, or a mixture are ambiguous and are
/// rejected before any private RPC is attempted.
pub fn forwarded_mesh_credential(
    headers: &HeaderMap,
) -> Result<ForwardedMeshCredential, ForwardedMeshCredentialError> {
    let sessions = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|cookie| {
            let cookie = cookie.trim();
            let value = cookie
                .strip_prefix(SESSION_COOKIE_NAME)?
                .strip_prefix('=')?;
            (!value.trim().is_empty()).then_some(value.trim().to_owned())
        })
        .collect::<Vec<_>>();
    let authorizations = headers
        .get_all(AUTHORIZATION)
        .iter()
        .map(|value| {
            value
                .to_str()
                .map(str::trim)
                .ok()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(ForwardedMeshCredentialError::InvalidAuthorization)
        })
        .collect::<Result<Vec<_>, _>>()?;

    match (sessions.as_slice(), authorizations.as_slice()) {
        ([session], []) => Ok(ForwardedMeshCredential::Session(session.clone())),
        ([], [authorization]) => Ok(ForwardedMeshCredential::Authorization(
            authorization.clone(),
        )),
        _ => Err(ForwardedMeshCredentialError::MissingOrAmbiguous),
    }
}

#[derive(Clone, Debug)]
pub enum MeshAuthorizationAdapter {
    Hosted(MeshAuthorizationClient),
    Local(LocalMeshAuthorization),
}

impl MeshAuthorizationAdapter {
    pub fn from_config(
        hosted: Option<&MeshAuthorizationConfig>,
        local: Option<&LocalMeshAuthorizationConfig>,
    ) -> Option<Self> {
        match (hosted, local) {
            (Some(config), None) => Some(Self::Hosted(MeshAuthorizationClient::new(config))),
            (None, Some(config)) => Some(Self::Local(LocalMeshAuthorization::from_config(config))),
            (None, None) => None,
            (Some(_), Some(_)) => None,
        }
    }

    pub async fn resolve(
        &self,
        org_id: &str,
        credential: ForwardedMeshCredential,
    ) -> Result<MeshAuthorizationContext, MeshAuthorizationAdapterError> {
        match self {
            Self::Hosted(client) => client
                .resolve(org_id, credential)
                .await
                .map_err(MeshAuthorizationAdapterError::Hosted),
            Self::Local(local) => local
                .resolve(org_id, credential)
                .map_err(MeshAuthorizationAdapterError::Local),
        }
    }
}

/// Network management is a product surface and accepts only the three
/// user-facing credential flavors.
pub fn is_network_product_principal(context: &MeshAuthorizationContext) -> bool {
    context.principal_kind == MeshAuthorizationPrincipalKind::User
        && (context.credential_kind == MeshAuthorizationCredentialKind::SessionCookie
            || context.credential_kind == MeshAuthorizationCredentialKind::OauthBearer
            || context.credential_kind == MeshAuthorizationCredentialKind::ApiKey)
}

#[derive(Debug, Error)]
pub enum MeshAuthorizationAdapterError {
    #[error(transparent)]
    Hosted(#[from] MeshAuthorizationClientError),
    #[error(transparent)]
    Local(#[from] LocalMeshAuthorizationError),
}

impl MeshAuthorizationAdapterError {
    pub fn status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::Hosted(MeshAuthorizationClientError::Rpc(error)) => error.code.http_status(),
            Self::Local(LocalMeshAuthorizationError::Unauthorized) => {
                axum::http::StatusCode::UNAUTHORIZED
            }
            Self::Local(LocalMeshAuthorizationError::Forbidden) => {
                axum::http::StatusCode::FORBIDDEN
            }
            Self::Hosted(_) => axum::http::StatusCode::BAD_GATEWAY,
        }
    }
}

#[derive(Debug, Error)]
pub enum MeshAuthorizationClientError {
    #[error("Mesh authorization endpoint is invalid")]
    InvalidEndpoint,
    #[error("Mesh authorization HMAC credential could not be issued")]
    Hmac,
    #[error("Mesh authorization metadata is invalid")]
    InvalidMetadata,
    #[error("Mesh authorization RPC failed")]
    Rpc(#[source] ConnectError),
    #[error("Mesh authorization response omitted its typed context")]
    MissingContext,
}

impl MeshAuthorizationClient {
    pub fn new(config: &MeshAuthorizationConfig) -> Self {
        Self {
            url: config.url.clone(),
            hmac_secret: config.hmac_secret().to_owned(),
            tls_roots: config.tls_roots_file().to_path_buf(),
        }
    }

    pub async fn resolve(
        &self,
        org_id: &str,
        credential: ForwardedMeshCredential,
    ) -> Result<MeshAuthorizationContext, MeshAuthorizationClientError> {
        let hmac = issue_internal_hmac_token(
            &self.hmac_secret,
            MESH_AUTHORIZATION_CALLER,
            MESH_AUTHORIZATION_METHOD,
            chrono::Utc::now(),
        )
        .map_err(|_| MeshAuthorizationClientError::Hmac)?;
        let config = ClientConfig::new(
            self.url
                .parse()
                .map_err(|_| MeshAuthorizationClientError::InvalidEndpoint)?,
        )
        .with_default_timeout(Duration::from_secs(5));
        // The https endpoint is verified against its mounted roots, reread for
        // this call, so the forwarded product credential never crosses the
        // cluster network in plaintext.
        let transport = ConnectOriginTransport::for_origin(&self.url, &self.tls_roots)
            .map_err(|_| MeshAuthorizationClientError::InvalidEndpoint)?;
        let client = MeshAuthorizationServiceClient::new(transport, config);
        let response = client
            .resolve_mesh_authorization_with_options(
                ResolveMeshAuthorizationRequest {
                    org_id: org_id.to_owned(),
                    ..Default::default()
                },
                request_options(&hmac, credential)?,
            )
            .await
            .map_err(MeshAuthorizationClientError::Rpc)?
            .into_owned();
        response
            .context
            .as_option()
            .cloned()
            .ok_or(MeshAuthorizationClientError::MissingContext)
    }
}

fn request_options(
    hmac: &str,
    credential: ForwardedMeshCredential,
) -> Result<CallOptions, MeshAuthorizationClientError> {
    let (credential_header, raw_credential) = match credential {
        ForwardedMeshCredential::Session(value) => (FORWARDED_SESSION_HEADER, value),
        ForwardedMeshCredential::Authorization(value) => (FORWARDED_AUTHORIZATION_HEADER, value),
    };
    let mut hmac_value = HeaderValue::from_str(&format!("Bearer {hmac}"))
        .map_err(|_| MeshAuthorizationClientError::InvalidMetadata)?;
    hmac_value.set_sensitive(true);
    let mut credential_value = HeaderValue::from_str(
        &base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw_credential),
    )
    .map_err(|_| MeshAuthorizationClientError::InvalidMetadata)?;
    credential_value.set_sensitive(true);

    CallOptions::default()
        .try_with_header(AUTHORIZATION, hmac_value)
        .and_then(|options| {
            options.try_with_header(
                HeaderName::from_str(credential_header)
                    .map_err(|_| ConnectError::new(ErrorCode::Internal, "invalid header name"))?,
                credential_value,
            )
        })
        .map_err(|_| MeshAuthorizationClientError::InvalidMetadata)
}

#[derive(Clone)]
pub struct LocalMeshAuthorization {
    organization_id: String,
    api_key_hash: String,
}

impl fmt::Debug for LocalMeshAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalMeshAuthorization")
            .field("organization_id", &self.organization_id)
            .field("api_key_hash", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalMeshAuthorizationError {
    #[error("local Mesh credential is not authorized")]
    Unauthorized,
    #[error("local Mesh credential is outside its organization")]
    Forbidden,
}

impl LocalMeshAuthorization {
    pub fn from_config(config: &LocalMeshAuthorizationConfig) -> Self {
        Self {
            organization_id: config.organization_id.clone(),
            api_key_hash: config.api_key_hash.clone(),
        }
    }

    fn resolve(
        &self,
        org_id: &str,
        credential: ForwardedMeshCredential,
    ) -> Result<MeshAuthorizationContext, LocalMeshAuthorizationError> {
        if org_id.trim() != self.organization_id {
            return Err(LocalMeshAuthorizationError::Forbidden);
        }
        let ForwardedMeshCredential::Authorization(authorization) = credential else {
            return Err(LocalMeshAuthorizationError::Unauthorized);
        };
        let token = authorization
            .strip_prefix("Bearer ")
            .filter(|value| !value.is_empty())
            .ok_or(LocalMeshAuthorizationError::Unauthorized)?;
        if hashes_equal(&hash_api_key(token), &self.api_key_hash) {
            return Ok(MeshAuthorizationContext {
                principal_id: format!("local-owner:{}", self.organization_id),
                principal_kind: MeshAuthorizationPrincipalKind::User.into(),
                org_id: self.organization_id.clone(),
                role: OrgRole::Owner.into(),
                credential_kind: MeshAuthorizationCredentialKind::ApiKey.into(),
                ..Default::default()
            });
        }
        Err(LocalMeshAuthorizationError::Unauthorized)
    }
}

fn hashes_equal(left: &str, right: &str) -> bool {
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::any;
    use codewire_server_core::internal_hmac::verify_internal_hmac_token;
    use tokio::sync::mpsc;

    #[test]
    fn credentials_are_redacted_and_exactly_one_is_required() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer cw_secret"));
        let credential = forwarded_mesh_credential(&headers).unwrap();
        assert!(!format!("{credential:?}").contains("cw_secret"));

        headers.insert(
            COOKIE,
            HeaderValue::from_static("codewire.session_token=session-secret"),
        );
        assert_eq!(
            forwarded_mesh_credential(&headers).unwrap_err(),
            ForwardedMeshCredentialError::MissingOrAmbiguous
        );
    }

    #[test]
    fn forwards_only_the_canonical_primary_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("theme=dark; codewire.session_token=session-secret"),
        );
        assert!(matches!(
            forwarded_mesh_credential(&headers),
            Ok(ForwardedMeshCredential::Session(value)) if value == "session-secret"
        ));

        headers.insert(
            COOKIE,
            HeaderValue::from_static("cw_session=legacy-session"),
        );
        assert_eq!(
            forwarded_mesh_credential(&headers).unwrap_err(),
            ForwardedMeshCredentialError::MissingOrAmbiguous
        );
    }

    #[test]
    fn local_authorization_is_exact_org_and_redacted() {
        let api_key = "cw_local_key";
        let local = LocalMeshAuthorization::from_config(&LocalMeshAuthorizationConfig {
            organization_id: "local-org".to_string(),
            api_key_hash: hash_api_key(api_key),
        });
        let context = local
            .resolve(
                "local-org",
                ForwardedMeshCredential::Authorization(format!("Bearer {api_key}")),
            )
            .unwrap();
        assert_eq!(
            context.credential_kind,
            MeshAuthorizationCredentialKind::ApiKey
        );
        assert_eq!(context.principal_id, "local-owner:local-org");
        assert_eq!(
            local
                .resolve(
                    "other-org",
                    ForwardedMeshCredential::Authorization(format!("Bearer {api_key}")),
                )
                .unwrap_err(),
            LocalMeshAuthorizationError::Forbidden
        );
        assert_eq!(
            local
                .resolve(
                    "local-org",
                    ForwardedMeshCredential::Authorization(
                        "Bearer retired-environment-bearer".to_owned(),
                    ),
                )
                .unwrap_err(),
            LocalMeshAuthorizationError::Unauthorized
        );
        assert!(!format!("{local:?}").contains(api_key));
    }

    #[test]
    fn product_networks_require_a_user_product_credential() {
        let unspecified = MeshAuthorizationContext {
            principal_kind: MeshAuthorizationPrincipalKind::Unspecified.into(),
            credential_kind: MeshAuthorizationCredentialKind::Unspecified.into(),
            ..Default::default()
        };
        assert!(!is_network_product_principal(&unspecified));

        let api_key = MeshAuthorizationContext {
            principal_kind: MeshAuthorizationPrincipalKind::User.into(),
            credential_kind: MeshAuthorizationCredentialKind::ApiKey.into(),
            ..Default::default()
        };
        assert!(is_network_product_principal(&api_key));
    }

    #[tokio::test]
    async fn hosted_client_sends_the_scoped_hmac_and_one_encoded_credential() {
        let (headers_tx, mut headers_rx) = mpsc::unbounded_channel();
        let app = Router::new().fallback(any(move |headers: HeaderMap| {
            let headers_tx = headers_tx.clone();
            async move {
                let _ = headers_tx.send(headers);
                StatusCode::UNAUTHORIZED
            }
        }));
        // Orchestration's internal listener is TLS-only, as in production.
        let pki = codewire_tls::test_support::SyntheticPki::new("localhost");
        let address = pki.serve(app).await;

        let secret = "mesh-generated-client-header-test";
        let client = MeshAuthorizationClient {
            url: format!("https://localhost:{}", address.port()),
            hmac_secret: secret.to_owned(),
            tls_roots: pki.roots.clone(),
        };
        let raw_credential = "Bearer cw_generated_client_test";
        let error = client
            .resolve(
                "org-header-test",
                ForwardedMeshCredential::Authorization(raw_credential.to_owned()),
            )
            .await
            .expect_err("capture server rejects after receiving the private request");
        assert!(matches!(error, MeshAuthorizationClientError::Rpc(_)));

        let headers = headers_rx.recv().await.expect("generated request headers");
        let hmac = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .expect("scoped HMAC authorization header");
        verify_internal_hmac_token(
            secret,
            hmac,
            MESH_AUTHORIZATION_CALLER,
            MESH_AUTHORIZATION_METHOD,
            chrono::Utc::now(),
        )
        .expect("generated client must send a valid scoped HMAC");
        let forwarded = headers
            .get(FORWARDED_AUTHORIZATION_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("forwarded authorization metadata");
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(forwarded)
            .expect("encoded forwarded authorization");
        assert_eq!(decoded, raw_credential.as_bytes());
        assert!(headers.get(FORWARDED_SESSION_HEADER).is_none());
    }
}
