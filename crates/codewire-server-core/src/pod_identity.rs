//! Exact-purpose authentication of Kubernetes projected Pod tokens.
//!
//! Only a successful TokenReview establishes the token's authenticity. Pod
//! coordinates come from its reviewed status; the finite expiry comes from the
//! exact reviewed request bytes, never an echoed response token or configured
//! projection lifetime. This is not a verifier for opaque Codewire OAuth tokens.
//! A verified identity is not a runtime grant: callers must still check live
//! Pod UIDs/deletion, controller associations and current platform authority.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codewire_gateway_proto::{
    CREDENTIAL_RELAY_SERVICE_ACCOUNT, CREDENTIAL_RELAY_TOKEN_AUDIENCE,
    CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE, SANDBOX_SERVICE_ACCOUNT, WORKSPACE_BINDING_TOKEN_AUDIENCE,
};
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec, TokenReviewStatus};
use kube::api::PostParams;
use kube::{Api, Client};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const TOKEN_REVIEW_TIMEOUT: Duration = Duration::from_secs(5);
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";
const SERVICE_ACCOUNT_USERNAME_PREFIX: &str = "system:serviceaccount:";

/// Closed authentication purposes. A request cannot choose an arbitrary audience.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PodIdentityPurpose {
    /// Orchestration relaying a bound workspace's credential bridge to the
    /// broker. Only orchestration's own service account may present it.
    CredentialRelay,
    CredentialWorkspace,
    WorkspaceBinding,
}

impl PodIdentityPurpose {
    pub const fn audience(self) -> &'static str {
        match self {
            Self::CredentialRelay => CREDENTIAL_RELAY_TOKEN_AUDIENCE,
            Self::CredentialWorkspace => CREDENTIAL_WORKSPACE_TOKEN_AUDIENCE,
            Self::WorkspaceBinding => WORKSPACE_BINDING_TOKEN_AUDIENCE,
        }
    }

    pub const fn service_account(self) -> &'static str {
        // Workspace Pods use the fixed sandbox account. Distinct audiences
        // prevent purpose substitution; live Pod role/owner checks are
        // additionally required by the runtime authority. The relay is
        // orchestration itself, under its own account.
        match self {
            Self::CredentialWorkspace | Self::WorkspaceBinding => SANDBOX_SERVICE_ACCOUNT,
            Self::CredentialRelay => CREDENTIAL_RELAY_SERVICE_ACCOUNT,
        }
    }
}

/// Authenticated coordinates and the original token's bounded Unix deadline.
/// No public constructor or wire deserializer can manufacture this result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPodIdentity {
    namespace: String,
    pod_name: String,
    pod_uid: String,
    purpose: PodIdentityPurpose,
    expires_at_unix: u64,
}

impl VerifiedPodIdentity {
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn pod_name(&self) -> &str {
        &self.pod_name
    }
    pub fn pod_uid(&self) -> &str {
        &self.pod_uid
    }
    pub fn purpose(&self) -> PodIdentityPurpose {
        self.purpose
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Value-blind failures: no Kubernetes status, token parser text or source chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PodIdentityError {
    #[error("Pod identity was not authenticated")]
    Unauthenticated,
    #[error("Pod identity is not permitted")]
    PermissionDenied,
    #[error("Kubernetes Pod identity verification is unavailable")]
    Unavailable,
}

#[async_trait]
trait TokenReviewer: Send + Sync {
    async fn review(&self, request: &TokenReview) -> Result<TokenReview, PodIdentityError>;
}

struct KubeTokenReviewer {
    token_reviews: Api<TokenReview>,
}

#[async_trait]
impl TokenReviewer for KubeTokenReviewer {
    async fn review(&self, request: &TokenReview) -> Result<TokenReview, PodIdentityError> {
        self.token_reviews
            .create(&PostParams::default(), request)
            .await
            .map_err(|_| PodIdentityError::Unavailable)
    }
}

/// Owns token-bearing API models across success, error, timeout and cancellation.
/// The kube client's internal transport allocations remain owned by that client.
struct SensitiveReview(TokenReview);

impl Zeroize for SensitiveReview {
    fn zeroize(&mut self) {
        if let Some(token) = self.0.spec.token.as_mut() {
            token.zeroize();
        }
    }
}

impl Drop for SensitiveReview {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Production verifier bound to one fixed purpose for its entire lifetime.
pub struct KubernetesPodIdentityVerifier {
    reviewer: Option<Arc<dyn TokenReviewer>>,
    purpose: PodIdentityPurpose,
    timeout: Duration,
}

impl KubernetesPodIdentityVerifier {
    pub fn new(client: Option<Client>, purpose: PodIdentityPurpose) -> Self {
        let reviewer = client.map(|client| {
            Arc::new(KubeTokenReviewer {
                token_reviews: Api::all(client),
            }) as Arc<dyn TokenReviewer>
        });
        Self {
            reviewer,
            purpose,
            timeout: TOKEN_REVIEW_TIMEOUT,
        }
    }

    /// Reject duplicate/noncanonical authorization before submitting one bounded
    /// TokenReview. Returned metadata does not authorize a platform operation.
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedPodIdentity, PodIdentityError> {
        let mut token = bearer(headers)?;
        let reviewer = self
            .reviewer
            .as_ref()
            .ok_or(PodIdentityError::Unavailable)?;
        let request = SensitiveReview(TokenReview {
            metadata: Default::default(),
            spec: TokenReviewSpec {
                audiences: Some(vec![self.purpose.audience().to_owned()]),
                token: Some(std::mem::take(&mut *token)),
            },
            status: None,
        });
        let mut reviewed = SensitiveReview(
            tokio::time::timeout(self.timeout, reviewer.review(&request.0))
                .await
                .map_err(|_| PodIdentityError::Unavailable)??,
        );
        let status = reviewed
            .0
            .status
            .take()
            .ok_or(PodIdentityError::Unauthenticated)?;
        let (namespace, pod_name, pod_uid) = validated_coordinates(status, self.purpose)?;
        // Only these same request bytes were authenticated. The response spec
        // is an untrusted echo and must never supply identity or a longer exp.
        let expires_at_unix = reviewed_expiry(
            request
                .0
                .spec
                .token
                .as_deref()
                .ok_or(PodIdentityError::Unauthenticated)?,
            unix_now()?,
        )?;
        Ok(VerifiedPodIdentity {
            namespace,
            pod_name,
            pod_uid,
            purpose: self.purpose,
            expires_at_unix,
        })
    }

    #[cfg(test)]
    fn for_test(reviewer: Arc<dyn TokenReviewer>, purpose: PodIdentityPurpose) -> Self {
        Self {
            reviewer: Some(reviewer),
            purpose,
            timeout: TOKEN_REVIEW_TIMEOUT,
        }
    }
}

/// Discards garbage before any TokenReview capacity is spent: exactly one
/// canonical bearer of at most 16 KiB that is a compact JWS (three non-empty
/// base64url segments) whose unverified `exp` lies in the future. This never
/// authenticates anything; TokenReview remains the only authentication, and
/// [`KubernetesPodIdentityVerifier::authenticate`] repeats every check.
pub fn pre_review_bearer_filter(headers: &HeaderMap) -> Result<(), PodIdentityError> {
    let token = bearer(headers)?;
    if token.split('.').count() != 3
        || !token
            .split('.')
            .all(|segment| !segment.is_empty() && segment.bytes().all(is_base64url_byte))
    {
        return Err(PodIdentityError::Unauthenticated);
    }
    reviewed_expiry(&token, unix_now()?).map(|_| ())
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn bearer(headers: &HeaderMap) -> Result<Zeroizing<String>, PodIdentityError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(PodIdentityError::Unauthenticated)?;
    if values.next().is_some() {
        return Err(PodIdentityError::Unauthenticated);
    }
    let value = value
        .to_str()
        .map_err(|_| PodIdentityError::Unauthenticated)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(PodIdentityError::Unauthenticated)?;
    if !valid_exact_value(token, MAX_TOKEN_BYTES) {
        return Err(PodIdentityError::Unauthenticated);
    }
    Ok(Zeroizing::new(token.to_owned()))
}

fn validated_coordinates(
    status: TokenReviewStatus,
    purpose: PodIdentityPurpose,
) -> Result<(String, String, String), PodIdentityError> {
    if status.authenticated != Some(true) || status.error.is_some() {
        return Err(PodIdentityError::Unauthenticated);
    }
    if !matches!(status.audiences.as_deref(), Some([audience]) if audience == purpose.audience()) {
        return Err(PodIdentityError::Unauthenticated);
    }
    let user = status.user.ok_or(PodIdentityError::Unauthenticated)?;
    let username = user.username.ok_or(PodIdentityError::Unauthenticated)?;
    let suffix = format!(":{}", purpose.service_account());
    let namespace = username
        .strip_prefix(SERVICE_ACCOUNT_USERNAME_PREFIX)
        .and_then(|value| value.strip_suffix(&suffix))
        .filter(|value| valid_exact_value(value, 63) && !value.contains(':'))
        .ok_or(PodIdentityError::PermissionDenied)?;
    let extra = user.extra.ok_or(PodIdentityError::PermissionDenied)?;
    let pod_name = singular_extra(&extra, POD_NAME_EXTRA, 253)?;
    let pod_uid = singular_extra(&extra, POD_UID_EXTRA, 128)?;
    Ok((
        namespace.to_owned(),
        pod_name.to_owned(),
        pod_uid.to_owned(),
    ))
}

fn singular_extra<'a>(
    extra: &'a std::collections::BTreeMap<String, Vec<String>>,
    key: &str,
    max_len: usize,
) -> Result<&'a str, PodIdentityError> {
    let values = extra.get(key).ok_or(PodIdentityError::PermissionDenied)?;
    let [value] = values.as_slice() else {
        return Err(PodIdentityError::PermissionDenied);
    };
    if !valid_exact_value(value, max_len) {
        return Err(PodIdentityError::PermissionDenied);
    }
    Ok(value)
}

fn valid_exact_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.is_ascii()
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
struct ProjectedExpiry {
    exp: u64,
}

fn reviewed_expiry(token: &str, now: u64) -> Result<u64, PodIdentityError> {
    // Kubernetes projected tokens are compact JWTs. Their signature and issuer
    // are verified by TokenReview, not by this expiry-only JSON extraction.
    let mut parts = token.split('.');
    let header = parts.next().filter(|value| !value.is_empty());
    let payload = parts.next().filter(|value| !value.is_empty());
    let signature = parts.next().filter(|value| !value.is_empty());
    if header.is_none() || signature.is_none() || parts.next().is_some() {
        return Err(PodIdentityError::Unauthenticated);
    }
    let payload = payload.ok_or(PodIdentityError::Unauthenticated)?;
    let mut decoded = Zeroizing::new(Vec::with_capacity(payload.len()));
    URL_SAFE_NO_PAD
        .decode_vec(payload, &mut decoded)
        .map_err(|_| PodIdentityError::Unauthenticated)?;
    let claims: ProjectedExpiry =
        serde_json::from_slice(&decoded).map_err(|_| PodIdentityError::Unauthenticated)?;
    let remaining = claims
        .exp
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or(PodIdentityError::Unauthenticated)?;
    if claims.exp > i64::MAX as u64
        || Instant::now()
            .checked_add(Duration::from_secs(remaining))
            .is_none()
    {
        return Err(PodIdentityError::Unauthenticated);
    }
    Ok(claims.exp)
}

fn unix_now() -> Result<u64, PodIdentityError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| PodIdentityError::Unavailable)
}

#[cfg(test)]
mod tests;
