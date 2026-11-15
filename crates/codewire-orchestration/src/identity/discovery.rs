//! The identity listener: per-org OIDC discovery and the JWKS (design §6).
//!
//! It serves exactly `/orgs/<org id>/.well-known/openid-configuration` and
//! `/orgs/<org id>/jwks.json`, and nothing else:
//!
//! - `issuer` and `jwks_uri` are built from configuration and the org's
//!   stored ID, never from `Host`, `X-Forwarded-*` or any other header;
//! - only the exact, canonical ID of an existing, active org is accepted, so
//!   the response never echoes request input and a deleted org's issuer
//!   stops answering;
//! - every other path, method or query string is 404, and nothing redirects;
//! - errors are `no-store`, so no cache keeps one; a success may be cached
//!   for five minutes;
//! - an empty or unreadable key set is a 503, never an empty JWKS.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Response, StatusCode, Uri, header};
use axum::routing::get;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::Mutex;

use codewire_server_core::bounded_http1::BoundedHttp1Limits;

use super::config::IssuerBase;
use super::keys::KeySet;
use super::transit::{TransitError, TransitKeyClient};

const SUCCESS_CACHE_CONTROL: &str = "public, max-age=300";
const ERROR_CACHE_CONTROL: &str = "no-store";
/// How long one read of the key set serves the JWKS. A new version is
/// published 24 hours before it signs, so a minute's delay never matters,
/// and it bounds OpenBao reads to one a minute per replica.
const KEY_SET_TTL: Duration = Duration::from_secs(60);
const MAX_ORG_ID_BYTES: usize = 64;
const ORG_POOL_CONNECTIONS: u32 = 2;
const ORG_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

/// The listener sits behind the TLS-terminating edge and the cluster
/// gateway, so every connection comes from a proxy: the per-peer limit is the
/// global one. Requests are bodiless GETs.
pub const LISTENER_LIMITS: BoundedHttp1Limits = BoundedHttp1Limits {
    max_connections: 256,
    max_connections_per_peer: 256,
    header_read_timeout: Duration::from_secs(5),
    max_headers: 64,
    max_header_bytes: 16 * 1024,
    max_body_bytes: 0,
    request_read_timeout: Duration::from_secs(5),
    connection_deadline: Duration::from_secs(15),
};

/// An org ID as it appears in an issuer path: the stored form, lowercase.
/// Anything else is refused before any lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OrgId(String);

impl OrgId {
    fn parse(value: &str) -> Option<Self> {
        let canonical = !value.is_empty()
            && value.len() <= MAX_ORG_ID_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            });
        canonical.then(|| Self(value.to_owned()))
    }
}

/// Whether an org exists and is not being deleted.
#[async_trait]
pub trait OrgDirectory: Send + Sync {
    async fn is_active(&self, org_id: &str) -> Result<bool, sqlx::Error>;
}

/// The org lookup on its own small pool, so a flood of discovery requests
/// can't take connections from the rest of orchestration.
pub struct PgOrgDirectory {
    pool: PgPool,
}

impl PgOrgDirectory {
    pub fn connect_lazy(database_url: &str) -> anyhow::Result<Self> {
        let pool = codewire_server_core::db::checked_pool_options()
            .max_connections(ORG_POOL_CONNECTIONS)
            .min_connections(0)
            .acquire_timeout(ORG_POOL_ACQUIRE_TIMEOUT)
            .idle_timeout(Some(Duration::from_secs(5 * 60)))
            .connect_lazy(database_url)?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl OrgDirectory for PgOrgDirectory {
    async fn is_active(&self, org_id: &str) -> Result<bool, sqlx::Error> {
        // `id` is compared exactly: an upper-case spelling of a real ID
        // matches nothing.
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id FROM organizations WHERE id = $1 AND deletion_state = 'active'",
        )
        .bind(org_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }
}

/// Where the published key set comes from.
#[async_trait]
pub trait KeySource: Send + Sync {
    async fn key_set(&self) -> Result<KeySet, TransitError>;
}

#[async_trait]
impl KeySource for TransitKeyClient {
    async fn key_set(&self) -> Result<KeySet, TransitError> {
        self.read_key().await
    }
}

/// The serialized JWKS from the last key read, reused for [`KEY_SET_TTL`].
/// It holds public keys only. One request refreshes it while the others
/// wait for that read.
struct JwksCache {
    source: Arc<dyn KeySource>,
    current: Mutex<Option<(Instant, Arc<[u8]>)>>,
}

impl JwksCache {
    async fn jwks(&self) -> Option<Arc<[u8]>> {
        let mut current = self.current.lock().await;
        if let Some((read_at, body)) = current.as_ref()
            && read_at.elapsed() < KEY_SET_TTL
        {
            return Some(body.clone());
        }
        match self.source.key_set().await {
            Ok(key_set) => {
                if !key_set.custody.is_pinned() {
                    tracing::error!(
                        custody = ?key_set.custody,
                        "sandbox identity key configuration differs from its pinned custody"
                    );
                }
                let body: Arc<[u8]> = serde_json::to_vec(&key_set.jwks()).ok()?.into();
                *current = Some((Instant::now(), body.clone()));
                Some(body)
            }
            Err(error) => {
                // An expired read is never served: after an emergency
                // rotation this listener drops the old key within the
                // minute. A cache in front of it (SUCCESS_CACHE_CONTROL) may
                // keep serving it for up to five minutes more, and a verifier
                // for as long as its own cache keeps the JWKS.
                tracing::warn!(%error, "sandbox identity key set unavailable");
                None
            }
        }
    }
}

#[derive(Clone)]
pub struct DiscoveryState {
    issuer_base: IssuerBase,
    orgs: Arc<dyn OrgDirectory>,
    jwks: Arc<JwksCache>,
}

impl DiscoveryState {
    pub fn new(
        issuer_base: IssuerBase,
        orgs: Arc<dyn OrgDirectory>,
        keys: Arc<dyn KeySource>,
    ) -> Self {
        Self {
            issuer_base,
            orgs,
            jwks: Arc::new(JwksCache {
                source: keys,
                current: Mutex::new(None),
            }),
        }
    }
}

/// "OIDC compatible, not strictly compliant", as Kubernetes' own service
/// account issuer is: there is no authorization endpoint.
#[derive(Serialize)]
struct DiscoveryDocument<'a> {
    issuer: &'a str,
    jwks_uri: &'a str,
    response_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
}

pub fn router(state: DiscoveryState) -> Router {
    Router::new()
        .route(
            "/orgs/{org_id}/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/orgs/{org_id}/jwks.json", get(jwks))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(state)
}

/// Why a request names no servable org.
enum Refusal {
    NotFound,
    Unavailable,
}

impl Refusal {
    fn response(self) -> Response<Body> {
        match self {
            Self::NotFound => not_found_response(),
            Self::Unavailable => unavailable_response(),
        }
    }
}

/// The org a request names, if the request is exactly the canonical path
/// for it: no query string, no percent-encoding, no alternative spelling.
async fn requested_org(
    state: &DiscoveryState,
    raw_org_id: &str,
    uri: &Uri,
    suffix: &str,
) -> Result<OrgId, Refusal> {
    let org_id = OrgId::parse(raw_org_id).ok_or(Refusal::NotFound)?;
    if uri.query().is_some() || uri.path() != format!("/orgs/{}/{suffix}", org_id.0) {
        return Err(Refusal::NotFound);
    }
    match state.orgs.is_active(&org_id.0).await {
        Ok(true) => Ok(org_id),
        Ok(false) => Err(Refusal::NotFound),
        Err(error) => {
            tracing::warn!(%error, "sandbox identity org lookup failed");
            Err(Refusal::Unavailable)
        }
    }
}

async fn openid_configuration(
    State(state): State<DiscoveryState>,
    Path(raw_org_id): Path<String>,
    uri: Uri,
) -> Response<Body> {
    let org_id = match requested_org(
        &state,
        &raw_org_id,
        &uri,
        ".well-known/openid-configuration",
    )
    .await
    {
        Ok(org_id) => org_id,
        Err(refusal) => return refusal.response(),
    };
    let issuer = format!("{}/orgs/{}", state.issuer_base.as_str(), org_id.0);
    let jwks_uri = format!("{issuer}/jwks.json");
    let document = DiscoveryDocument {
        issuer: &issuer,
        jwks_uri: &jwks_uri,
        response_types_supported: ["id_token"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
    };
    match serde_json::to_vec(&document) {
        Ok(body) => json_response(body.into()),
        Err(_) => unavailable_response(),
    }
}

async fn jwks(
    State(state): State<DiscoveryState>,
    Path(raw_org_id): Path<String>,
    uri: Uri,
) -> Response<Body> {
    if let Err(refusal) = requested_org(&state, &raw_org_id, &uri, "jwks.json").await {
        return refusal.response();
    }
    match state.jwks.jwks().await {
        Some(body) => json_response(Body::from(body.to_vec())),
        None => unavailable_response(),
    }
}

async fn not_found() -> Response<Body> {
    not_found_response()
}

fn json_response(body: Body) -> Response<Body> {
    response(
        StatusCode::OK,
        SUCCESS_CACHE_CONTROL,
        "application/json",
        body,
    )
}

fn not_found_response() -> Response<Body> {
    response(
        StatusCode::NOT_FOUND,
        ERROR_CACHE_CONTROL,
        "text/plain; charset=utf-8",
        Body::from("not found\n"),
    )
}

fn unavailable_response() -> Response<Body> {
    response(
        StatusCode::SERVICE_UNAVAILABLE,
        ERROR_CACHE_CONTROL,
        "text/plain; charset=utf-8",
        Body::from("unavailable\n"),
    )
}

fn response(
    status: StatusCode,
    cache_control: &'static str,
    content_type: &'static str,
    body: Body,
) -> Response<Body> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
