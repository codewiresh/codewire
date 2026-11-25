//! The sandbox identity socket (`docs/dev/SANDBOX-IDENTITY.md`, "In the
//! Sandbox"): `GET /token?resource=URI` on
//! [`codewire_daemon_proto::HOSTED_DAEMON_IDENTITY_SOCKET`] answers a token
//! for that audience as `text/plain`, minted by orchestration's
//! `IssueIdentityToken`. A refusal is a status with the refusal's name as the
//! body. The socket is mode 0600 and one of the platform's sockets, which SSH
//! socket forwards refuse.
//!
//! It keeps one token per audience until half its lifetime, so a token
//! issued before a kill switch keeps being served from here until then. That
//! cache is an [`IdentityTokens`], which other holders in the daemon share. The
//! daemon is no boundary: every rule is orchestration's, and any process
//! here can call the RPC itself. Logs name the audience, never the token.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use tokio::net::UnixListener;
use zeroize::Zeroizing;

use crate::platform_sockets::PlatformSocket;

/// Audiences kept at once. A Sandbox registers few.
pub const MAX_CACHED_AUDIENCES: usize = 64;

/// A token orchestration issued.
pub struct IssuedIdentityToken {
    pub token: Zeroizing<String>,
    /// Unix seconds.
    pub expires_at: i64,
}

/// Why no token: the spec's refusal names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityRefusal {
    InvalidTarget,
    NotRunning,
    IdentityStopped,
    ResourceExhausted,
    IdentityUnavailable,
    KeyNotYetPublished,
    /// A refusal orchestration named that this daemon doesn't know: one
    /// added later. The socket answers it as `identity_unavailable`, and a
    /// token file treats it as every refusal but the passing ones: the file
    /// is deleted.
    Unrecognized,
}

impl IdentityRefusal {
    const ALL: [Self; 6] = [
        Self::InvalidTarget,
        Self::NotRunning,
        Self::IdentityStopped,
        Self::ResourceExhausted,
        Self::IdentityUnavailable,
        Self::KeyNotYetPublished,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidTarget => "invalid_target",
            Self::NotRunning => "not_running",
            Self::IdentityStopped => "identity_stopped",
            Self::ResourceExhausted => "resource_exhausted",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::KeyNotYetPublished => "key_not_yet_published",
            Self::Unrecognized => "unrecognized",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.name() == name)
    }

    /// The socket's status for it. `not_running` has none of its own in the
    /// spec; like every other temporary refusal it is 503.
    pub fn status(self) -> StatusCode {
        match self {
            Self::InvalidTarget => StatusCode::BAD_REQUEST,
            Self::IdentityStopped => StatusCode::FORBIDDEN,
            Self::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            Self::NotRunning
            | Self::IdentityUnavailable
            | Self::KeyNotYetPublished
            | Self::Unrecognized => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The refusal the socket answers: a name the contract has.
    fn answered(self) -> Self {
        match self {
            Self::Unrecognized => Self::IdentityUnavailable,
            named => named,
        }
    }
}

/// Where tokens come from: the daemon's binding client in production.
pub trait IdentityTokenSource: Send + Sync + 'static {
    fn issue(
        &self,
        resource: &str,
    ) -> impl Future<Output = Result<IssuedIdentityToken, IdentityRefusal>> + Send;
}

struct Cached {
    token: Zeroizing<String>,
    expires_at: i64,
    stale_at: i64,
}

/// A token from [`IdentityTokens::token`]: freshly issued or cached.
pub struct IdentityToken {
    pub token: Zeroizing<String>,
    /// Unix seconds.
    pub expires_at: i64,
    /// Unix seconds: half the lifetime it had left when it was issued. From
    /// then on [`IdentityTokens::token`] asks the source again.
    pub stale_at: i64,
}

/// The token source and the one cache of its tokens, keyed by audience. The
/// socket and the token files hold the same one, so a file's audience asked
/// at the socket costs no second mint.
pub struct IdentityTokens<S> {
    source: S,
    cache: Mutex<HashMap<String, Cached>>,
    now: fn() -> i64,
}

/// The name the socket's tests know the cache by.
#[cfg(test)]
type Shared<S> = IdentityTokens<S>;

impl<S: IdentityTokenSource> IdentityTokens<S> {
    pub fn new(source: S) -> Self {
        Self::with_clock(source, unix_now)
    }

    /// [`Self::new`] on a clock of Unix seconds other than the system's.
    pub fn with_clock(source: S, now: fn() -> i64) -> Self {
        Self {
            source,
            cache: Mutex::new(HashMap::new()),
            now,
        }
    }

    /// Unix seconds on this cache's clock.
    pub fn now(&self) -> i64 {
        (self.now)()
    }

    /// The token for the canonical `audience`: the cached one until half
    /// its lifetime, otherwise one issued by the source and kept. A refusal
    /// is never cached.
    pub async fn token(&self, audience: &str) -> Result<IdentityToken, IdentityRefusal> {
        let now = self.now();
        if let Some(token) = self.cached(audience, now) {
            return Ok(token);
        }
        let issued = self.source.issue(audience).await?;
        let token = IdentityToken {
            token: issued.token.clone(),
            expires_at: issued.expires_at,
            stale_at: stale_at(&issued, now),
        };
        self.keep(audience.to_owned(), issued, now);
        Ok(token)
    }
}

/// Bind the socket at `path`, mode 0600, replacing a socket a previous
/// daemon left; anything else there is refused.
pub fn bind(path: &Path) -> io::Result<(UnixListener, PlatformSocket)> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(io::Error::other("the identity socket path is not a socket")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let bound = crate::platform_sockets::bind(path, "the daemon's identity socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(bound)
}

/// Serve the socket until `shutdown` resolves.
pub async fn serve<S: IdentityTokenSource>(
    listener: UnixListener,
    tokens: Arc<IdentityTokens<S>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(listener, router_for(tokens))
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
fn router<S: IdentityTokenSource>(source: S, now: fn() -> i64) -> Router {
    router_for(Arc::new(IdentityTokens::with_clock(source, now)))
}

fn router_for<S: IdentityTokenSource>(tokens: Arc<IdentityTokens<S>>) -> Router {
    Router::new()
        .route("/token", get(token::<S>))
        .with_state(tokens)
}

#[derive(Deserialize)]
struct TokenQuery {
    resource: Option<String>,
}

async fn token<S: IdentityTokenSource>(
    State(shared): State<Arc<IdentityTokens<S>>>,
    query: Result<Query<TokenQuery>, QueryRejection>,
) -> Response {
    let Some(resource) = query
        .ok()
        .and_then(|Query(query)| query.resource)
        .filter(|resource| {
            !resource.is_empty()
                && resource.len() <= codewire_daemon_proto::IDENTITY_RESOURCE_MAX_BYTES
        })
    else {
        return refusal(IdentityRefusal::InvalidTarget);
    };
    match shared.token(&resource).await {
        Ok(issued) => text(issued.token),
        Err(refused) => {
            tracing::info!(
                audience = %resource,
                refusal = refused.name(),
                "sandbox identity token refused"
            );
            refusal(refused)
        }
    }
}

impl<S> IdentityTokens<S> {
    fn cached(&self, resource: &str, now: i64) -> Option<IdentityToken> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(resource)
            .filter(|cached| now < cached.stale_at)
            .map(|cached| IdentityToken {
                token: cached.token.clone(),
                expires_at: cached.expires_at,
                stale_at: cached.stale_at,
            })
    }

    /// Keep `issued` until half the lifetime it has left now. A full cache
    /// drops its stale tokens, then the one that goes stale soonest.
    fn keep(&self, resource: String, issued: IssuedIdentityToken, now: i64) {
        let stale_at = stale_at(&issued, now);
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if !cache.contains_key(&resource) && cache.len() >= MAX_CACHED_AUDIENCES {
            cache.retain(|_, cached| cached.stale_at > now);
            if cache.len() >= MAX_CACHED_AUDIENCES
                && let Some(soonest) = cache
                    .iter()
                    .min_by_key(|(_, cached)| cached.stale_at)
                    .map(|(resource, _)| resource.clone())
            {
                cache.remove(&soonest);
            }
        }
        cache.insert(
            resource,
            Cached {
                token: issued.token,
                expires_at: issued.expires_at,
                stale_at,
            },
        );
    }
}

/// Half the lifetime `issued` has left at `now`.
fn stale_at(issued: &IssuedIdentityToken, now: i64) -> i64 {
    now.saturating_add(issued.expires_at.saturating_sub(now) / 2)
}

fn text(token: Zeroizing<String>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        token.to_string(),
    )
        .into_response()
}

fn refusal(refusal: IdentityRefusal) -> Response {
    let refusal = refusal.answered();
    (
        refusal.status(),
        [(header::CONTENT_TYPE, "text/plain")],
        refusal.name(),
    )
        .into_response()
}

/// What asking the socket can end in, for `cw identity token`.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// Nothing serves the socket: this is not a cloud Sandbox.
    #[error("no identity socket")]
    NoSocket,
    #[error("refused: {}", .0.name())]
    Refused(IdentityRefusal),
    /// The socket answered something that isn't a token or a refusal.
    #[error("the identity socket's answer is not a token")]
    InvalidAnswer,
}

/// The longest answer read from the socket: a token is a few kilobytes.
const MAX_ANSWER_BYTES: u64 = 64 * 1024;
/// Longer than the binding client's own deadline for the call it makes.
pub const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Ask the socket at `path` for a token for `resource`.
pub async fn fetch(path: &Path, resource: &str) -> Result<Zeroizing<String>, FetchError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|_| FetchError::NoSocket)?;
    let request = format!(
        "GET /token?resource={} HTTP/1.1\r\nHost: identity\r\nConnection: close\r\n\r\n",
        query_encoded(resource)
    );
    let exchange = async {
        stream.write_all(request.as_bytes()).await?;
        let mut answer = Zeroizing::new(Vec::new());
        (&mut stream)
            .take(MAX_ANSWER_BYTES)
            .read_to_end(&mut answer)
            .await?;
        Ok::<_, io::Error>(answer)
    };
    let answer = tokio::time::timeout(FETCH_TIMEOUT, exchange)
        .await
        .map_err(|_| FetchError::InvalidAnswer)?
        .map_err(|_| FetchError::InvalidAnswer)?;
    let text = std::str::from_utf8(&answer).map_err(|_| FetchError::InvalidAnswer)?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or(FetchError::InvalidAnswer)?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or(FetchError::InvalidAnswer)?;
    if status == 200 {
        let well_formed = body.split('.').count() == 3
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        return if well_formed {
            Ok(Zeroizing::new(body.to_owned()))
        } else {
            Err(FetchError::InvalidAnswer)
        };
    }
    match IdentityRefusal::from_name(body) {
        Some(refusal) if refusal.status().as_u16() == status => Err(FetchError::Refused(refusal)),
        _ => Err(FetchError::InvalidAnswer),
    }
}

/// `value` as a query component: unreserved bytes as they are, every other
/// byte percent-encoded.
fn query_encoded(value: &str) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            // Writing to a String can't fail.
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
