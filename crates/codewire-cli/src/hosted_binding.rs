//! Claim-time binding of an identity-free hosted daemon (Program #2238 B2,
//! design §8).
//!
//! An unbound daemon exposes only its local readiness marker. It long-polls
//! `WorkspaceBindingService.BindWorkspace` on the dedicated orchestration
//! listener with its Pod-bound projected token, validates the response against
//! its own downward-API Pod UID, installs the credential file and the selected
//! Codex configuration, and only then listens. It never listens on an
//! unvalidated response and never exits while unbound. Neither the projected
//! token nor the daemon credential is ever logged.

use std::path::{Path, PathBuf};
use std::time::Duration;

use codewire_daemon::{BindResponseFields, WorkspaceBinding, WorkspaceBindingConfig};
use codewire_proto::codewire::internal::v1::{
    BindWorkspaceRequest, BindWorkspaceResponse, WorkspaceBindingServiceClient,
};
use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use connectrpc::{ConnectError, ErrorCode};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

/// The projected token is a compact JWS well below this bound.
const MAX_BINDING_TOKEN_BYTES: usize = 16 * 1024;

/// Retry pacing for the binding loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindTiming {
    /// Server-side wait requested per attempt (clamped by the server).
    pub wait_seconds: u32,
    /// Client deadline beyond the requested wait.
    pub deadline_margin: Duration,
    /// First backoff after an error other than `not_found`.
    pub initial_backoff: Duration,
    /// Backoff ceiling.
    pub max_backoff: Duration,
    /// A `not_found` that returns faster than this is paced to it, so an
    /// abnormal immediate answer never becomes a tight loop.
    pub minimum_attempt: Duration,
}

impl Default for BindTiming {
    fn default() -> Self {
        Self {
            wait_seconds: codewire_daemon::config::WORKSPACE_BINDING_WAIT_SECONDS,
            deadline_margin: Duration::from_secs(10),
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(10),
            minimum_attempt: Duration::from_secs(1),
        }
    }
}

impl BindTiming {
    fn deadline(&self) -> Duration {
        Duration::from_secs(u64::from(self.wait_seconds)) + self.deadline_margin
    }
}

/// Why one attempt did not produce an accepted binding. Value-blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptError {
    /// Nothing recorded yet after the server's wait: call again at once.
    NotFound,
    /// The listener refused or failed the call with this code.
    Rejected(ErrorCode),
    /// The projected token is missing or malformed.
    IdentityUnavailable,
    /// The response failed validation; it is never served.
    InvalidResponse,
}

impl AttemptError {
    fn label(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Rejected(ErrorCode::Unauthenticated) => "unauthenticated",
            Self::Rejected(ErrorCode::PermissionDenied) => "permission_denied",
            Self::Rejected(ErrorCode::ResourceExhausted) => "resource_exhausted",
            Self::Rejected(ErrorCode::Unavailable) => "unavailable",
            Self::Rejected(ErrorCode::DeadlineExceeded) => "deadline_exceeded",
            Self::Rejected(_) => "rejected",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// The Connect client for one daemon's binding exchange.
pub(crate) struct BindingClient {
    client: WorkspaceBindingServiceClient<HttpClient>,
    token_path: PathBuf,
    timing: BindTiming,
}

impl BindingClient {
    /// HTTP/1.1 only: the tenant-reachable listener refuses HTTP/2.
    pub(crate) fn new(
        binding_url: &str,
        token_path: &Path,
        timing: BindTiming,
    ) -> anyhow::Result<Self> {
        let config =
            ClientConfig::new(binding_url.parse()?).with_default_timeout(timing.deadline());
        Ok(Self {
            client: WorkspaceBindingServiceClient::new(HttpClient::plaintext(), config),
            token_path: token_path.to_owned(),
            timing,
        })
    }

    /// One `BindWorkspace` call. The projected token is reread every time,
    /// because the kubelet rotates it.
    pub(crate) async fn attempt(
        &self,
        config: &WorkspaceBindingConfig,
    ) -> Result<WorkspaceBinding, AttemptError> {
        let token = read_binding_token(&self.token_path)
            .await
            .ok_or(AttemptError::IdentityUnavailable)?;
        let options = call_options(&token).ok_or(AttemptError::IdentityUnavailable)?;
        drop(token);
        let response: BindWorkspaceResponse = match self
            .client
            .bind_workspace_with_options(
                BindWorkspaceRequest {
                    wait_seconds: self.timing.wait_seconds,
                    ..Default::default()
                },
                options,
            )
            .await
        {
            Ok(response) => response.into_owned(),
            Err(error) => return Err(classify(&error)),
        };
        let fields = BindResponseFields {
            environment_id: &response.environment_id,
            pod_uid: &response.pod_uid,
            operation_generation: response.operation_generation,
            daemon_credential: &response.daemon_credential,
            projection_selection_sha256: &response.projection_selection_sha256,
            managed_credential_clients: &response.managed_credential_clients,
        };
        let accepted = config.validate(&fields);
        // The response owns a copy of the credential; wipe it either way.
        let mut response = response;
        drop(Zeroizing::new(std::mem::take(
            &mut response.daemon_credential,
        )));
        accepted.map_err(|_| AttemptError::InvalidResponse)
    }
}

fn classify(error: &ConnectError) -> AttemptError {
    match error.code {
        ErrorCode::NotFound => AttemptError::NotFound,
        code => AttemptError::Rejected(code),
    }
}

/// Call until an accepted binding arrives. `not_found` is called again at
/// once (paced to `minimum_attempt`); every other outcome backs off
/// exponentially with jitter. This never returns an error and never exits.
pub(crate) async fn bind_until_accepted(
    client: &BindingClient,
    config: &WorkspaceBindingConfig,
) -> WorkspaceBinding {
    let timing = client.timing;
    let mut backoff = timing.initial_backoff;
    let mut attempts = 0_u64;
    loop {
        attempts = attempts.saturating_add(1);
        let started = tokio::time::Instant::now();
        let error = match client.attempt(config).await {
            Ok(binding) => {
                tracing::info!(attempts, "workspace binding accepted");
                return binding;
            }
            Err(error) => error,
        };
        if error == AttemptError::NotFound {
            backoff = timing.initial_backoff;
            tracing::debug!(
                attempts,
                "workspace binding not recorded yet; calling again"
            );
            tokio::time::sleep_until(started + timing.minimum_attempt).await;
            continue;
        }
        let pause = jittered(backoff);
        tracing::warn!(
            attempts,
            outcome = error.label(),
            retry_ms = u64::try_from(pause.as_millis()).unwrap_or(u64::MAX),
            "workspace binding attempt failed; retrying"
        );
        tokio::time::sleep(pause).await;
        backoff = (backoff * 2).min(timing.max_backoff);
    }
}

/// A uniformly random pause in `[backoff / 2, backoff]`.
fn jittered(backoff: Duration) -> Duration {
    use rand::Rng as _;
    let half = backoff / 2;
    let span = u64::try_from((backoff - half).as_millis()).unwrap_or(0);
    half + Duration::from_millis(rand::thread_rng().gen_range(0..=span))
}

async fn read_binding_token(path: &Path) -> Option<Zeroizing<String>> {
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut token = Zeroizing::new(String::with_capacity(2048));
    file.take((MAX_BINDING_TOKEN_BYTES + 1) as u64)
        .read_to_string(&mut token)
        .await
        .ok()?;
    (!token.is_empty()
        && token.len() <= MAX_BINDING_TOKEN_BYTES
        && token.is_ascii()
        && !token.chars().any(|c| c.is_whitespace() || c.is_control()))
    .then_some(token)
}

fn call_options(token: &str) -> Option<CallOptions> {
    let authorization = Zeroizing::new(format!("Bearer {token}"));
    let mut value = HeaderValue::try_from(authorization.as_str()).ok()?;
    value.set_sensitive(true);
    CallOptions::default()
        .try_with_header(AUTHORIZATION, value)
        .ok()
}

#[cfg(test)]
#[path = "hosted_binding/tests.rs"]
mod tests;
