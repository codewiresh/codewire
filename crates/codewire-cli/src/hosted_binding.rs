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
//!
//! The listener serves TLS with the orchestration internal identity, checked
//! on every call against the mounted public roots (#2460) or, in a
//! confidential workspace, its measured roots (B2c). Besides the
//! binding, the same Pod-bound exchange refreshes the daemon's access grant,
//! records its SSH host public key and allocates UDP peer-relay endpoints.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use codewire_daemon::access::{AccessFields, MeshFields, WorkspaceAccessGrant};
use codewire_daemon::{BindResponseFields, WorkspaceBinding, WorkspaceBindingConfig};
#[cfg(any(target_os = "linux", test))]
use codewire_proto::codewire::internal::v1::{
    AllocatePeerRelayRequest, AllocatePeerRelayResponse, IssueMeshEnrollmentRequest,
    MeshAttachmentReport, RecordHostKeyRequest, RefreshAccessRequest, ReportMeshAttachmentRequest,
};
use codewire_proto::codewire::internal::v1::{
    BindWorkspaceRequest, BindWorkspaceResponse, WorkspaceAccess, WorkspaceBindingServiceClient,
};
use codewire_tls::ConnectOriginTransport;
use connectrpc::client::{CallOptions, ClientConfig};
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

/// A binding the daemon accepted, with its access grant when the listener
/// issued one.
#[derive(Debug)]
pub(crate) struct BoundWorkspace {
    pub binding: WorkspaceBinding,
    pub access: Option<WorkspaceAccessGrant>,
    /// What to write before serving (#3684). Its `Debug` shows no value.
    #[cfg(unix)]
    pub defaults: Option<codewire_daemon::workspace_defaults::WorkspaceDefaults>,
}

/// The daemon's form of the binding's saved project defaults and Git author.
#[cfg(unix)]
fn workspace_defaults(
    defaults: &codewire_proto::codewire::internal::v1::WorkspaceDefaults,
) -> codewire_daemon::workspace_defaults::WorkspaceDefaults {
    codewire_daemon::workspace_defaults::WorkspaceDefaults {
        environment: defaults
            .environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        git: defaults
            .git
            .as_option()
            .map(|git| codewire_daemon::workspace_defaults::GitAuthor {
                email: git.email.clone(),
                name: git.name.clone(),
            }),
    }
}

/// The Connect client for one daemon's binding exchange.
pub(crate) struct BindingClient {
    client: WorkspaceBindingServiceClient<ConnectOriginTransport>,
    token_path: PathBuf,
    timing: BindTiming,
    /// The listener admits one in-flight request per Pod: every call holds
    /// this for its whole duration.
    in_flight: tokio::sync::Mutex<()>,
}

/// The public roots the binding listener's certificate must chain to.
#[derive(Clone, Copy, Debug)]
pub(crate) enum BindingRoots<'a> {
    /// A standard workspace's mounted roots, reread on every call.
    Mounted(&'a Path),
    /// A confidential workspace's measured roots (B2c), held in memory and
    /// never read from a file.
    Measured(&'a str),
}

impl BindingClient {
    /// HTTPS only, verified against `roots`, and HTTP/1.1 only: the
    /// tenant-reachable listener refuses HTTP/2. Fails without usable roots.
    pub(crate) fn new(
        binding_url: &str,
        roots: BindingRoots<'_>,
        token_path: &Path,
        timing: BindTiming,
    ) -> anyhow::Result<Self> {
        let origin = binding_url.trim_end_matches('/');
        let transport = match roots {
            BindingRoots::Mounted(path) => ConnectOriginTransport::for_origin(origin, path),
            BindingRoots::Measured(pem) => {
                ConnectOriginTransport::for_origin_with_fixed_roots(origin, pem.as_bytes())
            }
        }
        .map_err(|_| anyhow::anyhow!("workspace binding requires an https origin and roots"))?
        .http1_only();
        let config = ClientConfig::new(origin.parse()?).with_default_timeout(timing.deadline());
        Ok(Self {
            client: WorkspaceBindingServiceClient::new(transport, config),
            token_path: token_path.to_owned(),
            timing,
            in_flight: tokio::sync::Mutex::new(()),
        })
    }

    /// Call options carrying the current projected token. It is reread every
    /// time, because the kubelet rotates it.
    async fn authorized(&self) -> Result<CallOptions, AttemptError> {
        let token = read_binding_token(&self.token_path)
            .await
            .ok_or(AttemptError::IdentityUnavailable)?;
        call_options(&token).ok_or(AttemptError::IdentityUnavailable)
    }

    /// One `BindWorkspace` call.
    pub(crate) async fn attempt(
        &self,
        config: &WorkspaceBindingConfig,
    ) -> Result<BoundWorkspace, AttemptError> {
        let _in_flight = self.in_flight.lock().await;
        let options = self.authorized().await?;
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
            working_directory: &response.working_directory,
        };
        let accepted = config.validate(&fields);
        // The response owns copies of the credential and peer token; wipe
        // them either way.
        let mut response = response;
        drop(Zeroizing::new(std::mem::take(
            &mut response.daemon_credential,
        )));
        let access = match response.access.as_option() {
            None => Ok(None),
            Some(access) => validate_access(access).map(Some),
        };
        if let Some(access) = response.access.as_option_mut() {
            drop(Zeroizing::new(std::mem::take(&mut access.peer_token)));
        }
        let binding = accepted.map_err(|_| AttemptError::InvalidResponse)?;
        // The grant names the environment's current operation generation,
        // which may move on after the binding's.
        Ok(BoundWorkspace {
            binding,
            access: access?,
            #[cfg(unix)]
            defaults: response.defaults.as_option().map(workspace_defaults),
        })
    }

    /// A fresh access grant for the bound Pod.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn refresh_access(&self) -> Result<WorkspaceAccessGrant, AttemptError> {
        let _in_flight = self.in_flight.lock().await;
        let options = self.authorized().await?;
        let mut response = self
            .client
            .refresh_access_with_options(RefreshAccessRequest::default(), options)
            .await
            .map_err(|error| classify(&error))?
            .into_owned();
        let access = response
            .access
            .as_option()
            .ok_or(AttemptError::InvalidResponse)
            .and_then(validate_access);
        if let Some(access) = response.access.as_option_mut() {
            drop(Zeroizing::new(std::mem::take(&mut access.peer_token)));
        }
        access
    }

    /// Record this Pod's SSH host public key (`ssh-ed25519 <base64>`).
    /// Recording the same key again succeeds; a different key for the same
    /// environment and generation is `failed_precondition`.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn record_host_key(
        &self,
        public_key_openssh: &str,
    ) -> Result<(), AttemptError> {
        let options = self.authorized().await?;
        self.client
            .record_host_key_with_options(
                RecordHostKeyRequest {
                    public_key_openssh: public_key_openssh.to_owned(),
                    ..Default::default()
                },
                options,
            )
            .await
            .map(|_| ())
            .map_err(|error| classify(&error))
    }

    /// Allocate a UDP peer-relay endpoint between this environment's node
    /// (`disco_keys[0]`) and one peer (`disco_keys[1]`).
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn allocate_peer_relay(
        &self,
        disco_keys: [String; 2],
        relay_generation: u32,
    ) -> Result<AllocatePeerRelayResponse, AttemptError> {
        let _in_flight = self.in_flight.lock().await;
        let options = self.authorized().await?;
        self.client
            .allocate_peer_relay_with_options(
                AllocatePeerRelayRequest {
                    disco_keys: disco_keys.to_vec(),
                    relay_generation,
                    ..Default::default()
                },
                options,
            )
            .await
            .map(|response| response.into_owned())
            .map_err(|error| classify(&error))
    }
}

impl BindingClient {
    /// One Mesh enrollment code for this Pod's next Mesh peer stream, and the
    /// network it joins (#3350). The code is never logged and is dropped
    /// after its one use.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn issue_mesh_enrollment(
        &self,
    ) -> Result<(Zeroizing<String>, codewire_daemon::access::MeshTarget), AttemptError> {
        let _in_flight = self.in_flight.lock().await;
        let options = self.authorized().await?;
        let mut response = self
            .client
            .issue_mesh_enrollment_with_options(IssueMeshEnrollmentRequest::default(), options)
            .await
            .map_err(|error| classify(&error))?
            .into_owned();
        let code = Zeroizing::new(std::mem::take(&mut response.enrollment_code));
        let target = response
            .attachment
            .as_option()
            .and_then(|mesh| {
                codewire_daemon::access::MeshTarget::from_fields(&MeshFields {
                    mesh_url: &mesh.mesh_url,
                    org_id: &mesh.org_id,
                    network_id: &mesh.network_id,
                    node_name: &mesh.node_name,
                })
            })
            .ok_or(AttemptError::InvalidResponse)?;
        let well_formed = code
            .strip_prefix("cw_eenr_")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        if !well_formed {
            return Err(AttemptError::InvalidResponse);
        }
        Ok((code, target))
    }

    /// Record what this Pod's daemon observed of its Mesh membership.
    #[cfg(any(target_os = "linux", test))]
    pub(crate) async fn report_mesh_attachment(
        &self,
        report: MeshAttachmentReport,
    ) -> Result<(), AttemptError> {
        let _in_flight = self.in_flight.lock().await;
        let options = self.authorized().await?;
        self.client
            .report_mesh_attachment_with_options(
                ReportMeshAttachmentRequest {
                    report: report.into(),
                    ..Default::default()
                },
                options,
            )
            .await
            .map(|_| ())
            .map_err(|error| classify(&error))
    }
}

fn validate_access(access: &WorkspaceAccess) -> Result<WorkspaceAccessGrant, AttemptError> {
    WorkspaceAccessGrant::validate(
        &AccessFields {
            peer_token: &access.peer_token,
            peer_token_expires_at: access.peer_token_expires_at,
            operation_generation: access.operation_generation,
            coordinator_url: &access.coordinator_url,
            direct_udp_endpoints: &access.direct_udp_endpoints,
            peer_relay_endpoints: &access.peer_relay_endpoints,
            app_ports: &access.app_ports,
            mesh: access.mesh.as_option().map(|mesh| MeshFields {
                mesh_url: &mesh.mesh_url,
                org_id: &mesh.org_id,
                network_id: &mesh.network_id,
                node_name: &mesh.node_name,
            }),
        },
        SystemTime::now(),
    )
    .map_err(|_| AttemptError::InvalidResponse)
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
) -> BoundWorkspace {
    let timing = client.timing;
    let mut backoff = timing.initial_backoff;
    let mut attempts = 0_u64;
    loop {
        attempts = attempts.saturating_add(1);
        let started = tokio::time::Instant::now();
        let error = match client.attempt(config).await {
            Ok(bound) => {
                tracing::info!(
                    attempts,
                    access = bound.access.is_some(),
                    "workspace binding accepted"
                );
                return bound;
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
