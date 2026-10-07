//! Incarnation capture and a durable, bounded metadata owner for cw updates.
//!
//! The journal component has no external command dispatch. Capture preserves
//! the existing operator/lifecycle gates,
//! then joins the exact B2 binding, checks the running Pod and pins that Pod's
//! credential/channel. No latest-binding credential lookup, repair, lifecycle
//! effect or legacy environment-token fallback occurs here.

mod execute;
mod intake;
pub mod model;
pub mod owner;
pub mod service;
#[cfg(test)]
mod service_test_support;
pub(crate) mod wire;

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use codewire_daemon_bridge::client::DaemonClient;
use codewire_gateway_proto::{DAEMON_CAPABILITY_EXEC, DAEMON_CAPABILITY_FILES};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::{AppError, AppResult};
use tonic::transport::Endpoint;
use uuid::Uuid;

use super::ApiState;
use super::proxy::{SandboxTarget, huma_error, resolve_running_sandbox_target};
use crate::confidential_storage::require_interactive_access;
use crate::sandbox::client::{ProbeResult, SandboxClient};
use crate::worker::environment_auth::{WorkspaceCredentialScope, daemon_credential_for};
use crate::worker::workspace_binding::{CwRuntimeLiveBinding, live_cw_runtime_binding};

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);

/// Nonsecret expected identity of an existing runtime. The current
/// environment generation and immutable binding generation are distinct:
/// B2 may preserve a running no-projection binding across relabelling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformCwRuntimeIncarnation {
    pub organization_id: String,
    pub environment_id: String,
    pub environment_generation: i64,
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: String,
    pub claim_uid: String,
    pub sandbox_uid: String,
    pub workspace_pvc_uid: Option<String>,
    pub binding_generation: i64,
    pub projection_selection_sha256: Option<String>,
    pub managed_credential_clients: String,
    pub binding_bound_at: chrono::DateTime<chrono::Utc>,
}

/// A channel authenticated only for the captured Pod. Its credential is never
/// a public field, serializable value or Debug output. Selection changes and
/// service retargeting do not replace this handle with a latest-binding token.
pub struct CapturedPlatformCwRuntime {
    incarnation: PlatformCwRuntimeIncarnation,
    row: CwRuntimeLiveBinding,
    daemon: DaemonClient,
}

impl CapturedPlatformCwRuntime {
    pub fn incarnation(&self) -> &PlatformCwRuntimeIncarnation {
        &self.incarnation
    }

    /// Nonsecret facts of this original captured binding, never a new lookup.
    pub(crate) fn binding_facts(&self) -> model::CapturedBindingFacts {
        model::CapturedBindingFacts::from(&self.row)
    }

    /// Clones the same authenticated channel. Callers must supply their own
    /// closed operation policy and bounds; capture does not authorize a new
    /// public arbitrary-command surface.
    pub fn daemon(&self) -> DaemonClient {
        self.daemon.clone()
    }

    /// Repeat authorization, the full live row comparison and exact Pod
    /// observation before preparing a later operation. This is observational:
    /// the future durable owner must additionally fence its admission write.
    pub async fn recheck(&self, state: &ApiState, user: &AuthUser) -> AppResult<()> {
        let backend = PlatformBackend { state, user };
        bounded(
            recheck_capture(&backend, &self.incarnation, &self.row),
            CAPTURE_TIMEOUT,
        )
        .await
    }

    /// Compare the identical captured row through the future owner's
    /// transaction. No credential/channel is resolved here. The caller must
    /// fence organization deletion and hold its environment/backend admission
    /// locks, then commit its durable request in that transaction. This SELECT
    /// does not establish ownership.
    pub async fn recheck_binding_in(&self, executor: impl sqlx::PgExecutor<'_>) -> AppResult<()> {
        let row = bounded(
            async {
                live_cw_runtime_binding(
                    executor,
                    &self.incarnation.organization_id,
                    &self.incarnation.environment_id,
                )
                .await
                .map_err(|_| binding_unavailable())
            },
            READ_TIMEOUT,
        )
        .await?;
        if row.as_ref() != Some(&self.row) {
            return Err(incarnation_changed());
        }
        Ok(())
    }
}

/// Capture a caller's expected existing incarnation. This entrypoint has no
/// default inheritance, environment creation or provider credential delivery.
pub async fn capture_platform_cw_runtime(
    state: &ApiState,
    user: &AuthUser,
    expected: &PlatformCwRuntimeIncarnation,
) -> AppResult<CapturedPlatformCwRuntime> {
    let backend = PlatformBackend { state, user };
    let captured = bounded(
        capture(&backend, expected, &state.session_secret),
        CAPTURE_TIMEOUT,
    )
    .await?;
    Ok(CapturedPlatformCwRuntime {
        incarnation: expected.clone(),
        row: captured.row,
        daemon: captured.client,
    })
}

struct Captured<C> {
    row: CwRuntimeLiveBinding,
    client: C,
}

#[async_trait]
trait CaptureBackend: Sync {
    type Client: Send;

    async fn authorize(&self, org: &str, env: &str) -> AppResult<SandboxTarget>;
    async fn binding(&self, org: &str, env: &str) -> AppResult<Option<CwRuntimeLiveBinding>>;
    async fn probe(&self, namespace: &str, env: &str) -> AppResult<ProbeResult>;
    fn confidential_access(&self, isolation_tier: &str) -> AppResult<()>;
    fn endpoint(&self, namespace: &str, env: &str) -> String;
    async fn connect(&self, endpoint: String, credential: String) -> AppResult<Self::Client>;
}

struct PlatformBackend<'a> {
    state: &'a ApiState,
    user: &'a AuthUser,
}

#[async_trait]
impl CaptureBackend for PlatformBackend<'_> {
    type Client = DaemonClient;

    async fn authorize(&self, org: &str, env: &str) -> AppResult<SandboxTarget> {
        // Reuse every current organization/operator/confidential/lifecycle
        // gate. Its name/IP target alone is not incarnation admission.
        resolve_running_sandbox_target(self.state, self.user, org, env)
            .await
            .map_err(|(status, message)| huma_error(status, message))
    }

    async fn binding(&self, org: &str, env: &str) -> AppResult<Option<CwRuntimeLiveBinding>> {
        live_cw_runtime_binding(&self.state.pool, org, env)
            .await
            .map_err(|_| binding_unavailable())
    }

    async fn probe(&self, namespace: &str, env: &str) -> AppResult<ProbeResult> {
        let kube = self.state.kube.clone().ok_or_else(binding_unavailable)?;
        SandboxClient::new(kube, namespace)
            .probe_environment(env)
            .await
            .map_err(|_| binding_unavailable())
    }

    fn confidential_access(&self, isolation_tier: &str) -> AppResult<()> {
        // Check the freshly joined tier too; a prior proxy read cannot
        // authorize a later change to confidential placement.
        require_interactive_access(
            self.state.confidential_storage_flags,
            self.user,
            isolation_tier,
        )
    }

    fn endpoint(&self, namespace: &str, env: &str) -> String {
        self.state
            .environment_daemon_endpoints
            .endpoint(namespace, env)
    }

    async fn connect(&self, endpoint: String, credential: String) -> AppResult<Self::Client> {
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|_| binding_unavailable())?
            .connect_timeout(READ_TIMEOUT)
            .connect()
            .await
            .map_err(|_| binding_unavailable())?;
        let client =
            DaemonClient::from_channel(channel, credential).map_err(|_| binding_unavailable())?;
        client
            .require_ready(&[DAEMON_CAPABILITY_EXEC, DAEMON_CAPABILITY_FILES])
            .await
            .map_err(|_| binding_unavailable())?;
        Ok(client)
    }
}

async fn capture<B: CaptureBackend>(
    backend: &B,
    expected: &PlatformCwRuntimeIncarnation,
    secret: &str,
) -> AppResult<Captured<B::Client>> {
    let row = admitted_row(backend, expected).await?;
    // This is the only credential derivation. In particular, do not call
    // environment_daemon_credential(), which can select a replacement Pod.
    let credential = daemon_credential_for(
        secret,
        &row.environment_id,
        &row.pod_uid,
        WorkspaceCredentialScope::Pod,
    )
    .map_err(|_| binding_unavailable())?;
    let endpoint = backend.endpoint(&row.namespace, &row.environment_id);
    // Bound this connect/readiness observation, not every later RPC made
    // through the retained channel. The operation owner supplies those bounds.
    let client = bounded(backend.connect(endpoint, credential), READ_TIMEOUT).await?;
    Ok(Captured { row, client })
}

async fn admitted_row<B: CaptureBackend>(
    backend: &B,
    expected: &PlatformCwRuntimeIncarnation,
) -> AppResult<CwRuntimeLiveBinding> {
    validate_expected(expected)?;
    let (org, env) = (&expected.organization_id, &expected.environment_id);
    let target = bounded(backend.authorize(org, env), READ_TIMEOUT).await?;
    let original = bounded(backend.binding(org, env), READ_TIMEOUT)
        .await?
        .ok_or_else(incarnation_changed)?;
    admit_row(backend, expected, &target, &original)?;
    let probe = bounded(backend.probe(&original.namespace, env), READ_TIMEOUT).await?;
    admit_probe(&original, &probe)?;
    // Re-read the complete tuple after the probe, including setup and mutable
    // environment gates. A matching Pod name or IP does not permit retargeting.
    let current = bounded(backend.binding(org, env), READ_TIMEOUT)
        .await?
        .ok_or_else(incarnation_changed)?;
    if current != original {
        return Err(incarnation_changed());
    }
    admit_row(backend, expected, &target, &current)?;
    Ok(current)
}

async fn recheck_capture<B: CaptureBackend>(
    backend: &B,
    expected: &PlatformCwRuntimeIncarnation,
    captured: &CwRuntimeLiveBinding,
) -> AppResult<()> {
    let current = admitted_row(backend, expected).await?;
    if &current != captured {
        return Err(incarnation_changed());
    }
    Ok(())
}

fn admit_row<B: CaptureBackend>(
    backend: &B,
    expected: &PlatformCwRuntimeIncarnation,
    target: &SandboxTarget,
    row: &CwRuntimeLiveBinding,
) -> AppResult<()> {
    if row.environment_state != "running"
        || row.desired_state != "started"
        || row.environment_type != "sandbox"
        || row.organization_deletion_state != "active"
        || row.deletion_requested_at.is_some()
        || !row.setup_complete
        || row.setup_owner_status.is_some()
    {
        return Err(AppError::Precondition(
            "environment runtime or setup is not ready".into(),
        ));
    }
    backend.confidential_access(&row.isolation_tier)?;
    if row.credential_scope != WorkspaceCredentialScope::Pod.as_str() {
        return Err(AppError::Precondition(
            "cw runtime capture requires a bound Pod-scoped daemon".into(),
        ));
    }
    if row.backend_namespace != row.namespace
        || row.backend_pod_name != row.pod_name
        || row.backend_pod_uid != row.pod_uid
        || row.backend_claim_uid.as_deref() != Some(row.claim_uid.as_str())
        || row.backend_pvc_uid != row.workspace_pvc_uid
        || target.environment_id != row.environment_id
        || target.namespace != row.namespace
        || target.pod_name != row.pod_name
        || incarnation(row) != *expected
        || row.backend_pod_ip.parse::<IpAddr>().is_err()
    {
        return Err(incarnation_changed());
    }
    Ok(())
}

fn admit_probe(row: &CwRuntimeLiveBinding, probe: &ProbeResult) -> AppResult<()> {
    if !probe.claim_exists
        || !probe.claim_ready
        || !probe.pod_exists
        || probe.pod_phase != "Running"
        || probe.pod_uid != row.pod_uid
        || probe.pod_name != row.pod_name
        || probe.pod_ip != row.backend_pod_ip
    {
        return Err(incarnation_changed());
    }
    Ok(())
}

fn incarnation(row: &CwRuntimeLiveBinding) -> PlatformCwRuntimeIncarnation {
    PlatformCwRuntimeIncarnation {
        organization_id: row.organization_id.clone(),
        environment_id: row.environment_id.clone(),
        environment_generation: row.environment_generation,
        namespace: row.namespace.clone(),
        pod_name: row.pod_name.clone(),
        pod_uid: row.pod_uid.clone(),
        claim_uid: row.claim_uid.clone(),
        sandbox_uid: row.sandbox_uid.clone(),
        workspace_pvc_uid: row.workspace_pvc_uid.clone(),
        binding_generation: row.binding_generation,
        projection_selection_sha256: row.projection_selection_sha256.clone(),
        managed_credential_clients: row.managed_credential_clients.clone(),
        binding_bound_at: row.binding_bound_at,
    }
}

fn validate_expected(expected: &PlatformCwRuntimeIncarnation) -> AppResult<()> {
    let uid = |value: &str| {
        Uuid::parse_str(value).is_ok_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
    };
    let name = |value: &str, maximum: usize| {
        !value.is_empty()
            && value.len() <= maximum
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            })
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                    && label.ends_with(|c: char| c.is_ascii_alphanumeric())
            })
    };
    let valid = !expected.organization_id.is_empty()
        && expected.organization_id.len() <= 128
        && !expected.organization_id.chars().any(char::is_control)
        && uid(&expected.environment_id)
        && uid(&expected.pod_uid)
        && uid(&expected.claim_uid)
        && uid(&expected.sandbox_uid)
        && expected.workspace_pvc_uid.as_deref().is_none_or(uid)
        && expected.environment_generation > 0
        && expected.binding_generation > 0
        && name(&expected.namespace, 63)
        && !expected.namespace.contains('.')
        && name(&expected.pod_name, 253)
        && expected
            .projection_selection_sha256
            .as_deref()
            .is_none_or(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        && expected.managed_credential_clients.len() <= 128
        && codewire_access::ManagedCredentialClients::decode(&expected.managed_credential_clients)
            .is_ok();
    if !valid {
        return Err(AppError::BadRequest(
            "expected runtime incarnation is invalid".into(),
        ));
    }
    Ok(())
}

async fn bounded<T>(
    future: impl std::future::Future<Output = AppResult<T>>,
    timeout: Duration,
) -> AppResult<T> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| binding_unavailable())?
}

fn incarnation_changed() -> AppError {
    AppError::Conflict("environment runtime incarnation changed".into())
}

fn binding_unavailable() -> AppError {
    AppError::Upstream("environment runtime capture is unavailable".into())
}

#[cfg(test)]
mod tests;
