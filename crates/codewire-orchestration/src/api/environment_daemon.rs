//! Authenticated platform adapter for the private environment-daemon service.
//!
//! Product clients authenticate to the public Connect service. This adapter
//! resolves their authorized environment, derives the daemon credential of
//! its live workspace binding inside the control plane (the per-Pod
//! credential for an identity-free Pod, the environment token for a legacy
//! one), and never returns that credential to the caller.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use codewire_daemon_bridge::client::DaemonClient;
use codewire_daemon_proto::daemon::v1;
use codewire_daemon_proto::{
    DAEMON_AUTH_TOKEN_HEADER, DAEMON_CAPABILITY_ATTACH, DAEMON_CAPABILITY_FILES,
    DAEMON_CAPABILITY_HEALTH, DAEMON_CAPABILITY_SESSIONS, DAEMON_PROTOCOL_VERSION,
};
use codewire_server_core::auth::AuthUser;
use codewire_server_core::org_deletion::{
    RuntimeMutationOutcome, run_environment_runtime_mutation_with_outcome,
};
use codewire_server_core::{AppError, AppResult};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, LogParams};
use sqlx::{PgPool, Row};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Streaming};

use super::ApiState;
use super::proxy::{
    huma_error, resolve_running_sandbox_target, resolve_running_sandbox_target_for_repair,
};
use crate::sandbox::client::{SandboxClient, WorkspacePodIdentity};
use crate::sandbox::template::{WORKSPACE_DAEMON_PORT, workspace_daemon_service_name};
use crate::worker::activity_authority::{
    ActivityAuthority, await_external_mutation, is_authority_lost,
};
use crate::worker::workspace_binding::{
    DaemonNotBound, bind_replacement_runtime, environment_daemon_credential,
};

#[cfg(test)]
mod repair_database_tests;
mod session_mutation;

const DAEMON_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
// Projection authorization already expires after 30 seconds. Launch/Restart
// must allow that bounded rendezvous plus cleanup; a connect-sized unary
// deadline otherwise cancels valid work while its durable record is Starting.
// This stays below the existing 60-second runtime-dispatch owner. Control RPCs
// and TCP connection establishment retain their five-second bounds.
const DAEMON_LAUNCH_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Clone, Copy)]
enum DaemonRequestBudget {
    Control,
    Launch,
}

impl DaemonRequestBudget {
    fn timeout(self) -> Duration {
        match self {
            Self::Control => DAEMON_CONTROL_TIMEOUT,
            Self::Launch => DAEMON_LAUNCH_TIMEOUT,
        }
    }
}
const DAEMON_REPAIR_TIMEOUT: Duration = Duration::from_secs(120);
const DAEMON_STATUS_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const DAEMON_LOG_TAIL_LINES: i64 = 500;
const MAXIMUM_TEST_ENDPOINT_CONFIG_BYTES: usize = 16 * 1024;
const MAXIMUM_TEST_ENDPOINTS: usize = 64;

#[derive(Debug, thiserror::Error)]
#[error("environment setup or recovery is in progress")]
struct DaemonRepairSetupBusy;

pub const TEST_DAEMON_ENDPOINTS_ENV: &str = "CODEWIRE_TEST_ENVIRONMENT_DAEMON_ENDPOINTS_JSON";

/// Loopback-only endpoint injection for the checked-in external wire fixture.
/// Production and ordinary development always resolve the environment's
/// cluster-local daemon Service.
#[derive(Clone, Debug, Default)]
pub struct EnvironmentDaemonEndpointOverrides {
    endpoints: Arc<BTreeMap<String, String>>,
}

impl EnvironmentDaemonEndpointOverrides {
    pub fn from_testing_config(
        testing_surface_enabled: bool,
        encoded: Option<&str>,
    ) -> anyhow::Result<Self> {
        let Some(encoded) = encoded else {
            return Ok(Self::default());
        };
        if !testing_surface_enabled {
            anyhow::bail!("{TEST_DAEMON_ENDPOINTS_ENV} requires CONNECT_TESTING_SURFACE=1");
        }
        if encoded.is_empty() || encoded.len() > MAXIMUM_TEST_ENDPOINT_CONFIG_BYTES {
            anyhow::bail!("invalid {TEST_DAEMON_ENDPOINTS_ENV}");
        }
        let configured: BTreeMap<String, String> = serde_json::from_str(encoded)
            .map_err(|_| anyhow::anyhow!("invalid {TEST_DAEMON_ENDPOINTS_ENV}"))?;
        if configured.is_empty() || configured.len() > MAXIMUM_TEST_ENDPOINTS {
            anyhow::bail!("invalid {TEST_DAEMON_ENDPOINTS_ENV}");
        }

        let mut endpoints = BTreeMap::new();
        for (environment_id, endpoint) in configured {
            if environment_id.is_empty()
                || environment_id.len() > 128
                || !environment_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                anyhow::bail!("invalid {TEST_DAEMON_ENDPOINTS_ENV}");
            }
            let url = url::Url::parse(&endpoint)
                .map_err(|_| anyhow::anyhow!("invalid {TEST_DAEMON_ENDPOINTS_ENV}"))?;
            let port = url
                .port()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow::anyhow!("invalid {TEST_DAEMON_ENDPOINTS_ENV}"))?;
            if endpoint.trim() != endpoint
                || url.scheme() != "http"
                || url.host_str() != Some("127.0.0.1")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                anyhow::bail!("invalid {TEST_DAEMON_ENDPOINTS_ENV}");
            }
            endpoints.insert(environment_id, format!("http://127.0.0.1:{port}"));
        }
        Ok(Self {
            endpoints: Arc::new(endpoints),
        })
    }

    pub(super) fn endpoint(&self, namespace: &str, environment_id: &str) -> String {
        self.endpoints
            .get(environment_id)
            .cloned()
            .unwrap_or_else(|| cluster_daemon_endpoint(namespace, environment_id))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentDaemonDiagnostic {
    pub name: String,
    pub healthy: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentDaemonStatus {
    pub state: v1::DaemonState,
    pub protocol_version: u32,
    pub minimum_protocol_version: u32,
    pub daemon_version: String,
    pub capabilities: Vec<String>,
    pub message: String,
    pub diagnostics: Vec<EnvironmentDaemonDiagnostic>,
    pub pod_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentDaemonRepair {
    pub status: EnvironmentDaemonStatus,
    pub replaced_pod_name: String,
}

/// Authenticated handle for a durable environment-daemon session attachment.
///
/// The private daemon protocol uses compact status frames. The public Connect
/// adapter resolves those frames to the authoritative session record before it
/// returns them to a product client, so this type deliberately retains the
/// private client and credential inside the control plane.
pub struct EnvironmentDaemonSessionAttachment {
    input: mpsc::Sender<v1::SessionAttachMessage>,
    output: Streaming<v1::SessionAttachMessage>,
    client: v1::daemon_service_client::DaemonServiceClient<Channel>,
    token: String,
}

pub async fn launch_environment_daemon_session_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    request: v1::LaunchSessionRequest,
) -> AppResult<v1::SessionRecord> {
    let required = if !request.name.is_empty() || request.parent_session_id.is_some() {
        &[
            DAEMON_CAPABILITY_SESSIONS,
            codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_METADATA,
        ][..]
    } else {
        &[DAEMON_CAPABILITY_SESSIONS][..]
    };
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        required,
        DaemonRequestBudget::Launch,
    )
    .await?;
    let request = authorize(request, &token)?;
    session_mutation::run(
        &state.pool,
        org_id,
        environment_id,
        session_mutation::Acknowledgement::Launch,
        async move {
            client
                .launch_session(request)
                .await
                .map(|reply| reply.into_inner().session)
        },
    )
    .await
}

pub async fn list_environment_daemon_sessions_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<Vec<v1::SessionRecord>> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS],
        DaemonRequestBudget::Control,
    )
    .await?;
    Ok(client
        .list_sessions(authorize(v1::ListSessionsRequest {}, &token)?)
        .await
        .map_err(daemon_session_error)?
        .into_inner()
        .sessions)
}

/// Worker-only daemon session path. The caller already owns durable
/// environment activity authority, so this resolves the same private daemon
/// service without manufacturing a public user identity.
pub(crate) async fn list_environment_daemon_sessions_for_worker(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
) -> AppResult<Vec<v1::SessionRecord>> {
    let (channel, token) =
        daemon_channel_for_runtime(pool, kube, session_secret, namespace, environment_id).await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    require_ready_daemon(&mut client, &token, &[DAEMON_CAPABILITY_SESSIONS]).await?;
    Ok(client
        .list_sessions(authorize(v1::ListSessionsRequest {}, &token)?)
        .await
        .map_err(daemon_session_error)?
        .into_inner()
        .sessions)
}

pub(crate) async fn stop_environment_daemon_session_for_worker(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
    session_id: &str,
) -> AppResult<v1::SessionRecord> {
    let (channel, token) =
        daemon_channel_for_runtime(pool, kube, session_secret, namespace, environment_id).await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    require_ready_daemon(&mut client, &token, &[DAEMON_CAPABILITY_SESSIONS]).await?;
    client
        .stop_session(authorize(
            v1::StopSessionRequest {
                session_id: session_id.to_string(),
            },
            &token,
        )?)
        .await
        .map_err(daemon_session_error)?
        .into_inner()
        .session
        .ok_or_else(|| AppError::InternalMsg("environment daemon returned no session".into()))
}

pub async fn get_environment_daemon_session_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    session_id: &str,
) -> AppResult<v1::SessionRecord> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS],
        DaemonRequestBudget::Control,
    )
    .await?;
    get_daemon_session(&mut client, &token, session_id).await
}

pub async fn stop_environment_daemon_session_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    session_id: &str,
) -> AppResult<v1::SessionRecord> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS],
        DaemonRequestBudget::Control,
    )
    .await?;
    let request = authorize(
        v1::StopSessionRequest {
            session_id: session_id.to_string(),
        },
        &token,
    )?;
    session_mutation::run(
        &state.pool,
        org_id,
        environment_id,
        session_mutation::Acknowledgement::Stop(session_id.to_string()),
        async move {
            client
                .stop_session(request)
                .await
                .map(|reply| reply.into_inner().session)
        },
    )
    .await
}

pub async fn restart_environment_daemon_session_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    session_id: &str,
    expected_launch_generation: Option<u64>,
) -> AppResult<v1::SessionRecord> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS],
        DaemonRequestBudget::Launch,
    )
    .await?;
    let request = authorize(
        v1::RestartSessionRequest {
            session_id: session_id.to_string(),
            expected_launch_generation,
        },
        &token,
    )?;
    session_mutation::run(
        &state.pool,
        org_id,
        environment_id,
        session_mutation::Acknowledgement::Restart(session_id.to_string()),
        async move {
            client
                .restart_session(request)
                .await
                .map(|reply| reply.into_inner().session)
        },
    )
    .await
}

/// Raw acknowledged input uses the same authorized running-environment target.
/// A deadline has an ambiguous write outcome and is never automatically retried.
pub async fn send_environment_daemon_session_input_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    request: v1::SendSessionInputRequest,
) -> AppResult<()> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[codewire_daemon_proto::DAEMON_CAPABILITY_SESSION_INPUT],
        DaemonRequestBudget::Control,
    )
    .await?;
    let mut request = authorize(request, &token)?;
    request.set_timeout(codewire_daemon_proto::SESSION_INPUT_TIMEOUT);
    client.send_session_input(request).await.map_err(|error| match error.code() {
        tonic::Code::DeadlineExceeded | tonic::Code::Cancelled | tonic::Code::Unavailable => AppError::Precondition(
            "session input outcome is ambiguous; input may have been written; do not retry automatically".into()),
        _ => daemon_session_error(error),
    })?;
    Ok(())
}

pub async fn read_environment_daemon_session_output_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    request: v1::ReadSessionOutputRequest,
) -> AppResult<v1::ReadSessionOutputResponse> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS],
        DaemonRequestBudget::Control,
    )
    .await?;
    client
        .read_session_output(authorize(request, &token)?)
        .await
        .map_err(daemon_session_error)
        .map(tonic::Response::into_inner)
}

pub async fn attach_environment_daemon_session_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    session_id: &str,
    output_offset: u64,
) -> AppResult<EnvironmentDaemonSessionAttachment> {
    let (mut client, token) = session_client_for_target(
        state,
        user,
        org_id,
        environment_id,
        &[DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH],
        DaemonRequestBudget::Control,
    )
    .await?;
    let (input, rx) = mpsc::channel(32);
    input
        .send(v1::SessionAttachMessage {
            payload: Some(v1::session_attach_message::Payload::Attach(
                v1::AttachSessionRequest {
                    session_id: session_id.to_string(),
                    output_offset,
                },
            )),
        })
        .await
        .map_err(|_| AppError::InternalMsg("failed to attach environment session".into()))?;
    let output = client
        .attach_session(authorize(ReceiverStream::new(rx), &token)?)
        .await
        .map_err(daemon_session_error)?
        .into_inner();
    Ok(EnvironmentDaemonSessionAttachment {
        input,
        output,
        client,
        token,
    })
}

impl EnvironmentDaemonSessionAttachment {
    /// Both transport halves remain inside orchestration. Dropping them
    /// releases the attachment, never dispatching StopSession.
    pub(crate) fn into_stream_parts(
        self,
    ) -> (
        mpsc::Sender<v1::SessionAttachMessage>,
        Streaming<v1::SessionAttachMessage>,
    ) {
        (self.input, self.output)
    }

    pub async fn send_input(&self, message: v1::SessionAttachMessage) -> AppResult<()> {
        self.input
            .send(message)
            .await
            .map_err(|_| AppError::Upstream("environment session input closed".into()))
    }

    pub async fn next_output(&mut self) -> AppResult<Option<v1::SessionAttachMessage>> {
        let Some(message) = self.output.message().await.map_err(daemon_session_error)? else {
            return Ok(None);
        };
        Ok(Some(message))
    }

    pub async fn session(&mut self, session_id: &str) -> AppResult<v1::SessionRecord> {
        get_daemon_session(&mut self.client, &self.token, session_id).await
    }
}

/// Resolve an authorized environment to the shared host-side daemon client.
///
/// The environment-scoped credential remains inside orchestration and is
/// marked sensitive by `DaemonClient`; public adapters receive only the typed
/// client handle.
pub(crate) async fn environment_daemon_bridge_client_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<DaemonClient> {
    if state.kube.is_none() {
        return Err(AppError::ServiceUnavailable(
            "sandbox client not configured".into(),
        ));
    }
    let target = resolve_target(state, user, org_id, environment_id).await?;
    let (channel, token) =
        daemon_channel_for_target(state, &target.namespace, &target.environment_id).await?;
    DaemonClient::from_channel(channel, token)
        .map_err(|_| AppError::InternalMsg("failed to authorize environment daemon".into()))
}

pub async fn get_environment_daemon_status_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<EnvironmentDaemonStatus> {
    let target = resolve_target(state, user, org_id, environment_id).await?;
    daemon_status_for_target(
        state,
        &target.namespace,
        &target.environment_id,
        &target.pod_name,
    )
    .await
}

pub async fn get_environment_daemon_logs_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<Vec<u8>> {
    let target = resolve_target(state, user, org_id, environment_id).await?;
    let kube = state
        .kube
        .as_ref()
        .ok_or_else(|| AppError::ServiceUnavailable("sandbox client not configured".into()))?;
    let sandbox = SandboxClient::new(kube.clone(), &target.namespace);
    let pod_name = resolve_pod_name(&sandbox, &target.environment_id, &target.pod_name).await?;
    let pods: Api<Pod> = Api::namespaced(kube.clone(), &target.namespace);
    pods.logs(
        &pod_name,
        &LogParams {
            container: Some("workspace".into()),
            tail_lines: Some(DAEMON_LOG_TAIL_LINES),
            timestamps: true,
            ..Default::default()
        },
    )
    .await
    .map(String::into_bytes)
    .map_err(|error| {
        tracing::warn!(
            environment_id,
            %pod_name,
            %error,
            "read environment daemon logs failed"
        );
        AppError::Upstream("environment daemon logs are unavailable".into())
    })
}

pub async fn repair_environment_daemon_core(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<EnvironmentDaemonRepair> {
    let target = resolve_running_sandbox_target_for_repair(state, user, org_id, environment_id)
        .await
        .map_err(|(status, message)| huma_error(status, message))?;
    let kube = state
        .kube
        .as_ref()
        .ok_or_else(|| AppError::ServiceUnavailable("sandbox client not configured".into()))?;
    let sandbox = SandboxClient::new(kube.clone(), &target.namespace);
    // No database connection is pinned across the long replacement wait.
    // Concurrent callers may observe the same incarnation, but deletion is
    // UID-fenced, replacement wait is keyed by that old UID, and the final
    // database update is generation-authorized. Those operations converge on
    // the same replacement without risking pool exhaustion or deleting a
    // newer Pod.
    let mut setup_check = state.pool.begin().await.map_err(AppError::from)?;
    let current: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT state, desired_state, environment_operation_generation \
           FROM environments WHERE id = $1 FOR UPDATE",
    )
    .bind(&target.environment_id)
    .fetch_optional(&mut *setup_check)
    .await
    .map_err(AppError::from)?;
    let generation = match current.as_ref() {
        Some((state, desired, generation))
            if state == "running" && desired == "started" && *generation > 0 =>
        {
            *generation
        }
        _ => {
            return Err(AppError::Conflict(
                "environment state changed during daemon repair".into(),
            ));
        }
    };
    let setup = sqlx::query(
        "SELECT COALESCE(setup_complete, false) AS setup_complete, setup_owner_status \
           FROM sandbox_environment_backend \
          WHERE environment_id = $1 FOR UPDATE",
    )
    .bind(&target.environment_id)
    .fetch_optional(&mut *setup_check)
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::ServiceUnavailable("sandbox backend not found".into()))?;
    let setup_complete: bool = setup.get("setup_complete");
    let setup_owner_status: Option<String> = setup.get("setup_owner_status");
    if !daemon_repair_setup_is_idle(setup_complete, setup_owner_status.as_deref()) {
        return Err(AppError::Conflict(
            "environment setup or recovery is in progress".into(),
        ));
    }
    setup_check.commit().await.map_err(AppError::from)?;
    let authority = ActivityAuthority::capture_required(
        &state.pool,
        &target.environment_id,
        "started",
        generation,
    )
    .await
    .map_err(|_| AppError::Conflict("environment state changed during daemon repair".into()))?;
    let current = sandbox
        .get_workspace_pod_identity(&target.environment_id)
        .await
        .map_err(|_| AppError::ServiceUnavailable("workspace Pod is unavailable".into()))?
        .ok_or_else(|| AppError::ServiceUnavailable("workspace Pod is unavailable".into()))?;
    run_daemon_repair(
        &state.pool,
        org_id,
        DaemonRepair {
            pool: state.pool.clone(),
            kube: kube.clone(),
            session_secret: state.session_secret.clone(),
            daemon_endpoints: state.environment_daemon_endpoints.clone(),
            namespace: target.namespace,
            environment_id: target.environment_id,
            sandbox,
            authority,
            current,
            support_image: state.sandbox_cfg.support_image().to_owned(),
        },
    )
    .await
}

/// Everything a daemon repair uses after admission, owned so the repair can
/// outlive the request that started it.
struct DaemonRepair {
    pool: PgPool,
    kube: kube::Client,
    session_secret: String,
    daemon_endpoints: EnvironmentDaemonEndpointOverrides,
    namespace: String,
    environment_id: String,
    sandbox: SandboxClient,
    authority: ActivityAuthority,
    current: WorkspacePodIdentity,
    /// The support image the replacement's daemon is re-pinned to.
    support_image: String,
}

/// Replace the workspace Pod behind the environment runtime fence.
///
/// Admission and the replacement run in the shared runtime-mutation owner
/// task, so a caller that leaves mid-repair cannot strand the lease: each path
/// still releases it or records its own recovery code. The replacement keeps
/// its own Pod and readiness deadlines; the owner adds none.
async fn run_daemon_repair(
    pool: &PgPool,
    org_id: &str,
    repair: DaemonRepair,
) -> AppResult<EnvironmentDaemonRepair> {
    let environment_id = repair.environment_id.clone();
    run_environment_runtime_mutation_with_outcome(
        pool,
        org_id,
        &environment_id,
        repair.replace_workspace_pod(),
    )
    .await?
}

impl DaemonRepair {
    async fn replace_workspace_pod(
        self,
    ) -> RuntimeMutationOutcome<AppResult<EnvironmentDaemonRepair>> {
        let environment_id = self.environment_id.as_str();
        if let Err(error) = delete_workspace_pod_while_setup_idle(
            &self.authority,
            &self.sandbox,
            environment_id,
            &self.current.name,
            &self.current.uid,
            &self.support_image,
        )
        .await
        {
            if error.downcast_ref::<DaemonRepairSetupBusy>().is_some() {
                return RuntimeMutationOutcome::release(Err(AppError::Conflict(
                    "environment setup or recovery is in progress".into(),
                )));
            }
            if is_authority_lost(&error) {
                return RuntimeMutationOutcome::release(Err(AppError::Conflict(
                    "environment state changed during daemon repair".into(),
                )));
            }
            tracing::warn!(environment_id, %error, "environment daemon repair failed");
            return RuntimeMutationOutcome::resolution_required(
                "environment_daemon_repair_ambiguous",
                Err(AppError::Upstream(
                    "environment daemon repair did not converge".into(),
                )),
            );
        }
        let replacement = match self
            .authority
            .run_while_authoritative_for_states(
                &["running"],
                self.sandbox.wait_for_replacement_workspace_pod(
                    &self.current.name,
                    &self.current.uid,
                    DAEMON_REPAIR_TIMEOUT,
                ),
            )
            .await
        {
            Ok(replacement) => replacement,
            Err(error) => {
                tracing::warn!(
                    environment_id,
                    %error,
                    "environment daemon repair failed"
                );
                return RuntimeMutationOutcome::resolution_required(
                    "environment_daemon_repair_ambiguous",
                    Err(AppError::Upstream(
                        "environment daemon repair did not converge".into(),
                    )),
                );
            }
        };
        // Design §10: the replacement binds before its daemon-status wait; an
        // identity-free daemon listens only once bound, so the wait would
        // otherwise never succeed.
        if let Err(error) = bind_replacement_runtime(
            &self.kube,
            &self.authority,
            &["running"],
            &replacement,
            DAEMON_REPAIR_TIMEOUT,
        )
        .await
        {
            tracing::warn!(environment_id, %error, "environment daemon repair binding failed");
            return RuntimeMutationOutcome::resolution_required(
                "environment_daemon_repair_binding_ambiguous",
                Err(if is_authority_lost(&error) {
                    AppError::Conflict("environment state changed during daemon repair".into())
                } else {
                    AppError::Upstream("environment daemon repair did not converge".into())
                }),
            );
        }
        let deadline = tokio::time::Instant::now() + DAEMON_REPAIR_TIMEOUT;
        let status = loop {
            if let Err(error) = self.authority.ensure_for_states(&["running"]).await {
                return RuntimeMutationOutcome::resolution_required(
                    "environment_daemon_repair_readiness_ambiguous",
                    Err(if is_authority_lost(&error) {
                        AppError::Conflict("environment state changed during daemon repair".into())
                    } else {
                        AppError::Upstream("environment daemon repair did not converge".into())
                    }),
                );
            }
            match self.daemon_status(&replacement.name).await {
                Ok(status)
                    if matches!(
                        status.state,
                        v1::DaemonState::Ready
                            | v1::DaemonState::Unsupported
                            | v1::DaemonState::UpgradeRequired
                            | v1::DaemonState::Unhealthy
                    ) =>
                {
                    break status;
                }
                Ok(_) | Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(DAEMON_STATUS_RETRY_INTERVAL).await;
                }
                Ok(status) => {
                    break status;
                }
                Err(error) => {
                    return RuntimeMutationOutcome::resolution_required(
                        "environment_daemon_repair_readiness_ambiguous",
                        Err(error),
                    );
                }
            }
        };
        let probe = match self
            .authority
            .run_while_authoritative_for_states(
                &["running"],
                self.sandbox.probe_environment(environment_id),
            )
            .await
        {
            Ok(probe)
                if probe.pod_exists
                    && probe.pod_name == replacement.name
                    && probe.pod_uid == replacement.uid
                    && !probe.pod_ip.is_empty() =>
            {
                probe
            }
            Ok(_) => {
                return RuntimeMutationOutcome::resolution_required(
                    "environment_daemon_repair_backend_ambiguous",
                    Err(AppError::Upstream(
                        "environment daemon repair did not converge".into(),
                    )),
                );
            }
            Err(error) => {
                tracing::warn!(environment_id, %error, "environment daemon repair backend did not converge");
                return RuntimeMutationOutcome::resolution_required(
                    "environment_daemon_repair_backend_ambiguous",
                    Err(if is_authority_lost(&error) {
                        AppError::Conflict("environment state changed during daemon repair".into())
                    } else {
                        AppError::Upstream("environment daemon repair did not converge".into())
                    }),
                );
            }
        };
        let backend_update = self
            .authority
            .execute_for_states(
                &["running"],
                sqlx::query(
                    "UPDATE sandbox_environment_backend SET pod_name = $1, pod_ip = $2 \
                     WHERE environment_id = $3",
                )
                .bind(&probe.pod_name)
                .bind(&probe.pod_ip)
                .bind(environment_id),
            )
            .await;
        if !matches!(backend_update, Ok(ref result) if result.rows_affected() == 1) {
            return RuntimeMutationOutcome::resolution_required(
                "environment_daemon_repair_backend_ambiguous",
                Err(AppError::Upstream(
                    "environment daemon repair did not converge".into(),
                )),
            );
        }
        RuntimeMutationOutcome::release(Ok(EnvironmentDaemonRepair {
            status,
            replaced_pod_name: replacement.name,
        }))
    }

    async fn daemon_status(&self, known_pod_name: &str) -> AppResult<EnvironmentDaemonStatus> {
        let (channel, token) = daemon_channel_for_endpoint(
            &self.pool,
            Some(&self.kube),
            &self.session_secret,
            &self.environment_id,
            self.daemon_endpoints
                .endpoint(&self.namespace, &self.environment_id),
            DaemonRequestBudget::Control,
        )
        .await?;
        query_daemon(channel, token, known_pod_name).await
    }
}

fn daemon_repair_setup_is_idle(setup_complete: bool, setup_owner_status: Option<&str>) -> bool {
    setup_complete && setup_owner_status.is_none()
}

/// `cw env daemon repair` upgrades the daemon: the replacement is built from
/// the Sandbox re-pinned to `support_image`, not from the one it was created
/// with.
async fn delete_workspace_pod_while_setup_idle(
    authority: &ActivityAuthority,
    sandbox: &SandboxClient,
    environment_id: &str,
    pod_name: &str,
    pod_uid: &str,
    support_image: &str,
) -> anyhow::Result<()> {
    let mut guard = authority.begin_external_mutation(&["running"]).await?;
    // Setup lease transitions use this same lock order: environment first,
    // backend second. The fresh check and UID-fenced deletion therefore share
    // one serialization boundary with every setup claim and exec attachment.
    let setup = sqlx::query(
        "SELECT COALESCE(setup_complete, false) AS setup_complete, setup_owner_status \
           FROM sandbox_environment_backend \
          WHERE environment_id = $1 \
          FOR UPDATE",
    )
    .bind(environment_id)
    .fetch_optional(&mut **guard.transaction())
    .await?
    .ok_or_else(|| anyhow::anyhow!("sandbox backend not found"))?;
    let setup_complete: bool = setup.get("setup_complete");
    let setup_owner_status: Option<String> = setup.get("setup_owner_status");
    await_external_mutation(delete_workspace_pod_after_setup_recheck(
        setup_complete,
        setup_owner_status,
        sandbox.replace_workspace_pod_if_uid(environment_id, pod_name, pod_uid, support_image),
    ))
    .await?;
    guard.commit().await
}

async fn delete_workspace_pod_after_setup_recheck<F, T>(
    setup_complete: bool,
    setup_owner_status: Option<String>,
    delete: F,
) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    if !daemon_repair_setup_is_idle(setup_complete, setup_owner_status.as_deref()) {
        return Err(DaemonRepairSetupBusy.into());
    }
    delete.await
}

async fn resolve_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
) -> AppResult<super::proxy::SandboxTarget> {
    if state.kube.is_none() {
        return Err(AppError::ServiceUnavailable(
            "sandbox client not configured".into(),
        ));
    }
    resolve_running_sandbox_target(state, user, org_id, environment_id)
        .await
        .map_err(|(status, message)| huma_error(status, message))
}

async fn daemon_status_for_target(
    state: &ApiState,
    namespace: &str,
    environment_id: &str,
    known_pod_name: &str,
) -> AppResult<EnvironmentDaemonStatus> {
    let (channel, token) = daemon_channel_for_target(state, namespace, environment_id).await?;

    query_daemon(channel, token, known_pod_name).await
}

async fn session_client_for_target(
    state: &ApiState,
    user: &AuthUser,
    org_id: &str,
    environment_id: &str,
    required_capabilities: &[&str],
    budget: DaemonRequestBudget,
) -> AppResult<(
    v1::daemon_service_client::DaemonServiceClient<Channel>,
    String,
)> {
    let target = resolve_target(state, user, org_id, environment_id).await?;
    let (channel, token) = daemon_channel_for_endpoint(
        &state.pool,
        state.kube.as_ref(),
        &state.session_secret,
        &target.environment_id,
        state
            .environment_daemon_endpoints
            .endpoint(&target.namespace, &target.environment_id),
        budget,
    )
    .await?;
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    // Even a launch-budget channel must prove readiness promptly. Do not let
    // this pre-dispatch probe inherit the longer process-start deadline.
    tokio::time::timeout(
        DAEMON_CONTROL_TIMEOUT,
        require_ready_daemon(&mut client, &token, required_capabilities),
    )
    .await
    .map_err(|_| AppError::Upstream("environment daemon is unavailable".into()))??;
    Ok((client, token))
}

async fn get_daemon_session(
    client: &mut v1::daemon_service_client::DaemonServiceClient<Channel>,
    token: &str,
    session_id: &str,
) -> AppResult<v1::SessionRecord> {
    client
        .get_session(authorize(
            v1::GetSessionRequest {
                session_id: session_id.to_string(),
            },
            token,
        )?)
        .await
        .map_err(daemon_session_error)?
        .into_inner()
        .session
        .ok_or_else(|| AppError::InternalMsg("environment daemon returned no session".into()))
}

async fn daemon_channel_for_target(
    state: &ApiState,
    namespace: &str,
    environment_id: &str,
) -> AppResult<(Channel, String)> {
    daemon_channel_for_endpoint(
        &state.pool,
        state.kube.as_ref(),
        &state.session_secret,
        environment_id,
        state
            .environment_daemon_endpoints
            .endpoint(namespace, environment_id),
        DaemonRequestBudget::Control,
    )
    .await
}

async fn daemon_channel_for_runtime(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    namespace: &str,
    environment_id: &str,
) -> AppResult<(Channel, String)> {
    daemon_channel_for_endpoint(
        pool,
        kube,
        session_secret,
        environment_id,
        cluster_daemon_endpoint(namespace, environment_id),
        DaemonRequestBudget::Control,
    )
    .await
}

/// Push the environment's exposed application ports to its bound daemon,
/// which serves exactly these on its tailnet address (#2460). Called after a
/// change commits; best effort: a failed push is logged, and the daemon's
/// next access renewal restates the set.
pub(crate) async fn push_environment_app_ports(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    endpoints: Option<&EnvironmentDaemonEndpointOverrides>,
    environment_id: &str,
) {
    let result: AppResult<Option<usize>> = async {
        let namespace: Option<String> = sqlx::query_scalar(
            "SELECT namespace FROM sandbox_environment_backend WHERE environment_id = $1",
        )
        .bind(environment_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| AppError::InternalMsg("load environment backend".into()))?;
        let Some(namespace) = namespace.filter(|namespace| !namespace.is_empty()) else {
            return Ok(None);
        };
        let ports = crate::workspace_binding::exposed_app_ports(pool, environment_id)
            .await
            .map_err(|_| AppError::InternalMsg("load environment app ports".into()))?;
        let endpoint = match endpoints {
            Some(endpoints) => endpoints.endpoint(&namespace, environment_id),
            None => cluster_daemon_endpoint(&namespace, environment_id),
        };
        let (channel, token) = daemon_channel_for_endpoint(
            pool,
            kube,
            session_secret,
            environment_id,
            endpoint,
            DaemonRequestBudget::Control,
        )
        .await?;
        let count = ports.len();
        send_app_ports(channel, &token, ports).await?;
        Ok(Some(count))
    }
    .await;
    match result {
        Ok(Some(app_port_count)) => {
            tracing::info!(
                environment_id,
                app_port_count,
                "application ports pushed to the environment daemon"
            );
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(
            environment_id,
            error = %error,
            "push application ports to the environment daemon failed; its next access renewal restates them"
        ),
    }
}

async fn send_app_ports(channel: Channel, token: &str, ports: Vec<i32>) -> AppResult<()> {
    v1::daemon_service_client::DaemonServiceClient::new(channel)
        .set_app_ports(authorize(v1::SetAppPortsRequest { ports }, token)?)
        .await
        .map_err(|status| {
            AppError::Upstream(
                format!(
                    "environment daemon refused application ports: {:?}",
                    status.code()
                )
                .into(),
            )
        })?;
    Ok(())
}

pub(crate) fn cluster_daemon_endpoint(namespace: &str, environment_id: &str) -> String {
    format!(
        "http://{}.{}.svc.cluster.local:{}",
        workspace_daemon_service_name(environment_id),
        namespace,
        WORKSPACE_DAEMON_PORT
    )
}

async fn daemon_channel_for_endpoint(
    pool: &PgPool,
    kube: Option<&kube::Client>,
    session_secret: &str,
    environment_id: &str,
    endpoint: String,
    budget: DaemonRequestBudget,
) -> AppResult<(Channel, String)> {
    // The live binding decides the credential (design §7); never a name. An
    // unbound Pod gets the environment token only when it is a legacy Pod.
    let token = environment_daemon_credential(pool, kube, session_secret, environment_id)
        .await
        .map_err(|error| {
            if error.downcast_ref::<DaemonNotBound>().is_some() {
                // Retryable, with the same public message as an unreachable
                // daemon: the Pod is not bound yet, or not a legacy Pod.
                return AppError::Upstream("environment daemon is unavailable".into());
            }
            tracing::error!(environment_id, %error, "issue environment daemon credential failed");
            AppError::InternalMsg("failed to authorize environment daemon".into())
        })?;
    let channel = Endpoint::from_shared(endpoint.clone())
        .map_err(|error| {
            tracing::error!(environment_id, %endpoint, %error, "build daemon endpoint failed");
            AppError::InternalMsg("failed to resolve environment daemon".into())
        })?
        .connect_timeout(DAEMON_CONNECT_TIMEOUT)
        .timeout(budget.timeout())
        .connect()
        .await
        .map_err(|error| {
            tracing::warn!(environment_id, %endpoint, %error, "connect environment daemon failed");
            AppError::Upstream("environment daemon is unavailable".into())
        })?;
    Ok((channel, token))
}

async fn require_ready_daemon(
    client: &mut v1::daemon_service_client::DaemonServiceClient<Channel>,
    token: &str,
    required_capabilities: &[&str],
) -> AppResult<()> {
    let capabilities = client
        .get_capabilities(authorize(
            v1::GetCapabilitiesRequest {
                protocol_version: DAEMON_PROTOCOL_VERSION,
                required_capabilities: required_capabilities
                    .iter()
                    .map(|capability| (*capability).to_string())
                    .collect(),
            },
            token,
        )?)
        .await
        .map_err(daemon_run_error)?
        .into_inner();
    match v1::DaemonState::try_from(capabilities.state).unwrap_or(v1::DaemonState::Unspecified) {
        v1::DaemonState::Ready => Ok(()),
        v1::DaemonState::Starting => Err(AppError::Precondition(
            "environment daemon is still starting".into(),
        )),
        v1::DaemonState::Unsupported | v1::DaemonState::UpgradeRequired => {
            Err(AppError::Precondition(
                "environment daemon upgrade is required; run `cw env daemon repair`".into(),
            ))
        }
        v1::DaemonState::Unhealthy | v1::DaemonState::Unspecified => Err(AppError::Precondition(
            "environment daemon is not ready; run `cw env daemon status`".into(),
        )),
    }
}

async fn query_daemon(
    channel: Channel,
    token: String,
    pod_name: &str,
) -> AppResult<EnvironmentDaemonStatus> {
    let mut client = v1::daemon_service_client::DaemonServiceClient::new(channel);
    let capabilities = client
        .get_capabilities(authorize(
            v1::GetCapabilitiesRequest {
                protocol_version: DAEMON_PROTOCOL_VERSION,
                required_capabilities: vec![
                    DAEMON_CAPABILITY_HEALTH.into(),
                    DAEMON_CAPABILITY_SESSIONS.into(),
                    DAEMON_CAPABILITY_ATTACH.into(),
                    DAEMON_CAPABILITY_FILES.into(),
                ],
            },
            &token,
        )?)
        .await
        .map_err(daemon_status_error)?
        .into_inner();
    let health = client
        .get_health(authorize(v1::GetHealthRequest {}, &token)?)
        .await
        .map_err(daemon_status_error)?
        .into_inner();

    let capability_state =
        v1::DaemonState::try_from(capabilities.state).unwrap_or(v1::DaemonState::Unspecified);
    let health_state =
        v1::DaemonState::try_from(health.state).unwrap_or(v1::DaemonState::Unspecified);
    let state = if capability_state == v1::DaemonState::Ready {
        health_state
    } else {
        capability_state
    };
    let message = if capability_state == v1::DaemonState::Ready {
        health.message
    } else {
        capabilities.message.clone()
    };

    Ok(EnvironmentDaemonStatus {
        state,
        protocol_version: capabilities.protocol_version,
        minimum_protocol_version: capabilities.minimum_protocol_version,
        daemon_version: capabilities.daemon_version,
        capabilities: capabilities.capabilities,
        message,
        diagnostics: health
            .diagnostics
            .into_iter()
            .map(|diagnostic| EnvironmentDaemonDiagnostic {
                name: diagnostic.name,
                healthy: diagnostic.healthy,
                message: diagnostic.message,
            })
            .collect(),
        pod_name: pod_name.to_string(),
    })
}

fn authorize<T>(message: T, token: &str) -> AppResult<Request<T>> {
    let mut request = Request::new(message);
    let token = MetadataValue::try_from(token).map_err(|error| {
        tracing::error!(%error, "encode environment daemon token failed");
        AppError::InternalMsg("failed to authorize environment daemon".into())
    })?;
    request
        .metadata_mut()
        .insert(DAEMON_AUTH_TOKEN_HEADER, token);
    Ok(request)
}

fn daemon_status_error(error: tonic::Status) -> AppError {
    tracing::warn!(code = ?error.code(), message = %error.message(), "environment daemon RPC failed");
    AppError::Upstream("environment daemon is unavailable".into())
}

fn daemon_run_error(error: tonic::Status) -> AppError {
    tracing::warn!(code = ?error.code(), message = %error.message(), "environment daemon command RPC failed");
    match error.code() {
        tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => AppError::Precondition(
            "environment daemon upgrade is required; run `cw env daemon repair`".into(),
        ),
        tonic::Code::InvalidArgument => {
            AppError::InternalMsg("environment daemon rejected the command stream".into())
        }
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
            AppError::Upstream("environment command transport was lost".into())
        }
        _ => AppError::InternalMsg("environment command failed".into()),
    }
}

fn daemon_session_error(error: tonic::Status) -> AppError {
    tracing::warn!(code = ?error.code(), message = %error.message(), "environment daemon session RPC failed");
    match error.code() {
        tonic::Code::NotFound => AppError::NotFound("environment session not found".into()),
        tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => AppError::Precondition(
            "environment daemon upgrade is required; run `cw env daemon repair`".into(),
        ),
        tonic::Code::InvalidArgument => {
            AppError::BadRequest("environment session request is invalid".into())
        }
        tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
            AppError::Upstream("environment session transport was lost".into())
        }
        _ => AppError::InternalMsg("environment session request failed".into()),
    }
}

async fn resolve_pod_name(
    sandbox: &SandboxClient,
    environment_id: &str,
    known_pod_name: &str,
) -> AppResult<String> {
    if !known_pod_name.trim().is_empty() {
        return Ok(known_pod_name.to_string());
    }
    sandbox.get_pod_name(environment_id).await.map_err(|error| {
        tracing::warn!(environment_id, %error, "resolve environment daemon Pod failed");
        AppError::Upstream("environment daemon Pod is unavailable".into())
    })
}

#[cfg(test)]
mod tests {
    use codewire_daemon::service::DaemonRuntimeState;
    use codewire_daemon::{Config, DaemonAuthToken, server};
    use codewire_daemon_proto::DAEMON_CAPABILITY_HEALTH;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration as TokioDuration, timeout};
    use tokio_stream::wrappers::TcpListenerStream;

    use super::*;

    #[test]
    fn launch_deadline_accounts_for_projection_without_relaxing_control_or_connect() {
        assert_eq!(DAEMON_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            DaemonRequestBudget::Control.timeout(),
            Duration::from_secs(5)
        );
        let projection =
            Duration::from_millis(codewire_workload_secrets::MAX_PROJECTION_LIFETIME_MS);
        assert_eq!(projection, Duration::from_secs(30));
        assert!(DaemonRequestBudget::Launch.timeout() >= projection + Duration::from_secs(10));
        assert!(DaemonRequestBudget::Launch.timeout() < Duration::from_secs(60));
    }

    #[test]
    fn daemon_repair_requires_completed_idle_setup() {
        assert!(daemon_repair_setup_is_idle(true, None));
        assert!(!daemon_repair_setup_is_idle(false, None));
        for status in ["claimed", "running", "reaping"] {
            assert!(!daemon_repair_setup_is_idle(true, Some(status)));
        }
    }

    #[tokio::test]
    async fn daemon_repair_busy_recheck_skips_pod_deletion() {
        let delete_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&delete_called);
        let result =
            delete_workspace_pod_after_setup_recheck(true, Some("running".into()), async move {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await;

        assert!(
            result
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<DaemonRepairSetupBusy>())
                .is_some()
        );
        assert!(!delete_called.load(std::sync::atomic::Ordering::SeqCst));
    }

    const TEST_DAEMON_TOKEN: &str = "daemon-proxy-test-token";

    #[test]
    fn external_wire_endpoint_overrides_are_testing_only_and_loopback_bound() {
        assert!(
            EnvironmentDaemonEndpointOverrides::from_testing_config(
                false,
                Some(r#"{"env":"http://127.0.0.1:7777"}"#),
            )
            .is_err()
        );
        for invalid in [
            "{}",
            r#"{"env":"https://127.0.0.1:7777"}"#,
            r#"{"env":"http://example.test:7777"}"#,
            r#"{"env":"http://127.0.0.1:0"}"#,
            r#"{"env":"http://127.0.0.1:7777/path"}"#,
            r#"{"env":"http://127.0.0.1:7777?query"}"#,
            r#"{"env":"http://127.0.0.1:7777#fragment"}"#,
            r#"{"env":"http://user@127.0.0.1:7777"}"#,
            r#"{"env":"http://user:password@127.0.0.1:7777"}"#,
            r#"{"env":"http://127.0.0.1:7777 "}"#,
            r#"{"../env":"http://127.0.0.1:7777"}"#,
        ] {
            assert!(
                EnvironmentDaemonEndpointOverrides::from_testing_config(true, Some(invalid))
                    .is_err(),
                "accepted invalid endpoint configuration: {invalid}"
            );
        }

        let overrides = EnvironmentDaemonEndpointOverrides::from_testing_config(
            true,
            Some(r#"{"env_wire":"http://127.0.0.1:7777"}"#),
        )
        .expect("valid external wire endpoint");
        assert_eq!(
            overrides.endpoint("wire", "env_wire"),
            "http://127.0.0.1:7777"
        );
        assert_eq!(
            overrides.endpoint("wire", "env_other"),
            "http://cw-daemon-env-other.wire.svc.cluster.local:7777"
        );
    }

    struct DaemonHarness {
        channel: Channel,
        shutdown: Option<oneshot::Sender<()>>,
        task: JoinHandle<()>,
        _temp: TempDir,
    }

    impl DaemonHarness {
        async fn spawn(runtime_state: DaemonRuntimeState) -> Self {
            let temp = tempfile::tempdir().expect("daemon proxy tempdir");
            let workspace_root = temp.path().join("workspace");
            let home_root = temp.path().join("home");
            std::fs::create_dir_all(&workspace_root).expect("workspace root");
            std::fs::create_dir_all(&home_root).expect("home root");
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("daemon proxy listener");
            let address = listener.local_addr().expect("daemon proxy address");
            let config = Config {
                listen_addr: address.to_string(),
                workspace_root,
                home_root,
                auth_token: DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
                process_execution: codewire_daemon::execution::ProcessExecution::Native,
                credential_bridge: None,
                managed_credential_clients: Default::default(),
                host: None,
                launch_projection: None,
                session_working_dir: None,
            };
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                server::serve_grpc_with_incoming_and_runtime_state(
                    config,
                    runtime_state,
                    TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
                .expect("serve daemon proxy harness");
            });
            let channel = Endpoint::from_shared(format!("http://{address}"))
                .expect("daemon proxy endpoint")
                .connect()
                .await
                .expect("connect daemon proxy harness");
            Self {
                channel,
                shutdown: Some(shutdown_tx),
                task,
                _temp: temp,
            }
        }

        async fn shutdown(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.await.expect("join daemon proxy harness");
        }
    }

    /// A daemon serving `SetAppPorts` into `app_ports` when given one.
    async fn app_ports_daemon(
        app_ports: Option<codewire_daemon::app_ports::AppPortsSender>,
    ) -> (Channel, TempDir) {
        let temp = tempfile::tempdir().expect("app ports daemon tempdir");
        let config = Config {
            listen_addr: "unused:0".into(),
            workspace_root: temp.path().to_path_buf(),
            home_root: temp.path().to_path_buf(),
            auth_token: DaemonAuthToken::new(TEST_DAEMON_TOKEN).unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            host: None,
            launch_projection: None,
            session_working_dir: None,
        };
        let mut daemon = codewire_daemon::service::DaemonServiceImpl::new(config);
        if let Some(app_ports) = app_ports {
            daemon = daemon.with_app_ports(app_ports);
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(v1::daemon_service_server::DaemonServiceServer::new(daemon))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let channel = Endpoint::from_shared(format!("http://{address}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        (channel, temp)
    }

    #[tokio::test]
    async fn pushed_app_ports_replace_the_bound_daemons_set() {
        let (app_ports, served) =
            tokio::sync::watch::channel(codewire_daemon::app_ports::AppPorts::from([8080]));
        let (channel, _temp) = app_ports_daemon(Some(app_ports)).await;
        // After an expose: the full set, including the new port.
        send_app_ports(channel.clone(), TEST_DAEMON_TOKEN, vec![3000, 8080])
            .await
            .unwrap();
        assert_eq!(
            *served.borrow(),
            codewire_daemon::app_ports::AppPorts::from([3000, 8080])
        );
        // After an unexpose: the set without it.
        send_app_ports(channel.clone(), TEST_DAEMON_TOKEN, vec![8080])
            .await
            .unwrap();
        assert_eq!(
            *served.borrow(),
            codewire_daemon::app_ports::AppPorts::from([8080])
        );
        // Only with the daemon credential.
        assert!(
            send_app_ports(channel, "wrong-daemon-token", vec![])
                .await
                .is_err()
        );
        assert_eq!(served.borrow().len(), 1);

        // A daemon that serves no tailnet refuses, and the caller only logs.
        let (legacy, _legacy_temp) = app_ports_daemon(None).await;
        assert!(
            send_app_ports(legacy, TEST_DAEMON_TOKEN, vec![3000])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_proxy_preserves_health_without_exposing_credential() {
        let harness = DaemonHarness::spawn(DaemonRuntimeState::ready()).await;
        let status = query_daemon(
            harness.channel.clone(),
            TEST_DAEMON_TOKEN.into(),
            "workspace-pod",
        )
        .await
        .expect("authenticated daemon status");

        assert_eq!(status.state, v1::DaemonState::Ready);
        assert_eq!(status.protocol_version, DAEMON_PROTOCOL_VERSION);
        assert_eq!(status.pod_name, "workspace-pod");
        assert!(
            status
                .capabilities
                .iter()
                .any(|capability| capability == DAEMON_CAPABILITY_HEALTH)
        );
        assert!(!format!("{status:?}").contains(TEST_DAEMON_TOKEN));

        let error = query_daemon(
            harness.channel.clone(),
            "wrong-daemon-token".into(),
            "workspace-pod",
        )
        .await
        .expect_err("invalid daemon credential must fail closed");
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(TEST_DAEMON_TOKEN));
        assert!(!rendered.contains("wrong-daemon-token"));
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn authenticated_proxy_preserves_unhealthy_diagnostics() {
        let runtime_state = DaemonRuntimeState::new(
            v1::DaemonState::Unhealthy,
            "workspace filesystem is unavailable",
            vec![v1::HealthDiagnostic {
                name: "workspace".into(),
                healthy: false,
                message: "workspace filesystem is unavailable".into(),
            }],
        );
        let harness = DaemonHarness::spawn(runtime_state).await;
        let status = query_daemon(
            harness.channel.clone(),
            TEST_DAEMON_TOKEN.into(),
            "workspace-pod",
        )
        .await
        .expect("unhealthy status remains a typed response");

        assert_eq!(status.state, v1::DaemonState::Unhealthy);
        assert_eq!(status.message, "workspace filesystem is unavailable");
        assert_eq!(
            status.diagnostics,
            vec![EnvironmentDaemonDiagnostic {
                name: "workspace".into(),
                healthy: false,
                message: "workspace filesystem is unavailable".into(),
            }]
        );
        harness.shutdown().await;
    }

    #[tokio::test]
    async fn authenticated_durable_session_proxy_preserves_resume_and_detach() {
        let harness = DaemonHarness::spawn(DaemonRuntimeState::ready()).await;
        let mut client =
            v1::daemon_service_client::DaemonServiceClient::new(harness.channel.clone());
        require_ready_daemon(
            &mut client,
            TEST_DAEMON_TOKEN,
            &[DAEMON_CAPABILITY_SESSIONS, DAEMON_CAPABILITY_ATTACH],
        )
        .await
        .expect("durable-session capabilities");
        let launched = client
            .launch_session(
                authorize(
                    v1::LaunchSessionRequest {
                        name: String::new(),
                        parent_session_id: None,
                        command: vec![
                            "/bin/sh".into(),
                            "-c".into(),
                            "read line; printf 'durable:%s' \"$line\"; while :; do sleep 1; done"
                                .into(),
                        ],
                        working_dir: String::new(),
                        env: Vec::new(),
                        pty: false,
                        term: String::new(),
                        width: 0,
                        height: 0,
                    },
                    TEST_DAEMON_TOKEN,
                )
                .expect("authorize durable launch"),
            )
            .await
            .expect("launch durable session")
            .into_inner()
            .session
            .expect("durable launch record");
        let session_id = launched.session_id;

        let (input, rx) = mpsc::channel(32);
        input
            .send(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Attach(
                    v1::AttachSessionRequest {
                        session_id: session_id.clone(),
                        output_offset: 0,
                    },
                )),
            })
            .await
            .expect("queue attach frame");
        let output = client
            .attach_session(
                authorize(ReceiverStream::new(rx), TEST_DAEMON_TOKEN)
                    .expect("authorize durable attach"),
            )
            .await
            .expect("attach durable session")
            .into_inner();
        let mut attachment = EnvironmentDaemonSessionAttachment {
            input,
            output,
            client: client.clone(),
            token: TEST_DAEMON_TOKEN.into(),
        };

        let initial = timeout(TokioDuration::from_secs(5), attachment.next_output())
            .await
            .expect("durable attach initial status deadline")
            .expect("durable attach initial status")
            .expect("durable attach initial frame");
        assert!(matches!(
            initial.payload,
            Some(v1::session_attach_message::Payload::Status(_))
        ));

        attachment
            .send_input(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Input(
                    v1::SessionInput {
                        data: b"hello\n".to_vec(),
                    },
                )),
            })
            .await
            .expect("send durable stdin");
        let mut output_data = Vec::new();
        while !String::from_utf8_lossy(&output_data).contains("durable:hello") {
            let frame = timeout(TokioDuration::from_secs(5), attachment.next_output())
                .await
                .expect("durable attach output deadline")
                .expect("durable attach output")
                .expect("durable attach frame");
            if let Some(v1::session_attach_message::Payload::Output(chunk)) = frame.payload {
                output_data.extend(chunk.data);
            }
        }

        let resumed = attachment
            .session(&session_id)
            .await
            .expect("read authoritative durable record");
        assert!(resumed.output_end_offset >= output_data.len() as u64);

        attachment
            .send_input(v1::SessionAttachMessage {
                payload: Some(v1::session_attach_message::Payload::Detach(
                    v1::DetachSessionRequest {
                        session_id: session_id.clone(),
                    },
                )),
            })
            .await
            .expect("detach durable session");
        let detached = timeout(TokioDuration::from_secs(5), attachment.next_output())
            .await
            .expect("durable detach status deadline")
            .expect("durable detach status")
            .expect("durable detach frame");
        assert!(matches!(
            detached.payload,
            Some(v1::session_attach_message::Payload::Status(_))
        ));

        client
            .stop_session(
                authorize(v1::StopSessionRequest { session_id }, TEST_DAEMON_TOKEN)
                    .expect("authorize durable stop"),
            )
            .await
            .expect("stop detached durable session");
        drop(attachment);
        drop(client);
        harness.shutdown().await;
    }
}
