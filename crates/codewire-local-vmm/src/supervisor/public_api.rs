//! Owner-only public Codewire service adapters for the native supervisor.
//!
//! The Unix peer UID is authorization. Public organization and environment
//! UUIDs are stable coordinates only; this module deliberately imports no
//! platform login, bearer-token, organization-membership, or TCP semantics.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::Request as AxumRequest;
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response as AxumResponse};
use buffa_types::{Duration as ProtoDuration, Timestamp};
use codewire_daemon::client::{
    DAEMON_MINIMUM_PROTOCOL_VERSION, DAEMON_PROTOCOL_VERSION,
    SessionAttachment as PrivateSessionAttachment, SessionClient, SessionClientError,
    v1 as daemon_v1,
};
use codewire_daemon_bridge::client::{DaemonClient, DaemonClientError};
use codewire_daemon_bridge::exec::ExecBackend;
use codewire_daemon_bridge::file::FileBackend;
use codewire_daemon_bridge::session::{
    EnvironmentSessionAttachment as BridgeAttachment, EnvironmentSessionBackend, FieldViolation,
};
use codewire_proto::codewire::v1 as proto;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult, ServiceStream};
use http::{HeaderValue, Method, StatusCode as HttpStatus, header};
use tonic::Request as TonicRequest;

use super::*;

const PRIVATE_SUPERVISOR_ROUTE: &str = "/codewire.local.v1.LocalSupervisorService/{*method}";
const PUBLIC_ENVIRONMENT_ROUTE: &str = "/codewire.v1.EnvironmentService/{*method}";
const PUBLIC_SESSION_ROUTE: &str = "/codewire.v1.EnvironmentSessionService/{*method}";
const PUBLIC_EXEC_ROUTE: &str = "/codewire.v1.ExecService/{*method}";
const PUBLIC_FILE_ROUTE: &str = "/codewire.v1.FileService/{*method}";
const ACCEPT_POST: &str =
    "application/connect+json, application/connect+proto, application/json, application/proto";
const GIB: u64 = 1024 * 1024 * 1024;
const DAEMON_REPAIR_TIMEOUT: Duration = Duration::from_secs(180);
const MAXIMUM_DAEMON_LOG_BYTES: usize = 64 * 1024;
const REQUIRED_LOCAL_DAEMON_CAPABILITIES: &[&str] = &[
    "attach.v1",
    "credential_bridge.v1",
    "exec.v1",
    "files.v1",
    "health.v1",
    "pty.v1",
    "session_input.v1",
    "session_metadata.v1",
    "sessions.v1",
];

pub(super) fn supervisor_router(supervisor: SupervisorRpc) -> axum::Router {
    let environment = connectrpc::ConnectRpcService::new(environment_router(supervisor.clone()));
    let environment = axum::Router::new()
        .route_service(PUBLIC_ENVIRONMENT_ROUTE, environment)
        .layer(axum::middleware::from_fn(enforce_connect_only));
    let sessions = connectrpc::ConnectRpcService::new(codewire_daemon_bridge::session::router(
        LocalSessionBackend {
            supervisor: supervisor.clone(),
        },
    ));
    let sessions = axum::Router::new()
        .route_service(PUBLIC_SESSION_ROUTE, sessions)
        .layer(axum::middleware::from_fn(enforce_connect_only));
    let exec = connectrpc::ConnectRpcService::new(codewire_daemon_bridge::exec::router(
        LocalExecBackend {
            supervisor: supervisor.clone(),
        },
    ));
    let exec = axum::Router::new()
        .route_service(PUBLIC_EXEC_ROUTE, exec)
        .layer(axum::middleware::from_fn(enforce_connect_only));
    let files = connectrpc::ConnectRpcService::new(codewire_daemon_bridge::file::router(
        LocalFileBackend {
            supervisor: supervisor.clone(),
        },
    ));
    let files = axum::Router::new()
        .route_service(PUBLIC_FILE_ROUTE, files)
        .layer(axum::middleware::from_fn(enforce_connect_only));

    let router = axum::Router::new();
    let router = router.route_service(
        "/codewire.local.v1.LinuxCwRuntimeService/{*method}",
        v1::linux_cw_runtime_service_server::LinuxCwRuntimeServiceServer::new(supervisor.clone()),
    );
    router
        .route_service(
            PRIVATE_SUPERVISOR_ROUTE,
            LocalSupervisorServiceServer::new(supervisor),
        )
        .merge(environment)
        .merge(sessions)
        .merge(exec)
        .merge(files)
}

fn environment_router(supervisor: SupervisorRpc) -> connectrpc::Router {
    let router = connectrpc::Router::new().add_service(Arc::new(supervisor));
    debug_assert_eq!(
        router.methods().collect::<BTreeSet<_>>(),
        ENVIRONMENT_RPC_SEMANTICS
            .iter()
            .map(|entry| entry.spec.procedure.trim_start_matches('/'))
            .collect::<BTreeSet<_>>()
    );
    debug_assert!(
        ENVIRONMENT_RPC_SEMANTICS
            .iter()
            .any(|entry| entry.behavior == RpcBehavior::Local)
    );
    debug_assert!(PUBLIC_MESSAGE_SEMANTICS.iter().all(|message| {
        !message.full_name.is_empty()
            && message.fields.iter().all(|field| {
                field.number > 0
                    && !field.name.is_empty()
                    && matches!(
                        field.behavior,
                        FieldBehavior::Local
                            | FieldBehavior::FixedLocal
                            | FieldBehavior::ZeroOrAbsent
                            | FieldBehavior::RejectedWhenSet
                    )
            })
    }));
    router
}

async fn enforce_connect_only(request: AxumRequest, next: Next) -> AxumResponse {
    let admitted = match *request.method() {
        Method::GET => true,
        Method::POST => {
            let mut values = request.headers().get_all(header::CONTENT_TYPE).iter();
            let first = values.next();
            values.next().is_none() && first.is_some_and(connect_content_type)
        }
        _ => false,
    };
    if admitted {
        return next.run(request).await;
    }
    let mut response = HttpStatus::UNSUPPORTED_MEDIA_TYPE.into_response();
    response.headers_mut().insert(
        http::HeaderName::from_static("accept-post"),
        HeaderValue::from_static(ACCEPT_POST),
    );
    response
}

fn connect_content_type(value: &HeaderValue) -> bool {
    let Ok(value) = value.to_str() else {
        return false;
    };
    let essence = value.split(';').next().unwrap_or_default().trim();
    [
        "application/connect+json",
        "application/connect+proto",
        "application/json",
        "application/proto",
    ]
    .iter()
    .any(|allowed| essence.eq_ignore_ascii_case(allowed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RpcBehavior {
    Local,
    UnimplementedPlatformOnly,
}

#[derive(Debug, Clone, Copy)]
struct RpcSemantics {
    spec: connectrpc::Spec,
    behavior: RpcBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldBehavior {
    /// Read, validated, or populated from durable local runtime state.
    Local,
    /// Populated with a documented local-runtime discriminator or status.
    FixedLocal,
    /// Intentionally encoded as protobuf zero/absent until its owning slice.
    ZeroOrAbsent,
    /// The method is local, but setting this platform-shaped field is rejected.
    RejectedWhenSet,
}

#[derive(Debug, Clone, Copy)]
struct FieldSemantics {
    number: i32,
    name: &'static str,
    behavior: FieldBehavior,
}

#[derive(Debug, Clone, Copy)]
struct MessageSemantics {
    full_name: &'static str,
    fields: &'static [FieldSemantics],
}

const fn field(number: i32, name: &'static str, behavior: FieldBehavior) -> FieldSemantics {
    FieldSemantics {
        number,
        name,
        behavior,
    }
}

const LOCAL: FieldBehavior = FieldBehavior::Local;
const FIXED: FieldBehavior = FieldBehavior::FixedLocal;
const ZERO: FieldBehavior = FieldBehavior::ZeroOrAbsent;
const REJECTED: FieldBehavior = FieldBehavior::RejectedWhenSet;

const ENVIRONMENT_FIELDS: &[FieldSemantics] = &[
    field(1, "id", LOCAL),
    field(2, "org_id", LOCAL),
    field(3, "created_by", ZERO),
    field(4, "preset_id", ZERO),
    field(5, "type", FIXED),
    field(6, "name", LOCAL),
    field(7, "state", LOCAL),
    field(8, "desired_state", LOCAL),
    field(9, "error_reason", LOCAL),
    field(10, "recoverable", ZERO),
    field(11, "state_changed_at", ZERO),
    field(12, "retry_count", ZERO),
    field(13, "setup_phase", ZERO),
    field(14, "setup_complete", LOCAL),
    field(15, "setup_error", ZERO),
    field(16, "ttl_seconds", ZERO),
    field(17, "shutdown_at", ZERO),
    field(18, "cpu_millicores", LOCAL),
    field(19, "memory_mb", LOCAL),
    field(20, "disk_gb", LOCAL),
    field(21, "total_running_seconds", ZERO),
    field(22, "created_at", ZERO),
    field(23, "started_at", ZERO),
    field(24, "stopped_at", ZERO),
    field(25, "destroyed_at", ZERO),
    field(26, "protected", ZERO),
    field(27, "deletion_requested_at", ZERO),
    field(28, "deletion_grace_until", ZERO),
    field(29, "preset_name", ZERO),
    field(30, "network", ZERO),
    field(31, "ports", ZERO),
    field(32, "isolation_tier", FIXED),
    field(33, "operation_generation", LOCAL),
    field(34, "source_selection", LOCAL),
];

const PUBLIC_MESSAGE_SEMANTICS: &[MessageSemantics] = &[
    MessageSemantics {
        full_name: "codewire.v1.ProjectSecretBindings",
        fields: &[
            field(1, "project", LOCAL),
            field(4, "organization", LOCAL),
            field(6, "user", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.ProjectCredentialBinding",
        fields: &[field(1, "profile", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentSourceSelection",
        fields: &[
            field(1, "secrets", LOCAL),
            field(2, "credentials", LOCAL),
            field(3, "profile_revision", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.UpdateEnvironmentSourcesRequest",
        fields: &[
            field(1, "org_id", LOCAL),
            field(2, "environment_id", LOCAL),
            field(3, "expected_operation_generation", LOCAL),
            field(4, "expected", LOCAL),
            field(5, "replacement", LOCAL),
            field(6, "allow_restart", LOCAL),
            field(7, "confirm_personal_credentials", LOCAL),
            field(8, "confirm_personal_secrets", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.UpdateEnvironmentSourcesResponse",
        fields: &[
            field(1, "environment_id", LOCAL),
            field(2, "operation_generation", LOCAL),
            field(3, "selection", LOCAL),
            field(4, "outcome", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.Environment",
        fields: ENVIRONMENT_FIELDS,
    },
    MessageSemantics {
        full_name: "codewire.v1.ListEnvironmentsRequest",
        fields: &[
            field(1, "org_id", LOCAL),
            field(2, "type", LOCAL),
            field(3, "state", LOCAL),
            field(4, "include_destroyed", ZERO),
            field(5, "page_size", REJECTED),
            field(6, "page_token", REJECTED),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.ListEnvironmentsResponse",
        fields: &[
            field(1, "environments", LOCAL),
            field(2, "next_page_token", ZERO),
            field(3, "poll_interval", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentResponse",
        fields: &[
            field(1, "environment", LOCAL),
            field(2, "poll_interval", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.PlanEnvironmentResizeRequest",
        fields: &[
            field(1, "org_id", LOCAL),
            field(2, "environment_id", LOCAL),
            field(3, "cpu_millicores", LOCAL),
            field(4, "memory_mb", LOCAL),
            field(5, "disk_gb", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.PlanEnvironmentResizeResponse",
        fields: &[field(1, "plan", LOCAL), field(2, "environment", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.ResizeEnvironmentRequest",
        fields: &[
            field(1, "org_id", LOCAL),
            field(2, "environment_id", LOCAL),
            field(3, "cpu_millicores", LOCAL),
            field(4, "memory_mb", LOCAL),
            field(5, "disk_gb", LOCAL),
            field(6, "request_id", LOCAL),
            field(7, "force", REJECTED),
            field(8, "disruption_policy", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.ResizeEnvironmentResponse",
        fields: &[
            field(1, "operation", LOCAL),
            field(2, "environment", LOCAL),
            field(3, "poll_interval", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentResizeOperationRequest",
        fields: &[
            field(1, "org_id", LOCAL),
            field(2, "environment_id", LOCAL),
            field(3, "operation_id", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentResizeOperationResponse",
        fields: &[
            field(1, "operation", LOCAL),
            field(2, "environment", LOCAL),
            field(3, "poll_interval", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.DeleteEnvironmentRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.DeleteEnvironmentResponse",
        fields: &[],
    },
    MessageSemantics {
        full_name: "codewire.v1.StopEnvironmentRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.StopEnvironmentResponse",
        fields: &[field(1, "status", FIXED)],
    },
    MessageSemantics {
        full_name: "codewire.v1.StartEnvironmentRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.StartEnvironmentResponse",
        fields: &[field(1, "status", FIXED), field(2, "outcome", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentDaemonDiagnostic",
        fields: &[
            field(1, "name", FIXED),
            field(2, "healthy", LOCAL),
            field(3, "message", FIXED),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentDaemonStatus",
        fields: &[
            field(1, "state", LOCAL),
            field(2, "protocol_version", LOCAL),
            field(3, "minimum_protocol_version", LOCAL),
            field(4, "daemon_version", FIXED),
            field(5, "capabilities", LOCAL),
            field(6, "message", FIXED),
            field(7, "diagnostics", LOCAL),
            field(8, "pod_name", ZERO),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentHostKeyRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    // One host key for every boot of a local environment (#3025).
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentHostKeyResponse",
        fields: &[
            field(1, "generation", FIXED),
            field(2, "public_key_openssh", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentDaemonStatusRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.GetEnvironmentDaemonStatusResponse",
        fields: &[field(1, "status", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.StreamEnvironmentDaemonLogsRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.StreamEnvironmentDaemonLogsResponse",
        fields: &[field(1, "data", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.RepairEnvironmentDaemonRequest",
        fields: &[field(1, "org_id", LOCAL), field(2, "environment_id", LOCAL)],
    },
    MessageSemantics {
        full_name: "codewire.v1.RepairEnvironmentDaemonResponse",
        fields: &[
            field(1, "status", LOCAL),
            field(2, "replaced_pod_name", ZERO),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentResources",
        fields: &[
            field(1, "cpu_millicores", LOCAL),
            field(2, "memory_mb", LOCAL),
            field(3, "disk_gb", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentResizePlan",
        fields: &[
            field(1, "previous_resources", LOCAL),
            field(2, "desired_resources", LOCAL),
            field(3, "execution_mode", LOCAL),
            field(4, "active_session_count", ZERO),
            field(5, "active_sessions_will_be_terminated", ZERO),
            field(6, "reason", LOCAL),
            field(7, "warnings", LOCAL),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentResizeOperation",
        fields: &[
            field(1, "id", LOCAL),
            field(2, "environment_id", LOCAL),
            field(3, "request_id", LOCAL),
            field(4, "previous_resources", LOCAL),
            field(5, "desired_resources", LOCAL),
            field(6, "last_applied_resources", LOCAL),
            field(7, "state", LOCAL),
            field(8, "failure", LOCAL),
            field(9, "created_at", LOCAL),
            field(10, "updated_at", LOCAL),
            field(11, "completed_at", LOCAL),
            field(12, "disruption_policy", LOCAL),
            field(13, "planned_mode", LOCAL),
            field(14, "applied_mode", LOCAL),
            field(15, "pod_replaced", ZERO),
        ],
    },
    MessageSemantics {
        full_name: "codewire.v1.EnvironmentResizeFailure",
        fields: &[field(1, "code", LOCAL), field(2, "message", FIXED)],
    },
];

const ENVIRONMENT_RPC_SEMANTICS: &[RpcSemantics] = &[
    rpc(
        proto::ENVIRONMENT_SERVICE_UPDATE_ENVIRONMENT_SOURCES_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_LIST_ENVIRONMENTS_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_CREATE_ENVIRONMENT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_PLAN_ENVIRONMENT_RESIZE_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_RESIZE_ENVIRONMENT_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_RESIZE_OPERATION_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_DELETE_ENVIRONMENT_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_STOP_ENVIRONMENT_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_START_ENVIRONMENT_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_PROTECT_ENVIRONMENT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_UNPROTECT_ENVIRONMENT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_CANCEL_ENVIRONMENT_DELETION_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_EXTEND_ENVIRONMENT_TTL_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_TRUST_REPORT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_HOST_KEY_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_DAEMON_STATUS_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_STREAM_ENVIRONMENT_DAEMON_LOGS_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_REPAIR_ENVIRONMENT_DAEMON_SPEC,
        RpcBehavior::Local,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_LIST_ENVIRONMENT_ACCESS_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GRANT_ENVIRONMENT_ACCESS_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_REVOKE_ENVIRONMENT_ACCESS_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_WATCH_ENVIRONMENT_CREATE_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_STREAM_LOGS_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
];

const fn rpc(spec: connectrpc::Spec, behavior: RpcBehavior) -> RpcSemantics {
    RpcSemantics { spec, behavior }
}

impl SupervisorRpc {
    async fn public_namespace_id(&self) -> Result<Uuid, connectrpc::ConnectError> {
        self.supervisor
            .core()
            .store
            .namespace_id()
            .map_err(|_| local_internal())
    }

    async fn public_environments(&self) -> Result<Vec<v1::Environment>, connectrpc::ConnectError> {
        LocalSupervisorService::list_environments(
            self,
            TonicRequest::new(v1::ListEnvironmentsRequest {}),
        )
        .await
        .map(tonic::Response::into_inner)
        .map(|response| response.environments)
        .map_err(local_status)
    }

    async fn public_environment(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<(Uuid, v1::Environment), connectrpc::ConnectError> {
        let namespace = self.public_namespace_id().await?;
        require_namespace(namespace, org_id, false)?;
        let environment_id = parse_coordinate(environment_id, "environment_id")?;
        let environment = self
            .public_environments()
            .await?
            .into_iter()
            .find(|environment| {
                Uuid::parse_str(&environment.id)
                    .ok()
                    .is_some_and(|id| id == environment_id)
            })
            .ok_or_else(|| {
                connectrpc::ConnectError::not_found("local environment was not found")
            })?;
        Ok((namespace, environment))
    }

    async fn public_daemon_access(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<v1::DaemonAccess, connectrpc::ConnectError> {
        let environment_id = parse_coordinate(environment_id, "environment_id")?;
        let namespace = self.public_namespace_id().await?;
        require_namespace(namespace, org_id, false)?;
        self.environment_daemon_access(environment_id)
            .await
            .map_err(local_status)
    }

    /// Daemon access for one environment, named by its UUID, after any
    /// pending operation runs; its credential broker is started alongside.
    pub(super) async fn environment_daemon_access(
        &self,
        environment_id: Uuid,
    ) -> Result<v1::DaemonAccess, Status> {
        let (access, broker_request) = {
            let name = self
                .supervisor
                .core()
                .state
                .environments
                .values()
                .find(|environment| environment.id == environment_id)
                .map(|environment| environment.name.clone())
                .ok_or_else(|| Status::not_found("local environment was not found"))?;
            // It waits for this environment's own operations only (#2978).
            let _lease = self
                .supervisor
                .quiet_lease(&name)
                .await
                .map_err(Status::from)?;
            if self.supervisor.environment(&name).map_err(Status::from)?.id != environment_id {
                return Err(Status::not_found("local environment was not found"));
            }
            let access = self
                .supervisor
                .daemon_access(&name)
                .await
                .map_err(Status::from)?;
            let broker_request = self
                .supervisor
                .core()
                .credential_broker_ensure_request(&name)
                .map_err(Status::from)?;
            (access, broker_request)
        };
        // Credential brokerage is auxiliary to daemon/session transport.
        // Start its authority-owned retry lifecycle, but never make an offline
        // shell depend on remote provider DNS or inference availability. A
        // failure is still recorded, by its closed cause, so a VM that has no
        // credentials says why (an unreachable authority, for one).
        let log = self.supervisor.log.clone();
        drop(tokio::spawn(async move {
            if let Err(error) = ensure_credential_broker(broker_request).await {
                diagnostic_log::record(
                    log.as_deref(),
                    "credential_broker_failed",
                    &[
                        ("environment", LogField::Id(environment_id)),
                        ("cause", LogField::Name(lifecycle_failure_cause(&error))),
                    ],
                );
            }
        }));
        if access.generation_capability.is_empty() {
            return Err(Status::internal("local supervisor request failed"));
        }
        Ok(access)
    }

    async fn public_daemon_probe_client(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<SessionClient, connectrpc::ConnectError> {
        let access = self.public_daemon_access(org_id, environment_id).await?;
        let capability = zeroize::Zeroizing::new(access.generation_capability);
        let client = crate::hybrid_vsock::connect_daemon(
            std::path::Path::new(&access.hybrid_socket),
            access.guest_port,
            capability.as_str(),
        )
        .await
        .map_err(|_| {
            connectrpc::ConnectError::unavailable("local environment daemon is unavailable")
        })?;
        Ok(client)
    }

    async fn public_daemon_client(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<SessionClient, connectrpc::ConnectError> {
        let client = self
            .public_daemon_probe_client(org_id, environment_id)
            .await?;
        client.require_ready().await.map_err(local_session_error)?;
        Ok(client)
    }

    async fn public_bridge_daemon_client(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        let access = self.public_daemon_access(org_id, environment_id).await?;
        let capability = zeroize::Zeroizing::new(access.generation_capability);
        let target = crate::hybrid_vsock::HybridVsockTarget::new(
            std::path::PathBuf::from(access.hybrid_socket),
            access.guest_port,
        )
        .map_err(|_| {
            connectrpc::ConnectError::unavailable("local environment daemon is unavailable")
        })?;
        let channel = target.connect_channel().await.map_err(|_| {
            connectrpc::ConnectError::unavailable("local environment daemon is unavailable")
        })?;
        DaemonClient::from_channel(channel, capability.as_str()).map_err(|_| local_internal())
    }

    async fn public_daemon_status(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<proto::EnvironmentDaemonStatus, connectrpc::ConnectError> {
        let (_, environment) = self.public_environment(org_id, environment_id).await?;
        match private_environment_state(environment.state)? {
            v1::EnvironmentState::Stopped => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Starting,
                    "local environment is stopped",
                ));
            }
            v1::EnvironmentState::Starting => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Starting,
                    "local environment daemon is starting",
                ));
            }
            v1::EnvironmentState::Error | v1::EnvironmentState::Orphaned => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Unhealthy,
                    "local environment runtime requires repair",
                ));
            }
            v1::EnvironmentState::Running => {}
            v1::EnvironmentState::Unspecified => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Unhealthy,
                    "local environment runtime state is unavailable",
                ));
            }
        }

        let client = match self
            .public_daemon_probe_client(org_id, environment_id)
            .await
        {
            Ok(client) => client,
            Err(_) => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Unhealthy,
                    "local environment daemon is unavailable",
                ));
            }
        };
        let capabilities = match client
            .get_capabilities(REQUIRED_LOCAL_DAEMON_CAPABILITIES)
            .await
        {
            Ok(capabilities) => capabilities,
            Err(_) => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Unhealthy,
                    "local environment daemon probe failed",
                ));
            }
        };
        let health = match client.get_health().await {
            Ok(health) => health,
            Err(_) => {
                return Ok(fixed_daemon_status(
                    proto::EnvironmentDaemonState::Unhealthy,
                    "local environment daemon health probe failed",
                ));
            }
        };
        Ok(project_daemon_status(&capabilities, &health))
    }

    async fn public_daemon_logs(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<u8>, connectrpc::ConnectError> {
        let (_, environment) = self.public_environment(org_id, environment_id).await?;
        let environment_id = parse_coordinate(&environment.id, "environment_id")?;
        let operations = self
            .operation_reader
            .lock()
            .await
            .recent_environment_operations(environment_id)
            .map_err(|_| local_internal())?;
        trusted_daemon_logs(&operations)
    }

    async fn wait_for_terminal_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<(), connectrpc::ConnectError> {
        let mut events = self.operation_events.subscribe();
        let deadline = tokio::time::Instant::now() + DAEMON_REPAIR_TIMEOUT;
        let mut operation = self.operation(operation_id).await.map_err(local_status)?;
        loop {
            match operation.phase {
                OperationPhase::Completed => return Ok(()),
                OperationPhase::Failed | OperationPhase::Interrupted => {
                    return Err(connectrpc::ConnectError::unavailable(
                        "local environment daemon repair did not converge",
                    ));
                }
                OperationPhase::Intent | OperationPhase::EffectApplied => {}
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(next)) if next.operation_id == operation_id => operation = next,
                Ok(Ok(_)) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                    operation = self.operation(operation_id).await.map_err(local_status)?;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => {
                    return Err(connectrpc::ConnectError::unavailable(
                        "local environment daemon repair did not converge",
                    ));
                }
            }
        }
    }
}

fn fixed_daemon_status(
    state: proto::EnvironmentDaemonState,
    message: &'static str,
) -> proto::EnvironmentDaemonStatus {
    proto::EnvironmentDaemonStatus {
        state: state.into(),
        protocol_version: DAEMON_PROTOCOL_VERSION,
        minimum_protocol_version: DAEMON_MINIMUM_PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        message: message.to_owned(),
        diagnostics: vec![proto::EnvironmentDaemonDiagnostic {
            name: "daemon".to_owned(),
            healthy: state == proto::EnvironmentDaemonState::Ready,
            message: message.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn project_daemon_status(
    capabilities: &daemon_v1::GetCapabilitiesResponse,
    health: &daemon_v1::GetHealthResponse,
) -> proto::EnvironmentDaemonStatus {
    let reported = capabilities
        .capabilities
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let admitted = REQUIRED_LOCAL_DAEMON_CAPABILITIES
        .iter()
        .filter(|capability| reported.contains(**capability))
        .map(|capability| (*capability).to_owned())
        .collect::<Vec<_>>();
    let protocol_compatible = capabilities.minimum_protocol_version <= DAEMON_PROTOCOL_VERSION
        && capabilities.protocol_version >= DAEMON_PROTOCOL_VERSION;
    let bundle_compatible = capabilities.daemon_version == env!("CARGO_PKG_VERSION");
    let capability_state = daemon_state(capabilities.state);
    let mut state = if !protocol_compatible || !bundle_compatible {
        proto::EnvironmentDaemonState::UpgradeRequired
    } else if capability_state == proto::EnvironmentDaemonState::Ready
        && admitted.len() != REQUIRED_LOCAL_DAEMON_CAPABILITIES.len()
    {
        proto::EnvironmentDaemonState::Unsupported
    } else if capability_state == proto::EnvironmentDaemonState::Ready {
        daemon_state(health.state)
    } else {
        capability_state
    };
    if state == proto::EnvironmentDaemonState::Unspecified {
        state = proto::EnvironmentDaemonState::Unhealthy;
    }
    let message = daemon_state_message(state);
    proto::EnvironmentDaemonStatus {
        state: state.into(),
        protocol_version: capabilities.protocol_version,
        minimum_protocol_version: capabilities.minimum_protocol_version,
        daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: admitted,
        message: message.to_owned(),
        diagnostics: vec![proto::EnvironmentDaemonDiagnostic {
            name: "daemon".to_owned(),
            healthy: state == proto::EnvironmentDaemonState::Ready,
            message: message.to_owned(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn daemon_state(value: i32) -> proto::EnvironmentDaemonState {
    match daemon_v1::DaemonState::try_from(value).unwrap_or(daemon_v1::DaemonState::Unspecified) {
        daemon_v1::DaemonState::Unspecified => proto::EnvironmentDaemonState::Unspecified,
        daemon_v1::DaemonState::Unsupported => proto::EnvironmentDaemonState::Unsupported,
        daemon_v1::DaemonState::Starting => proto::EnvironmentDaemonState::Starting,
        daemon_v1::DaemonState::Ready => proto::EnvironmentDaemonState::Ready,
        daemon_v1::DaemonState::Unhealthy => proto::EnvironmentDaemonState::Unhealthy,
        daemon_v1::DaemonState::UpgradeRequired => proto::EnvironmentDaemonState::UpgradeRequired,
    }
}

fn daemon_state_message(state: proto::EnvironmentDaemonState) -> &'static str {
    match state {
        proto::EnvironmentDaemonState::Unspecified | proto::EnvironmentDaemonState::Unhealthy => {
            "local environment daemon is unhealthy"
        }
        proto::EnvironmentDaemonState::Unsupported => {
            "local environment daemon is missing required capabilities"
        }
        proto::EnvironmentDaemonState::Starting => "local environment daemon is starting",
        proto::EnvironmentDaemonState::Ready => "local environment daemon is ready",
        proto::EnvironmentDaemonState::UpgradeRequired => {
            "local environment daemon bundle is incompatible"
        }
    }
}

fn trusted_daemon_logs(
    operations: &[OperationRecord],
) -> Result<Vec<u8>, connectrpc::ConnectError> {
    let mut output = Vec::new();
    for operation in operations {
        let stage = operation_stage(operation).map_err(local_status)?;
        let line = format!(
            "time_unix_ms={} operation={} kind={} phase={} checkpoint={} stage={} error={}\n",
            operation.updated_unix_ms,
            operation.operation_id,
            operation.kind.as_str(),
            operation.phase.as_str(),
            operation.checkpoint,
            stage.as_str_name(),
            operation.error_code.as_deref().unwrap_or("-"),
        );
        if output.len().saturating_add(line.len()) > MAXIMUM_DAEMON_LOG_BYTES {
            break;
        }
        output.extend_from_slice(line.as_bytes());
    }
    Ok(output)
}

#[derive(Clone)]
struct LocalExecBackend {
    supervisor: SupervisorRpc,
}

#[async_trait]
impl ExecBackend for LocalExecBackend {
    fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        Ok(())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_bridge_validation("exec", &violations)
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_exec_error(error)
    }

    fn timeout_error(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::deadline_exceeded("local environment command timed out")
    }

    fn output_limit_error(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::resource_exhausted(
            "local environment command output is too large",
        )
    }

    fn invalid_daemon_frame(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::internal(
            "local environment daemon returned an invalid command stream",
        )
    }

    async fn daemon(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        self.supervisor
            .public_bridge_daemon_client(org_id, environment_id)
            .await
    }
}

#[derive(Clone)]
struct LocalFileBackend {
    supervisor: SupervisorRpc,
}

#[async_trait]
impl FileBackend for LocalFileBackend {
    fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        Ok(())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_bridge_validation("file", &violations)
    }

    fn daemon_error(
        &self,
        error: DaemonClientError,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        local_file_error(error)
    }

    fn invalid_file_type(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::invalid_argument("local file path is not a regular file")
    }

    async fn daemon(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<DaemonClient, connectrpc::ConnectError> {
        self.supervisor
            .public_bridge_daemon_client(org_id, environment_id)
            .await
    }
}

fn local_bridge_validation(
    operation: &str,
    violations: &[FieldViolation],
) -> connectrpc::ConnectError {
    let fields = violations
        .iter()
        .map(|violation| violation.path)
        .collect::<Vec<_>>()
        .join(", ");
    connectrpc::ConnectError::invalid_argument(format!(
        "local {operation} request is invalid: {fields}"
    ))
}

fn local_exec_error(error: DaemonClientError) -> connectrpc::ConnectError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::InvalidArgument => {
                connectrpc::ConnectError::invalid_argument("local command request is invalid")
            }
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => {
                connectrpc::ConnectError::failed_precondition(
                    "local environment daemon does not support this command operation",
                )
            }
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable(
                    "local environment command transport was lost",
                )
            }
            _ => connectrpc::ConnectError::internal("local environment command failed"),
        },
        DaemonClientError::NotReady { .. }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for commands",
            )
        }
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local environment command transport was lost")
        }
        DaemonClientError::Remote(_) => {
            connectrpc::ConnectError::failed_precondition("local environment command failed")
        }
        DaemonClientError::InvalidEndpoint
        | DaemonClientError::InvalidCredential
        | DaemonClientError::MissingResponse(_)
        | DaemonClientError::InvalidFrame(_) => {
            connectrpc::ConnectError::internal("local environment command failed")
        }
    }
}

fn local_file_error(error: DaemonClientError) -> connectrpc::ConnectError {
    match error {
        DaemonClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => {
                connectrpc::ConnectError::not_found("local file was not found")
            }
            tonic::Code::InvalidArgument | tonic::Code::PermissionDenied => {
                connectrpc::ConnectError::invalid_argument("local file path is invalid or denied")
            }
            tonic::Code::AlreadyExists => {
                connectrpc::ConnectError::already_exists("local file already exists")
            }
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => {
                connectrpc::ConnectError::failed_precondition(
                    "local environment daemon does not support this file operation",
                )
            }
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable("local file transport was lost")
            }
            _ => connectrpc::ConnectError::internal("local file request failed"),
        },
        DaemonClientError::NotReady { .. }
        | DaemonClientError::MissingCapability { .. }
        | DaemonClientError::IncompatibleProtocol { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for files",
            )
        }
        DaemonClientError::Connect | DaemonClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local file transport was lost")
        }
        DaemonClientError::InvalidEndpoint
        | DaemonClientError::InvalidCredential
        | DaemonClientError::MissingResponse(_)
        | DaemonClientError::InvalidFrame(_)
        | DaemonClientError::Remote(_) => {
            connectrpc::ConnectError::internal("local file request failed")
        }
    }
}

#[derive(Clone)]
struct LocalSessionBackend {
    supervisor: SupervisorRpc,
}

struct LocalSessionAttachment {
    client: SessionClient,
    attachment: PrivateSessionAttachment,
}

#[async_trait]
impl EnvironmentSessionBackend for LocalSessionBackend {
    type Attachment = LocalSessionAttachment;

    fn authorize(&self, _ctx: &RequestContext) -> Result<(), connectrpc::ConnectError> {
        Ok(())
    }

    fn validation_error(
        &self,
        violations: Vec<FieldViolation>,
        _request_id: Option<&str>,
    ) -> connectrpc::ConnectError {
        let fields = violations
            .iter()
            .map(|violation| violation.path)
            .collect::<Vec<_>>()
            .join(", ");
        connectrpc::ConnectError::invalid_argument(format!(
            "local session request is invalid: {fields}"
        ))
    }

    fn invalid_daemon_frame(&self, _request_id: Option<&str>) -> connectrpc::ConnectError {
        connectrpc::ConnectError::internal("local environment daemon returned an invalid frame")
    }

    async fn launch(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: daemon_v1::LaunchSessionRequest,
    ) -> Result<daemon_v1::SessionRecord, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .launch(request)
            .await
            .map_err(local_session_error)
    }

    async fn list(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
    ) -> Result<Vec<daemon_v1::SessionRecord>, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .list()
            .await
            .map_err(local_session_error)
    }

    async fn get(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<daemon_v1::SessionRecord, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .get(session_id)
            .await
            .map_err(local_session_error)
    }

    async fn stop(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
    ) -> Result<daemon_v1::SessionRecord, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .stop(session_id)
            .await
            .map_err(local_session_error)
    }

    async fn restart(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
        expected_launch_generation: Option<u64>,
    ) -> Result<daemon_v1::SessionRecord, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .restart_with_generation(session_id, expected_launch_generation)
            .await
            .map_err(local_session_error)
    }

    async fn send_input(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: daemon_v1::SendSessionInputRequest,
    ) -> Result<(), connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .send_input(&request.session_id, request.data)
            .await
            .map_err(local_session_error)
    }

    async fn read_output(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        request: daemon_v1::ReadSessionOutputRequest,
    ) -> Result<daemon_v1::ReadSessionOutputResponse, connectrpc::ConnectError> {
        self.supervisor
            .public_daemon_client(org_id, environment_id)
            .await?
            .read_output(request)
            .await
            .map_err(local_session_error)
    }

    async fn attach(
        &self,
        _ctx: &RequestContext,
        org_id: &str,
        environment_id: &str,
        session_id: &str,
        output_offset: u64,
    ) -> Result<Self::Attachment, connectrpc::ConnectError> {
        let client = self
            .supervisor
            .public_daemon_client(org_id, environment_id)
            .await?;
        let attachment = client
            .attach(session_id.to_owned(), output_offset)
            .await
            .map_err(local_session_error)?;
        Ok(LocalSessionAttachment { client, attachment })
    }
}

#[async_trait]
impl BridgeAttachment for LocalSessionAttachment {
    async fn send_input(
        &self,
        message: daemon_v1::SessionAttachMessage,
    ) -> Result<(), connectrpc::ConnectError> {
        let input = self.attachment.input_handle();
        match message.payload {
            Some(daemon_v1::session_attach_message::Payload::Input(input_message)) => input
                .send_input(input_message.data)
                .await
                .map_err(local_session_error),
            Some(daemon_v1::session_attach_message::Payload::Resize(resize)) => input
                .resize(resize.width, resize.height)
                .await
                .map_err(local_session_error),
            Some(daemon_v1::session_attach_message::Payload::Detach(_)) => {
                input.detach().await.map_err(local_session_error)
            }
            _ => Err(connectrpc::ConnectError::internal(
                "local session bridge produced an invalid input frame",
            )),
        }
    }

    async fn next_output(
        &mut self,
    ) -> Result<Option<daemon_v1::SessionAttachMessage>, connectrpc::ConnectError> {
        self.attachment
            .next_event()
            .await
            .map_err(local_session_error)
    }

    async fn session(
        &mut self,
        session_id: &str,
    ) -> Result<daemon_v1::SessionRecord, connectrpc::ConnectError> {
        self.client
            .get(session_id)
            .await
            .map_err(local_session_error)
    }
}

fn local_session_error(error: SessionClientError) -> connectrpc::ConnectError {
    match error {
        SessionClientError::Status(status) => match status.code() {
            tonic::Code::NotFound => {
                connectrpc::ConnectError::not_found("local environment session was not found")
            }
            tonic::Code::InvalidArgument => connectrpc::ConnectError::invalid_argument(
                "local environment session request is invalid",
            ),
            tonic::Code::Unimplemented | tonic::Code::FailedPrecondition => {
                connectrpc::ConnectError::failed_precondition(
                    "local environment daemon does not support this session operation",
                )
            }
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled => {
                connectrpc::ConnectError::unavailable(
                    "local environment session transport was lost",
                )
            }
            _ => connectrpc::ConnectError::internal("local environment session request failed"),
        },
        SessionClientError::NotReady { .. } | SessionClientError::MissingCapability { .. } => {
            connectrpc::ConnectError::failed_precondition(
                "local environment daemon is not ready for sessions",
            )
        }
        SessionClientError::Connect | SessionClientError::RequestClosed => {
            connectrpc::ConnectError::unavailable("local environment session transport was lost")
        }
        SessionClientError::InvalidEndpoint
        | SessionClientError::InvalidCredential
        | SessionClientError::MissingSessionRecord => {
            connectrpc::ConnectError::internal("local environment session request failed")
        }
    }
}

fn require_namespace(
    namespace: Uuid,
    value: &str,
    allow_empty: bool,
) -> Result<(), connectrpc::ConnectError> {
    if allow_empty && value.is_empty() {
        return Ok(());
    }
    let requested = parse_coordinate(value, "org_id")?;
    if requested != namespace {
        return Err(connectrpc::ConnectError::not_found(
            "local namespace was not found",
        ));
    }
    Ok(())
}

fn parse_coordinate(value: &str, field: &str) -> Result<Uuid, connectrpc::ConnectError> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| !id.is_nil())
        .ok_or_else(|| connectrpc::ConnectError::invalid_argument(format!("{field} is invalid")))
}

fn local_status(status: tonic::Status) -> connectrpc::ConnectError {
    let (code, message) = match status.code() {
        tonic::Code::Cancelled => (
            connectrpc::ErrorCode::Canceled,
            "local request was canceled",
        ),
        tonic::Code::InvalidArgument => (
            connectrpc::ErrorCode::InvalidArgument,
            "local request is invalid",
        ),
        tonic::Code::NotFound => (
            connectrpc::ErrorCode::NotFound,
            "local environment was not found",
        ),
        tonic::Code::AlreadyExists => (
            connectrpc::ErrorCode::AlreadyExists,
            "local environment already exists",
        ),
        tonic::Code::FailedPrecondition => (
            connectrpc::ErrorCode::FailedPrecondition,
            "local environment is not in the required state",
        ),
        tonic::Code::Aborted => (
            connectrpc::ErrorCode::Aborted,
            "local request conflicts with durable state",
        ),
        tonic::Code::OutOfRange => (
            connectrpc::ErrorCode::OutOfRange,
            "local request is out of range",
        ),
        tonic::Code::Unimplemented => (
            connectrpc::ErrorCode::Unimplemented,
            "local operation is not implemented",
        ),
        tonic::Code::Unavailable => (
            connectrpc::ErrorCode::Unavailable,
            "local supervisor is unavailable",
        ),
        tonic::Code::DeadlineExceeded => (
            connectrpc::ErrorCode::DeadlineExceeded,
            "local request deadline was exceeded",
        ),
        _ => (
            connectrpc::ErrorCode::Internal,
            "local supervisor request failed",
        ),
    };
    connectrpc::ConnectError::new(code, message)
}

fn local_internal() -> connectrpc::ConnectError {
    connectrpc::ConnectError::internal("local supervisor request failed")
}

fn unsupported<T>() -> ServiceResult<T> {
    Err(connectrpc::ConnectError::unimplemented(
        "this public RPC has no local runtime semantics",
    ))
}

fn private_environment_state(value: i32) -> Result<v1::EnvironmentState, connectrpc::ConnectError> {
    v1::EnvironmentState::try_from(value).map_err(|_| local_internal())
}

fn public_environment_state(state: v1::EnvironmentState) -> proto::EnvironmentState {
    match state {
        v1::EnvironmentState::Stopped => proto::EnvironmentState::Stopped,
        v1::EnvironmentState::Starting => proto::EnvironmentState::Starting,
        v1::EnvironmentState::Running => proto::EnvironmentState::Running,
        v1::EnvironmentState::Error | v1::EnvironmentState::Orphaned => {
            proto::EnvironmentState::Error
        }
        v1::EnvironmentState::Unspecified => proto::EnvironmentState::Unknown,
    }
}

fn public_desired_state(state: v1::EnvironmentState) -> proto::DesiredState {
    match state {
        v1::EnvironmentState::Starting | v1::EnvironmentState::Running => {
            proto::DesiredState::Started
        }
        v1::EnvironmentState::Stopped => proto::DesiredState::Stopped,
        v1::EnvironmentState::Error
        | v1::EnvironmentState::Orphaned
        | v1::EnvironmentState::Unspecified => proto::DesiredState::Unspecified,
    }
}

fn public_environment(
    namespace: Uuid,
    environment: &v1::Environment,
) -> Result<proto::Environment, connectrpc::ConnectError> {
    let state = private_environment_state(environment.state)?;
    let (cpu_millicores, memory_mb, disk_gb) = public_resource_values(environment)?;
    let error_reason = match state {
        v1::EnvironmentState::Error => "local_runtime_error",
        v1::EnvironmentState::Orphaned => "local_runtime_orphaned",
        _ => "",
    };
    Ok(proto::Environment {
        id: environment.id.clone(),
        org_id: namespace.to_string(),
        r#type: "local".to_owned(),
        name: environment.name.clone(),
        state: public_environment_state(state).into(),
        desired_state: public_desired_state(state).into(),
        error_reason: error_reason.to_owned(),
        setup_complete: matches!(
            state,
            v1::EnvironmentState::Stopped | v1::EnvironmentState::Running
        ),
        cpu_millicores,
        memory_mb,
        disk_gb,
        isolation_tier: proto::IsolationTier::Standard.into(),
        operation_generation: environment.generation,
        source_selection: public_source_selection(environment)?.into(),
        ..Default::default()
    })
}

fn source_selection_model(
    selection: proto::EnvironmentSourceSelection,
) -> Result<(codewire_project::ProjectSpec, Option<u64>), connectrpc::ConnectError> {
    let mut wire = codewire_project_proto::to_proto(codewire_project::ProjectSpec::default());
    wire.secrets = selection.secrets;
    wire.credentials = selection.credentials;
    let project = codewire_project_proto::from_proto(wire)
        .map_err(|_| connectrpc::ConnectError::invalid_argument("invalid source selection"))?;
    match (&project.credentials, selection.profile_revision) {
        (None, None) => {}
        (Some(_), Some(revision)) if revision > 0 => {}
        _ => {
            return Err(connectrpc::ConnectError::invalid_argument(
                "profile selection requires one positive exact revision",
            ));
        }
    }
    for reference in std::iter::once(project.secrets.project.as_str()).chain(
        project
            .credentials
            .iter()
            .map(|binding| binding.profile.as_str()),
    ) {
        if !reference.is_empty() {
            exact_source_reference(reference)?;
        }
    }
    Ok((project, selection.profile_revision))
}

fn exact_source_reference(
    value: &str,
) -> Result<(codewire_project::StoragePlacement, Uuid), connectrpc::ConnectError> {
    let reference = codewire_project::StorageReference::project(value).map_err(|_| {
        connectrpc::ConnectError::invalid_argument(
            "source selection requires an exact qualified ID",
        )
    })?;
    let placement = reference.placement.ok_or_else(|| {
        connectrpc::ConnectError::invalid_argument(
            "source selection requires an explicit storage origin",
        )
    })?;
    let id = reference.selector.strip_prefix("id:").ok_or_else(|| {
        connectrpc::ConnectError::invalid_argument("source selection requires an exact ID")
    })?;
    let parsed = parse_coordinate(id, "source ID")?;
    if parsed.to_string() != id {
        return Err(connectrpc::ConnectError::invalid_argument(
            "source ID must be canonical",
        ));
    }
    Ok((placement, parsed))
}

fn source_selection_wire(
    project: &codewire_project::ProjectSpec,
    revision: Option<u64>,
) -> proto::EnvironmentSourceSelection {
    let wire = codewire_project_proto::to_proto(project.clone());
    proto::EnvironmentSourceSelection {
        secrets: wire.secrets,
        credentials: wire.credentials,
        profile_revision: revision,
        ..Default::default()
    }
}

fn public_source_selection(
    environment: &v1::Environment,
) -> Result<Option<proto::EnvironmentSourceSelection>, connectrpc::ConnectError> {
    if environment.project_spec_json.is_empty() && environment.project_spec_sha256.is_empty() {
        // Missing private metadata is an unavailable capability, not an empty
        // selection which an API client could accidentally use to clear pins.
        return Ok(None);
    }
    validate_project_intent(
        &environment.project_spec_json,
        &environment.project_spec_sha256,
        None,
    )
    .map_err(|_| local_internal())?;
    let project: codewire_project::ProjectSpec =
        serde_json::from_slice(&environment.project_spec_json).map_err(|_| local_internal())?;
    sources::validate_source_metadata(
        &project,
        &environment.access_profile_id,
        environment.access_profile_revision,
        &environment.access_profile,
        environment.platform_source_authority.as_ref(),
    )
    .map_err(|_| local_internal())?;
    Ok(Some(source_selection_wire(
        &project,
        project
            .credentials
            .as_ref()
            .map(|_| environment.access_profile_revision),
    )))
}

fn native_source_replacement(
    request: &proto::UpdateEnvironmentSourcesRequest,
    environment: &v1::Environment,
) -> Result<(codewire_project::ProjectSpec, Option<u64>, bool), connectrpc::ConnectError> {
    if request.expected_operation_generation == 0
        || request.expected_operation_generation != environment.generation
    {
        return Err(connectrpc::ConnectError::failed_precondition(
            "local environment generation changed; inspect before retrying",
        ));
    }
    let expected = request.expected.as_option().cloned().ok_or_else(|| {
        connectrpc::ConnectError::invalid_argument("expected source selection is required")
    })?;
    let replacement = request.replacement.as_option().cloned().ok_or_else(|| {
        connectrpc::ConnectError::invalid_argument("replacement source selection is required")
    })?;
    let current = public_source_selection(environment)?.ok_or_else(|| {
        connectrpc::ConnectError::failed_precondition("local source metadata is unavailable")
    })?;
    let (expected, expected_revision) = source_selection_model(expected)?;
    let (current, current_revision) = source_selection_model(current)?;
    let (replacement, replacement_revision) = source_selection_model(replacement)?;
    if expected.secrets != current.secrets
        || expected.credentials != current.credentials
        || expected_revision != current_revision
    {
        return Err(connectrpc::ConnectError::failed_precondition(
            "local source selection changed; inspect before retrying",
        ));
    }
    let unchanged = replacement.secrets == current.secrets
        && replacement.credentials == current.credentials
        && replacement_revision == current_revision;
    let mut target: codewire_project::ProjectSpec =
        serde_json::from_slice(&environment.project_spec_json).map_err(|_| local_internal())?;
    target.secrets = replacement.secrets;
    target.credentials = replacement.credentials;
    Ok((target, replacement_revision, unchanged))
}

fn native_platform_source_authority(
    project: &codewire_project::ProjectSpec,
    current: &v1::Environment,
) -> Result<Option<v1::PlatformSourceAuthority>, connectrpc::ConnectError> {
    let mut platform = project.secrets.organization
        || project.secrets.user == Some(codewire_project::StoragePlacement::Platform);
    if !project.secrets.project.is_empty() {
        platform |= exact_source_reference(&project.secrets.project)?.0
            == codewire_project::StoragePlacement::Platform;
    }
    if let Some(binding) = &project.credentials {
        platform |= exact_source_reference(&binding.profile)?.0
            == codewire_project::StoragePlacement::Platform;
    }
    if !platform {
        return Ok(None);
    }
    current.platform_source_authority.clone().map(Some).ok_or_else(|| connectrpc::ConnectError::failed_precondition(
        "selecting a new platform authority requires the authenticated descriptor-bearing native source resolver"))
}

fn public_resource_values(
    environment: &v1::Environment,
) -> Result<(i32, i32, i32), connectrpc::ConnectError> {
    let cpu_millicores = environment
        .vcpus
        .checked_mul(1000)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(local_internal)?;
    let memory_mb = i32::try_from(environment.memory_mib).map_err(|_| local_internal())?;
    if !environment.disk_bytes.is_multiple_of(GIB) {
        return Err(local_internal());
    }
    let disk_gb = i32::try_from(environment.disk_bytes / GIB).map_err(|_| local_internal())?;
    Ok((cpu_millicores, memory_mb, disk_gb))
}

fn public_resources(
    environment: &v1::Environment,
) -> Result<proto::EnvironmentResources, connectrpc::ConnectError> {
    let (cpu_millicores, memory_mb, disk_gb) = public_resource_values(environment)?;
    Ok(proto::EnvironmentResources {
        cpu_millicores,
        memory_mb,
        disk_gb,
        ..Default::default()
    })
}

fn private_resources(
    cpu_millicores: i32,
    memory_mb: i32,
    disk_gb: i32,
) -> Result<(u32, u32, u64), connectrpc::ConnectError> {
    if cpu_millicores <= 0
        || cpu_millicores % 1000 != 0
        || !(128..=65_536).contains(&memory_mb)
        || !(1..=1024).contains(&disk_gb)
    {
        return Err(connectrpc::ConnectError::invalid_argument(
            "local resources require whole CPU cores, 128 to 65536 MiB memory, and 1 to 1024 GiB disk",
        ));
    }
    let vcpus = u32::try_from(cpu_millicores / 1000)
        .ok()
        .filter(|value| (1..=32).contains(value))
        .ok_or_else(|| {
            connectrpc::ConnectError::invalid_argument(
                "local CPU resources must contain 1 to 32 whole cores",
            )
        })?;
    let memory_mib = u32::try_from(memory_mb).map_err(|_| local_internal())?;
    let disk_bytes = u64::try_from(disk_gb)
        .ok()
        .and_then(|value| value.checked_mul(GIB))
        .filter(|value| *value >= crate::state::MINIMUM_STATE_DISK_BYTES)
        .ok_or_else(|| {
            connectrpc::ConnectError::invalid_argument("local disk resources are out of range")
        })?;
    Ok((vcpus, memory_mib, disk_bytes))
}

fn resize_mode(
    environment: &v1::Environment,
    desired: &proto::EnvironmentResources,
) -> Result<proto::EnvironmentResizeExecutionMode, connectrpc::ConnectError> {
    let previous = public_resources(environment)?;
    if previous == *desired {
        return Ok(proto::EnvironmentResizeExecutionMode::Noop);
    }
    match private_environment_state(environment.state)? {
        v1::EnvironmentState::Stopped => Ok(proto::EnvironmentResizeExecutionMode::ApplyOnStart),
        v1::EnvironmentState::Running => Ok(proto::EnvironmentResizeExecutionMode::Restart),
        v1::EnvironmentState::Starting => Err(connectrpc::ConnectError::failed_precondition(
            "local environment is still starting",
        )),
        v1::EnvironmentState::Error | v1::EnvironmentState::Orphaned => {
            Err(connectrpc::ConnectError::failed_precondition(
                "local environment must be repaired before resize",
            ))
        }
        v1::EnvironmentState::Unspecified => Err(local_internal()),
    }
}

fn resize_plan(
    environment: &v1::Environment,
    desired: proto::EnvironmentResources,
) -> Result<proto::EnvironmentResizePlan, connectrpc::ConnectError> {
    let previous = public_resources(environment)?;
    let mode = resize_mode(environment, &desired)?;
    let (reason, warnings) = match mode {
        proto::EnvironmentResizeExecutionMode::Noop => ("resources are unchanged", Vec::new()),
        proto::EnvironmentResizeExecutionMode::ApplyOnStart => (
            "resources will be applied before the environment next starts",
            Vec::new(),
        ),
        proto::EnvironmentResizeExecutionMode::Restart => (
            "the local microVM must restart to apply resource changes",
            vec![
                "local public session counts are unavailable; restart may terminate active sessions"
                    .to_owned(),
            ],
        ),
        _ => return Err(local_internal()),
    };
    Ok(proto::EnvironmentResizePlan {
        previous_resources: Some(previous).into(),
        desired_resources: Some(desired).into(),
        execution_mode: mode.into(),
        reason: reason.to_owned(),
        warnings,
        ..Default::default()
    })
}

fn disruption_policy(
    value: buffa::EnumValue<proto::EnvironmentResizeDisruptionPolicy>,
) -> Result<proto::EnvironmentResizeDisruptionPolicy, connectrpc::ConnectError> {
    match value.as_known() {
        Some(proto::EnvironmentResizeDisruptionPolicy::Unspecified)
        | Some(proto::EnvironmentResizeDisruptionPolicy::LiveOnly) => {
            Ok(proto::EnvironmentResizeDisruptionPolicy::LiveOnly)
        }
        Some(proto::EnvironmentResizeDisruptionPolicy::AllowRestart) => {
            Ok(proto::EnvironmentResizeDisruptionPolicy::AllowRestart)
        }
        None => Err(connectrpc::ConnectError::invalid_argument(
            "resize disruption_policy is invalid",
        )),
    }
}

fn deterministic_request_id(namespace: Uuid, environment: Uuid, request_id: &str) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"codewire-local-public-resize-request-v1\0");
    digest.update(namespace.as_bytes());
    digest.update(environment.as_bytes());
    digest.update(request_id.as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn operation_public_request_id(operation: &OperationRecord) -> String {
    operation
        .payload
        .get("public_request_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| operation.request_id.to_string())
}

fn operation_resources(
    operation: &OperationRecord,
    prefix: &str,
) -> Result<proto::EnvironmentResources, connectrpc::ConnectError> {
    let field = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}_{name}")
        }
    };
    let vcpus = operation
        .payload
        .get(field("vcpus"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| value.checked_mul(1000))
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(local_internal)?;
    let memory_mb = operation
        .payload
        .get(field("memory_mib"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(local_internal)?;
    let disk_bytes = operation
        .payload
        .get(field("disk_bytes"))
        .and_then(serde_json::Value::as_u64)
        .filter(|value| value.is_multiple_of(GIB))
        .ok_or_else(local_internal)?;
    let disk_gb = i32::try_from(disk_bytes / GIB).map_err(|_| local_internal())?;
    Ok(proto::EnvironmentResources {
        cpu_millicores: vcpus,
        memory_mb,
        disk_gb,
        ..Default::default()
    })
}

fn operation_timestamp(unix_ms: i64) -> Result<Timestamp, connectrpc::ConnectError> {
    let seconds = unix_ms.div_euclid(1000);
    let nanos =
        i32::try_from(unix_ms.rem_euclid(1000) * 1_000_000).map_err(|_| local_internal())?;
    Timestamp::from_unix_checked(seconds, nanos).ok_or_else(local_internal)
}

fn public_resize_operation(
    operation: &OperationRecord,
    environment: &v1::Environment,
) -> Result<proto::EnvironmentResizeOperation, connectrpc::ConnectError> {
    if !matches!(
        operation.kind,
        OperationKind::Restart | OperationKind::GrowDisk
    ) || operation.environment_id.map(|id| id.to_string()).as_deref()
        != Some(environment.id.as_str())
    {
        return Err(connectrpc::ConnectError::not_found(
            "local resize operation was not found",
        ));
    }
    let previous = operation_resources(operation, "previous")?;
    let desired = operation_resources(operation, "")?;
    let applied = public_resources(environment)?;
    let was_running = operation
        .payload
        .get("was_running")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(local_internal)?;
    let planned_mode = if was_running {
        proto::EnvironmentResizeExecutionMode::Restart
    } else {
        proto::EnvironmentResizeExecutionMode::ApplyOnStart
    };
    let policy = match operation
        .payload
        .get("public_disruption_policy")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
    {
        "live_only" => proto::EnvironmentResizeDisruptionPolicy::LiveOnly,
        "" | "allow_restart" => proto::EnvironmentResizeDisruptionPolicy::AllowRestart,
        _ => return Err(local_internal()),
    };
    let (state, applied_mode, completed_at) = match operation.phase {
        OperationPhase::Intent => (
            proto::EnvironmentResizeOperationState::Pending,
            proto::EnvironmentResizeExecutionMode::Unspecified,
            None,
        ),
        OperationPhase::EffectApplied => (
            if was_running {
                proto::EnvironmentResizeOperationState::Restarting
            } else {
                proto::EnvironmentResizeOperationState::Applying
            },
            proto::EnvironmentResizeExecutionMode::Unspecified,
            None,
        ),
        OperationPhase::Completed => (
            proto::EnvironmentResizeOperationState::Completed,
            planned_mode,
            Some(operation_timestamp(operation.updated_unix_ms)?),
        ),
        OperationPhase::Failed | OperationPhase::Interrupted => (
            proto::EnvironmentResizeOperationState::Failed,
            proto::EnvironmentResizeExecutionMode::Unspecified,
            Some(operation_timestamp(operation.updated_unix_ms)?),
        ),
    };
    let failure = operation
        .error_code
        .as_ref()
        .map(|code| proto::EnvironmentResizeFailure {
            code: code.clone(),
            message: "local resize operation failed".to_owned(),
            ..Default::default()
        });
    Ok(proto::EnvironmentResizeOperation {
        id: operation.operation_id.to_string(),
        environment_id: environment.id.clone(),
        request_id: operation_public_request_id(operation),
        previous_resources: Some(previous).into(),
        desired_resources: Some(desired).into(),
        last_applied_resources: Some(applied).into(),
        state: state.into(),
        failure: failure.into(),
        created_at: Some(operation_timestamp(operation.created_unix_ms)?).into(),
        updated_at: Some(operation_timestamp(operation.updated_unix_ms)?).into(),
        completed_at: completed_at.into(),
        disruption_policy: policy.into(),
        planned_mode: planned_mode.into(),
        applied_mode: applied_mode.into(),
        ..Default::default()
    })
}

fn poll_interval(
    operation: &OperationRecord,
) -> buffa::MessageField<ProtoDuration, buffa::Inline<ProtoDuration>> {
    (!operation.phase.terminal())
        .then(|| ProtoDuration::from_secs(1))
        .into()
}

#[allow(refining_impl_trait)]
impl proto::EnvironmentService for SupervisorRpc {
    async fn list_environments(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::ListEnvironmentsRequest>,
    ) -> ServiceResult<proto::ListEnvironmentsResponse> {
        let request = request.view();
        if !request.page_token.is_empty() || request.page_size != 0 {
            return Err(connectrpc::ConnectError::invalid_argument(
                "local environment pagination is not supported",
            ));
        }
        let namespace = self.public_namespace_id().await?;
        require_namespace(namespace, request.org_id, true)?;
        let state_filter = match request.state.as_known() {
            Some(proto::EnvironmentState::Unspecified) => None,
            Some(state) => Some(state),
            None => {
                return Err(connectrpc::ConnectError::invalid_argument(
                    "environment state filter is invalid",
                ));
            }
        };
        let mut environments = Vec::new();
        for environment in self.public_environments().await? {
            let environment = public_environment(namespace, &environment)?;
            if !request.r#type.is_empty() && request.r#type != "local" {
                continue;
            }
            if state_filter.is_some_and(|state| environment.state.as_known() != Some(state)) {
                continue;
            }
            environments.push(environment);
        }
        let poll = environments
            .iter()
            .any(|environment| {
                environment.state.as_known() == Some(proto::EnvironmentState::Starting)
            })
            .then(|| ProtoDuration::from_secs(1));
        connectrpc::Response::ok(proto::ListEnvironmentsResponse {
            environments,
            poll_interval: poll.into(),
            ..Default::default()
        })
    }

    async fn create_environment(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::CreateEnvironmentRequest>,
    ) -> ServiceResult<proto::CreateEnvironmentResponse> {
        unsupported()
    }

    async fn get_environment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentRequest>,
    ) -> ServiceResult<proto::GetEnvironmentResponse> {
        let request = request.view();
        let (namespace, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let environment = public_environment(namespace, &environment)?;
        let poll = (environment.state.as_known() == Some(proto::EnvironmentState::Starting))
            .then(|| ProtoDuration::from_secs(1));
        connectrpc::Response::ok(proto::GetEnvironmentResponse {
            environment: Some(environment).into(),
            poll_interval: poll.into(),
            ..Default::default()
        })
    }

    async fn plan_environment_resize(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::PlanEnvironmentResizeRequest>,
    ) -> ServiceResult<proto::PlanEnvironmentResizeResponse> {
        let request = request.view();
        let (vcpus, memory_mib, disk_bytes) =
            private_resources(request.cpu_millicores, request.memory_mb, request.disk_gb)?;
        let desired = proto::EnvironmentResources {
            cpu_millicores: i32::try_from(vcpus * 1000).map_err(|_| local_internal())?,
            memory_mb: i32::try_from(memory_mib).map_err(|_| local_internal())?,
            disk_gb: i32::try_from(disk_bytes / GIB).map_err(|_| local_internal())?,
            ..Default::default()
        };
        let (namespace, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let plan = resize_plan(&environment, desired)?;
        connectrpc::Response::ok(proto::PlanEnvironmentResizeResponse {
            plan: Some(plan).into(),
            environment: Some(public_environment(namespace, &environment)?).into(),
            ..Default::default()
        })
    }

    async fn resize_environment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::ResizeEnvironmentRequest>,
    ) -> ServiceResult<proto::ResizeEnvironmentResponse> {
        let request = request.view();
        if request.force {
            return Err(connectrpc::ConnectError::unimplemented(
                "force has no local runtime semantics",
            ));
        }
        let public_request_id = request.request_id.trim();
        if public_request_id.is_empty() || public_request_id.len() > 128 {
            return Err(connectrpc::ConnectError::invalid_argument(
                "request_id must contain 1 to 128 characters",
            ));
        }
        let policy = disruption_policy(request.disruption_policy)?;
        let (vcpus, memory_mib, disk_bytes) =
            private_resources(request.cpu_millicores, request.memory_mb, request.disk_gb)?;
        let desired = proto::EnvironmentResources {
            cpu_millicores: i32::try_from(vcpus * 1000).map_err(|_| local_internal())?,
            memory_mb: i32::try_from(memory_mib).map_err(|_| local_internal())?,
            disk_gb: i32::try_from(disk_bytes / GIB).map_err(|_| local_internal())?,
            ..Default::default()
        };
        let (namespace, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let mode = resize_mode(&environment, &desired)?;
        if mode == proto::EnvironmentResizeExecutionMode::Noop {
            return Err(connectrpc::ConnectError::invalid_argument(
                "requested resources already match the local environment",
            ));
        }
        if mode == proto::EnvironmentResizeExecutionMode::Restart
            && policy != proto::EnvironmentResizeDisruptionPolicy::AllowRestart
        {
            return Err(connectrpc::ConnectError::failed_precondition(
                "local resize requires allow_restart",
            ));
        }
        let environment_id = parse_coordinate(&environment.id, "environment_id")?;
        let request_id = deterministic_request_id(namespace, environment_id, public_request_id);
        let operation = LocalSupervisorService::resize_environment(
            self,
            TonicRequest::new(v1::ResizeEnvironmentRequest {
                name: environment.name.clone(),
                vcpus,
                memory_mib,
                disk_bytes,
                request_id: request_id.to_string(),
                environment_id: environment.id.clone(),
                public_request_id: public_request_id.to_owned(),
                public_disruption_policy: match policy {
                    proto::EnvironmentResizeDisruptionPolicy::LiveOnly => "live_only",
                    proto::EnvironmentResizeDisruptionPolicy::AllowRestart => "allow_restart",
                    _ => return Err(local_internal()),
                }
                .to_owned(),
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(local_status)?;
        let operation_id = parse_coordinate(&operation.operation_id, "operation_id")?;
        let operation = self.operation(operation_id).await.map_err(local_status)?;
        let poll_interval = poll_interval(&operation);
        connectrpc::Response::ok(proto::ResizeEnvironmentResponse {
            operation: Some(public_resize_operation(&operation, &environment)?).into(),
            environment: Some(public_environment(namespace, &environment)?).into(),
            poll_interval,
            ..Default::default()
        })
    }

    async fn get_environment_resize_operation(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentResizeOperationRequest>,
    ) -> ServiceResult<proto::GetEnvironmentResizeOperationResponse> {
        let request = request.view();
        let (namespace, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let operation_id = parse_coordinate(request.operation_id, "operation_id")?;
        let operation = self.operation(operation_id).await.map_err(local_status)?;
        let poll_interval = poll_interval(&operation);
        connectrpc::Response::ok(proto::GetEnvironmentResizeOperationResponse {
            operation: Some(public_resize_operation(&operation, &environment)?).into(),
            environment: Some(public_environment(namespace, &environment)?).into(),
            poll_interval,
            ..Default::default()
        })
    }

    async fn delete_environment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::DeleteEnvironmentRequest>,
    ) -> ServiceResult<proto::DeleteEnvironmentResponse> {
        let request = request.view();
        let (_, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        LocalSupervisorService::delete_environment(
            self,
            TonicRequest::new(v1::EnvironmentSelector {
                name: environment.name,
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment.id,
            }),
        )
        .await
        .map_err(local_status)?;
        connectrpc::Response::ok(proto::DeleteEnvironmentResponse::default())
    }

    async fn stop_environment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::StopEnvironmentRequest>,
    ) -> ServiceResult<proto::StopEnvironmentResponse> {
        let request = request.view();
        let (_, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        LocalSupervisorService::stop_environment(
            self,
            TonicRequest::new(v1::EnvironmentSelector {
                name: environment.name,
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment.id,
            }),
        )
        .await
        .map_err(local_status)?;
        connectrpc::Response::ok(proto::StopEnvironmentResponse {
            status: "stop requested".to_owned(),
            ..Default::default()
        })
    }

    async fn start_environment(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::StartEnvironmentRequest>,
    ) -> ServiceResult<proto::StartEnvironmentResponse> {
        let request = request.view();
        let (_, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let retried = private_environment_state(environment.state)? == v1::EnvironmentState::Error;
        LocalSupervisorService::start_environment(
            self,
            TonicRequest::new(v1::EnvironmentSelector {
                name: environment.name,
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment.id,
            }),
        )
        .await
        .map_err(local_status)?;
        connectrpc::Response::ok(proto::StartEnvironmentResponse {
            status: if retried {
                "retry requested"
            } else {
                "start requested"
            }
            .to_owned(),
            outcome: if retried {
                proto::StartOutcome::Retried
            } else {
                proto::StartOutcome::Started
            }
            .into(),
            ..Default::default()
        })
    }

    async fn update_environment_sources(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::UpdateEnvironmentSourcesRequest>,
    ) -> ServiceResult<proto::UpdateEnvironmentSourcesResponse> {
        let request = request.to_owned_message();
        let (_, environment) = self
            .public_environment(&request.org_id, &request.environment_id)
            .await?;
        let (project, profile_revision, unchanged) =
            native_source_replacement(&request, &environment)?;
        if !matches!(
            private_environment_state(environment.state)?,
            v1::EnvironmentState::Running | v1::EnvironmentState::Stopped
        ) {
            return Err(connectrpc::ConnectError::failed_precondition(
                "source updates require a stable running or stopped local environment",
            ));
        }
        let selection = source_selection_wire(&project, profile_revision);
        if unchanged {
            return connectrpc::Response::ok(proto::UpdateEnvironmentSourcesResponse {
                environment_id: environment.id,
                operation_generation: environment.generation,
                selection: Some(selection).into(),
                outcome: proto::EnvironmentSourcesUpdateOutcome::Unchanged.into(),
                ..Default::default()
            });
        }
        if private_environment_state(environment.state)? == v1::EnvironmentState::Running
            && !request.allow_restart
        {
            return Err(connectrpc::ConnectError::failed_precondition(
                "running local source updates require allow_restart",
            ));
        }
        if project.secrets.user.is_some() && !request.confirm_personal_secrets {
            return Err(connectrpc::ConnectError::failed_precondition(
                "personal secret selection requires explicit confirmation",
            ));
        }
        let platform_source_authority = native_platform_source_authority(&project, &environment)?;
        let (profile_id, revision, reference) = match &project.credentials {
            None => (String::new(), 0, String::new()),
            Some(binding) => {
                let (placement, id) = exact_source_reference(&binding.profile)?;
                let revision = profile_revision.ok_or_else(|| {
                    connectrpc::ConnectError::invalid_argument("profile revision is required")
                })?;
                let reference = match placement {
                    codewire_project::StoragePlacement::Local => {
                        let config = self.supervisor.config.credential_authority_config();
                        let mut metadata =
                            codewire_local_credentials::LocalCredentialClient::connect(&config)
                                .await
                                .map_err(|_| {
                                    connectrpc::ConnectError::unavailable(
                                        "local credential authority is unavailable",
                                    )
                                })?;
                        let exact_id =
                            AccessProfileId::parse(id.to_string()).map_err(|_| local_internal())?;
                        let profile = metadata
                            .get_profile_revision(&exact_id, revision)
                            .await
                            .map_err(local_status)?;
                        if profile.profile.id != exact_id
                            || profile.profile.revision != revision
                            || profile.profile.placement != codewire_access::Placement::Local
                            || !matches!(profile.profile.owner, codewire_access::Owner::User(_))
                        {
                            return Err(local_internal());
                        }
                        format!("user/{}", profile.profile.name)
                    }
                    codewire_project::StoragePlacement::Platform => {
                        // The public source contract has no authenticated
                        // origin descriptor/name resolution input. Retain an
                        // already pinned tuple, never read ambient platform auth.
                        if environment.access_profile_id != id.to_string()
                            || environment.access_profile_revision != revision
                        {
                            return Err(connectrpc::ConnectError::failed_precondition(
                                "selecting a new platform profile requires the authenticated descriptor-bearing native source resolver",
                            ));
                        }
                        let current: codewire_project::ProjectSpec =
                            serde_json::from_slice(&environment.project_spec_json)
                                .map_err(|_| local_internal())?;
                        if current.credentials.as_ref() != Some(binding) {
                            return Err(connectrpc::ConnectError::failed_precondition(
                                "platform profile origin must match the existing native pin",
                            ));
                        }
                        environment.access_profile.clone()
                    }
                };
                if reference
                    .parse::<AccessProfileReference>()
                    .map_err(|_| local_internal())?
                    .scope()
                    == AccessProfileScope::User
                    && !request.confirm_personal_credentials
                {
                    return Err(connectrpc::ConnectError::failed_precondition(
                        "personal credential selection requires explicit confirmation",
                    ));
                }
                (id.to_string(), revision, reference)
            }
        };
        let canonical = project.canonical_json().map_err(|_| {
            connectrpc::ConnectError::invalid_argument("invalid source replacement")
        })?;
        let target_generation = environment
            .generation
            .checked_add(1)
            .ok_or_else(local_internal)?;
        let operation = LocalSupervisorService::update_environment_sources(
            self,
            TonicRequest::new(v1::UpdateEnvironmentSourcesRequest {
                name: environment.name,
                request_id: Uuid::new_v4().to_string(),
                expected_environment_id: environment.id.clone(),
                expected_generation: request.expected_operation_generation,
                expected_project_spec_sha256: environment.project_spec_sha256,
                expected_access_profile_id: environment.access_profile_id,
                expected_access_profile_revision: environment.access_profile_revision,
                project_spec_sha256: format!("{:x}", Sha256::digest(&canonical)),
                project_spec_json: canonical,
                access_profile_id: profile_id,
                access_profile_revision: revision,
                access_profile_reference: reference,
                allow_restart: request.allow_restart,
                expected_platform_source_authority: environment.platform_source_authority,
                platform_source_authority,
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(local_status)?;
        let operation_id = parse_coordinate(&operation.operation_id, "operation_id")?;
        // The durable worker, not this HTTP request, owns stop/CAS/restart.
        // Timeout/disconnect leaves its existing journal pending for inspection.
        self.wait_for_terminal_operation(operation_id).await.map_err(|_| connectrpc::ConnectError::unavailable(
            "local source update has not completed; inspect the environment and its durable operation"))?;
        connectrpc::Response::ok(proto::UpdateEnvironmentSourcesResponse {
            environment_id: environment.id,
            operation_generation: target_generation,
            selection: Some(selection).into(),
            outcome: proto::EnvironmentSourcesUpdateOutcome::Stored.into(),
            ..Default::default()
        })
    }

    async fn protect_environment(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::ProtectEnvironmentRequest>,
    ) -> ServiceResult<proto::ProtectEnvironmentResponse> {
        unsupported()
    }

    async fn unprotect_environment(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::UnprotectEnvironmentRequest>,
    ) -> ServiceResult<proto::UnprotectEnvironmentResponse> {
        unsupported()
    }

    async fn cancel_environment_deletion(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::CancelEnvironmentDeletionRequest>,
    ) -> ServiceResult<proto::CancelEnvironmentDeletionResponse> {
        unsupported()
    }

    async fn extend_environment_ttl(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::ExtendEnvironmentTtlRequest>,
    ) -> ServiceResult<proto::ExtendEnvironmentTtlResponse> {
        unsupported()
    }

    async fn get_environment_trust_report(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::GetEnvironmentTrustReportRequest>,
    ) -> ServiceResult<proto::GetEnvironmentTrustReportResponse> {
        unsupported()
    }

    async fn get_environment_host_key(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentHostKeyRequest>,
    ) -> ServiceResult<proto::GetEnvironmentHostKeyResponse> {
        // The supervisor terminates a local environment's SSH, with this
        // environment's own key kept on the host (#3025): the guest supplies
        // no trust material.
        let request = request.view();
        let (_, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let environment_id = parse_coordinate(&environment.id, "environment_id")?;
        let public_key_openssh = self
            .host_keys
            .public_line(environment_id)
            .map_err(|_| local_internal())?;
        connectrpc::Response::ok(proto::GetEnvironmentHostKeyResponse {
            // One key for every boot of this environment.
            generation: 1,
            public_key_openssh,
            ..Default::default()
        })
    }

    async fn get_environment_daemon_status(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::GetEnvironmentDaemonStatusRequest>,
    ) -> ServiceResult<proto::GetEnvironmentDaemonStatusResponse> {
        let request = request.view();
        let status = self
            .public_daemon_status(request.org_id, request.environment_id)
            .await?;
        connectrpc::Response::ok(proto::GetEnvironmentDaemonStatusResponse {
            status: Some(status).into(),
            ..Default::default()
        })
    }

    async fn stream_environment_daemon_logs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::StreamEnvironmentDaemonLogsRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamEnvironmentDaemonLogsResponse>> {
        let request = request.view();
        let data = self
            .public_daemon_logs(request.org_id, request.environment_id)
            .await?;
        connectrpc::Response::stream_ok(futures::stream::iter([Ok(
            proto::StreamEnvironmentDaemonLogsResponse {
                data,
                ..Default::default()
            },
        )]))
    }

    async fn repair_environment_daemon(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, proto::RepairEnvironmentDaemonRequest>,
    ) -> ServiceResult<proto::RepairEnvironmentDaemonResponse> {
        let request = request.view();
        let (_, environment) = self
            .public_environment(request.org_id, request.environment_id)
            .await?;
        let operation = LocalSupervisorService::restart_environment(
            self,
            TonicRequest::new(v1::EnvironmentSelector {
                name: environment.name,
                request_id: Uuid::new_v4().to_string(),
                environment_id: environment.id,
            }),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(local_status)?;
        let operation_id = parse_coordinate(&operation.operation_id, "operation_id")?;
        self.wait_for_terminal_operation(operation_id).await?;
        let status = self
            .public_daemon_status(request.org_id, request.environment_id)
            .await?;
        connectrpc::Response::ok(proto::RepairEnvironmentDaemonResponse {
            status: Some(status).into(),
            ..Default::default()
        })
    }

    async fn list_environment_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::ListEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::ListEnvironmentAccessResponse> {
        unsupported()
    }

    async fn grant_environment_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::GrantEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::GrantEnvironmentAccessResponse> {
        unsupported()
    }

    async fn revoke_environment_access(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::RevokeEnvironmentAccessRequest>,
    ) -> ServiceResult<proto::RevokeEnvironmentAccessResponse> {
        unsupported()
    }

    async fn watch_environment_create(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::WatchEnvironmentCreateRequest>,
    ) -> ServiceResult<ServiceStream<proto::WatchEnvironmentCreateResponse>> {
        unsupported()
    }

    async fn stream_logs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, proto::StreamLogsRequest>,
    ) -> ServiceResult<ServiceStream<proto::StreamLogsResponse>> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use codewire_proto::codewire::v1::{
        EnvironmentServiceClient, EnvironmentSessionServiceClient, ExecServiceClient,
        FileServiceClient,
    };
    use connectrpc::Protocol;
    use connectrpc::client::{ClientConfig, Http2Connection};
    use prost::Message as _;

    use crate::uds::{bind_owner_only_listener, owner_only_connector, remove_bound_socket};

    #[test]
    fn generated_environment_routes_have_one_explicit_local_semantic() {
        let descriptor = prost_types::FileDescriptorSet::decode(
            include_bytes!("../../../codewire-proto/codewire_descriptor.bin").as_slice(),
        )
        .unwrap();
        let methods = descriptor
            .file
            .iter()
            .filter(|file| file.package.as_deref() == Some("codewire.v1"))
            .flat_map(|file| &file.service)
            .find(|service| service.name.as_deref() == Some("EnvironmentService"))
            .unwrap()
            .method
            .iter()
            .map(|method| method.name.as_deref().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        let semantics = ENVIRONMENT_RPC_SEMANTICS
            .iter()
            .map(|entry| entry.spec.method().to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(methods, semantics);
        assert_eq!(semantics.len(), ENVIRONMENT_RPC_SEMANTICS.len());
        assert_eq!(
            ENVIRONMENT_RPC_SEMANTICS
                .iter()
                .filter(|entry| entry.behavior == RpcBehavior::Local)
                .count(),
            13
        );
    }

    #[test]
    fn implemented_public_messages_have_exhaustive_field_semantics() {
        let descriptor = prost_types::FileDescriptorSet::decode(
            include_bytes!("../../../codewire-proto/codewire_descriptor.bin").as_slice(),
        )
        .unwrap();
        let messages = descriptor
            .file
            .iter()
            .flat_map(|file| {
                let package = file.package.as_deref().unwrap_or_default();
                file.message_type.iter().map(move |message| {
                    (
                        format!("{package}.{}", message.name.as_deref().unwrap()),
                        message,
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        let semantics = PUBLIC_MESSAGE_SEMANTICS
            .iter()
            .map(|message| (message.full_name, message))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(semantics.len(), PUBLIC_MESSAGE_SEMANTICS.len());

        for (full_name, expected) in &semantics {
            let descriptor = messages
                .get(*full_name)
                .unwrap_or_else(|| panic!("missing generated message descriptor for {full_name}"));
            let actual_fields = descriptor
                .field
                .iter()
                .map(|field| {
                    (
                        field.number.unwrap(),
                        field.name.as_deref().unwrap().to_owned(),
                    )
                })
                .collect::<BTreeSet<_>>();
            let expected_fields = expected
                .fields
                .iter()
                .map(|field| (field.number, field.name.to_owned()))
                .collect::<BTreeSet<_>>();
            assert_eq!(actual_fields, expected_fields, "{full_name}");
            assert_eq!(expected_fields.len(), expected.fields.len(), "{full_name}");

            for field_semantics in expected
                .fields
                .iter()
                .filter(|field| field.behavior == FieldBehavior::Local)
            {
                let field = descriptor
                    .field
                    .iter()
                    .find(|field| field.number == Some(field_semantics.number))
                    .unwrap();
                if field.r#type == Some(prost_types::field_descriptor_proto::Type::Message as i32)
                    && field
                        .type_name
                        .as_deref()
                        .is_some_and(|name| name.starts_with(".codewire.v1."))
                {
                    let nested = field.type_name.as_deref().unwrap().trim_start_matches('.');
                    assert!(
                        semantics.contains_key(nested),
                        "local field {full_name}.{} lacks nested semantics for {nested}",
                        field_semantics.name
                    );
                }
            }
        }

        let environment_service = descriptor
            .file
            .iter()
            .filter(|file| file.package.as_deref() == Some("codewire.v1"))
            .flat_map(|file| &file.service)
            .find(|service| service.name.as_deref() == Some("EnvironmentService"))
            .unwrap();
        for rpc in ENVIRONMENT_RPC_SEMANTICS
            .iter()
            .filter(|rpc| rpc.behavior == RpcBehavior::Local)
        {
            let method = environment_service
                .method
                .iter()
                .find(|method| method.name.as_deref() == Some(rpc.spec.method()))
                .unwrap();
            for message in [method.input_type.as_deref(), method.output_type.as_deref()] {
                let full_name = message.unwrap().trim_start_matches('.');
                assert!(
                    semantics.contains_key(full_name),
                    "implemented RPC {} lacks field semantics for {full_name}",
                    rpc.spec.method()
                );
            }
        }
    }

    #[test]
    fn connect_content_type_policy_never_admits_grpc_or_grpc_web() {
        for allowed in [
            "application/connect+json",
            "application/connect+proto",
            "application/json; charset=utf-8",
            "application/proto",
        ] {
            assert!(connect_content_type(
                &HeaderValue::from_str(allowed).unwrap()
            ));
        }
        for rejected in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc-web",
            "application/grpc-web+proto",
            "text/plain",
        ] {
            assert!(!connect_content_type(
                &HeaderValue::from_str(rejected).unwrap()
            ));
        }
    }

    #[test]
    fn public_source_metadata_is_exact_and_never_projects_the_rest_of_project_configuration() {
        let mut environment = super::super::tests::project_environment();
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(environment.project_spec_json.as_deref().unwrap()).unwrap();
        project.environment.insert(
            "PRIVATE_CONFIGURATION".into(),
            "synthetic-configuration-sentinel".into(),
        );
        project.secrets.user = Some(codewire_project::StoragePlacement::Local);
        let json = project.canonical_json().unwrap();
        environment.project_spec_sha256 = Some(format!("{:x}", Sha256::digest(&json)));
        environment.project_spec_json = Some(json);
        let mut private = environment.proto(false);
        let public = public_environment(Uuid::new_v4(), &private).unwrap();
        assert_eq!(public.operation_generation, 1);
        assert_eq!(
            public.source_selection.secrets.user.unwrap().as_known(),
            Some(proto::ProjectStoragePlacement::Local)
        );
        assert!(!format!("{public:?}").contains("synthetic-configuration-sentinel"));
        private.project_spec_json.clear();
        private.project_spec_sha256.clear();
        assert!(public_source_selection(&private).unwrap().is_none());
    }

    #[test]
    fn public_source_update_requires_complete_sets_and_exact_generation_without_defaults() {
        let environment = super::super::tests::project_environment().proto(false);
        let current = public_source_selection(&environment).unwrap().unwrap();
        let mut request = proto::UpdateEnvironmentSourcesRequest {
            expected_operation_generation: environment.generation,
            expected: Some(current.clone()).into(),
            replacement: Some(current).into(),
            ..Default::default()
        };
        assert!(native_source_replacement(&request, &environment).unwrap().2);
        request.replacement = None.into();
        assert!(native_source_replacement(&request, &environment).is_err());
        request.replacement = Some(proto::EnvironmentSourceSelection {
            secrets: Some(proto::ProjectSecretBindings {
                user: Some(proto::ProjectStoragePlacement::Local.into()),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        })
        .into();
        let (target, revision, unchanged) =
            native_source_replacement(&request, &environment).unwrap();
        assert!(!unchanged);
        assert!(revision.is_none());
        assert_eq!(
            target.secrets.user,
            Some(codewire_project::StoragePlacement::Local)
        );
        request.expected_operation_generation += 1;
        assert!(native_source_replacement(&request, &environment).is_err());
        request.expected_operation_generation = environment.generation;
        request.expected = request.replacement.clone();
        assert!(native_source_replacement(&request, &environment).is_err());
        let invalid = proto::EnvironmentSourceSelection {
            secrets: Some(proto::ProjectSecretBindings {
                user: Some(proto::ProjectStoragePlacement::Unspecified.into()),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(source_selection_model(invalid).is_err());
        let incomplete_profile = proto::EnvironmentSourceSelection {
            credentials: Some(proto::ProjectCredentialBinding {
                profile: "local:id:11111111-1111-4111-8111-111111111111".into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(source_selection_model(incomplete_profile).is_err());
    }

    #[test]
    fn public_source_clear_is_complete_and_new_platform_authority_is_never_inferred() {
        let mut environment = super::super::tests::project_environment().proto(false);
        let mut project: codewire_project::ProjectSpec =
            serde_json::from_slice(&environment.project_spec_json).unwrap();
        project.secrets.user = Some(codewire_project::StoragePlacement::Local);
        environment.project_spec_json = project.canonical_json().unwrap();
        environment.project_spec_sha256 =
            format!("{:x}", Sha256::digest(&environment.project_spec_json));
        let request = proto::UpdateEnvironmentSourcesRequest {
            expected_operation_generation: environment.generation,
            expected: public_source_selection(&environment).unwrap().into(),
            replacement: Some(proto::EnvironmentSourceSelection::default()).into(),
            ..Default::default()
        };
        let (cleared, revision, unchanged) =
            native_source_replacement(&request, &environment).unwrap();
        assert!(cleared.secrets.is_empty());
        assert!(cleared.credentials.is_none());
        assert!(revision.is_none());
        assert!(!unchanged);
        project.secrets.user = Some(codewire_project::StoragePlacement::Platform);
        assert!(native_platform_source_authority(&project, &environment).is_err());
        let authority = v1::PlatformSourceAuthority {
            anthropic_form: String::new(),
            server_url: "https://synthetic.invalid".into(),
            organization_id: "org".into(),
            user_id: "owner".into(),
            profile_slots: Vec::new(),
        };
        environment.platform_source_authority = Some(authority.clone());
        assert_eq!(
            native_platform_source_authority(&project, &environment).unwrap(),
            Some(authority)
        );
        assert!(
            native_platform_source_authority(&cleared, &environment)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn real_public_uds_source_update_uses_the_durable_native_operation_and_complete_cas() {
        let (_parent, core) =
            super::super::tests::test_supervisor_core(super::super::tests::project_environment());
        let socket = core.config.supervisor_socket();
        let environment_id = core.environment("dev").unwrap().id.to_string();
        let service = super::super::tests::test_supervisor_service(core);
        let namespace = service.public_namespace_id().await.unwrap();
        let (identity, shutdown, server) =
            super::super::tests::spawn_test_supervisor_server(&socket, service.clone());
        let authority: http::Uri = "http://codewire-local-control".parse().unwrap();
        let transport = Http2Connection::connect_with_connector(
            owner_only_connector(&socket).unwrap(),
            authority.clone(),
        )
        .await
        .unwrap()
        .shared(32);
        let client = EnvironmentServiceClient::new(transport, ClientConfig::new(authority).proto());
        let mut request = proto::UpdateEnvironmentSourcesRequest {
            org_id: namespace.to_string(),
            environment_id: environment_id.clone(),
            expected_operation_generation: 1,
            expected: Some(proto::EnvironmentSourceSelection::default()).into(),
            replacement: Some(proto::EnvironmentSourceSelection {
                secrets: Some(proto::ProjectSecretBindings {
                    user: Some(proto::ProjectStoragePlacement::Local.into()),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let denied = client
            .update_environment_sources(request.clone())
            .await
            .unwrap_err();
        assert_eq!(denied.code, connectrpc::ErrorCode::FailedPrecondition);
        assert!(
            service
                .supervisor
                .core()
                .store
                .pending_operations()
                .unwrap()
                .is_empty()
        );
        request.confirm_personal_secrets = true;
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            client.update_environment_sources(request.clone()),
        )
        .await
        .unwrap()
        .unwrap()
        .into_owned();
        assert_eq!(result.operation_generation, 2);
        assert_eq!(
            result.outcome.as_known(),
            Some(proto::EnvironmentSourcesUpdateOutcome::Stored)
        );
        assert_eq!(result.selection, request.replacement);
        let stale = client
            .update_environment_sources(request.clone())
            .await
            .unwrap_err();
        assert_eq!(stale.code, connectrpc::ErrorCode::FailedPrecondition);
        request.expected_operation_generation = 2;
        request.expected = request.replacement.clone();
        let unchanged = client
            .update_environment_sources(request)
            .await
            .unwrap()
            .into_owned();
        assert_eq!(unchanged.operation_generation, 2);
        assert_eq!(
            unchanged.outcome.as_known(),
            Some(proto::EnvironmentSourcesUpdateOutcome::Unchanged)
        );
        let current = client
            .get_environment(proto::GetEnvironmentRequest {
                org_id: namespace.to_string(),
                environment_id,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(current.environment.operation_generation, 2);
        assert_eq!(current.environment.source_selection, result.selection);
        assert_eq!(
            current.environment.state.as_known(),
            Some(proto::EnvironmentState::Stopped)
        );
        drop(client);
        shutdown.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &identity).unwrap();
    }

    #[test]
    fn daemon_status_projection_never_reflects_guest_controlled_text() {
        let sentinel = "guest-bearer-and-terminal-sentinel\u{1b}[31m";
        let capabilities = daemon_v1::GetCapabilitiesResponse {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            minimum_protocol_version: DAEMON_MINIMUM_PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: REQUIRED_LOCAL_DAEMON_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .chain([sentinel.to_owned()])
                .collect(),
            state: daemon_v1::DaemonState::Ready as i32,
            message: sentinel.to_owned(),
        };
        let health = daemon_v1::GetHealthResponse {
            state: daemon_v1::DaemonState::Ready as i32,
            message: sentinel.to_owned(),
            diagnostics: vec![daemon_v1::HealthDiagnostic {
                name: sentinel.to_owned(),
                healthy: false,
                message: sentinel.to_owned(),
            }],
        };

        let status = project_daemon_status(&capabilities, &health);
        assert_eq!(
            status.state.as_known(),
            Some(proto::EnvironmentDaemonState::Ready)
        );
        assert_eq!(status.capabilities, REQUIRED_LOCAL_DAEMON_CAPABILITIES);
        assert_eq!(status.message, "local environment daemon is ready");
        assert_eq!(status.diagnostics.len(), 1);
        assert_eq!(status.diagnostics[0].name, "daemon");
        assert!(status.diagnostics[0].healthy);
        assert!(!format!("{status:?}").contains(sentinel));

        for required in ["session_input.v1", "session_metadata.v1"] {
            let mut older = capabilities.clone();
            older.capabilities.retain(|value| value != required);
            let status = project_daemon_status(&older, &health);
            assert_eq!(
                status.state.as_known(),
                Some(proto::EnvironmentDaemonState::Unsupported),
                "missing {required} must not report the current session profile ready"
            );
            assert!(!status.diagnostics[0].healthy);
        }

        let mut incompatible = capabilities;
        incompatible.daemon_version = sentinel.to_owned();
        let status = project_daemon_status(&incompatible, &health);
        assert_eq!(
            status.state.as_known(),
            Some(proto::EnvironmentDaemonState::UpgradeRequired)
        );
        assert_eq!(status.daemon_version, env!("CARGO_PKG_VERSION"));
        assert!(!format!("{status:?}").contains(sentinel));
    }

    #[test]
    fn daemon_logs_render_only_trusted_journal_fields() {
        let sentinel = "guest-output-and-token-sentinel";
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            environment_id: Some(Uuid::new_v4()),
            kind: OperationKind::Create,
            phase: OperationPhase::Completed,
            checkpoint: 7,
            payload: serde_json::json!({"name": sentinel}),
            result: Some(serde_json::json!({"message": sentinel})),
            error_code: None,
            created_unix_ms: 1_000,
            updated_unix_ms: 2_000,
        };

        let logs = String::from_utf8(trusted_daemon_logs(&[operation]).unwrap()).unwrap();
        assert!(logs.contains("time_unix_ms=2000"));
        assert!(logs.contains("kind=create"));
        assert!(logs.contains("phase=completed"));
        assert!(logs.contains("stage=OPERATION_STAGE_COMPLETED"));
        assert!(!logs.contains(sentinel));
        assert!(logs.len() <= MAXIMUM_DAEMON_LOG_BYTES);
    }

    #[test]
    fn public_resize_identity_and_resources_round_trip_through_the_durable_operation() {
        let environment = super::super::tests::project_environment();
        let private_environment = environment.proto(false);
        let namespace = Uuid::new_v4();
        let public_request_id = "codex-profile:secondary";
        let durable_request_id =
            deterministic_request_id(namespace, environment.id, public_request_id);
        assert_eq!(
            durable_request_id,
            deterministic_request_id(namespace, environment.id, public_request_id)
        );
        assert_ne!(
            durable_request_id,
            deterministic_request_id(namespace, environment.id, "codex-profile:primary")
        );
        let operation = OperationRecord {
            operation_id: Uuid::new_v4(),
            request_id: durable_request_id,
            environment_id: Some(environment.id),
            kind: OperationKind::Restart,
            phase: OperationPhase::Intent,
            checkpoint: 0,
            payload: serde_json::json!({
                "name": "dev",
                "vcpus": 3,
                "memory_mib": 24 * 1024,
                "disk_bytes": 24 * GIB,
                "was_running": false,
                "previous_vcpus": 2,
                "previous_memory_mib": 16 * 1024,
                "previous_disk_bytes": 20 * GIB,
                "public_request_id": public_request_id,
                "public_disruption_policy": "allow_restart",
            }),
            result: None,
            error_code: None,
            created_unix_ms: 1_000,
            updated_unix_ms: 2_000,
        };

        let public = public_resize_operation(&operation, &private_environment).unwrap();
        assert_eq!(public.environment_id, environment.id.to_string());
        assert_eq!(public.request_id, public_request_id);
        assert_eq!(public.previous_resources.cpu_millicores, 2_000);
        assert_eq!(public.previous_resources.memory_mb, 16 * 1024);
        assert_eq!(public.previous_resources.disk_gb, 20);
        assert_eq!(public.desired_resources.cpu_millicores, 3_000);
        assert_eq!(public.desired_resources.memory_mb, 24 * 1024);
        assert_eq!(public.desired_resources.disk_gb, 24);
        assert_eq!(
            public.state.as_known(),
            Some(proto::EnvironmentResizeOperationState::Pending)
        );
        assert_eq!(
            public.disruption_policy.as_known(),
            Some(proto::EnvironmentResizeDisruptionPolicy::AllowRestart)
        );
        assert_eq!(
            public.planned_mode.as_known(),
            Some(proto::EnvironmentResizeExecutionMode::ApplyOnStart)
        );
        assert!(private_resources(2_000, 16 * 1024, 1024).is_ok());
        let too_large = private_resources(2_000, 16 * 1024, 1025).unwrap_err();
        assert_eq!(too_large.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn real_uds_connect_client_shares_the_owner_only_supervisor_endpoint() {
        let (parent, core) =
            super::super::tests::test_supervisor_core(super::super::tests::project_environment());
        let socket = core.config.supervisor_socket();
        let service = super::super::tests::test_supervisor_service(core);
        let namespace = service.public_namespace_id().await.unwrap();
        let (listener, socket_identity) = bind_owner_only_listener(&socket).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_service = service.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, supervisor_router(server_service))
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        let authority: http::Uri = "http://codewire-local-control".parse().unwrap();
        let transport = Http2Connection::connect_with_connector(
            owner_only_connector(&socket).unwrap(),
            authority.clone(),
        )
        .await
        .unwrap()
        .shared(32);
        let client = EnvironmentServiceClient::new(
            transport.clone(),
            ClientConfig::new(authority.clone()).proto(),
        );
        let listed = client
            .list_environments(proto::ListEnvironmentsRequest::default())
            .await
            .unwrap()
            .into_owned();
        assert_eq!(listed.environments.len(), 1);
        let listed_environment = &listed.environments[0];
        assert_eq!(listed_environment.org_id, namespace.to_string());
        assert_eq!(listed_environment.name, "dev");
        assert_eq!(listed_environment.r#type, "local");
        assert_eq!(listed_environment.cpu_millicores, 2_000);
        assert_eq!(listed_environment.memory_mb, 16 * 1024);
        assert_eq!(listed_environment.disk_gb, 20);
        assert_eq!(
            listed_environment.state.as_known(),
            Some(proto::EnvironmentState::Stopped)
        );
        let environment_id = listed_environment.id.clone();

        let fetched = client
            .get_environment(proto::GetEnvironmentRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(fetched.environment.id, environment_id);
        assert_eq!(fetched.environment.org_id, namespace.to_string());

        let daemon_status = client
            .get_environment_daemon_status(proto::GetEnvironmentDaemonStatusRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned()
            .status
            .into_option()
            .unwrap();
        assert_eq!(
            daemon_status.state.as_known(),
            Some(proto::EnvironmentDaemonState::Starting)
        );
        assert_eq!(daemon_status.message, "local environment is stopped");
        assert!(daemon_status.pod_name.is_empty());

        let mut daemon_logs = client
            .stream_environment_daemon_logs(proto::StreamEnvironmentDaemonLogsRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap();
        let daemon_logs = daemon_logs
            .message::<proto::StreamEnvironmentDaemonLogsResponse>()
            .await
            .unwrap()
            .unwrap()
            .to_owned_message();
        assert!(daemon_logs.data.is_empty());

        let repair_error = client
            .repair_environment_daemon(proto::RepairEnvironmentDaemonRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(repair_error.code, connectrpc::ErrorCode::FailedPrecondition);

        let plan = client
            .plan_environment_resize(proto::PlanEnvironmentResizeRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                cpu_millicores: 3_000,
                memory_mb: 16 * 1024,
                disk_gb: 20,
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(
            plan.plan.execution_mode.as_known(),
            Some(proto::EnvironmentResizeExecutionMode::ApplyOnStart)
        );

        let stopped = client
            .stop_environment(proto::StopEnvironmentRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap()
            .into_owned();
        assert_eq!(stopped.status, "stop requested");

        let create_error = client
            .create_environment(proto::CreateEnvironmentRequest::default())
            .await
            .unwrap_err();
        assert_eq!(create_error.code, connectrpc::ErrorCode::Unimplemented);

        let sessions = EnvironmentSessionServiceClient::new(
            transport.clone(),
            ClientConfig::new(authority.clone()).proto(),
        );
        let stopped_error = sessions
            .list_sessions(proto::ListSessionsRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(
            stopped_error.code,
            connectrpc::ErrorCode::FailedPrecondition
        );
        assert_eq!(
            stopped_error.message.as_deref(),
            Some("local environment is not in the required state")
        );

        let exec = ExecServiceClient::new(
            transport.clone(),
            ClientConfig::new(authority.clone()).proto(),
        );
        let stopped_error = exec
            .exec(proto::ExecRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                command: vec!["true".to_owned()],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(
            stopped_error.code,
            connectrpc::ErrorCode::FailedPrecondition
        );
        assert_eq!(
            stopped_error.message.as_deref(),
            Some("local environment is not in the required state")
        );

        let files = FileServiceClient::new(transport, ClientConfig::new(authority.clone()).proto());
        let stopped_error = files
            .list_files(proto::ListFilesRequest {
                org_id: namespace.to_string(),
                environment_id: environment_id.clone(),
                path: "/workspace".to_owned(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(
            stopped_error.code,
            connectrpc::ErrorCode::FailedPrecondition
        );
        assert_eq!(
            stopped_error.message.as_deref(),
            Some("local environment is not in the required state")
        );

        drop(client);
        let grpc_transport = Http2Connection::connect_with_connector(
            owner_only_connector(&socket).unwrap(),
            authority.clone(),
        )
        .await
        .unwrap()
        .shared(32);
        let grpc_client = EnvironmentServiceClient::new(
            grpc_transport,
            ClientConfig::new(authority)
                .with_protocol(Protocol::Grpc)
                .proto(),
        );
        assert!(
            grpc_client
                .list_environments(proto::ListEnvironmentsRequest::default())
                .await
                .is_err()
        );

        drop(grpc_client);
        shutdown_tx.send(()).unwrap();
        server.await.unwrap();
        remove_bound_socket(&socket, &socket_identity).unwrap();
        drop(parent);
    }
}
