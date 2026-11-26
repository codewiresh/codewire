//! What each public EnvironmentService method and message field means for a
//! local VM: served from local state, or refused as platform-only.

use codewire_proto::codewire::v1 as proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RpcBehavior {
    Local,
    UnimplementedPlatformOnly,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RpcSemantics {
    pub(super) spec: connectrpc::Spec,
    pub(super) behavior: RpcBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FieldBehavior {
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
pub(super) struct FieldSemantics {
    pub(super) number: i32,
    pub(super) name: &'static str,
    pub(super) behavior: FieldBehavior,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct MessageSemantics {
    pub(super) full_name: &'static str,
    pub(super) fields: &'static [FieldSemantics],
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
    // A local VM's Mesh attachment is reported by its supervisor's own control API, never
    // through this public view: like `network`, the hosted attachment state stays absent (#3350).
    field(35, "network_state", ZERO),
    field(36, "network_failure", ZERO),
    field(37, "error_code", ZERO),
    // A local VM's network policy is reported by its supervisor's own control
    // API (`EnvironmentNetworkPolicy` there); this public view leaves the
    // hosted one absent (#4000).
    field(38, "network_policy", ZERO),
    // A local VM is stopped only by its user; there is no reason to report.
    field(39, "stop_reason", ZERO),
    // A local VM never stops itself for being idle, so says nothing of it (#3384).
    field(40, "idle_stop_seconds", ZERO),
    field(41, "idle_stop_enforced", ZERO),
    // Only the platform records an unplanned restart; a local VM reports none (#5997).
    field(43, "restarted_at", ZERO),
    field(44, "restart_cause", ZERO),
    // A local VM runs on this computer, not on an enrolled host (#3609).
    field(45, "host", ZERO),
    // Only a `standard` cloud sandbox suspends; a local VM never does (#5529).
    field(46, "idle_suspend_seconds", ZERO),
    field(47, "suspended_at", ZERO),
];

pub(super) const PUBLIC_MESSAGE_SEMANTICS: &[MessageSemantics] = &[
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
            field(7, "include_failed_creates", ZERO),
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
        // A local start writes no `complete` log row (#3938).
        fields: &[
            field(1, "status", FIXED),
            field(2, "outcome", LOCAL),
            field(3, "completes_with_log", ZERO),
        ],
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

pub(super) const ENVIRONMENT_RPC_SEMANTICS: &[RpcSemantics] = &[
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
        proto::ENVIRONMENT_SERVICE_SET_ENVIRONMENT_IDLE_STOP_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_SET_ENVIRONMENT_IDLE_SUSPEND_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_SET_ENVIRONMENT_STARTUP_SCRIPT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_TRUST_REPORT_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
    ),
    rpc(
        proto::ENVIRONMENT_SERVICE_GET_ENVIRONMENT_PROJECT_SPEC_SPEC,
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
    // Retry setup runs the hosted setup worker (#4767).
    rpc(
        proto::ENVIRONMENT_SERVICE_RETRY_ENVIRONMENT_SETUP_SPEC,
        RpcBehavior::UnimplementedPlatformOnly,
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
