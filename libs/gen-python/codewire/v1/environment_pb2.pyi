import datetime

from codewire.v1 import common_pb2 as _common_pb2
from codewire.v1 import port_pb2 as _port_pb2
from codewire.v1 import preset_pb2 as _preset_pb2
from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_STATE_UNSPECIFIED: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_PENDING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_PENDING_BUILD: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_BUILDING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_BUILD_FAILED: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_PULLING_SNAPSHOT: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_CREATING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_STARTING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_RUNNING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_STOPPING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_STOPPED: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_ARCHIVING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_ARCHIVED: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_RESTORING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_RESIZING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_DESTROYING: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_DESTROYED: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_ERROR: _ClassVar[EnvironmentState]
    ENVIRONMENT_STATE_UNKNOWN: _ClassVar[EnvironmentState]

class DesiredState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DESIRED_STATE_UNSPECIFIED: _ClassVar[DesiredState]
    DESIRED_STATE_STARTED: _ClassVar[DesiredState]
    DESIRED_STATE_STOPPED: _ClassVar[DesiredState]
    DESIRED_STATE_DESTROYED: _ClassVar[DesiredState]
    DESIRED_STATE_ARCHIVED: _ClassVar[DesiredState]
    DESIRED_STATE_RESIZED: _ClassVar[DesiredState]

class IsolationTier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ISOLATION_TIER_UNSPECIFIED: _ClassVar[IsolationTier]
    ISOLATION_TIER_STANDARD: _ClassVar[IsolationTier]
    ISOLATION_TIER_CONFIDENTIAL: _ClassVar[IsolationTier]

class EnvironmentSourcesUpdateOutcome(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNSPECIFIED: _ClassVar[EnvironmentSourcesUpdateOutcome]
    ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNCHANGED: _ClassVar[EnvironmentSourcesUpdateOutcome]
    ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED: _ClassVar[EnvironmentSourcesUpdateOutcome]
    ENVIRONMENT_SOURCES_UPDATE_OUTCOME_RESTART_REQUIRED: _ClassVar[EnvironmentSourcesUpdateOutcome]

class EnvironmentResizeOperationState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_RESIZE_OPERATION_STATE_UNSPECIFIED: _ClassVar[EnvironmentResizeOperationState]
    ENVIRONMENT_RESIZE_OPERATION_STATE_PENDING: _ClassVar[EnvironmentResizeOperationState]
    ENVIRONMENT_RESIZE_OPERATION_STATE_APPLYING: _ClassVar[EnvironmentResizeOperationState]
    ENVIRONMENT_RESIZE_OPERATION_STATE_RESTARTING: _ClassVar[EnvironmentResizeOperationState]
    ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED: _ClassVar[EnvironmentResizeOperationState]
    ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED: _ClassVar[EnvironmentResizeOperationState]

class EnvironmentResizeDisruptionPolicy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_RESIZE_DISRUPTION_POLICY_UNSPECIFIED: _ClassVar[EnvironmentResizeDisruptionPolicy]
    ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY: _ClassVar[EnvironmentResizeDisruptionPolicy]
    ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART: _ClassVar[EnvironmentResizeDisruptionPolicy]

class EnvironmentResizeExecutionMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_RESIZE_EXECUTION_MODE_UNSPECIFIED: _ClassVar[EnvironmentResizeExecutionMode]
    ENVIRONMENT_RESIZE_EXECUTION_MODE_NOOP: _ClassVar[EnvironmentResizeExecutionMode]
    ENVIRONMENT_RESIZE_EXECUTION_MODE_APPLY_ON_START: _ClassVar[EnvironmentResizeExecutionMode]
    ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE: _ClassVar[EnvironmentResizeExecutionMode]
    ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART: _ClassVar[EnvironmentResizeExecutionMode]

class StartOutcome(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    START_OUTCOME_UNSPECIFIED: _ClassVar[StartOutcome]
    START_OUTCOME_STARTED: _ClassVar[StartOutcome]
    START_OUTCOME_RETRIED: _ClassVar[StartOutcome]

class AccessPermission(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACCESS_PERMISSION_UNSPECIFIED: _ClassVar[AccessPermission]
    ACCESS_PERMISSION_VIEWER: _ClassVar[AccessPermission]
    ACCESS_PERMISSION_OPERATOR: _ClassVar[AccessPermission]
    ACCESS_PERMISSION_OWNER: _ClassVar[AccessPermission]

class EnvironmentDaemonState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_DAEMON_STATE_UNSPECIFIED: _ClassVar[EnvironmentDaemonState]
    ENVIRONMENT_DAEMON_STATE_UNSUPPORTED: _ClassVar[EnvironmentDaemonState]
    ENVIRONMENT_DAEMON_STATE_STARTING: _ClassVar[EnvironmentDaemonState]
    ENVIRONMENT_DAEMON_STATE_READY: _ClassVar[EnvironmentDaemonState]
    ENVIRONMENT_DAEMON_STATE_UNHEALTHY: _ClassVar[EnvironmentDaemonState]
    ENVIRONMENT_DAEMON_STATE_UPGRADE_REQUIRED: _ClassVar[EnvironmentDaemonState]
ENVIRONMENT_STATE_UNSPECIFIED: EnvironmentState
ENVIRONMENT_STATE_PENDING: EnvironmentState
ENVIRONMENT_STATE_PENDING_BUILD: EnvironmentState
ENVIRONMENT_STATE_BUILDING: EnvironmentState
ENVIRONMENT_STATE_BUILD_FAILED: EnvironmentState
ENVIRONMENT_STATE_PULLING_SNAPSHOT: EnvironmentState
ENVIRONMENT_STATE_CREATING: EnvironmentState
ENVIRONMENT_STATE_STARTING: EnvironmentState
ENVIRONMENT_STATE_RUNNING: EnvironmentState
ENVIRONMENT_STATE_STOPPING: EnvironmentState
ENVIRONMENT_STATE_STOPPED: EnvironmentState
ENVIRONMENT_STATE_ARCHIVING: EnvironmentState
ENVIRONMENT_STATE_ARCHIVED: EnvironmentState
ENVIRONMENT_STATE_RESTORING: EnvironmentState
ENVIRONMENT_STATE_RESIZING: EnvironmentState
ENVIRONMENT_STATE_DESTROYING: EnvironmentState
ENVIRONMENT_STATE_DESTROYED: EnvironmentState
ENVIRONMENT_STATE_ERROR: EnvironmentState
ENVIRONMENT_STATE_UNKNOWN: EnvironmentState
DESIRED_STATE_UNSPECIFIED: DesiredState
DESIRED_STATE_STARTED: DesiredState
DESIRED_STATE_STOPPED: DesiredState
DESIRED_STATE_DESTROYED: DesiredState
DESIRED_STATE_ARCHIVED: DesiredState
DESIRED_STATE_RESIZED: DesiredState
ISOLATION_TIER_UNSPECIFIED: IsolationTier
ISOLATION_TIER_STANDARD: IsolationTier
ISOLATION_TIER_CONFIDENTIAL: IsolationTier
ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNSPECIFIED: EnvironmentSourcesUpdateOutcome
ENVIRONMENT_SOURCES_UPDATE_OUTCOME_UNCHANGED: EnvironmentSourcesUpdateOutcome
ENVIRONMENT_SOURCES_UPDATE_OUTCOME_STORED: EnvironmentSourcesUpdateOutcome
ENVIRONMENT_SOURCES_UPDATE_OUTCOME_RESTART_REQUIRED: EnvironmentSourcesUpdateOutcome
ENVIRONMENT_RESIZE_OPERATION_STATE_UNSPECIFIED: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_OPERATION_STATE_PENDING: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_OPERATION_STATE_APPLYING: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_OPERATION_STATE_RESTARTING: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_OPERATION_STATE_COMPLETED: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_OPERATION_STATE_FAILED: EnvironmentResizeOperationState
ENVIRONMENT_RESIZE_DISRUPTION_POLICY_UNSPECIFIED: EnvironmentResizeDisruptionPolicy
ENVIRONMENT_RESIZE_DISRUPTION_POLICY_LIVE_ONLY: EnvironmentResizeDisruptionPolicy
ENVIRONMENT_RESIZE_DISRUPTION_POLICY_ALLOW_RESTART: EnvironmentResizeDisruptionPolicy
ENVIRONMENT_RESIZE_EXECUTION_MODE_UNSPECIFIED: EnvironmentResizeExecutionMode
ENVIRONMENT_RESIZE_EXECUTION_MODE_NOOP: EnvironmentResizeExecutionMode
ENVIRONMENT_RESIZE_EXECUTION_MODE_APPLY_ON_START: EnvironmentResizeExecutionMode
ENVIRONMENT_RESIZE_EXECUTION_MODE_IN_PLACE: EnvironmentResizeExecutionMode
ENVIRONMENT_RESIZE_EXECUTION_MODE_RESTART: EnvironmentResizeExecutionMode
START_OUTCOME_UNSPECIFIED: StartOutcome
START_OUTCOME_STARTED: StartOutcome
START_OUTCOME_RETRIED: StartOutcome
ACCESS_PERMISSION_UNSPECIFIED: AccessPermission
ACCESS_PERMISSION_VIEWER: AccessPermission
ACCESS_PERMISSION_OPERATOR: AccessPermission
ACCESS_PERMISSION_OWNER: AccessPermission
ENVIRONMENT_DAEMON_STATE_UNSPECIFIED: EnvironmentDaemonState
ENVIRONMENT_DAEMON_STATE_UNSUPPORTED: EnvironmentDaemonState
ENVIRONMENT_DAEMON_STATE_STARTING: EnvironmentDaemonState
ENVIRONMENT_DAEMON_STATE_READY: EnvironmentDaemonState
ENVIRONMENT_DAEMON_STATE_UNHEALTHY: EnvironmentDaemonState
ENVIRONMENT_DAEMON_STATE_UPGRADE_REQUIRED: EnvironmentDaemonState

class Environment(_message.Message):
    __slots__ = ("id", "org_id", "created_by", "preset_id", "type", "name", "state", "desired_state", "error_reason", "recoverable", "state_changed_at", "retry_count", "setup_phase", "setup_complete", "setup_error", "ttl_seconds", "shutdown_at", "cpu_millicores", "memory_mb", "disk_gb", "total_running_seconds", "created_at", "started_at", "stopped_at", "destroyed_at", "protected", "deletion_requested_at", "deletion_grace_until", "preset_name", "network", "ports", "isolation_tier", "operation_generation", "source_selection")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    DESIRED_STATE_FIELD_NUMBER: _ClassVar[int]
    ERROR_REASON_FIELD_NUMBER: _ClassVar[int]
    RECOVERABLE_FIELD_NUMBER: _ClassVar[int]
    STATE_CHANGED_AT_FIELD_NUMBER: _ClassVar[int]
    RETRY_COUNT_FIELD_NUMBER: _ClassVar[int]
    SETUP_PHASE_FIELD_NUMBER: _ClassVar[int]
    SETUP_COMPLETE_FIELD_NUMBER: _ClassVar[int]
    SETUP_ERROR_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    SHUTDOWN_AT_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_FIELD_NUMBER: _ClassVar[int]
    TOTAL_RUNNING_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    STOPPED_AT_FIELD_NUMBER: _ClassVar[int]
    DESTROYED_AT_FIELD_NUMBER: _ClassVar[int]
    PROTECTED_FIELD_NUMBER: _ClassVar[int]
    DELETION_REQUESTED_AT_FIELD_NUMBER: _ClassVar[int]
    DELETION_GRACE_UNTIL_FIELD_NUMBER: _ClassVar[int]
    PRESET_NAME_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    PORTS_FIELD_NUMBER: _ClassVar[int]
    ISOLATION_TIER_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_SELECTION_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    created_by: str
    preset_id: str
    type: str
    name: str
    state: EnvironmentState
    desired_state: DesiredState
    error_reason: str
    recoverable: bool
    state_changed_at: _timestamp_pb2.Timestamp
    retry_count: int
    setup_phase: int
    setup_complete: bool
    setup_error: str
    ttl_seconds: int
    shutdown_at: _timestamp_pb2.Timestamp
    cpu_millicores: int
    memory_mb: int
    disk_gb: int
    total_running_seconds: int
    created_at: _timestamp_pb2.Timestamp
    started_at: _timestamp_pb2.Timestamp
    stopped_at: _timestamp_pb2.Timestamp
    destroyed_at: _timestamp_pb2.Timestamp
    protected: bool
    deletion_requested_at: _timestamp_pb2.Timestamp
    deletion_grace_until: _timestamp_pb2.Timestamp
    preset_name: str
    network: str
    ports: _containers.RepeatedCompositeFieldContainer[_port_pb2.Port]
    isolation_tier: IsolationTier
    operation_generation: int
    source_selection: EnvironmentSourceSelection
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., created_by: _Optional[str] = ..., preset_id: _Optional[str] = ..., type: _Optional[str] = ..., name: _Optional[str] = ..., state: _Optional[_Union[EnvironmentState, str]] = ..., desired_state: _Optional[_Union[DesiredState, str]] = ..., error_reason: _Optional[str] = ..., recoverable: _Optional[bool] = ..., state_changed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., retry_count: _Optional[int] = ..., setup_phase: _Optional[int] = ..., setup_complete: _Optional[bool] = ..., setup_error: _Optional[str] = ..., ttl_seconds: _Optional[int] = ..., shutdown_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ..., total_running_seconds: _Optional[int] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., stopped_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., destroyed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protected: _Optional[bool] = ..., deletion_requested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., deletion_grace_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., preset_name: _Optional[str] = ..., network: _Optional[str] = ..., ports: _Optional[_Iterable[_Union[_port_pb2.Port, _Mapping]]] = ..., isolation_tier: _Optional[_Union[IsolationTier, str]] = ..., operation_generation: _Optional[int] = ..., source_selection: _Optional[_Union[EnvironmentSourceSelection, _Mapping]] = ...) -> None: ...

class ListEnvironmentsRequest(_message.Message):
    __slots__ = ("org_id", "type", "state", "include_destroyed", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_DESTROYED_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    type: str
    state: EnvironmentState
    include_destroyed: bool
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., type: _Optional[str] = ..., state: _Optional[_Union[EnvironmentState, str]] = ..., include_destroyed: _Optional[bool] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListEnvironmentsResponse(_message.Message):
    __slots__ = ("environments", "next_page_token", "poll_interval")
    ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    environments: _containers.RepeatedCompositeFieldContainer[Environment]
    next_page_token: str
    poll_interval: _duration_pb2.Duration
    def __init__(self, environments: _Optional[_Iterable[_Union[Environment, _Mapping]]] = ..., next_page_token: _Optional[str] = ..., poll_interval: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class CreateEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "preset_id", "name", "ttl_seconds", "isolation_tier", "project_spec", "expected_profile_revision", "confirm_personal_credentials", "confirm_personal_secrets", "omit_application_previews")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    ISOLATION_TIER_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PROFILE_REVISION_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_PERSONAL_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_PERSONAL_SECRETS_FIELD_NUMBER: _ClassVar[int]
    OMIT_APPLICATION_PREVIEWS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    name: str
    ttl_seconds: int
    isolation_tier: IsolationTier
    project_spec: _common_pb2.ProjectSpec
    expected_profile_revision: int
    confirm_personal_credentials: bool
    confirm_personal_secrets: bool
    omit_application_previews: bool
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ..., name: _Optional[str] = ..., ttl_seconds: _Optional[int] = ..., isolation_tier: _Optional[_Union[IsolationTier, str]] = ..., project_spec: _Optional[_Union[_common_pb2.ProjectSpec, _Mapping]] = ..., expected_profile_revision: _Optional[int] = ..., confirm_personal_credentials: _Optional[bool] = ..., confirm_personal_secrets: _Optional[bool] = ..., omit_application_previews: _Optional[bool] = ...) -> None: ...

class EnvironmentSourceSelection(_message.Message):
    __slots__ = ("secrets", "credentials", "profile_revision")
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    PROFILE_REVISION_FIELD_NUMBER: _ClassVar[int]
    secrets: _common_pb2.ProjectSecretBindings
    credentials: _common_pb2.ProjectCredentialBinding
    profile_revision: int
    def __init__(self, secrets: _Optional[_Union[_common_pb2.ProjectSecretBindings, _Mapping]] = ..., credentials: _Optional[_Union[_common_pb2.ProjectCredentialBinding, _Mapping]] = ..., profile_revision: _Optional[int] = ...) -> None: ...

class UpdateEnvironmentSourcesRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "expected_operation_generation", "expected", "replacement", "allow_restart", "confirm_personal_credentials", "confirm_personal_secrets")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_FIELD_NUMBER: _ClassVar[int]
    REPLACEMENT_FIELD_NUMBER: _ClassVar[int]
    ALLOW_RESTART_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_PERSONAL_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_PERSONAL_SECRETS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    expected_operation_generation: int
    expected: EnvironmentSourceSelection
    replacement: EnvironmentSourceSelection
    allow_restart: bool
    confirm_personal_credentials: bool
    confirm_personal_secrets: bool
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., expected_operation_generation: _Optional[int] = ..., expected: _Optional[_Union[EnvironmentSourceSelection, _Mapping]] = ..., replacement: _Optional[_Union[EnvironmentSourceSelection, _Mapping]] = ..., allow_restart: _Optional[bool] = ..., confirm_personal_credentials: _Optional[bool] = ..., confirm_personal_secrets: _Optional[bool] = ...) -> None: ...

class UpdateEnvironmentSourcesResponse(_message.Message):
    __slots__ = ("environment_id", "operation_generation", "selection", "outcome")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    SELECTION_FIELD_NUMBER: _ClassVar[int]
    OUTCOME_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    operation_generation: int
    selection: EnvironmentSourceSelection
    outcome: EnvironmentSourcesUpdateOutcome
    def __init__(self, environment_id: _Optional[str] = ..., operation_generation: _Optional[int] = ..., selection: _Optional[_Union[EnvironmentSourceSelection, _Mapping]] = ..., outcome: _Optional[_Union[EnvironmentSourcesUpdateOutcome, str]] = ...) -> None: ...

class CreateEnvironmentResponse(_message.Message):
    __slots__ = ("environment",)
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    environment: Environment
    def __init__(self, environment: _Optional[_Union[Environment, _Mapping]] = ...) -> None: ...

class GetEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentResponse(_message.Message):
    __slots__ = ("environment", "poll_interval")
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    environment: Environment
    poll_interval: _duration_pb2.Duration
    def __init__(self, environment: _Optional[_Union[Environment, _Mapping]] = ..., poll_interval: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class EnvironmentResources(_message.Message):
    __slots__ = ("cpu_millicores", "memory_mb", "disk_gb")
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_FIELD_NUMBER: _ClassVar[int]
    cpu_millicores: int
    memory_mb: int
    disk_gb: int
    def __init__(self, cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ...) -> None: ...

class EnvironmentResizePlan(_message.Message):
    __slots__ = ("previous_resources", "desired_resources", "execution_mode", "active_session_count", "active_sessions_will_be_terminated", "reason", "warnings")
    PREVIOUS_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    DESIRED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    EXECUTION_MODE_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SESSION_COUNT_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SESSIONS_WILL_BE_TERMINATED_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    previous_resources: EnvironmentResources
    desired_resources: EnvironmentResources
    execution_mode: EnvironmentResizeExecutionMode
    active_session_count: int
    active_sessions_will_be_terminated: bool
    reason: str
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, previous_resources: _Optional[_Union[EnvironmentResources, _Mapping]] = ..., desired_resources: _Optional[_Union[EnvironmentResources, _Mapping]] = ..., execution_mode: _Optional[_Union[EnvironmentResizeExecutionMode, str]] = ..., active_session_count: _Optional[int] = ..., active_sessions_will_be_terminated: _Optional[bool] = ..., reason: _Optional[str] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class EnvironmentResizeFailure(_message.Message):
    __slots__ = ("code", "message")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    code: str
    message: str
    def __init__(self, code: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class EnvironmentResizeOperation(_message.Message):
    __slots__ = ("id", "environment_id", "request_id", "previous_resources", "desired_resources", "last_applied_resources", "state", "failure", "created_at", "updated_at", "completed_at", "disruption_policy", "planned_mode", "applied_mode", "pod_replaced")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    DESIRED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    LAST_APPLIED_RESOURCES_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    COMPLETED_AT_FIELD_NUMBER: _ClassVar[int]
    DISRUPTION_POLICY_FIELD_NUMBER: _ClassVar[int]
    PLANNED_MODE_FIELD_NUMBER: _ClassVar[int]
    APPLIED_MODE_FIELD_NUMBER: _ClassVar[int]
    POD_REPLACED_FIELD_NUMBER: _ClassVar[int]
    id: str
    environment_id: str
    request_id: str
    previous_resources: EnvironmentResources
    desired_resources: EnvironmentResources
    last_applied_resources: EnvironmentResources
    state: EnvironmentResizeOperationState
    failure: EnvironmentResizeFailure
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    completed_at: _timestamp_pb2.Timestamp
    disruption_policy: EnvironmentResizeDisruptionPolicy
    planned_mode: EnvironmentResizeExecutionMode
    applied_mode: EnvironmentResizeExecutionMode
    pod_replaced: bool
    def __init__(self, id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ..., previous_resources: _Optional[_Union[EnvironmentResources, _Mapping]] = ..., desired_resources: _Optional[_Union[EnvironmentResources, _Mapping]] = ..., last_applied_resources: _Optional[_Union[EnvironmentResources, _Mapping]] = ..., state: _Optional[_Union[EnvironmentResizeOperationState, str]] = ..., failure: _Optional[_Union[EnvironmentResizeFailure, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., completed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., disruption_policy: _Optional[_Union[EnvironmentResizeDisruptionPolicy, str]] = ..., planned_mode: _Optional[_Union[EnvironmentResizeExecutionMode, str]] = ..., applied_mode: _Optional[_Union[EnvironmentResizeExecutionMode, str]] = ..., pod_replaced: _Optional[bool] = ...) -> None: ...

class PlanEnvironmentResizeRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "cpu_millicores", "memory_mb", "disk_gb")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    cpu_millicores: int
    memory_mb: int
    disk_gb: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ...) -> None: ...

class PlanEnvironmentResizeResponse(_message.Message):
    __slots__ = ("plan", "environment")
    PLAN_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    plan: EnvironmentResizePlan
    environment: Environment
    def __init__(self, plan: _Optional[_Union[EnvironmentResizePlan, _Mapping]] = ..., environment: _Optional[_Union[Environment, _Mapping]] = ...) -> None: ...

class ResizeEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "cpu_millicores", "memory_mb", "disk_gb", "request_id", "force", "disruption_policy")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    FORCE_FIELD_NUMBER: _ClassVar[int]
    DISRUPTION_POLICY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    cpu_millicores: int
    memory_mb: int
    disk_gb: int
    request_id: str
    force: bool
    disruption_policy: EnvironmentResizeDisruptionPolicy
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ..., request_id: _Optional[str] = ..., force: _Optional[bool] = ..., disruption_policy: _Optional[_Union[EnvironmentResizeDisruptionPolicy, str]] = ...) -> None: ...

class ResizeEnvironmentResponse(_message.Message):
    __slots__ = ("operation", "environment", "poll_interval")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentResizeOperation
    environment: Environment
    poll_interval: _duration_pb2.Duration
    def __init__(self, operation: _Optional[_Union[EnvironmentResizeOperation, _Mapping]] = ..., environment: _Optional[_Union[Environment, _Mapping]] = ..., poll_interval: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class GetEnvironmentResizeOperationRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "operation_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    operation_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., operation_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentResizeOperationResponse(_message.Message):
    __slots__ = ("operation", "environment", "poll_interval")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    POLL_INTERVAL_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentResizeOperation
    environment: Environment
    poll_interval: _duration_pb2.Duration
    def __init__(self, operation: _Optional[_Union[EnvironmentResizeOperation, _Mapping]] = ..., environment: _Optional[_Union[Environment, _Mapping]] = ..., poll_interval: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class DeleteEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class DeleteEnvironmentResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class StopEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StopEnvironmentResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: str
    def __init__(self, status: _Optional[str] = ...) -> None: ...

class StartEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StartEnvironmentResponse(_message.Message):
    __slots__ = ("status", "outcome")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    OUTCOME_FIELD_NUMBER: _ClassVar[int]
    status: str
    outcome: StartOutcome
    def __init__(self, status: _Optional[str] = ..., outcome: _Optional[_Union[StartOutcome, str]] = ...) -> None: ...

class ProtectEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class ProtectEnvironmentResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: str
    def __init__(self, status: _Optional[str] = ...) -> None: ...

class UnprotectEnvironmentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class UnprotectEnvironmentResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: str
    def __init__(self, status: _Optional[str] = ...) -> None: ...

class CancelEnvironmentDeletionRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class CancelEnvironmentDeletionResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: str
    def __init__(self, status: _Optional[str] = ...) -> None: ...

class ExtendEnvironmentTtlRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "additional_seconds")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    additional_seconds: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., additional_seconds: _Optional[int] = ...) -> None: ...

class ExtendEnvironmentTtlResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: str
    def __init__(self, status: _Optional[str] = ...) -> None: ...

class AccessGrant(_message.Message):
    __slots__ = ("id", "environment_id", "user_id", "permission", "granted_by", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    GRANTED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    environment_id: str
    user_id: str
    permission: AccessPermission
    granted_by: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., environment_id: _Optional[str] = ..., user_id: _Optional[str] = ..., permission: _Optional[_Union[AccessPermission, str]] = ..., granted_by: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListEnvironmentAccessRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListEnvironmentAccessResponse(_message.Message):
    __slots__ = ("access_grants", "next_page_token")
    ACCESS_GRANTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    access_grants: _containers.RepeatedCompositeFieldContainer[AccessGrant]
    next_page_token: str
    def __init__(self, access_grants: _Optional[_Iterable[_Union[AccessGrant, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class GrantEnvironmentAccessRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "user_id", "permission")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    PERMISSION_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    user_id: str
    permission: AccessPermission
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., user_id: _Optional[str] = ..., permission: _Optional[_Union[AccessPermission, str]] = ...) -> None: ...

class GrantEnvironmentAccessResponse(_message.Message):
    __slots__ = ("access_grant",)
    ACCESS_GRANT_FIELD_NUMBER: _ClassVar[int]
    access_grant: AccessGrant
    def __init__(self, access_grant: _Optional[_Union[AccessGrant, _Mapping]] = ...) -> None: ...

class RevokeEnvironmentAccessRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "user_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    user_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., user_id: _Optional[str] = ...) -> None: ...

class RevokeEnvironmentAccessResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetEnvironmentTrustReportRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentTrustReportResponse(_message.Message):
    __slots__ = ("trust_report",)
    TRUST_REPORT_FIELD_NUMBER: _ClassVar[int]
    trust_report: EnvironmentTrustReport
    def __init__(self, trust_report: _Optional[_Union[EnvironmentTrustReport, _Mapping]] = ...) -> None: ...

class EnvironmentTrustReport(_message.Message):
    __slots__ = ("environment", "runtime", "placement", "images", "provenance", "attestation", "trustee", "summary")
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_FIELD_NUMBER: _ClassVar[int]
    PLACEMENT_FIELD_NUMBER: _ClassVar[int]
    IMAGES_FIELD_NUMBER: _ClassVar[int]
    PROVENANCE_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    TRUSTEE_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    environment: TrustReportEnvironment
    runtime: TrustReportRuntime
    placement: TrustReportPlacement
    images: TrustReportImages
    provenance: TrustReportProvenance
    attestation: TrustReportAttestation
    trustee: TrustReportTrustee
    summary: TrustReportSummary
    def __init__(self, environment: _Optional[_Union[TrustReportEnvironment, _Mapping]] = ..., runtime: _Optional[_Union[TrustReportRuntime, _Mapping]] = ..., placement: _Optional[_Union[TrustReportPlacement, _Mapping]] = ..., images: _Optional[_Union[TrustReportImages, _Mapping]] = ..., provenance: _Optional[_Union[TrustReportProvenance, _Mapping]] = ..., attestation: _Optional[_Union[TrustReportAttestation, _Mapping]] = ..., trustee: _Optional[_Union[TrustReportTrustee, _Mapping]] = ..., summary: _Optional[_Union[TrustReportSummary, _Mapping]] = ...) -> None: ...

class TrustReportEnvironment(_message.Message):
    __slots__ = ("id", "org_id", "type", "state", "isolation_tier")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ISOLATION_TIER_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    type: str
    state: str
    isolation_tier: IsolationTier
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., type: _Optional[str] = ..., state: _Optional[str] = ..., isolation_tier: _Optional[_Union[IsolationTier, str]] = ...) -> None: ...

class TrustReportRuntime(_message.Message):
    __slots__ = ("profile", "runtime_class", "handler", "confidential")
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    RUNTIME_CLASS_FIELD_NUMBER: _ClassVar[int]
    HANDLER_FIELD_NUMBER: _ClassVar[int]
    CONFIDENTIAL_FIELD_NUMBER: _ClassVar[int]
    profile: str
    runtime_class: str
    handler: str
    confidential: bool
    def __init__(self, profile: _Optional[str] = ..., runtime_class: _Optional[str] = ..., handler: _Optional[str] = ..., confidential: _Optional[bool] = ...) -> None: ...

class TrustReportPlacement(_message.Message):
    __slots__ = ("namespace", "workspace_pod", "pod_ip", "node", "zone", "region")
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_POD_FIELD_NUMBER: _ClassVar[int]
    POD_IP_FIELD_NUMBER: _ClassVar[int]
    NODE_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    namespace: str
    workspace_pod: str
    pod_ip: str
    node: str
    zone: str
    region: str
    def __init__(self, namespace: _Optional[str] = ..., workspace_pod: _Optional[str] = ..., pod_ip: _Optional[str] = ..., node: _Optional[str] = ..., zone: _Optional[str] = ..., region: _Optional[str] = ...) -> None: ...

class TrustReportImages(_message.Message):
    __slots__ = ("workspace_image", "workspace_image_id", "gateway_image", "gateway_image_id", "dind_image", "dind_image_id", "daemon_init_image", "daemon_init_image_id")
    WORKSPACE_IMAGE_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_IMAGE_ID_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_IMAGE_FIELD_NUMBER: _ClassVar[int]
    GATEWAY_IMAGE_ID_FIELD_NUMBER: _ClassVar[int]
    DIND_IMAGE_FIELD_NUMBER: _ClassVar[int]
    DIND_IMAGE_ID_FIELD_NUMBER: _ClassVar[int]
    DAEMON_INIT_IMAGE_FIELD_NUMBER: _ClassVar[int]
    DAEMON_INIT_IMAGE_ID_FIELD_NUMBER: _ClassVar[int]
    workspace_image: str
    workspace_image_id: str
    gateway_image: str
    gateway_image_id: str
    dind_image: str
    dind_image_id: str
    daemon_init_image: str
    daemon_init_image_id: str
    def __init__(self, workspace_image: _Optional[str] = ..., workspace_image_id: _Optional[str] = ..., gateway_image: _Optional[str] = ..., gateway_image_id: _Optional[str] = ..., dind_image: _Optional[str] = ..., dind_image_id: _Optional[str] = ..., daemon_init_image: _Optional[str] = ..., daemon_init_image_id: _Optional[str] = ...) -> None: ...

class TrustReportProvenance(_message.Message):
    __slots__ = ("status", "guest_kernel", "guest_initrd", "guest_image", "firmware", "source", "notes")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    GUEST_KERNEL_FIELD_NUMBER: _ClassVar[int]
    GUEST_INITRD_FIELD_NUMBER: _ClassVar[int]
    GUEST_IMAGE_FIELD_NUMBER: _ClassVar[int]
    FIRMWARE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    status: str
    guest_kernel: str
    guest_initrd: str
    guest_image: str
    firmware: str
    source: str
    notes: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[str] = ..., guest_kernel: _Optional[str] = ..., guest_initrd: _Optional[str] = ..., guest_image: _Optional[str] = ..., firmware: _Optional[str] = ..., source: _Optional[str] = ..., notes: _Optional[_Iterable[str]] = ...) -> None: ...

class TrustReportAttestation(_message.Message):
    __slots__ = ("status", "tee", "report_available", "report_source", "metadata")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TEE_FIELD_NUMBER: _ClassVar[int]
    REPORT_AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    REPORT_SOURCE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    status: str
    tee: str
    report_available: bool
    report_source: str
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, status: _Optional[str] = ..., tee: _Optional[str] = ..., report_available: _Optional[bool] = ..., report_source: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class TrustReportTrustee(_message.Message):
    __slots__ = ("status", "resource_uri", "reference_values", "policy", "evidence_issues")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_URI_FIELD_NUMBER: _ClassVar[int]
    REFERENCE_VALUES_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_ISSUES_FIELD_NUMBER: _ClassVar[int]
    status: str
    resource_uri: str
    reference_values: str
    policy: str
    evidence_issues: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, status: _Optional[str] = ..., resource_uri: _Optional[str] = ..., reference_values: _Optional[str] = ..., policy: _Optional[str] = ..., evidence_issues: _Optional[_Iterable[str]] = ...) -> None: ...

class TrustReportSummary(_message.Message):
    __slots__ = ("trust_level", "production_verified", "warnings")
    TRUST_LEVEL_FIELD_NUMBER: _ClassVar[int]
    PRODUCTION_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    WARNINGS_FIELD_NUMBER: _ClassVar[int]
    trust_level: str
    production_verified: bool
    warnings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, trust_level: _Optional[str] = ..., production_verified: _Optional[bool] = ..., warnings: _Optional[_Iterable[str]] = ...) -> None: ...

class WatchEnvironmentCreateRequest(_message.Message):
    __slots__ = ("org_id", "draft")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    DRAFT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    draft: CreateEnvironmentRequest
    def __init__(self, org_id: _Optional[str] = ..., draft: _Optional[_Union[CreateEnvironmentRequest, _Mapping]] = ...) -> None: ...

class WatchEnvironmentCreateResponse(_message.Message):
    __slots__ = ("progress", "complete")
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    progress: PrepareProgress
    complete: PrepareComplete
    def __init__(self, progress: _Optional[_Union[PrepareProgress, _Mapping]] = ..., complete: _Optional[_Union[PrepareComplete, _Mapping]] = ...) -> None: ...

class PrepareProgress(_message.Message):
    __slots__ = ("phase", "message", "total", "repo")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    TOTAL_FIELD_NUMBER: _ClassVar[int]
    REPO_FIELD_NUMBER: _ClassVar[int]
    phase: str
    message: str
    total: int
    repo: str
    def __init__(self, phase: _Optional[str] = ..., message: _Optional[str] = ..., total: _Optional[int] = ..., repo: _Optional[str] = ...) -> None: ...

class PrepareComplete(_message.Message):
    __slots__ = ("draft", "resolved_preset", "repo_config")
    DRAFT_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_PRESET_FIELD_NUMBER: _ClassVar[int]
    REPO_CONFIG_FIELD_NUMBER: _ClassVar[int]
    draft: CreateEnvironmentRequest
    resolved_preset: _preset_pb2.Preset
    repo_config: RepoConfig
    def __init__(self, draft: _Optional[_Union[CreateEnvironmentRequest, _Mapping]] = ..., resolved_preset: _Optional[_Union[_preset_pb2.Preset, _Mapping]] = ..., repo_config: _Optional[_Union[RepoConfig, _Mapping]] = ...) -> None: ...

class RepoConfig(_message.Message):
    __slots__ = ("id", "org_id", "repo_url", "created_by", "updated_at", "project_spec")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    REPO_URL_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    repo_url: str
    created_by: str
    updated_at: str
    project_spec: _common_pb2.ProjectSpec
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., repo_url: _Optional[str] = ..., created_by: _Optional[str] = ..., updated_at: _Optional[str] = ..., project_spec: _Optional[_Union[_common_pb2.ProjectSpec, _Mapping]] = ...) -> None: ...

class StreamLogsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "follow", "after_log_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    FOLLOW_FIELD_NUMBER: _ClassVar[int]
    AFTER_LOG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    follow: bool
    after_log_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., follow: _Optional[bool] = ..., after_log_id: _Optional[str] = ...) -> None: ...

class StreamLogsResponse(_message.Message):
    __slots__ = ("log", "heartbeat")
    LOG_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_FIELD_NUMBER: _ClassVar[int]
    log: EnvironmentLog
    heartbeat: StreamHeartbeat
    def __init__(self, log: _Optional[_Union[EnvironmentLog, _Mapping]] = ..., heartbeat: _Optional[_Union[StreamHeartbeat, _Mapping]] = ...) -> None: ...

class StreamHeartbeat(_message.Message):
    __slots__ = ("sent_at",)
    SENT_AT_FIELD_NUMBER: _ClassVar[int]
    sent_at: _timestamp_pb2.Timestamp
    def __init__(self, sent_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnvironmentLog(_message.Message):
    __slots__ = ("id", "environment_id", "phase", "status", "message", "metadata", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    environment_id: str
    phase: str
    status: str
    message: str
    metadata: _struct_pb2.Struct
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., environment_id: _Optional[str] = ..., phase: _Optional[str] = ..., status: _Optional[str] = ..., message: _Optional[str] = ..., metadata: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnvironmentDaemonDiagnostic(_message.Message):
    __slots__ = ("name", "healthy", "message")
    NAME_FIELD_NUMBER: _ClassVar[int]
    HEALTHY_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    name: str
    healthy: bool
    message: str
    def __init__(self, name: _Optional[str] = ..., healthy: _Optional[bool] = ..., message: _Optional[str] = ...) -> None: ...

class EnvironmentDaemonStatus(_message.Message):
    __slots__ = ("state", "protocol_version", "minimum_protocol_version", "daemon_version", "capabilities", "message", "diagnostics", "pod_name")
    STATE_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    DAEMON_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DIAGNOSTICS_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    state: EnvironmentDaemonState
    protocol_version: int
    minimum_protocol_version: int
    daemon_version: str
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    message: str
    diagnostics: _containers.RepeatedCompositeFieldContainer[EnvironmentDaemonDiagnostic]
    pod_name: str
    def __init__(self, state: _Optional[_Union[EnvironmentDaemonState, str]] = ..., protocol_version: _Optional[int] = ..., minimum_protocol_version: _Optional[int] = ..., daemon_version: _Optional[str] = ..., capabilities: _Optional[_Iterable[str]] = ..., message: _Optional[str] = ..., diagnostics: _Optional[_Iterable[_Union[EnvironmentDaemonDiagnostic, _Mapping]]] = ..., pod_name: _Optional[str] = ...) -> None: ...

class GetEnvironmentDaemonStatusRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentDaemonStatusResponse(_message.Message):
    __slots__ = ("status",)
    STATUS_FIELD_NUMBER: _ClassVar[int]
    status: EnvironmentDaemonStatus
    def __init__(self, status: _Optional[_Union[EnvironmentDaemonStatus, _Mapping]] = ...) -> None: ...

class StreamEnvironmentDaemonLogsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StreamEnvironmentDaemonLogsResponse(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class RepairEnvironmentDaemonRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class RepairEnvironmentDaemonResponse(_message.Message):
    __slots__ = ("status", "replaced_pod_name")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REPLACED_POD_NAME_FIELD_NUMBER: _ClassVar[int]
    status: EnvironmentDaemonStatus
    replaced_pod_name: str
    def __init__(self, status: _Optional[_Union[EnvironmentDaemonStatus, _Mapping]] = ..., replaced_pod_name: _Optional[str] = ...) -> None: ...
