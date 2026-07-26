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
    __slots__ = ("id", "org_id", "created_by", "preset_id", "type", "name", "state", "desired_state", "error_reason", "recoverable", "state_changed_at", "retry_count", "setup_phase", "setup_complete", "setup_error", "ttl_seconds", "shutdown_at", "cpu_millicores", "memory_mb", "disk_gb", "total_running_seconds", "created_at", "started_at", "stopped_at", "destroyed_at", "protected", "deletion_requested_at", "deletion_grace_until", "preset_name", "network", "ports")
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
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., created_by: _Optional[str] = ..., preset_id: _Optional[str] = ..., type: _Optional[str] = ..., name: _Optional[str] = ..., state: _Optional[_Union[EnvironmentState, str]] = ..., desired_state: _Optional[_Union[DesiredState, str]] = ..., error_reason: _Optional[str] = ..., recoverable: _Optional[bool] = ..., state_changed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., retry_count: _Optional[int] = ..., setup_phase: _Optional[int] = ..., setup_complete: _Optional[bool] = ..., setup_error: _Optional[str] = ..., ttl_seconds: _Optional[int] = ..., shutdown_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ..., total_running_seconds: _Optional[int] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., started_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., stopped_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., destroyed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protected: _Optional[bool] = ..., deletion_requested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., deletion_grace_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., preset_name: _Optional[str] = ..., network: _Optional[str] = ..., ports: _Optional[_Iterable[_Union[_port_pb2.Port, _Mapping]]] = ...) -> None: ...

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
    __slots__ = ("org_id", "preset_id", "name", "cpu_millicores", "memory_mb", "disk_gb", "ttl_seconds", "preset_slug", "repo_url", "branch", "repos", "image", "install_command", "startup_script", "env_vars", "agents", "install_agents", "agent", "agent_env", "secret_project", "app_ports", "include_org_secrets", "include_user_secrets")
    class EnvVarsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    class AgentEnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    DISK_GB_FIELD_NUMBER: _ClassVar[int]
    TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PRESET_SLUG_FIELD_NUMBER: _ClassVar[int]
    REPO_URL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    REPOS_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    INSTALL_COMMAND_FIELD_NUMBER: _ClassVar[int]
    STARTUP_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    ENV_VARS_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    INSTALL_AGENTS_FIELD_NUMBER: _ClassVar[int]
    AGENT_FIELD_NUMBER: _ClassVar[int]
    AGENT_ENV_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ORG_SECRETS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    name: str
    cpu_millicores: int
    memory_mb: int
    disk_gb: int
    ttl_seconds: int
    preset_slug: str
    repo_url: str
    branch: str
    repos: _containers.RepeatedCompositeFieldContainer[_common_pb2.RepoEntry]
    image: str
    install_command: str
    startup_script: str
    env_vars: _containers.ScalarMap[str, str]
    agents: _containers.RepeatedCompositeFieldContainer[_common_pb2.SetupAgent]
    install_agents: bool
    agent: str
    agent_env: _containers.ScalarMap[str, str]
    secret_project: str
    app_ports: _containers.RepeatedCompositeFieldContainer[_common_pb2.AppPort]
    include_org_secrets: bool
    include_user_secrets: bool
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ..., name: _Optional[str] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ..., disk_gb: _Optional[int] = ..., ttl_seconds: _Optional[int] = ..., preset_slug: _Optional[str] = ..., repo_url: _Optional[str] = ..., branch: _Optional[str] = ..., repos: _Optional[_Iterable[_Union[_common_pb2.RepoEntry, _Mapping]]] = ..., image: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., env_vars: _Optional[_Mapping[str, str]] = ..., agents: _Optional[_Iterable[_Union[_common_pb2.SetupAgent, _Mapping]]] = ..., install_agents: _Optional[bool] = ..., agent: _Optional[str] = ..., agent_env: _Optional[_Mapping[str, str]] = ..., secret_project: _Optional[str] = ..., app_ports: _Optional[_Iterable[_Union[_common_pb2.AppPort, _Mapping]]] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ...) -> None: ...

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
    __slots__ = ("id", "org_id", "type", "state")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    type: str
    state: str
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., type: _Optional[str] = ..., state: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("org_id", "draft", "analyze")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    DRAFT_FIELD_NUMBER: _ClassVar[int]
    ANALYZE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    draft: CreateEnvironmentRequest
    analyze: bool
    def __init__(self, org_id: _Optional[str] = ..., draft: _Optional[_Union[CreateEnvironmentRequest, _Mapping]] = ..., analyze: _Optional[bool] = ...) -> None: ...

class WatchEnvironmentCreateResponse(_message.Message):
    __slots__ = ("progress", "repo_fetched", "complete")
    PROGRESS_FIELD_NUMBER: _ClassVar[int]
    REPO_FETCHED_FIELD_NUMBER: _ClassVar[int]
    COMPLETE_FIELD_NUMBER: _ClassVar[int]
    progress: PrepareProgress
    repo_fetched: RepoFetched
    complete: PrepareComplete
    def __init__(self, progress: _Optional[_Union[PrepareProgress, _Mapping]] = ..., repo_fetched: _Optional[_Union[RepoFetched, _Mapping]] = ..., complete: _Optional[_Union[PrepareComplete, _Mapping]] = ...) -> None: ...

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

class RepoFetched(_message.Message):
    __slots__ = ("index", "repo", "ok")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    REPO_FIELD_NUMBER: _ClassVar[int]
    OK_FIELD_NUMBER: _ClassVar[int]
    index: int
    repo: str
    ok: bool
    def __init__(self, index: _Optional[int] = ..., repo: _Optional[str] = ..., ok: _Optional[bool] = ...) -> None: ...

class PrepareComplete(_message.Message):
    __slots__ = ("draft", "detection", "resolved_preset", "repo_config")
    DRAFT_FIELD_NUMBER: _ClassVar[int]
    DETECTION_FIELD_NUMBER: _ClassVar[int]
    RESOLVED_PRESET_FIELD_NUMBER: _ClassVar[int]
    REPO_CONFIG_FIELD_NUMBER: _ClassVar[int]
    draft: CreateEnvironmentRequest
    detection: DetectionResult
    resolved_preset: _preset_pb2.Preset
    repo_config: RepoConfig
    def __init__(self, draft: _Optional[_Union[CreateEnvironmentRequest, _Mapping]] = ..., detection: _Optional[_Union[DetectionResult, _Mapping]] = ..., resolved_preset: _Optional[_Union[_preset_pb2.Preset, _Mapping]] = ..., repo_config: _Optional[_Union[RepoConfig, _Mapping]] = ...) -> None: ...

class DetectionResult(_message.Message):
    __slots__ = ("project_type", "preset_slug", "preset_image", "install_command", "startup_script", "language", "framework", "suggested_name", "needs_docker", "has_compose", "app_ports", "agents", "install_agents", "secret_project", "include_org_secrets", "include_user_secrets", "cpu", "memory", "setup_notes")
    PROJECT_TYPE_FIELD_NUMBER: _ClassVar[int]
    PRESET_SLUG_FIELD_NUMBER: _ClassVar[int]
    PRESET_IMAGE_FIELD_NUMBER: _ClassVar[int]
    INSTALL_COMMAND_FIELD_NUMBER: _ClassVar[int]
    STARTUP_SCRIPT_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    FRAMEWORK_FIELD_NUMBER: _ClassVar[int]
    SUGGESTED_NAME_FIELD_NUMBER: _ClassVar[int]
    NEEDS_DOCKER_FIELD_NUMBER: _ClassVar[int]
    HAS_COMPOSE_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    INSTALL_AGENTS_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECT_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_ORG_SECRETS_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_USER_SECRETS_FIELD_NUMBER: _ClassVar[int]
    CPU_FIELD_NUMBER: _ClassVar[int]
    MEMORY_FIELD_NUMBER: _ClassVar[int]
    SETUP_NOTES_FIELD_NUMBER: _ClassVar[int]
    project_type: str
    preset_slug: str
    preset_image: str
    install_command: str
    startup_script: str
    language: str
    framework: str
    suggested_name: str
    needs_docker: bool
    has_compose: bool
    app_ports: _containers.RepeatedCompositeFieldContainer[_common_pb2.AppPort]
    agents: _containers.RepeatedCompositeFieldContainer[_common_pb2.SetupAgent]
    install_agents: bool
    secret_project: str
    include_org_secrets: bool
    include_user_secrets: bool
    cpu: str
    memory: str
    setup_notes: str
    def __init__(self, project_type: _Optional[str] = ..., preset_slug: _Optional[str] = ..., preset_image: _Optional[str] = ..., install_command: _Optional[str] = ..., startup_script: _Optional[str] = ..., language: _Optional[str] = ..., framework: _Optional[str] = ..., suggested_name: _Optional[str] = ..., needs_docker: _Optional[bool] = ..., has_compose: _Optional[bool] = ..., app_ports: _Optional[_Iterable[_Union[_common_pb2.AppPort, _Mapping]]] = ..., agents: _Optional[_Iterable[_Union[_common_pb2.SetupAgent, _Mapping]]] = ..., install_agents: _Optional[bool] = ..., secret_project: _Optional[str] = ..., include_org_secrets: _Optional[bool] = ..., include_user_secrets: _Optional[bool] = ..., cpu: _Optional[str] = ..., memory: _Optional[str] = ..., setup_notes: _Optional[str] = ...) -> None: ...

class RepoConfig(_message.Message):
    __slots__ = ("id", "org_id", "repo_url", "preset_id", "setup_config", "created_by", "updated_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    REPO_URL_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    SETUP_CONFIG_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    repo_url: str
    preset_id: str
    setup_config: _struct_pb2.Struct
    created_by: str
    updated_at: str
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., repo_url: _Optional[str] = ..., preset_id: _Optional[str] = ..., setup_config: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., created_by: _Optional[str] = ..., updated_at: _Optional[str] = ...) -> None: ...

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
