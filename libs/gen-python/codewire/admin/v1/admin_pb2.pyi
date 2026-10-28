import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import struct_pb2 as _struct_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetStatsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetStatsResponse(_message.Message):
    __slots__ = ("total_environments", "active_environments", "monthly_cpu_hours", "monthly_memory_gb_hours", "monthly_cost_cents")
    TOTAL_ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    MONTHLY_CPU_HOURS_FIELD_NUMBER: _ClassVar[int]
    MONTHLY_MEMORY_GB_HOURS_FIELD_NUMBER: _ClassVar[int]
    MONTHLY_COST_CENTS_FIELD_NUMBER: _ClassVar[int]
    total_environments: int
    active_environments: int
    monthly_cpu_hours: float
    monthly_memory_gb_hours: float
    monthly_cost_cents: int
    def __init__(self, total_environments: _Optional[int] = ..., active_environments: _Optional[int] = ..., monthly_cpu_hours: _Optional[float] = ..., monthly_memory_gb_hours: _Optional[float] = ..., monthly_cost_cents: _Optional[int] = ...) -> None: ...

class Organization(_message.Message):
    __slots__ = ("id", "name", "slug", "created_at", "billing_plan", "billing_status")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    BILLING_PLAN_FIELD_NUMBER: _ClassVar[int]
    BILLING_STATUS_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    slug: str
    created_at: _timestamp_pb2.Timestamp
    billing_plan: str
    billing_status: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., billing_plan: _Optional[str] = ..., billing_status: _Optional[str] = ...) -> None: ...

class ListOrganizationsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListOrganizationsResponse(_message.Message):
    __slots__ = ("organizations",)
    ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    organizations: _containers.RepeatedCompositeFieldContainer[Organization]
    def __init__(self, organizations: _Optional[_Iterable[_Union[Organization, _Mapping]]] = ...) -> None: ...

class ListAuditLogsRequest(_message.Message):
    __slots__ = ("limit", "offset", "action", "severity")
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    limit: int
    offset: int
    action: str
    severity: str
    def __init__(self, limit: _Optional[int] = ..., offset: _Optional[int] = ..., action: _Optional[str] = ..., severity: _Optional[str] = ...) -> None: ...

class AuditLogEntry(_message.Message):
    __slots__ = ("id", "timestamp", "action", "user_id", "user_email", "ip_address", "user_agent", "metadata", "severity")
    ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    USER_EMAIL_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    USER_AGENT_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    id: str
    timestamp: _timestamp_pb2.Timestamp
    action: str
    user_id: str
    user_email: str
    ip_address: str
    user_agent: str
    metadata: _struct_pb2.Struct
    severity: str
    def __init__(self, id: _Optional[str] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., action: _Optional[str] = ..., user_id: _Optional[str] = ..., user_email: _Optional[str] = ..., ip_address: _Optional[str] = ..., user_agent: _Optional[str] = ..., metadata: _Optional[_Union[_struct_pb2.Struct, _Mapping]] = ..., severity: _Optional[str] = ...) -> None: ...

class ListAuditLogsResponse(_message.Message):
    __slots__ = ("audit_logs",)
    AUDIT_LOGS_FIELD_NUMBER: _ClassVar[int]
    audit_logs: _containers.RepeatedCompositeFieldContainer[AuditLogEntry]
    def __init__(self, audit_logs: _Optional[_Iterable[_Union[AuditLogEntry, _Mapping]]] = ...) -> None: ...

class ListEnvironmentLifecycleJournalRequest(_message.Message):
    __slots__ = ("environment_id", "limit")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    limit: int
    def __init__(self, environment_id: _Optional[str] = ..., limit: _Optional[int] = ...) -> None: ...

class EnvironmentLifecycleJournalEntry(_message.Message):
    __slots__ = ("id", "environment_id", "kind", "actor", "phase", "status", "from_state", "to_state", "checkpoint", "reason", "metadata", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    FROM_STATE_FIELD_NUMBER: _ClassVar[int]
    TO_STATE_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    environment_id: str
    kind: str
    actor: str
    phase: str
    status: str
    from_state: str
    to_state: str
    checkpoint: str
    reason: str
    metadata: _struct_pb2.Value
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., environment_id: _Optional[str] = ..., kind: _Optional[str] = ..., actor: _Optional[str] = ..., phase: _Optional[str] = ..., status: _Optional[str] = ..., from_state: _Optional[str] = ..., to_state: _Optional[str] = ..., checkpoint: _Optional[str] = ..., reason: _Optional[str] = ..., metadata: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListEnvironmentLifecycleJournalResponse(_message.Message):
    __slots__ = ("entries",)
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[EnvironmentLifecycleJournalEntry]
    def __init__(self, entries: _Optional[_Iterable[_Union[EnvironmentLifecycleJournalEntry, _Mapping]]] = ...) -> None: ...

class GetEnvironmentStartupSummaryRequest(_message.Message):
    __slots__ = ("window",)
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    window: _duration_pb2.Duration
    def __init__(self, window: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class StartupPhaseSummary(_message.Message):
    __slots__ = ("phase", "sample_count", "p50", "p95")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    SAMPLE_COUNT_FIELD_NUMBER: _ClassVar[int]
    P50_FIELD_NUMBER: _ClassVar[int]
    P95_FIELD_NUMBER: _ClassVar[int]
    phase: str
    sample_count: int
    p50: _duration_pb2.Duration
    p95: _duration_pb2.Duration
    def __init__(self, phase: _Optional[str] = ..., sample_count: _Optional[int] = ..., p50: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., p95: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class GetEnvironmentStartupSummaryResponse(_message.Message):
    __slots__ = ("generated_at", "window", "starting_backlog_count", "starting_backlog_over_5m_count", "starting_backlog_over_10m_count", "running_without_access_ready_count", "phase_durations")
    GENERATED_AT_FIELD_NUMBER: _ClassVar[int]
    WINDOW_FIELD_NUMBER: _ClassVar[int]
    STARTING_BACKLOG_COUNT_FIELD_NUMBER: _ClassVar[int]
    STARTING_BACKLOG_OVER_5M_COUNT_FIELD_NUMBER: _ClassVar[int]
    STARTING_BACKLOG_OVER_10M_COUNT_FIELD_NUMBER: _ClassVar[int]
    RUNNING_WITHOUT_ACCESS_READY_COUNT_FIELD_NUMBER: _ClassVar[int]
    PHASE_DURATIONS_FIELD_NUMBER: _ClassVar[int]
    generated_at: _timestamp_pb2.Timestamp
    window: _duration_pb2.Duration
    starting_backlog_count: int
    starting_backlog_over_5m_count: int
    starting_backlog_over_10m_count: int
    running_without_access_ready_count: int
    phase_durations: _containers.RepeatedCompositeFieldContainer[StartupPhaseSummary]
    def __init__(self, generated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., window: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., starting_backlog_count: _Optional[int] = ..., starting_backlog_over_5m_count: _Optional[int] = ..., starting_backlog_over_10m_count: _Optional[int] = ..., running_without_access_ready_count: _Optional[int] = ..., phase_durations: _Optional[_Iterable[_Union[StartupPhaseSummary, _Mapping]]] = ...) -> None: ...

class GetEnvironmentStartupTimingsRequest(_message.Message):
    __slots__ = ("environment_id",)
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    def __init__(self, environment_id: _Optional[str] = ...) -> None: ...

class EnvironmentStartupTiming(_message.Message):
    __slots__ = ("phase", "status", "message", "duration", "metadata", "created_at")
    PHASE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    DURATION_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    phase: str
    status: str
    message: str
    duration: _duration_pb2.Duration
    metadata: _struct_pb2.Value
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, phase: _Optional[str] = ..., status: _Optional[str] = ..., message: _Optional[str] = ..., duration: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., metadata: _Optional[_Union[_struct_pb2.Value, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class GetEnvironmentStartupTimingsResponse(_message.Message):
    __slots__ = ("environment_id", "created_at", "timings")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    TIMINGS_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    created_at: _timestamp_pb2.Timestamp
    timings: _containers.RepeatedCompositeFieldContainer[EnvironmentStartupTiming]
    def __init__(self, environment_id: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., timings: _Optional[_Iterable[_Union[EnvironmentStartupTiming, _Mapping]]] = ...) -> None: ...

class EnvironmentQuota(_message.Message):
    __slots__ = ("max_concurrent_environments", "max_concurrent_sandbox", "max_cpu_millicores", "max_memory_mb")
    MAX_CONCURRENT_ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_SANDBOX_FIELD_NUMBER: _ClassVar[int]
    MAX_CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MAX_MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    max_concurrent_environments: int
    max_concurrent_sandbox: int
    max_cpu_millicores: int
    max_memory_mb: int
    def __init__(self, max_concurrent_environments: _Optional[int] = ..., max_concurrent_sandbox: _Optional[int] = ..., max_cpu_millicores: _Optional[int] = ..., max_memory_mb: _Optional[int] = ...) -> None: ...

class GetOrganizationEnvironmentQuotaRequest(_message.Message):
    __slots__ = ("organization_id",)
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    def __init__(self, organization_id: _Optional[str] = ...) -> None: ...

class GetOrganizationEnvironmentQuotaResponse(_message.Message):
    __slots__ = ("organization_id", "explicit", "effective")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    EXPLICIT_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVE_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    explicit: EnvironmentQuota
    effective: EnvironmentQuota
    def __init__(self, organization_id: _Optional[str] = ..., explicit: _Optional[_Union[EnvironmentQuota, _Mapping]] = ..., effective: _Optional[_Union[EnvironmentQuota, _Mapping]] = ...) -> None: ...

class SetOrganizationEnvironmentQuotaRequest(_message.Message):
    __slots__ = ("organization_id", "quota")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    quota: EnvironmentQuota
    def __init__(self, organization_id: _Optional[str] = ..., quota: _Optional[_Union[EnvironmentQuota, _Mapping]] = ...) -> None: ...

class SetOrganizationEnvironmentQuotaResponse(_message.Message):
    __slots__ = ("organization_id", "quota")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    quota: EnvironmentQuota
    def __init__(self, organization_id: _Optional[str] = ..., quota: _Optional[_Union[EnvironmentQuota, _Mapping]] = ...) -> None: ...

class ClearOrganizationEnvironmentQuotaRequest(_message.Message):
    __slots__ = ("organization_id",)
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    def __init__(self, organization_id: _Optional[str] = ...) -> None: ...

class ClearOrganizationEnvironmentQuotaResponse(_message.Message):
    __slots__ = ("organization_id", "cleared")
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    CLEARED_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    cleared: bool
    def __init__(self, organization_id: _Optional[str] = ..., cleared: _Optional[bool] = ...) -> None: ...

class GetOrganizationOverviewRequest(_message.Message):
    __slots__ = ("organization_id",)
    ORGANIZATION_ID_FIELD_NUMBER: _ClassVar[int]
    organization_id: str
    def __init__(self, organization_id: _Optional[str] = ...) -> None: ...

class OrganizationMember(_message.Message):
    __slots__ = ("user_id", "email", "role", "joined_at")
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    JOINED_AT_FIELD_NUMBER: _ClassVar[int]
    user_id: str
    email: str
    role: str
    joined_at: _timestamp_pb2.Timestamp
    def __init__(self, user_id: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[str] = ..., joined_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class OrganizationSubscription(_message.Message):
    __slots__ = ("kind", "plan", "status", "updated_at")
    KIND_FIELD_NUMBER: _ClassVar[int]
    PLAN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    kind: str
    plan: str
    status: str
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, kind: _Optional[str] = ..., plan: _Optional[str] = ..., status: _Optional[str] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class OrganizationBilling(_message.Message):
    __slots__ = ("billing_plan", "billing_status", "billing_exempt", "effective_plan", "subscriptions")
    BILLING_PLAN_FIELD_NUMBER: _ClassVar[int]
    BILLING_STATUS_FIELD_NUMBER: _ClassVar[int]
    BILLING_EXEMPT_FIELD_NUMBER: _ClassVar[int]
    EFFECTIVE_PLAN_FIELD_NUMBER: _ClassVar[int]
    SUBSCRIPTIONS_FIELD_NUMBER: _ClassVar[int]
    billing_plan: str
    billing_status: str
    billing_exempt: bool
    effective_plan: str
    subscriptions: _containers.RepeatedCompositeFieldContainer[OrganizationSubscription]
    def __init__(self, billing_plan: _Optional[str] = ..., billing_status: _Optional[str] = ..., billing_exempt: _Optional[bool] = ..., effective_plan: _Optional[str] = ..., subscriptions: _Optional[_Iterable[_Union[OrganizationSubscription, _Mapping]]] = ...) -> None: ...

class OrganizationEnvironmentUsage(_message.Message):
    __slots__ = ("active_environments", "active_sandboxes", "cpu_millicores", "memory_mb")
    ACTIVE_ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLICORES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MB_FIELD_NUMBER: _ClassVar[int]
    active_environments: int
    active_sandboxes: int
    cpu_millicores: int
    memory_mb: int
    def __init__(self, active_environments: _Optional[int] = ..., active_sandboxes: _Optional[int] = ..., cpu_millicores: _Optional[int] = ..., memory_mb: _Optional[int] = ...) -> None: ...

class OrganizationApiKey(_message.Message):
    __slots__ = ("name", "created_at", "last_used_at", "disabled", "expires_at")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    LAST_USED_AT_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    name: str
    created_at: _timestamp_pb2.Timestamp
    last_used_at: _timestamp_pb2.Timestamp
    disabled: bool
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, name: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last_used_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., disabled: _Optional[bool] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class GetOrganizationOverviewResponse(_message.Message):
    __slots__ = ("organization", "members", "billing", "quota", "usage", "api_keys")
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    BILLING_FIELD_NUMBER: _ClassVar[int]
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    USAGE_FIELD_NUMBER: _ClassVar[int]
    API_KEYS_FIELD_NUMBER: _ClassVar[int]
    organization: Organization
    members: _containers.RepeatedCompositeFieldContainer[OrganizationMember]
    billing: OrganizationBilling
    quota: GetOrganizationEnvironmentQuotaResponse
    usage: OrganizationEnvironmentUsage
    api_keys: _containers.RepeatedCompositeFieldContainer[OrganizationApiKey]
    def __init__(self, organization: _Optional[_Union[Organization, _Mapping]] = ..., members: _Optional[_Iterable[_Union[OrganizationMember, _Mapping]]] = ..., billing: _Optional[_Union[OrganizationBilling, _Mapping]] = ..., quota: _Optional[_Union[GetOrganizationEnvironmentQuotaResponse, _Mapping]] = ..., usage: _Optional[_Union[OrganizationEnvironmentUsage, _Mapping]] = ..., api_keys: _Optional[_Iterable[_Union[OrganizationApiKey, _Mapping]]] = ...) -> None: ...

class GetDefaultEnvironmentQuotaRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetDefaultEnvironmentQuotaResponse(_message.Message):
    __slots__ = ("quota", "stored")
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    STORED_FIELD_NUMBER: _ClassVar[int]
    quota: EnvironmentQuota
    stored: bool
    def __init__(self, quota: _Optional[_Union[EnvironmentQuota, _Mapping]] = ..., stored: _Optional[bool] = ...) -> None: ...

class SetDefaultEnvironmentQuotaRequest(_message.Message):
    __slots__ = ("quota",)
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    quota: EnvironmentQuota
    def __init__(self, quota: _Optional[_Union[EnvironmentQuota, _Mapping]] = ...) -> None: ...

class SetDefaultEnvironmentQuotaResponse(_message.Message):
    __slots__ = ("quota",)
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    quota: EnvironmentQuota
    def __init__(self, quota: _Optional[_Union[EnvironmentQuota, _Mapping]] = ...) -> None: ...
