import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AuditEventKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUDIT_EVENT_KIND_UNSPECIFIED: _ClassVar[AuditEventKind]
    AUDIT_EVENT_KIND_ACCESS: _ClassVar[AuditEventKind]
    AUDIT_EVENT_KIND_LIFECYCLE: _ClassVar[AuditEventKind]
    AUDIT_EVENT_KIND_POLICY: _ClassVar[AuditEventKind]
    AUDIT_EVENT_KIND_REFUSED: _ClassVar[AuditEventKind]
    AUDIT_EVENT_KIND_CREDENTIALS: _ClassVar[AuditEventKind]

class AuditRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUDIT_ROLE_UNSPECIFIED: _ClassVar[AuditRole]
    AUDIT_ROLE_OWNER: _ClassVar[AuditRole]
    AUDIT_ROLE_ADMIN: _ClassVar[AuditRole]
    AUDIT_ROLE_MEMBER: _ClassVar[AuditRole]
    AUDIT_ROLE_STAFF: _ClassVar[AuditRole]

class AuditSurface(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUDIT_SURFACE_UNSPECIFIED: _ClassVar[AuditSurface]
    AUDIT_SURFACE_TERMINAL: _ClassVar[AuditSurface]
    AUDIT_SURFACE_SSH: _ClassVar[AuditSurface]
    AUDIT_SURFACE_EXEC: _ClassVar[AuditSurface]
    AUDIT_SURFACE_DESKTOP: _ClassVar[AuditSurface]
    AUDIT_SURFACE_PREVIEW: _ClassVar[AuditSurface]

class AuditPlatformReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUDIT_PLATFORM_REASON_UNSPECIFIED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_IDLE: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_OUT_OF_CREDIT: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_SUSPENDED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_SYSTEMD_REFUSED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_POD_FAILED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_RUNTIME_REPLACED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_NODE_LOST: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_CONFIGURATION_CHANGED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_SOURCES_CHANGED: _ClassVar[AuditPlatformReason]
    AUDIT_PLATFORM_REASON_EXPIRED: _ClassVar[AuditPlatformReason]

class AuditProtocol(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    AUDIT_PROTOCOL_UNSPECIFIED: _ClassVar[AuditProtocol]
    AUDIT_PROTOCOL_DNS: _ClassVar[AuditProtocol]
    AUDIT_PROTOCOL_TCP: _ClassVar[AuditProtocol]
    AUDIT_PROTOCOL_UDP: _ClassVar[AuditProtocol]
AUDIT_EVENT_KIND_UNSPECIFIED: AuditEventKind
AUDIT_EVENT_KIND_ACCESS: AuditEventKind
AUDIT_EVENT_KIND_LIFECYCLE: AuditEventKind
AUDIT_EVENT_KIND_POLICY: AuditEventKind
AUDIT_EVENT_KIND_REFUSED: AuditEventKind
AUDIT_EVENT_KIND_CREDENTIALS: AuditEventKind
AUDIT_ROLE_UNSPECIFIED: AuditRole
AUDIT_ROLE_OWNER: AuditRole
AUDIT_ROLE_ADMIN: AuditRole
AUDIT_ROLE_MEMBER: AuditRole
AUDIT_ROLE_STAFF: AuditRole
AUDIT_SURFACE_UNSPECIFIED: AuditSurface
AUDIT_SURFACE_TERMINAL: AuditSurface
AUDIT_SURFACE_SSH: AuditSurface
AUDIT_SURFACE_EXEC: AuditSurface
AUDIT_SURFACE_DESKTOP: AuditSurface
AUDIT_SURFACE_PREVIEW: AuditSurface
AUDIT_PLATFORM_REASON_UNSPECIFIED: AuditPlatformReason
AUDIT_PLATFORM_REASON_IDLE: AuditPlatformReason
AUDIT_PLATFORM_REASON_OUT_OF_CREDIT: AuditPlatformReason
AUDIT_PLATFORM_REASON_SUSPENDED: AuditPlatformReason
AUDIT_PLATFORM_REASON_SYSTEMD_REFUSED: AuditPlatformReason
AUDIT_PLATFORM_REASON_POD_FAILED: AuditPlatformReason
AUDIT_PLATFORM_REASON_RUNTIME_REPLACED: AuditPlatformReason
AUDIT_PLATFORM_REASON_NODE_LOST: AuditPlatformReason
AUDIT_PLATFORM_REASON_CONFIGURATION_CHANGED: AuditPlatformReason
AUDIT_PLATFORM_REASON_SOURCES_CHANGED: AuditPlatformReason
AUDIT_PLATFORM_REASON_EXPIRED: AuditPlatformReason
AUDIT_PROTOCOL_UNSPECIFIED: AuditProtocol
AUDIT_PROTOCOL_DNS: AuditProtocol
AUDIT_PROTOCOL_TCP: AuditProtocol
AUDIT_PROTOCOL_UDP: AuditProtocol

class ListAuditEventsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "environment_name", "kinds", "since", "until", "limit", "cursor", "group_by_subject")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_NAME_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    SINCE_FIELD_NUMBER: _ClassVar[int]
    UNTIL_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    CURSOR_FIELD_NUMBER: _ClassVar[int]
    GROUP_BY_SUBJECT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    environment_name: str
    kinds: _containers.RepeatedScalarFieldContainer[AuditEventKind]
    since: _timestamp_pb2.Timestamp
    until: _timestamp_pb2.Timestamp
    limit: int
    cursor: str
    group_by_subject: bool
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., environment_name: _Optional[str] = ..., kinds: _Optional[_Iterable[_Union[AuditEventKind, str]]] = ..., since: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., limit: _Optional[int] = ..., cursor: _Optional[str] = ..., group_by_subject: _Optional[bool] = ...) -> None: ...

class ListAuditEventsResponse(_message.Message):
    __slots__ = ("environment", "policy", "events", "next_cursor", "left_out")
    ENVIRONMENT_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_CURSOR_FIELD_NUMBER: _ClassVar[int]
    LEFT_OUT_FIELD_NUMBER: _ClassVar[int]
    environment: AuditEnvironment
    policy: AuditPolicyRevision
    events: _containers.RepeatedCompositeFieldContainer[AuditEvent]
    next_cursor: str
    left_out: int
    def __init__(self, environment: _Optional[_Union[AuditEnvironment, _Mapping]] = ..., policy: _Optional[_Union[AuditPolicyRevision, _Mapping]] = ..., events: _Optional[_Iterable[_Union[AuditEvent, _Mapping]]] = ..., next_cursor: _Optional[str] = ..., left_out: _Optional[int] = ...) -> None: ...

class AuditEnvironment(_message.Message):
    __slots__ = ("id", "name", "deleted")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DELETED_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    deleted: bool
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., deleted: _Optional[bool] = ...) -> None: ...

class AuditPolicyRevision(_message.Message):
    __slots__ = ("name", "revision")
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    name: str
    revision: int
    def __init__(self, name: _Optional[str] = ..., revision: _Optional[int] = ...) -> None: ...

class AuditEvent(_message.Message):
    __slots__ = ("id", "kind", "first", "last", "count", "actor", "access", "lifecycle", "policy", "refused", "credentials", "refused_overflow")
    ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    FIRST_FIELD_NUMBER: _ClassVar[int]
    LAST_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    REFUSED_FIELD_NUMBER: _ClassVar[int]
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    REFUSED_OVERFLOW_FIELD_NUMBER: _ClassVar[int]
    id: str
    kind: AuditEventKind
    first: _timestamp_pb2.Timestamp
    last: _timestamp_pb2.Timestamp
    count: int
    actor: AuditActor
    access: AuditAccess
    lifecycle: AuditLifecycle
    policy: AuditPolicyChange
    refused: AuditRefusal
    credentials: AuditCredentials
    refused_overflow: AuditRefusalOverflow
    def __init__(self, id: _Optional[str] = ..., kind: _Optional[_Union[AuditEventKind, str]] = ..., first: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., last: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., count: _Optional[int] = ..., actor: _Optional[_Union[AuditActor, _Mapping]] = ..., access: _Optional[_Union[AuditAccess, _Mapping]] = ..., lifecycle: _Optional[_Union[AuditLifecycle, _Mapping]] = ..., policy: _Optional[_Union[AuditPolicyChange, _Mapping]] = ..., refused: _Optional[_Union[AuditRefusal, _Mapping]] = ..., credentials: _Optional[_Union[AuditCredentials, _Mapping]] = ..., refused_overflow: _Optional[_Union[AuditRefusalOverflow, _Mapping]] = ...) -> None: ...

class AuditActor(_message.Message):
    __slots__ = ("user", "api_key", "platform", "sandbox")
    USER_FIELD_NUMBER: _ClassVar[int]
    API_KEY_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_FIELD_NUMBER: _ClassVar[int]
    user: AuditUser
    api_key: AuditApiKey
    platform: AuditPlatform
    sandbox: AuditSandbox
    def __init__(self, user: _Optional[_Union[AuditUser, _Mapping]] = ..., api_key: _Optional[_Union[AuditApiKey, _Mapping]] = ..., platform: _Optional[_Union[AuditPlatform, _Mapping]] = ..., sandbox: _Optional[_Union[AuditSandbox, _Mapping]] = ...) -> None: ...

class AuditUser(_message.Message):
    __slots__ = ("id", "email", "role")
    ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    id: str
    email: str
    role: AuditRole
    def __init__(self, id: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[_Union[AuditRole, str]] = ...) -> None: ...

class AuditApiKey(_message.Message):
    __slots__ = ("id", "name")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class AuditPlatform(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AuditSandbox(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AuditAccess(_message.Message):
    __slots__ = ("surface", "client_ip")
    SURFACE_FIELD_NUMBER: _ClassVar[int]
    CLIENT_IP_FIELD_NUMBER: _ClassVar[int]
    surface: AuditSurface
    client_ip: str
    def __init__(self, surface: _Optional[_Union[AuditSurface, str]] = ..., client_ip: _Optional[str] = ...) -> None: ...

class AuditSize(_message.Message):
    __slots__ = ("vcpu", "memory_mib")
    VCPU_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    vcpu: int
    memory_mib: int
    def __init__(self, vcpu: _Optional[int] = ..., memory_mib: _Optional[int] = ...) -> None: ...

class AuditLifecycle(_message.Message):
    __slots__ = ("action", "reason", "preset", "from_snapshot", "to", "snapshot", "idle_stop_seconds")
    class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ACTION_UNSPECIFIED: _ClassVar[AuditLifecycle.Action]
        ACTION_CREATED: _ClassVar[AuditLifecycle.Action]
        ACTION_STARTED: _ClassVar[AuditLifecycle.Action]
        ACTION_STOPPED: _ClassVar[AuditLifecycle.Action]
        ACTION_RESTARTED: _ClassVar[AuditLifecycle.Action]
        ACTION_RESIZED: _ClassVar[AuditLifecycle.Action]
        ACTION_SNAPSHOT_TAKEN: _ClassVar[AuditLifecycle.Action]
        ACTION_DELETED: _ClassVar[AuditLifecycle.Action]
    ACTION_UNSPECIFIED: AuditLifecycle.Action
    ACTION_CREATED: AuditLifecycle.Action
    ACTION_STARTED: AuditLifecycle.Action
    ACTION_STOPPED: AuditLifecycle.Action
    ACTION_RESTARTED: AuditLifecycle.Action
    ACTION_RESIZED: AuditLifecycle.Action
    ACTION_SNAPSHOT_TAKEN: AuditLifecycle.Action
    ACTION_DELETED: AuditLifecycle.Action
    ACTION_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    PRESET_FIELD_NUMBER: _ClassVar[int]
    FROM_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FROM_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    IDLE_STOP_SECONDS_FIELD_NUMBER: _ClassVar[int]
    action: AuditLifecycle.Action
    reason: AuditPlatformReason
    preset: str
    from_snapshot: str
    to: AuditSize
    snapshot: str
    idle_stop_seconds: int
    def __init__(self, action: _Optional[_Union[AuditLifecycle.Action, str]] = ..., reason: _Optional[_Union[AuditPlatformReason, str]] = ..., preset: _Optional[str] = ..., from_snapshot: _Optional[str] = ..., to: _Optional[_Union[AuditSize, _Mapping]] = ..., snapshot: _Optional[str] = ..., idle_stop_seconds: _Optional[int] = ..., **kwargs) -> None: ...

class AuditPolicyChange(_message.Message):
    __slots__ = ("action", "to", "policy", "from_revision", "to_revision", "added", "removed", "revision", "failure_code")
    class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ACTION_UNSPECIFIED: _ClassVar[AuditPolicyChange.Action]
        ACTION_SELECTED: _ClassVar[AuditPolicyChange.Action]
        ACTION_EDITED: _ClassVar[AuditPolicyChange.Action]
        ACTION_ENFORCING: _ClassVar[AuditPolicyChange.Action]
        ACTION_FAILED_CLOSED: _ClassVar[AuditPolicyChange.Action]
    ACTION_UNSPECIFIED: AuditPolicyChange.Action
    ACTION_SELECTED: AuditPolicyChange.Action
    ACTION_EDITED: AuditPolicyChange.Action
    ACTION_ENFORCING: AuditPolicyChange.Action
    ACTION_FAILED_CLOSED: AuditPolicyChange.Action
    ACTION_FIELD_NUMBER: _ClassVar[int]
    FROM_FIELD_NUMBER: _ClassVar[int]
    TO_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    FROM_REVISION_FIELD_NUMBER: _ClassVar[int]
    TO_REVISION_FIELD_NUMBER: _ClassVar[int]
    ADDED_FIELD_NUMBER: _ClassVar[int]
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_CODE_FIELD_NUMBER: _ClassVar[int]
    action: AuditPolicyChange.Action
    to: str
    policy: str
    from_revision: int
    to_revision: int
    added: _containers.RepeatedScalarFieldContainer[str]
    removed: _containers.RepeatedScalarFieldContainer[str]
    revision: int
    failure_code: str
    def __init__(self, action: _Optional[_Union[AuditPolicyChange.Action, str]] = ..., to: _Optional[str] = ..., policy: _Optional[str] = ..., from_revision: _Optional[int] = ..., to_revision: _Optional[int] = ..., added: _Optional[_Iterable[str]] = ..., removed: _Optional[_Iterable[str]] = ..., revision: _Optional[int] = ..., failure_code: _Optional[str] = ..., **kwargs) -> None: ...

class AuditRefusal(_message.Message):
    __slots__ = ("destination", "withheld", "address", "port", "protocol", "reason", "source", "policy", "revision", "allowed_since_revision")
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    WITHHELD_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_SINCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    destination: str
    withheld: bool
    address: str
    port: int
    protocol: AuditProtocol
    reason: str
    source: str
    policy: str
    revision: int
    allowed_since_revision: int
    def __init__(self, destination: _Optional[str] = ..., withheld: _Optional[bool] = ..., address: _Optional[str] = ..., port: _Optional[int] = ..., protocol: _Optional[_Union[AuditProtocol, str]] = ..., reason: _Optional[str] = ..., source: _Optional[str] = ..., policy: _Optional[str] = ..., revision: _Optional[int] = ..., allowed_since_revision: _Optional[int] = ...) -> None: ...

class AuditRefusalOverflow(_message.Message):
    __slots__ = ("subjects", "at_least")
    SUBJECTS_FIELD_NUMBER: _ClassVar[int]
    AT_LEAST_FIELD_NUMBER: _ClassVar[int]
    subjects: int
    at_least: bool
    def __init__(self, subjects: _Optional[int] = ..., at_least: _Optional[bool] = ...) -> None: ...

class AuditCredentials(_message.Message):
    __slots__ = ("action", "provider", "name", "host", "withheld")
    class Action(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ACTION_UNSPECIFIED: _ClassVar[AuditCredentials.Action]
        ACTION_ATTACHED: _ClassVar[AuditCredentials.Action]
        ACTION_DETACHED: _ClassVar[AuditCredentials.Action]
        ACTION_USED: _ClassVar[AuditCredentials.Action]
    ACTION_UNSPECIFIED: AuditCredentials.Action
    ACTION_ATTACHED: AuditCredentials.Action
    ACTION_DETACHED: AuditCredentials.Action
    ACTION_USED: AuditCredentials.Action
    ACTION_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    WITHHELD_FIELD_NUMBER: _ClassVar[int]
    action: AuditCredentials.Action
    provider: str
    name: str
    host: str
    withheld: bool
    def __init__(self, action: _Optional[_Union[AuditCredentials.Action, str]] = ..., provider: _Optional[str] = ..., name: _Optional[str] = ..., host: _Optional[str] = ..., withheld: _Optional[bool] = ...) -> None: ...
