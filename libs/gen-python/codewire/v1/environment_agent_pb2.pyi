from codewire.v1 import environment_cw_runtime_pb2 as _environment_cw_runtime_pb2
from codewire.v1 import environment_session_pb2 as _environment_session_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentAgentKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_AGENT_KIND_UNSPECIFIED: _ClassVar[EnvironmentAgentKind]
    ENVIRONMENT_AGENT_KIND_CODEX: _ClassVar[EnvironmentAgentKind]
    ENVIRONMENT_AGENT_KIND_CLAUDE: _ClassVar[EnvironmentAgentKind]

class EnvironmentAgentAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_AGENT_ACTION_UNSPECIFIED: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_MESSAGE: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_STEER: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_INTERRUPT: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_STOP: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_RESTART: _ClassVar[EnvironmentAgentAction]
    ENVIRONMENT_AGENT_ACTION_RESUME: _ClassVar[EnvironmentAgentAction]

class EnvironmentAgentPhase(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_AGENT_PHASE_UNSPECIFIED: _ClassVar[EnvironmentAgentPhase]
    ENVIRONMENT_AGENT_PHASE_ADMITTED: _ClassVar[EnvironmentAgentPhase]
    ENVIRONMENT_AGENT_PHASE_ISSUED: _ClassVar[EnvironmentAgentPhase]
    ENVIRONMENT_AGENT_PHASE_COMPLETED: _ClassVar[EnvironmentAgentPhase]
    ENVIRONMENT_AGENT_PHASE_REJECTED: _ClassVar[EnvironmentAgentPhase]
    ENVIRONMENT_AGENT_PHASE_UNKNOWN: _ClassVar[EnvironmentAgentPhase]

class EnvironmentAgentRecordKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_AGENT_RECORD_KIND_UNSPECIFIED: _ClassVar[EnvironmentAgentRecordKind]
    ENVIRONMENT_AGENT_RECORD_KIND_CURRENT: _ClassVar[EnvironmentAgentRecordKind]
    ENVIRONMENT_AGENT_RECORD_KIND_MESSAGE: _ClassVar[EnvironmentAgentRecordKind]
ENVIRONMENT_AGENT_KIND_UNSPECIFIED: EnvironmentAgentKind
ENVIRONMENT_AGENT_KIND_CODEX: EnvironmentAgentKind
ENVIRONMENT_AGENT_KIND_CLAUDE: EnvironmentAgentKind
ENVIRONMENT_AGENT_ACTION_UNSPECIFIED: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_MESSAGE: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_STEER: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_INTERRUPT: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_STOP: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_RESTART: EnvironmentAgentAction
ENVIRONMENT_AGENT_ACTION_RESUME: EnvironmentAgentAction
ENVIRONMENT_AGENT_PHASE_UNSPECIFIED: EnvironmentAgentPhase
ENVIRONMENT_AGENT_PHASE_ADMITTED: EnvironmentAgentPhase
ENVIRONMENT_AGENT_PHASE_ISSUED: EnvironmentAgentPhase
ENVIRONMENT_AGENT_PHASE_COMPLETED: EnvironmentAgentPhase
ENVIRONMENT_AGENT_PHASE_REJECTED: EnvironmentAgentPhase
ENVIRONMENT_AGENT_PHASE_UNKNOWN: EnvironmentAgentPhase
ENVIRONMENT_AGENT_RECORD_KIND_UNSPECIFIED: EnvironmentAgentRecordKind
ENVIRONMENT_AGENT_RECORD_KIND_CURRENT: EnvironmentAgentRecordKind
ENVIRONMENT_AGENT_RECORD_KIND_MESSAGE: EnvironmentAgentRecordKind

class EnvironmentAgentScope(_message.Message):
    __slots__ = ("incarnation", "support_image_sha256", "support_image_size")
    INCARNATION_FIELD_NUMBER: _ClassVar[int]
    SUPPORT_IMAGE_SHA256_FIELD_NUMBER: _ClassVar[int]
    SUPPORT_IMAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    incarnation: _environment_cw_runtime_pb2.EnvironmentCwRuntimeIncarnation
    support_image_sha256: bytes
    support_image_size: int
    def __init__(self, incarnation: _Optional[_Union[_environment_cw_runtime_pb2.EnvironmentCwRuntimeIncarnation, _Mapping]] = ..., support_image_sha256: _Optional[bytes] = ..., support_image_size: _Optional[int] = ...) -> None: ...

class EnvironmentAgentSupport(_message.Message):
    __slots__ = ("agent", "provider_sha256", "provider_size", "provider_version", "proxy_only_qualified", "steer", "interrupt")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_SHA256_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_SIZE_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_VERSION_FIELD_NUMBER: _ClassVar[int]
    PROXY_ONLY_QUALIFIED_FIELD_NUMBER: _ClassVar[int]
    STEER_FIELD_NUMBER: _ClassVar[int]
    INTERRUPT_FIELD_NUMBER: _ClassVar[int]
    agent: EnvironmentAgentKind
    provider_sha256: bytes
    provider_size: int
    provider_version: str
    proxy_only_qualified: bool
    steer: bool
    interrupt: bool
    def __init__(self, agent: _Optional[_Union[EnvironmentAgentKind, str]] = ..., provider_sha256: _Optional[bytes] = ..., provider_size: _Optional[int] = ..., provider_version: _Optional[str] = ..., proxy_only_qualified: _Optional[bool] = ..., steer: _Optional[bool] = ..., interrupt: _Optional[bool] = ...) -> None: ...

class GetEnvironmentAgentInfoRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentAgentInfoResponse(_message.Message):
    __slots__ = ("scope", "support_image_version", "agents")
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    SUPPORT_IMAGE_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENTS_FIELD_NUMBER: _ClassVar[int]
    scope: EnvironmentAgentScope
    support_image_version: str
    agents: _containers.RepeatedCompositeFieldContainer[EnvironmentAgentSupport]
    def __init__(self, scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., support_image_version: _Optional[str] = ..., agents: _Optional[_Iterable[_Union[EnvironmentAgentSupport, _Mapping]]] = ...) -> None: ...

class EnvironmentAgentLaunch(_message.Message):
    __slots__ = ("agent", "model", "effort", "working_dir", "name", "prompt", "parent_session_id", "expected_parent_launch_generation", "expected_provider_sha256", "expected_provider_size", "expected_provider_version")
    AGENT_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    EFFORT_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIR_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROMPT_FIELD_NUMBER: _ClassVar[int]
    PARENT_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PARENT_LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PROVIDER_SHA256_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PROVIDER_SIZE_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_PROVIDER_VERSION_FIELD_NUMBER: _ClassVar[int]
    agent: EnvironmentAgentKind
    model: str
    effort: str
    working_dir: str
    name: str
    prompt: str
    parent_session_id: str
    expected_parent_launch_generation: int
    expected_provider_sha256: bytes
    expected_provider_size: int
    expected_provider_version: str
    def __init__(self, agent: _Optional[_Union[EnvironmentAgentKind, str]] = ..., model: _Optional[str] = ..., effort: _Optional[str] = ..., working_dir: _Optional[str] = ..., name: _Optional[str] = ..., prompt: _Optional[str] = ..., parent_session_id: _Optional[str] = ..., expected_parent_launch_generation: _Optional[int] = ..., expected_provider_sha256: _Optional[bytes] = ..., expected_provider_size: _Optional[int] = ..., expected_provider_version: _Optional[str] = ...) -> None: ...

class EnvironmentAgentControl(_message.Message):
    __slots__ = ("action", "session_id", "driver_id", "expected_launch_generation", "text", "reply_to", "expected_turn_id", "expected_active_message_id", "cleanup_of_request_id")
    ACTION_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    TEXT_FIELD_NUMBER: _ClassVar[int]
    REPLY_TO_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_TURN_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_ACTIVE_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    CLEANUP_OF_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    action: EnvironmentAgentAction
    session_id: str
    driver_id: str
    expected_launch_generation: int
    text: str
    reply_to: str
    expected_turn_id: str
    expected_active_message_id: str
    cleanup_of_request_id: str
    def __init__(self, action: _Optional[_Union[EnvironmentAgentAction, str]] = ..., session_id: _Optional[str] = ..., driver_id: _Optional[str] = ..., expected_launch_generation: _Optional[int] = ..., text: _Optional[str] = ..., reply_to: _Optional[str] = ..., expected_turn_id: _Optional[str] = ..., expected_active_message_id: _Optional[str] = ..., cleanup_of_request_id: _Optional[str] = ...) -> None: ...

class MutateEnvironmentAgentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "request_id", "expected_scope", "launch", "control")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SCOPE_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_FIELD_NUMBER: _ClassVar[int]
    CONTROL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    request_id: str
    expected_scope: EnvironmentAgentScope
    launch: EnvironmentAgentLaunch
    control: EnvironmentAgentControl
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ..., expected_scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., launch: _Optional[_Union[EnvironmentAgentLaunch, _Mapping]] = ..., control: _Optional[_Union[EnvironmentAgentControl, _Mapping]] = ...) -> None: ...

class EnvironmentAgentOperation(_message.Message):
    __slots__ = ("request_id", "scope", "fingerprint_sha256", "phase", "session_id", "driver_id", "message_id", "launch_generation", "lifecycle", "exit_code", "cleanup_unknown", "pipe_acknowledged", "native_acknowledged", "reason_code", "cleanup_of_request_id")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_SHA256_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    LIFECYCLE_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    CLEANUP_UNKNOWN_FIELD_NUMBER: _ClassVar[int]
    PIPE_ACKNOWLEDGED_FIELD_NUMBER: _ClassVar[int]
    NATIVE_ACKNOWLEDGED_FIELD_NUMBER: _ClassVar[int]
    REASON_CODE_FIELD_NUMBER: _ClassVar[int]
    CLEANUP_OF_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    scope: EnvironmentAgentScope
    fingerprint_sha256: bytes
    phase: EnvironmentAgentPhase
    session_id: str
    driver_id: str
    message_id: str
    launch_generation: int
    lifecycle: _environment_session_pb2.EnvironmentSessionState
    exit_code: int
    cleanup_unknown: bool
    pipe_acknowledged: bool
    native_acknowledged: bool
    reason_code: str
    cleanup_of_request_id: str
    def __init__(self, request_id: _Optional[str] = ..., scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., fingerprint_sha256: _Optional[bytes] = ..., phase: _Optional[_Union[EnvironmentAgentPhase, str]] = ..., session_id: _Optional[str] = ..., driver_id: _Optional[str] = ..., message_id: _Optional[str] = ..., launch_generation: _Optional[int] = ..., lifecycle: _Optional[_Union[_environment_session_pb2.EnvironmentSessionState, str]] = ..., exit_code: _Optional[int] = ..., cleanup_unknown: _Optional[bool] = ..., pipe_acknowledged: _Optional[bool] = ..., native_acknowledged: _Optional[bool] = ..., reason_code: _Optional[str] = ..., cleanup_of_request_id: _Optional[str] = ...) -> None: ...

class MutateEnvironmentAgentResponse(_message.Message):
    __slots__ = ("operation",)
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentAgentOperation
    def __init__(self, operation: _Optional[_Union[EnvironmentAgentOperation, _Mapping]] = ...) -> None: ...

class ObserveEnvironmentAgentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "request_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    request_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ...) -> None: ...

class ObserveEnvironmentAgentResponse(_message.Message):
    __slots__ = ("operation",)
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentAgentOperation
    def __init__(self, operation: _Optional[_Union[EnvironmentAgentOperation, _Mapping]] = ...) -> None: ...

class ListEnvironmentAgentsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "expected_scope", "after_session_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SCOPE_FIELD_NUMBER: _ClassVar[int]
    AFTER_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    expected_scope: EnvironmentAgentScope
    after_session_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., expected_scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., after_session_id: _Optional[str] = ...) -> None: ...

class ListEnvironmentAgentsResponse(_message.Message):
    __slots__ = ("scope", "sessions", "next_after_session_id")
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    SESSIONS_FIELD_NUMBER: _ClassVar[int]
    NEXT_AFTER_SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    scope: EnvironmentAgentScope
    sessions: _containers.RepeatedCompositeFieldContainer[_environment_session_pb2.EnvironmentSession]
    next_after_session_id: str
    def __init__(self, scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., sessions: _Optional[_Iterable[_Union[_environment_session_pb2.EnvironmentSession, _Mapping]]] = ..., next_after_session_id: _Optional[str] = ...) -> None: ...

class ReadEnvironmentAgentRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "expected_scope", "session_id", "driver_id", "expected_launch_generation", "kind", "message_id", "limit")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SCOPE_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    expected_scope: EnvironmentAgentScope
    session_id: str
    driver_id: str
    expected_launch_generation: int
    kind: EnvironmentAgentRecordKind
    message_id: str
    limit: int
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., expected_scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., session_id: _Optional[str] = ..., driver_id: _Optional[str] = ..., expected_launch_generation: _Optional[int] = ..., kind: _Optional[_Union[EnvironmentAgentRecordKind, str]] = ..., message_id: _Optional[str] = ..., limit: _Optional[int] = ...) -> None: ...

class ReadEnvironmentAgentResponse(_message.Message):
    __slots__ = ("scope", "session_id", "driver_id", "launch_generation", "kind", "message_id", "record_json", "record_sha256")
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_GENERATION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    RECORD_JSON_FIELD_NUMBER: _ClassVar[int]
    RECORD_SHA256_FIELD_NUMBER: _ClassVar[int]
    scope: EnvironmentAgentScope
    session_id: str
    driver_id: str
    launch_generation: int
    kind: EnvironmentAgentRecordKind
    message_id: str
    record_json: bytes
    record_sha256: bytes
    def __init__(self, scope: _Optional[_Union[EnvironmentAgentScope, _Mapping]] = ..., session_id: _Optional[str] = ..., driver_id: _Optional[str] = ..., launch_generation: _Optional[int] = ..., kind: _Optional[_Union[EnvironmentAgentRecordKind, str]] = ..., message_id: _Optional[str] = ..., record_json: _Optional[bytes] = ..., record_sha256: _Optional[bytes] = ...) -> None: ...
