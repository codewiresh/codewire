from codewire.v1 import host_pb2 as _host_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class HostEnvironmentState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOST_ENVIRONMENT_STATE_UNSPECIFIED: _ClassVar[HostEnvironmentState]
    HOST_ENVIRONMENT_STATE_STOPPED: _ClassVar[HostEnvironmentState]
    HOST_ENVIRONMENT_STATE_STARTING: _ClassVar[HostEnvironmentState]
    HOST_ENVIRONMENT_STATE_RUNNING: _ClassVar[HostEnvironmentState]
    HOST_ENVIRONMENT_STATE_ERROR: _ClassVar[HostEnvironmentState]
    HOST_ENVIRONMENT_STATE_ABSENT: _ClassVar[HostEnvironmentState]

class HostTunnelKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HOST_TUNNEL_KIND_UNSPECIFIED: _ClassVar[HostTunnelKind]
    HOST_TUNNEL_KIND_DAEMON_GRPC: _ClassVar[HostTunnelKind]
HOST_ENVIRONMENT_STATE_UNSPECIFIED: HostEnvironmentState
HOST_ENVIRONMENT_STATE_STOPPED: HostEnvironmentState
HOST_ENVIRONMENT_STATE_STARTING: HostEnvironmentState
HOST_ENVIRONMENT_STATE_RUNNING: HostEnvironmentState
HOST_ENVIRONMENT_STATE_ERROR: HostEnvironmentState
HOST_ENVIRONMENT_STATE_ABSENT: HostEnvironmentState
HOST_TUNNEL_KIND_UNSPECIFIED: HostTunnelKind
HOST_TUNNEL_KIND_DAEMON_GRPC: HostTunnelKind

class AttachHostRequest(_message.Message):
    __slots__ = ("open", "proof", "hello", "ping", "operation_progress", "operation_result", "environment_observed")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    PROOF_FIELD_NUMBER: _ClassVar[int]
    HELLO_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    OPERATION_PROGRESS_FIELD_NUMBER: _ClassVar[int]
    OPERATION_RESULT_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_OBSERVED_FIELD_NUMBER: _ClassVar[int]
    open: HostAttachOpen
    proof: HostAttachProof
    hello: HostHello
    ping: HostPing
    operation_progress: HostOperationProgress
    operation_result: HostOperationResult
    environment_observed: HostEnvironmentObservation
    def __init__(self, open: _Optional[_Union[HostAttachOpen, _Mapping]] = ..., proof: _Optional[_Union[HostAttachProof, _Mapping]] = ..., hello: _Optional[_Union[HostHello, _Mapping]] = ..., ping: _Optional[_Union[HostPing, _Mapping]] = ..., operation_progress: _Optional[_Union[HostOperationProgress, _Mapping]] = ..., operation_result: _Optional[_Union[HostOperationResult, _Mapping]] = ..., environment_observed: _Optional[_Union[HostEnvironmentObservation, _Mapping]] = ...) -> None: ...

class AttachHostResponse(_message.Message):
    __slots__ = ("challenge", "attached", "pong", "revoked", "operation", "superseded", "open_tunnel")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    PONG_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDED_FIELD_NUMBER: _ClassVar[int]
    OPEN_TUNNEL_FIELD_NUMBER: _ClassVar[int]
    challenge: HostChallenge
    attached: HostAttached
    pong: HostPong
    revoked: HostRevoked
    operation: HostOperation
    superseded: HostSuperseded
    open_tunnel: HostOpenTunnel
    def __init__(self, challenge: _Optional[_Union[HostChallenge, _Mapping]] = ..., attached: _Optional[_Union[HostAttached, _Mapping]] = ..., pong: _Optional[_Union[HostPong, _Mapping]] = ..., revoked: _Optional[_Union[HostRevoked, _Mapping]] = ..., operation: _Optional[_Union[HostOperation, _Mapping]] = ..., superseded: _Optional[_Union[HostSuperseded, _Mapping]] = ..., open_tunnel: _Optional[_Union[HostOpenTunnel, _Mapping]] = ...) -> None: ...

class HostAttachOpen(_message.Message):
    __slots__ = ("host_id",)
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    host_id: str
    def __init__(self, host_id: _Optional[str] = ...) -> None: ...

class HostChallenge(_message.Message):
    __slots__ = ("nonce",)
    NONCE_FIELD_NUMBER: _ClassVar[int]
    nonce: bytes
    def __init__(self, nonce: _Optional[bytes] = ...) -> None: ...

class HostAttachProof(_message.Message):
    __slots__ = ("signature",)
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    signature: bytes
    def __init__(self, signature: _Optional[bytes] = ...) -> None: ...

class HostAttached(_message.Message):
    __slots__ = ("ping_interval_seconds", "offline_after_seconds", "rechallenge_interval_seconds", "proof_timeout_seconds", "session_generation")
    PING_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    OFFLINE_AFTER_SECONDS_FIELD_NUMBER: _ClassVar[int]
    RECHALLENGE_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PROOF_TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    SESSION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    ping_interval_seconds: int
    offline_after_seconds: int
    rechallenge_interval_seconds: int
    proof_timeout_seconds: int
    session_generation: int
    def __init__(self, ping_interval_seconds: _Optional[int] = ..., offline_after_seconds: _Optional[int] = ..., rechallenge_interval_seconds: _Optional[int] = ..., proof_timeout_seconds: _Optional[int] = ..., session_generation: _Optional[int] = ...) -> None: ...

class HostHello(_message.Message):
    __slots__ = ("capability_version", "platform", "inventory")
    CAPABILITY_VERSION_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_FIELD_NUMBER: _ClassVar[int]
    INVENTORY_FIELD_NUMBER: _ClassVar[int]
    capability_version: int
    platform: _host_pb2.HostPlatform
    inventory: _containers.RepeatedCompositeFieldContainer[HostEnvironmentObservation]
    def __init__(self, capability_version: _Optional[int] = ..., platform: _Optional[_Union[_host_pb2.HostPlatform, str]] = ..., inventory: _Optional[_Iterable[_Union[HostEnvironmentObservation, _Mapping]]] = ...) -> None: ...

class HostPing(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostPong(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostRevoked(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostSuperseded(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostOperation(_message.Message):
    __slots__ = ("operation_id", "environment_id", "local_environment_id", "expected_generation", "create", "start", "stop", "destroy")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CREATE_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    STOP_FIELD_NUMBER: _ClassVar[int]
    DESTROY_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    environment_id: str
    local_environment_id: str
    expected_generation: int
    create: HostCreate
    start: HostStart
    stop: HostStop
    destroy: HostDestroy
    def __init__(self, operation_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., expected_generation: _Optional[int] = ..., create: _Optional[_Union[HostCreate, _Mapping]] = ..., start: _Optional[_Union[HostStart, _Mapping]] = ..., stop: _Optional[_Union[HostStop, _Mapping]] = ..., destroy: _Optional[_Union[HostDestroy, _Mapping]] = ...) -> None: ...

class HostCreate(_message.Message):
    __slots__ = ("vcpus", "memory_mib", "disk_bytes", "docker_disk_bytes", "project_spec_json", "project_spec_sha256")
    VCPUS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    DOCKER_DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_JSON_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_SHA256_FIELD_NUMBER: _ClassVar[int]
    vcpus: int
    memory_mib: int
    disk_bytes: int
    docker_disk_bytes: int
    project_spec_json: bytes
    project_spec_sha256: str
    def __init__(self, vcpus: _Optional[int] = ..., memory_mib: _Optional[int] = ..., disk_bytes: _Optional[int] = ..., docker_disk_bytes: _Optional[int] = ..., project_spec_json: _Optional[bytes] = ..., project_spec_sha256: _Optional[str] = ...) -> None: ...

class HostStart(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostStop(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostDestroy(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostOperationProgress(_message.Message):
    __slots__ = ("operation_id", "stage", "sequence")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    STAGE_FIELD_NUMBER: _ClassVar[int]
    SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    stage: str
    sequence: int
    def __init__(self, operation_id: _Optional[str] = ..., stage: _Optional[str] = ..., sequence: _Optional[int] = ...) -> None: ...

class HostOperationResult(_message.Message):
    __slots__ = ("operation_id", "done", "failed", "stale_generation")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    DONE_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    STALE_GENERATION_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    done: HostEnvironmentObservation
    failed: HostOperationFailure
    stale_generation: HostStaleGeneration
    def __init__(self, operation_id: _Optional[str] = ..., done: _Optional[_Union[HostEnvironmentObservation, _Mapping]] = ..., failed: _Optional[_Union[HostOperationFailure, _Mapping]] = ..., stale_generation: _Optional[_Union[HostStaleGeneration, _Mapping]] = ...) -> None: ...

class HostOperationFailure(_message.Message):
    __slots__ = ("code", "message")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    code: str
    message: str
    def __init__(self, code: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class HostStaleGeneration(_message.Message):
    __slots__ = ("expected_generation", "current_generation")
    EXPECTED_GENERATION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    expected_generation: int
    current_generation: int
    def __init__(self, expected_generation: _Optional[int] = ..., current_generation: _Optional[int] = ...) -> None: ...

class HostEnvironmentObservation(_message.Message):
    __slots__ = ("environment_id", "local_environment_id", "generation", "state", "error_code", "vcpus", "memory_mib", "disk_bytes", "ssh_host_key")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    VCPUS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    DISK_BYTES_FIELD_NUMBER: _ClassVar[int]
    SSH_HOST_KEY_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    local_environment_id: str
    generation: int
    state: HostEnvironmentState
    error_code: str
    vcpus: int
    memory_mib: int
    disk_bytes: int
    ssh_host_key: str
    def __init__(self, environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., generation: _Optional[int] = ..., state: _Optional[_Union[HostEnvironmentState, str]] = ..., error_code: _Optional[str] = ..., vcpus: _Optional[int] = ..., memory_mib: _Optional[int] = ..., disk_bytes: _Optional[int] = ..., ssh_host_key: _Optional[str] = ...) -> None: ...

class HostOpenTunnel(_message.Message):
    __slots__ = ("tunnel_id", "environment_id", "local_environment_id", "generation", "kind", "nonce")
    TUNNEL_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    tunnel_id: str
    environment_id: str
    local_environment_id: str
    generation: int
    kind: HostTunnelKind
    nonce: bytes
    def __init__(self, tunnel_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., generation: _Optional[int] = ..., kind: _Optional[_Union[HostTunnelKind, str]] = ..., nonce: _Optional[bytes] = ...) -> None: ...

class OpenHostTunnelRequest(_message.Message):
    __slots__ = ("open", "ready", "failed", "data")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    FAILED_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    open: HostTunnelOpen
    ready: HostTunnelReady
    failed: HostOperationFailure
    data: bytes
    def __init__(self, open: _Optional[_Union[HostTunnelOpen, _Mapping]] = ..., ready: _Optional[_Union[HostTunnelReady, _Mapping]] = ..., failed: _Optional[_Union[HostOperationFailure, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class OpenHostTunnelResponse(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class HostTunnelOpen(_message.Message):
    __slots__ = ("host_id", "tunnel_id", "signature")
    HOST_ID_FIELD_NUMBER: _ClassVar[int]
    TUNNEL_ID_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    host_id: str
    tunnel_id: str
    signature: bytes
    def __init__(self, host_id: _Optional[str] = ..., tunnel_id: _Optional[str] = ..., signature: _Optional[bytes] = ...) -> None: ...

class HostTunnelReady(_message.Message):
    __slots__ = ("daemon_capability",)
    DAEMON_CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    daemon_capability: str
    def __init__(self, daemon_capability: _Optional[str] = ...) -> None: ...
