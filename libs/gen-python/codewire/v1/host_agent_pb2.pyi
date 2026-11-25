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
    __slots__ = ("open", "proof", "hello", "ping", "operation_progress", "operation_result", "environment_observed", "access_refresh", "host_key_record", "peer_relay_allocate")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    PROOF_FIELD_NUMBER: _ClassVar[int]
    HELLO_FIELD_NUMBER: _ClassVar[int]
    PING_FIELD_NUMBER: _ClassVar[int]
    OPERATION_PROGRESS_FIELD_NUMBER: _ClassVar[int]
    OPERATION_RESULT_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_OBSERVED_FIELD_NUMBER: _ClassVar[int]
    ACCESS_REFRESH_FIELD_NUMBER: _ClassVar[int]
    HOST_KEY_RECORD_FIELD_NUMBER: _ClassVar[int]
    PEER_RELAY_ALLOCATE_FIELD_NUMBER: _ClassVar[int]
    open: HostAttachOpen
    proof: HostAttachProof
    hello: HostHello
    ping: HostPing
    operation_progress: HostOperationProgress
    operation_result: HostOperationResult
    environment_observed: HostEnvironmentObservation
    access_refresh: HostAccessRefresh
    host_key_record: HostKeyRecord
    peer_relay_allocate: HostPeerRelayAllocate
    def __init__(self, open: _Optional[_Union[HostAttachOpen, _Mapping]] = ..., proof: _Optional[_Union[HostAttachProof, _Mapping]] = ..., hello: _Optional[_Union[HostHello, _Mapping]] = ..., ping: _Optional[_Union[HostPing, _Mapping]] = ..., operation_progress: _Optional[_Union[HostOperationProgress, _Mapping]] = ..., operation_result: _Optional[_Union[HostOperationResult, _Mapping]] = ..., environment_observed: _Optional[_Union[HostEnvironmentObservation, _Mapping]] = ..., access_refresh: _Optional[_Union[HostAccessRefresh, _Mapping]] = ..., host_key_record: _Optional[_Union[HostKeyRecord, _Mapping]] = ..., peer_relay_allocate: _Optional[_Union[HostPeerRelayAllocate, _Mapping]] = ...) -> None: ...

class AttachHostResponse(_message.Message):
    __slots__ = ("challenge", "attached", "pong", "revoked", "operation", "superseded", "open_tunnel", "access_grant", "host_key_recorded", "peer_relay_allocation", "access_refused")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    PONG_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    SUPERSEDED_FIELD_NUMBER: _ClassVar[int]
    OPEN_TUNNEL_FIELD_NUMBER: _ClassVar[int]
    ACCESS_GRANT_FIELD_NUMBER: _ClassVar[int]
    HOST_KEY_RECORDED_FIELD_NUMBER: _ClassVar[int]
    PEER_RELAY_ALLOCATION_FIELD_NUMBER: _ClassVar[int]
    ACCESS_REFUSED_FIELD_NUMBER: _ClassVar[int]
    challenge: HostChallenge
    attached: HostAttached
    pong: HostPong
    revoked: HostRevoked
    operation: HostOperation
    superseded: HostSuperseded
    open_tunnel: HostOpenTunnel
    access_grant: HostAccessGrant
    host_key_recorded: HostKeyRecorded
    peer_relay_allocation: HostPeerRelayAllocation
    access_refused: HostAccessRefusal
    def __init__(self, challenge: _Optional[_Union[HostChallenge, _Mapping]] = ..., attached: _Optional[_Union[HostAttached, _Mapping]] = ..., pong: _Optional[_Union[HostPong, _Mapping]] = ..., revoked: _Optional[_Union[HostRevoked, _Mapping]] = ..., operation: _Optional[_Union[HostOperation, _Mapping]] = ..., superseded: _Optional[_Union[HostSuperseded, _Mapping]] = ..., open_tunnel: _Optional[_Union[HostOpenTunnel, _Mapping]] = ..., access_grant: _Optional[_Union[HostAccessGrant, _Mapping]] = ..., host_key_recorded: _Optional[_Union[HostKeyRecorded, _Mapping]] = ..., peer_relay_allocation: _Optional[_Union[HostPeerRelayAllocation, _Mapping]] = ..., access_refused: _Optional[_Union[HostAccessRefusal, _Mapping]] = ...) -> None: ...

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

class HostAccessRefresh(_message.Message):
    __slots__ = ("request_id", "environment_id", "local_environment_id", "generation")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    environment_id: str
    local_environment_id: str
    generation: int
    def __init__(self, request_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., generation: _Optional[int] = ...) -> None: ...

class HostAccessGrant(_message.Message):
    __slots__ = ("request_id", "peer_token", "peer_token_expires_at", "operation_generation", "coordinator_url", "app_ports")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    PEER_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PEER_TOKEN_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_URL_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    peer_token: str
    peer_token_expires_at: int
    operation_generation: int
    coordinator_url: str
    app_ports: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, request_id: _Optional[str] = ..., peer_token: _Optional[str] = ..., peer_token_expires_at: _Optional[int] = ..., operation_generation: _Optional[int] = ..., coordinator_url: _Optional[str] = ..., app_ports: _Optional[_Iterable[int]] = ...) -> None: ...

class HostKeyRecord(_message.Message):
    __slots__ = ("request_id", "environment_id", "local_environment_id", "generation", "public_key_openssh")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_OPENSSH_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    environment_id: str
    local_environment_id: str
    generation: int
    public_key_openssh: str
    def __init__(self, request_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., generation: _Optional[int] = ..., public_key_openssh: _Optional[str] = ...) -> None: ...

class HostKeyRecorded(_message.Message):
    __slots__ = ("request_id",)
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    def __init__(self, request_id: _Optional[str] = ...) -> None: ...

class HostPeerRelayAllocate(_message.Message):
    __slots__ = ("request_id", "environment_id", "local_environment_id", "generation", "disco_keys", "relay_generation")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    LOCAL_ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    DISCO_KEYS_FIELD_NUMBER: _ClassVar[int]
    RELAY_GENERATION_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    environment_id: str
    local_environment_id: str
    generation: int
    disco_keys: _containers.RepeatedScalarFieldContainer[str]
    relay_generation: int
    def __init__(self, request_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., local_environment_id: _Optional[str] = ..., generation: _Optional[int] = ..., disco_keys: _Optional[_Iterable[str]] = ..., relay_generation: _Optional[int] = ...) -> None: ...

class HostPeerRelayAllocation(_message.Message):
    __slots__ = ("request_id", "relay_generation", "server_disco_key", "disco_keys", "lamport_id", "vni", "bind_lifetime_ns", "steady_state_lifetime_ns", "addr_ports")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    RELAY_GENERATION_FIELD_NUMBER: _ClassVar[int]
    SERVER_DISCO_KEY_FIELD_NUMBER: _ClassVar[int]
    DISCO_KEYS_FIELD_NUMBER: _ClassVar[int]
    LAMPORT_ID_FIELD_NUMBER: _ClassVar[int]
    VNI_FIELD_NUMBER: _ClassVar[int]
    BIND_LIFETIME_NS_FIELD_NUMBER: _ClassVar[int]
    STEADY_STATE_LIFETIME_NS_FIELD_NUMBER: _ClassVar[int]
    ADDR_PORTS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    relay_generation: int
    server_disco_key: str
    disco_keys: _containers.RepeatedScalarFieldContainer[str]
    lamport_id: int
    vni: int
    bind_lifetime_ns: int
    steady_state_lifetime_ns: int
    addr_ports: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, request_id: _Optional[str] = ..., relay_generation: _Optional[int] = ..., server_disco_key: _Optional[str] = ..., disco_keys: _Optional[_Iterable[str]] = ..., lamport_id: _Optional[int] = ..., vni: _Optional[int] = ..., bind_lifetime_ns: _Optional[int] = ..., steady_state_lifetime_ns: _Optional[int] = ..., addr_ports: _Optional[_Iterable[str]] = ...) -> None: ...

class HostAccessRefusal(_message.Message):
    __slots__ = ("request_id", "code", "retryable")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    CODE_FIELD_NUMBER: _ClassVar[int]
    RETRYABLE_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    code: str
    retryable: bool
    def __init__(self, request_id: _Optional[str] = ..., code: _Optional[str] = ..., retryable: _Optional[bool] = ...) -> None: ...
