from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshAttachmentReport(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_ATTACHMENT_REPORT_UNSPECIFIED: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_ATTACHED: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_MESH_UNREACHABLE: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_NETWORK_NOT_FOUND: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_NOT_A_MEMBER: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_NODE_NAME_TAKEN: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_REVOKED: _ClassVar[MeshAttachmentReport]
    MESH_ATTACHMENT_REPORT_REFUSED: _ClassVar[MeshAttachmentReport]
MESH_ATTACHMENT_REPORT_UNSPECIFIED: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_ATTACHED: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_MESH_UNREACHABLE: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_NETWORK_NOT_FOUND: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_NOT_A_MEMBER: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_NODE_NAME_TAKEN: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_REVOKED: MeshAttachmentReport
MESH_ATTACHMENT_REPORT_REFUSED: MeshAttachmentReport

class BindWorkspaceRequest(_message.Message):
    __slots__ = ("wait_seconds",)
    WAIT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    wait_seconds: int
    def __init__(self, wait_seconds: _Optional[int] = ...) -> None: ...

class BindWorkspaceResponse(_message.Message):
    __slots__ = ("environment_id", "pod_uid", "operation_generation", "daemon_credential", "projection_selection_sha256", "managed_credential_clients", "access", "working_directory")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    DAEMON_CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    PROJECTION_SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    MANAGED_CREDENTIAL_CLIENTS_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    WORKING_DIRECTORY_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    pod_uid: str
    operation_generation: int
    daemon_credential: str
    projection_selection_sha256: str
    managed_credential_clients: str
    access: WorkspaceAccess
    working_directory: str
    def __init__(self, environment_id: _Optional[str] = ..., pod_uid: _Optional[str] = ..., operation_generation: _Optional[int] = ..., daemon_credential: _Optional[str] = ..., projection_selection_sha256: _Optional[str] = ..., managed_credential_clients: _Optional[str] = ..., access: _Optional[_Union[WorkspaceAccess, _Mapping]] = ..., working_directory: _Optional[str] = ...) -> None: ...

class WorkspaceAccess(_message.Message):
    __slots__ = ("peer_token", "peer_token_expires_at", "operation_generation", "coordinator_url", "direct_udp_endpoints", "peer_relay_endpoints", "app_ports", "mesh")
    PEER_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PEER_TOKEN_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    COORDINATOR_URL_FIELD_NUMBER: _ClassVar[int]
    DIRECT_UDP_ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    PEER_RELAY_ENDPOINTS_FIELD_NUMBER: _ClassVar[int]
    APP_PORTS_FIELD_NUMBER: _ClassVar[int]
    MESH_FIELD_NUMBER: _ClassVar[int]
    peer_token: str
    peer_token_expires_at: int
    operation_generation: int
    coordinator_url: str
    direct_udp_endpoints: _containers.RepeatedScalarFieldContainer[str]
    peer_relay_endpoints: _containers.RepeatedScalarFieldContainer[str]
    app_ports: _containers.RepeatedScalarFieldContainer[int]
    mesh: WorkspaceMeshAttachment
    def __init__(self, peer_token: _Optional[str] = ..., peer_token_expires_at: _Optional[int] = ..., operation_generation: _Optional[int] = ..., coordinator_url: _Optional[str] = ..., direct_udp_endpoints: _Optional[_Iterable[str]] = ..., peer_relay_endpoints: _Optional[_Iterable[str]] = ..., app_ports: _Optional[_Iterable[int]] = ..., mesh: _Optional[_Union[WorkspaceMeshAttachment, _Mapping]] = ...) -> None: ...

class WorkspaceMeshAttachment(_message.Message):
    __slots__ = ("mesh_url", "org_id", "network_id", "node_name")
    MESH_URL_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    mesh_url: str
    org_id: str
    network_id: str
    node_name: str
    def __init__(self, mesh_url: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., node_name: _Optional[str] = ...) -> None: ...

class RefreshAccessRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RefreshAccessResponse(_message.Message):
    __slots__ = ("access",)
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    access: WorkspaceAccess
    def __init__(self, access: _Optional[_Union[WorkspaceAccess, _Mapping]] = ...) -> None: ...

class RecordHostKeyRequest(_message.Message):
    __slots__ = ("public_key_openssh",)
    PUBLIC_KEY_OPENSSH_FIELD_NUMBER: _ClassVar[int]
    public_key_openssh: str
    def __init__(self, public_key_openssh: _Optional[str] = ...) -> None: ...

class RecordHostKeyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AllocatePeerRelayRequest(_message.Message):
    __slots__ = ("disco_keys", "relay_generation")
    DISCO_KEYS_FIELD_NUMBER: _ClassVar[int]
    RELAY_GENERATION_FIELD_NUMBER: _ClassVar[int]
    disco_keys: _containers.RepeatedScalarFieldContainer[str]
    relay_generation: int
    def __init__(self, disco_keys: _Optional[_Iterable[str]] = ..., relay_generation: _Optional[int] = ...) -> None: ...

class AllocatePeerRelayResponse(_message.Message):
    __slots__ = ("relay_generation", "server_disco_key", "disco_keys", "lamport_id", "vni", "bind_lifetime_ns", "steady_state_lifetime_ns", "addr_ports")
    RELAY_GENERATION_FIELD_NUMBER: _ClassVar[int]
    SERVER_DISCO_KEY_FIELD_NUMBER: _ClassVar[int]
    DISCO_KEYS_FIELD_NUMBER: _ClassVar[int]
    LAMPORT_ID_FIELD_NUMBER: _ClassVar[int]
    VNI_FIELD_NUMBER: _ClassVar[int]
    BIND_LIFETIME_NS_FIELD_NUMBER: _ClassVar[int]
    STEADY_STATE_LIFETIME_NS_FIELD_NUMBER: _ClassVar[int]
    ADDR_PORTS_FIELD_NUMBER: _ClassVar[int]
    relay_generation: int
    server_disco_key: str
    disco_keys: _containers.RepeatedScalarFieldContainer[str]
    lamport_id: int
    vni: int
    bind_lifetime_ns: int
    steady_state_lifetime_ns: int
    addr_ports: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, relay_generation: _Optional[int] = ..., server_disco_key: _Optional[str] = ..., disco_keys: _Optional[_Iterable[str]] = ..., lamport_id: _Optional[int] = ..., vni: _Optional[int] = ..., bind_lifetime_ns: _Optional[int] = ..., steady_state_lifetime_ns: _Optional[int] = ..., addr_ports: _Optional[_Iterable[str]] = ...) -> None: ...

class IssueMeshEnrollmentRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueMeshEnrollmentResponse(_message.Message):
    __slots__ = ("enrollment_code", "expires_at", "attachment")
    ENROLLMENT_CODE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    enrollment_code: str
    expires_at: int
    attachment: WorkspaceMeshAttachment
    def __init__(self, enrollment_code: _Optional[str] = ..., expires_at: _Optional[int] = ..., attachment: _Optional[_Union[WorkspaceMeshAttachment, _Mapping]] = ...) -> None: ...

class ReportMeshAttachmentRequest(_message.Message):
    __slots__ = ("report",)
    REPORT_FIELD_NUMBER: _ClassVar[int]
    report: MeshAttachmentReport
    def __init__(self, report: _Optional[_Union[MeshAttachmentReport, str]] = ...) -> None: ...

class ReportMeshAttachmentResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
