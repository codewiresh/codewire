from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EgressEnforcementState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EGRESS_ENFORCEMENT_STATE_UNSPECIFIED: _ClassVar[EgressEnforcementState]
    EGRESS_ENFORCEMENT_STATE_ENFORCED: _ClassVar[EgressEnforcementState]
    EGRESS_ENFORCEMENT_STATE_FAILED_CLOSED: _ClassVar[EgressEnforcementState]
    EGRESS_ENFORCEMENT_STATE_DISCONNECTED: _ClassVar[EgressEnforcementState]

class EgressTransport(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EGRESS_TRANSPORT_UNSPECIFIED: _ClassVar[EgressTransport]
    EGRESS_TRANSPORT_DNS: _ClassVar[EgressTransport]
    EGRESS_TRANSPORT_TCP: _ClassVar[EgressTransport]
    EGRESS_TRANSPORT_UDP: _ClassVar[EgressTransport]
EGRESS_ENFORCEMENT_STATE_UNSPECIFIED: EgressEnforcementState
EGRESS_ENFORCEMENT_STATE_ENFORCED: EgressEnforcementState
EGRESS_ENFORCEMENT_STATE_FAILED_CLOSED: EgressEnforcementState
EGRESS_ENFORCEMENT_STATE_DISCONNECTED: EgressEnforcementState
EGRESS_TRANSPORT_UNSPECIFIED: EgressTransport
EGRESS_TRANSPORT_DNS: EgressTransport
EGRESS_TRANSPORT_TCP: EgressTransport
EGRESS_TRANSPORT_UDP: EgressTransport

class AdmitRequest(_message.Message):
    __slots__ = ("guest_token", "peer_ip")
    GUEST_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PEER_IP_FIELD_NUMBER: _ClassVar[int]
    guest_token: str
    peer_ip: str
    def __init__(self, guest_token: _Optional[str] = ..., peer_ip: _Optional[str] = ...) -> None: ...

class AdmitResponse(_message.Message):
    __slots__ = ("pod_uid", "assignment", "pod_name", "ca_certificate_der")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    ASSIGNMENT_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    CA_CERTIFICATE_DER_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    assignment: EgressAssignment
    pod_name: str
    ca_certificate_der: bytes
    def __init__(self, pod_uid: _Optional[str] = ..., assignment: _Optional[_Union[EgressAssignment, _Mapping]] = ..., pod_name: _Optional[str] = ..., ca_certificate_der: _Optional[bytes] = ...) -> None: ...

class WatchAssignmentRequest(_message.Message):
    __slots__ = ("pod_uid", "pod_name")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    pod_name: str
    def __init__(self, pod_uid: _Optional[str] = ..., pod_name: _Optional[str] = ...) -> None: ...

class WatchAssignmentResponse(_message.Message):
    __slots__ = ("assignment",)
    ASSIGNMENT_FIELD_NUMBER: _ClassVar[int]
    assignment: EgressAssignment
    def __init__(self, assignment: _Optional[_Union[EgressAssignment, _Mapping]] = ...) -> None: ...

class EgressAssignment(_message.Message):
    __slots__ = ("unbound", "bound", "platform_allows")
    UNBOUND_FIELD_NUMBER: _ClassVar[int]
    BOUND_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_ALLOWS_FIELD_NUMBER: _ClassVar[int]
    unbound: UnboundAssignment
    bound: BoundAssignment
    platform_allows: _containers.RepeatedCompositeFieldContainer[PlatformAllow]
    def __init__(self, unbound: _Optional[_Union[UnboundAssignment, _Mapping]] = ..., bound: _Optional[_Union[BoundAssignment, _Mapping]] = ..., platform_allows: _Optional[_Iterable[_Union[PlatformAllow, _Mapping]]] = ...) -> None: ...

class UnboundAssignment(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BoundAssignment(_message.Message):
    __slots__ = ("environment_id", "operation_generation", "policy", "interception", "interception_bindings")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    INTERCEPTION_FIELD_NUMBER: _ClassVar[int]
    INTERCEPTION_BINDINGS_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    operation_generation: int
    policy: EgressPolicyRevision
    interception: bool
    interception_bindings: _containers.RepeatedCompositeFieldContainer[InterceptionBinding]
    def __init__(self, environment_id: _Optional[str] = ..., operation_generation: _Optional[int] = ..., policy: _Optional[_Union[EgressPolicyRevision, _Mapping]] = ..., interception: _Optional[bool] = ..., interception_bindings: _Optional[_Iterable[_Union[InterceptionBinding, _Mapping]]] = ...) -> None: ...

class InterceptionBinding(_message.Message):
    __slots__ = ("host", "port", "suffix")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    SUFFIX_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    suffix: bool
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ..., suffix: _Optional[bool] = ...) -> None: ...

class EgressPolicyRevision(_message.Message):
    __slots__ = ("reference", "revision", "document", "digest")
    REFERENCE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DOCUMENT_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    reference: str
    revision: int
    document: bytes
    digest: bytes
    def __init__(self, reference: _Optional[str] = ..., revision: _Optional[int] = ..., document: _Optional[bytes] = ..., digest: _Optional[bytes] = ...) -> None: ...

class PlatformAllow(_message.Message):
    __slots__ = ("host", "port")
    HOST_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    host: str
    port: int
    def __init__(self, host: _Optional[str] = ..., port: _Optional[int] = ...) -> None: ...

class ReportEnforcementRequest(_message.Message):
    __slots__ = ("pod_uid", "pod_name", "state", "revision", "digest", "detail")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    pod_name: str
    state: EgressEnforcementState
    revision: int
    digest: bytes
    detail: str
    def __init__(self, pod_uid: _Optional[str] = ..., pod_name: _Optional[str] = ..., state: _Optional[_Union[EgressEnforcementState, str]] = ..., revision: _Optional[int] = ..., digest: _Optional[bytes] = ..., detail: _Optional[str] = ...) -> None: ...

class ReportEnforcementResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReportRecordsRequest(_message.Message):
    __slots__ = ("pod_uid", "pod_name", "records")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    pod_name: str
    records: _containers.RepeatedCompositeFieldContainer[EgressRecord]
    def __init__(self, pod_uid: _Optional[str] = ..., pod_name: _Optional[str] = ..., records: _Optional[_Iterable[_Union[EgressRecord, _Mapping]]] = ...) -> None: ...

class ReportRecordsResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EgressRecord(_message.Message):
    __slots__ = ("name", "address_only", "address", "transport", "port", "refusal", "policy_reference", "policy_revision", "policy_digest", "first_seen_unix_ms", "last_seen_unix_ms", "count")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_ONLY_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    TRANSPORT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    REFUSAL_FIELD_NUMBER: _ClassVar[int]
    POLICY_REFERENCE_FIELD_NUMBER: _ClassVar[int]
    POLICY_REVISION_FIELD_NUMBER: _ClassVar[int]
    POLICY_DIGEST_FIELD_NUMBER: _ClassVar[int]
    FIRST_SEEN_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    name: str
    address_only: str
    address: str
    transport: EgressTransport
    port: int
    refusal: str
    policy_reference: str
    policy_revision: int
    policy_digest: bytes
    first_seen_unix_ms: int
    last_seen_unix_ms: int
    count: int
    def __init__(self, name: _Optional[str] = ..., address_only: _Optional[str] = ..., address: _Optional[str] = ..., transport: _Optional[_Union[EgressTransport, str]] = ..., port: _Optional[int] = ..., refusal: _Optional[str] = ..., policy_reference: _Optional[str] = ..., policy_revision: _Optional[int] = ..., policy_digest: _Optional[bytes] = ..., first_seen_unix_ms: _Optional[int] = ..., last_seen_unix_ms: _Optional[int] = ..., count: _Optional[int] = ...) -> None: ...

class FrontDoorSessionRequest(_message.Message):
    __slots__ = ("open", "bridge")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    BRIDGE_FIELD_NUMBER: _ClassVar[int]
    open: FrontDoorSessionOpen
    bridge: bytes
    def __init__(self, open: _Optional[_Union[FrontDoorSessionOpen, _Mapping]] = ..., bridge: _Optional[bytes] = ...) -> None: ...

class FrontDoorSessionOpen(_message.Message):
    __slots__ = ("pod_name", "pod_uid")
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    pod_name: str
    pod_uid: str
    def __init__(self, pod_name: _Optional[str] = ..., pod_uid: _Optional[str] = ...) -> None: ...

class FrontDoorSessionResponse(_message.Message):
    __slots__ = ("attached", "bridge")
    ATTACHED_FIELD_NUMBER: _ClassVar[int]
    BRIDGE_FIELD_NUMBER: _ClassVar[int]
    attached: FrontDoorSessionAttached
    bridge: bytes
    def __init__(self, attached: _Optional[_Union[FrontDoorSessionAttached, _Mapping]] = ..., bridge: _Optional[bytes] = ...) -> None: ...

class FrontDoorSessionAttached(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SignInterceptionLeavesRequest(_message.Message):
    __slots__ = ("pod_uid", "pod_name", "leaf_public_key")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    LEAF_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    pod_name: str
    leaf_public_key: bytes
    def __init__(self, pod_uid: _Optional[str] = ..., pod_name: _Optional[str] = ..., leaf_public_key: _Optional[bytes] = ...) -> None: ...

class InterceptionLeaf(_message.Message):
    __slots__ = ("certificate_der",)
    CERTIFICATE_DER_FIELD_NUMBER: _ClassVar[int]
    certificate_der: bytes
    def __init__(self, certificate_der: _Optional[bytes] = ...) -> None: ...

class SignInterceptionLeavesResponse(_message.Message):
    __slots__ = ("leaves", "renew_at_unix")
    LEAVES_FIELD_NUMBER: _ClassVar[int]
    RENEW_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    leaves: _containers.RepeatedCompositeFieldContainer[InterceptionLeaf]
    renew_at_unix: int
    def __init__(self, leaves: _Optional[_Iterable[_Union[InterceptionLeaf, _Mapping]]] = ..., renew_at_unix: _Optional[int] = ...) -> None: ...
