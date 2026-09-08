from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CredentialBridgeFailureReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CREDENTIAL_BRIDGE_FAILURE_REASON_UNSPECIFIED: _ClassVar[CredentialBridgeFailureReason]
    CREDENTIAL_BRIDGE_FAILURE_REASON_DENIED: _ClassVar[CredentialBridgeFailureReason]
    CREDENTIAL_BRIDGE_FAILURE_REASON_UNAVAILABLE: _ClassVar[CredentialBridgeFailureReason]
    CREDENTIAL_BRIDGE_FAILURE_REASON_UPSTREAM_FAILED: _ClassVar[CredentialBridgeFailureReason]
    CREDENTIAL_BRIDGE_FAILURE_REASON_RESPONSE_TOO_LARGE: _ClassVar[CredentialBridgeFailureReason]

class EnvironmentProjectionSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_PROJECTION_SOURCE_UNSPECIFIED: _ClassVar[EnvironmentProjectionSource]
    ENVIRONMENT_PROJECTION_SOURCE_ORGANIZATION: _ClassVar[EnvironmentProjectionSource]
    ENVIRONMENT_PROJECTION_SOURCE_PROJECT: _ClassVar[EnvironmentProjectionSource]
    ENVIRONMENT_PROJECTION_SOURCE_USER: _ClassVar[EnvironmentProjectionSource]
CREDENTIAL_BRIDGE_FAILURE_REASON_UNSPECIFIED: CredentialBridgeFailureReason
CREDENTIAL_BRIDGE_FAILURE_REASON_DENIED: CredentialBridgeFailureReason
CREDENTIAL_BRIDGE_FAILURE_REASON_UNAVAILABLE: CredentialBridgeFailureReason
CREDENTIAL_BRIDGE_FAILURE_REASON_UPSTREAM_FAILED: CredentialBridgeFailureReason
CREDENTIAL_BRIDGE_FAILURE_REASON_RESPONSE_TOO_LARGE: CredentialBridgeFailureReason
ENVIRONMENT_PROJECTION_SOURCE_UNSPECIFIED: EnvironmentProjectionSource
ENVIRONMENT_PROJECTION_SOURCE_ORGANIZATION: EnvironmentProjectionSource
ENVIRONMENT_PROJECTION_SOURCE_PROJECT: EnvironmentProjectionSource
ENVIRONMENT_PROJECTION_SOURCE_USER: EnvironmentProjectionSource

class CredentialBridgeOpen(_message.Message):
    __slots__ = ("protocol_version", "environment_id", "environment_generation")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    environment_id: str
    environment_generation: int
    def __init__(self, protocol_version: _Optional[int] = ..., environment_id: _Optional[str] = ..., environment_generation: _Optional[int] = ...) -> None: ...

class CredentialHttpHeader(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: bytes
    def __init__(self, name: _Optional[str] = ..., value: _Optional[bytes] = ...) -> None: ...

class CredentialBridgeResponseStart(_message.Message):
    __slots__ = ("request_id", "status_code", "headers")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    status_code: int
    headers: _containers.RepeatedCompositeFieldContainer[CredentialHttpHeader]
    def __init__(self, request_id: _Optional[str] = ..., status_code: _Optional[int] = ..., headers: _Optional[_Iterable[_Union[CredentialHttpHeader, _Mapping]]] = ...) -> None: ...

class CredentialBridgeResponseBody(_message.Message):
    __slots__ = ("request_id", "data")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    data: bytes
    def __init__(self, request_id: _Optional[str] = ..., data: _Optional[bytes] = ...) -> None: ...

class CredentialBridgeResponseEnd(_message.Message):
    __slots__ = ("request_id",)
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    def __init__(self, request_id: _Optional[str] = ...) -> None: ...

class CredentialBridgeResponseFailure(_message.Message):
    __slots__ = ("request_id", "reason")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    reason: CredentialBridgeFailureReason
    def __init__(self, request_id: _Optional[str] = ..., reason: _Optional[_Union[CredentialBridgeFailureReason, str]] = ...) -> None: ...

class CredentialBridgeHostMessage(_message.Message):
    __slots__ = ("open", "response_start", "response_body", "response_end", "response_failure", "environment_projection", "ssh")
    OPEN_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_START_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_BODY_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_END_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FAILURE_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_PROJECTION_FIELD_NUMBER: _ClassVar[int]
    SSH_FIELD_NUMBER: _ClassVar[int]
    open: CredentialBridgeOpen
    response_start: CredentialBridgeResponseStart
    response_body: CredentialBridgeResponseBody
    response_end: CredentialBridgeResponseEnd
    response_failure: CredentialBridgeResponseFailure
    environment_projection: EnvironmentProjectionResponse
    ssh: CredentialSshResponse
    def __init__(self, open: _Optional[_Union[CredentialBridgeOpen, _Mapping]] = ..., response_start: _Optional[_Union[CredentialBridgeResponseStart, _Mapping]] = ..., response_body: _Optional[_Union[CredentialBridgeResponseBody, _Mapping]] = ..., response_end: _Optional[_Union[CredentialBridgeResponseEnd, _Mapping]] = ..., response_failure: _Optional[_Union[CredentialBridgeResponseFailure, _Mapping]] = ..., environment_projection: _Optional[_Union[EnvironmentProjectionResponse, _Mapping]] = ..., ssh: _Optional[_Union[CredentialSshResponse, _Mapping]] = ...) -> None: ...

class CredentialBridgeReady(_message.Message):
    __slots__ = ("protocol_version", "environment_id", "environment_generation")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    protocol_version: int
    environment_id: str
    environment_generation: int
    def __init__(self, protocol_version: _Optional[int] = ..., environment_id: _Optional[str] = ..., environment_generation: _Optional[int] = ...) -> None: ...

class CredentialBridgeRequest(_message.Message):
    __slots__ = ("request_id", "method", "path", "query", "headers", "body", "capability_slot", "route")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    QUERY_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_SLOT_FIELD_NUMBER: _ClassVar[int]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    method: str
    path: str
    query: str
    headers: _containers.RepeatedCompositeFieldContainer[CredentialHttpHeader]
    body: bytes
    capability_slot: str
    route: str
    def __init__(self, request_id: _Optional[str] = ..., method: _Optional[str] = ..., path: _Optional[str] = ..., query: _Optional[str] = ..., headers: _Optional[_Iterable[_Union[CredentialHttpHeader, _Mapping]]] = ..., body: _Optional[bytes] = ..., capability_slot: _Optional[str] = ..., route: _Optional[str] = ...) -> None: ...

class CredentialBridgeCancel(_message.Message):
    __slots__ = ("request_id",)
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    def __init__(self, request_id: _Optional[str] = ...) -> None: ...

class CredentialBridgeGuestMessage(_message.Message):
    __slots__ = ("ready", "request", "cancel", "environment_projection", "ssh")
    READY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    CANCEL_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_PROJECTION_FIELD_NUMBER: _ClassVar[int]
    SSH_FIELD_NUMBER: _ClassVar[int]
    ready: CredentialBridgeReady
    request: CredentialBridgeRequest
    cancel: CredentialBridgeCancel
    environment_projection: EnvironmentProjectionRequest
    ssh: CredentialSshRequest
    def __init__(self, ready: _Optional[_Union[CredentialBridgeReady, _Mapping]] = ..., request: _Optional[_Union[CredentialBridgeRequest, _Mapping]] = ..., cancel: _Optional[_Union[CredentialBridgeCancel, _Mapping]] = ..., environment_projection: _Optional[_Union[EnvironmentProjectionRequest, _Mapping]] = ..., ssh: _Optional[_Union[CredentialSshRequest, _Mapping]] = ...) -> None: ...

class CredentialSshRequest(_message.Message):
    __slots__ = ("request_id", "deadline_unix_ms", "identities", "sign")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    IDENTITIES_FIELD_NUMBER: _ClassVar[int]
    SIGN_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    deadline_unix_ms: int
    identities: CredentialSshIdentitiesRequest
    sign: CredentialSshSignRequest
    def __init__(self, request_id: _Optional[str] = ..., deadline_unix_ms: _Optional[int] = ..., identities: _Optional[_Union[CredentialSshIdentitiesRequest, _Mapping]] = ..., sign: _Optional[_Union[CredentialSshSignRequest, _Mapping]] = ...) -> None: ...

class CredentialSshIdentitiesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CredentialSshSignRequest(_message.Message):
    __slots__ = ("public_key_blob", "data", "flags")
    PUBLIC_KEY_BLOB_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    FLAGS_FIELD_NUMBER: _ClassVar[int]
    public_key_blob: bytes
    data: bytes
    flags: int
    def __init__(self, public_key_blob: _Optional[bytes] = ..., data: _Optional[bytes] = ..., flags: _Optional[int] = ...) -> None: ...

class CredentialSshIdentity(_message.Message):
    __slots__ = ("public_key_blob",)
    PUBLIC_KEY_BLOB_FIELD_NUMBER: _ClassVar[int]
    public_key_blob: bytes
    def __init__(self, public_key_blob: _Optional[bytes] = ...) -> None: ...

class CredentialSshSignature(_message.Message):
    __slots__ = ("signature_blob",)
    SIGNATURE_BLOB_FIELD_NUMBER: _ClassVar[int]
    signature_blob: bytes
    def __init__(self, signature_blob: _Optional[bytes] = ...) -> None: ...

class CredentialSshResponse(_message.Message):
    __slots__ = ("request_id", "identity", "signature", "failure")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    identity: CredentialSshIdentity
    signature: CredentialSshSignature
    failure: CredentialBridgeFailureReason
    def __init__(self, request_id: _Optional[str] = ..., identity: _Optional[_Union[CredentialSshIdentity, _Mapping]] = ..., signature: _Optional[_Union[CredentialSshSignature, _Mapping]] = ..., failure: _Optional[_Union[CredentialBridgeFailureReason, str]] = ...) -> None: ...

class EnvironmentProjectionRequest(_message.Message):
    __slots__ = ("request_id", "recipient_public_key", "selection_sha256", "deadline_unix_ms", "local_inventories")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LOCAL_INVENTORIES_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    recipient_public_key: bytes
    selection_sha256: bytes
    deadline_unix_ms: int
    local_inventories: _containers.RepeatedCompositeFieldContainer[EnvironmentProjectionInventory]
    def __init__(self, request_id: _Optional[str] = ..., recipient_public_key: _Optional[bytes] = ..., selection_sha256: _Optional[bytes] = ..., deadline_unix_ms: _Optional[int] = ..., local_inventories: _Optional[_Iterable[_Union[EnvironmentProjectionInventory, _Mapping]]] = ...) -> None: ...

class EnvironmentProjectionResponse(_message.Message):
    __slots__ = ("request_id", "sealed_projection", "failure", "composition")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SEALED_PROJECTION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    COMPOSITION_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    sealed_projection: bytes
    failure: CredentialBridgeFailureReason
    composition: EnvironmentProjectionComposition
    def __init__(self, request_id: _Optional[str] = ..., sealed_projection: _Optional[bytes] = ..., failure: _Optional[_Union[CredentialBridgeFailureReason, str]] = ..., composition: _Optional[_Union[EnvironmentProjectionComposition, _Mapping]] = ...) -> None: ...

class EnvironmentProjectionInventory(_message.Message):
    __slots__ = ("source", "source_identity", "keys")
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    source: EnvironmentProjectionSource
    source_identity: str
    keys: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, source: _Optional[_Union[EnvironmentProjectionSource, str]] = ..., source_identity: _Optional[str] = ..., keys: _Optional[_Iterable[str]] = ...) -> None: ...

class EnvironmentProjectionComposition(_message.Message):
    __slots__ = ("sealed_platform_fragment", "platform_inventories")
    SEALED_PLATFORM_FRAGMENT_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_INVENTORIES_FIELD_NUMBER: _ClassVar[int]
    sealed_platform_fragment: bytes
    platform_inventories: _containers.RepeatedCompositeFieldContainer[EnvironmentProjectionInventory]
    def __init__(self, sealed_platform_fragment: _Optional[bytes] = ..., platform_inventories: _Optional[_Iterable[_Union[EnvironmentProjectionInventory, _Mapping]]] = ...) -> None: ...
