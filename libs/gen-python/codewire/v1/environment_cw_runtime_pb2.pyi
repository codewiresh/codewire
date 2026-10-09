import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentCwRuntimeIdentity(_message.Message):
    __slots__ = ("schema_version", "package_version", "protocol_version", "record_version", "target", "source_revision", "source_tree_sha256", "rustc", "sha256", "size")
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    PACKAGE_VERSION_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    RECORD_VERSION_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    SOURCE_REVISION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_TREE_SHA256_FIELD_NUMBER: _ClassVar[int]
    RUSTC_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    schema_version: int
    package_version: str
    protocol_version: int
    record_version: int
    target: str
    source_revision: str
    source_tree_sha256: str
    rustc: str
    sha256: str
    size: int
    def __init__(self, schema_version: _Optional[int] = ..., package_version: _Optional[str] = ..., protocol_version: _Optional[int] = ..., record_version: _Optional[int] = ..., target: _Optional[str] = ..., source_revision: _Optional[str] = ..., source_tree_sha256: _Optional[str] = ..., rustc: _Optional[str] = ..., sha256: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...

class EnvironmentCwRuntimeIncarnation(_message.Message):
    __slots__ = ("org_id", "environment_id", "environment_generation", "namespace", "pod_name", "pod_uid", "claim_uid", "sandbox_uid", "workspace_pvc_uid", "binding_generation", "projection_selection_sha256", "managed_credential_clients", "binding_bound_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_GENERATION_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    POD_NAME_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    CLAIM_UID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_UID_FIELD_NUMBER: _ClassVar[int]
    WORKSPACE_PVC_UID_FIELD_NUMBER: _ClassVar[int]
    BINDING_GENERATION_FIELD_NUMBER: _ClassVar[int]
    PROJECTION_SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    MANAGED_CREDENTIAL_CLIENTS_FIELD_NUMBER: _ClassVar[int]
    BINDING_BOUND_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    environment_generation: int
    namespace: str
    pod_name: str
    pod_uid: str
    claim_uid: str
    sandbox_uid: str
    workspace_pvc_uid: str
    binding_generation: int
    projection_selection_sha256: str
    managed_credential_clients: str
    binding_bound_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., environment_generation: _Optional[int] = ..., namespace: _Optional[str] = ..., pod_name: _Optional[str] = ..., pod_uid: _Optional[str] = ..., claim_uid: _Optional[str] = ..., sandbox_uid: _Optional[str] = ..., workspace_pvc_uid: _Optional[str] = ..., binding_generation: _Optional[int] = ..., projection_selection_sha256: _Optional[str] = ..., managed_credential_clients: _Optional[str] = ..., binding_bound_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnvironmentCwRuntimeExpectation(_message.Message):
    __slots__ = ("generation", "current_sha256", "previous_sha256")
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_SHA256_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_SHA256_FIELD_NUMBER: _ClassVar[int]
    generation: int
    current_sha256: str
    previous_sha256: str
    def __init__(self, generation: _Optional[int] = ..., current_sha256: _Optional[str] = ..., previous_sha256: _Optional[str] = ...) -> None: ...

class EnvironmentCwRuntimeSelection(_message.Message):
    __slots__ = ("generation", "current", "previous", "pending", "consistent", "retained_count")
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_FIELD_NUMBER: _ClassVar[int]
    PENDING_FIELD_NUMBER: _ClassVar[int]
    CONSISTENT_FIELD_NUMBER: _ClassVar[int]
    RETAINED_COUNT_FIELD_NUMBER: _ClassVar[int]
    generation: int
    current: EnvironmentCwRuntimeIdentity
    previous: EnvironmentCwRuntimeIdentity
    pending: bool
    consistent: bool
    retained_count: int
    def __init__(self, generation: _Optional[int] = ..., current: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., previous: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., pending: _Optional[bool] = ..., consistent: _Optional[bool] = ..., retained_count: _Optional[int] = ...) -> None: ...

class GetEnvironmentCwRuntimeRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentCwRuntimeResponse(_message.Message):
    __slots__ = ("incarnation", "supported_image", "bootstrap_identity", "selection")
    INCARNATION_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_IMAGE_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    SELECTION_FIELD_NUMBER: _ClassVar[int]
    incarnation: EnvironmentCwRuntimeIncarnation
    supported_image: bool
    bootstrap_identity: EnvironmentCwRuntimeIdentity
    selection: EnvironmentCwRuntimeSelection
    def __init__(self, incarnation: _Optional[_Union[EnvironmentCwRuntimeIncarnation, _Mapping]] = ..., supported_image: _Optional[bool] = ..., bootstrap_identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., selection: _Optional[_Union[EnvironmentCwRuntimeSelection, _Mapping]] = ...) -> None: ...

class UpdateEnvironmentCwRuntimeHeader(_message.Message):
    __slots__ = ("org_id", "environment_id", "request_id", "expected_incarnation", "expected_selection", "identity", "bootstrap_identity")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_INCARNATION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SELECTION_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    request_id: str
    expected_incarnation: EnvironmentCwRuntimeIncarnation
    expected_selection: EnvironmentCwRuntimeExpectation
    identity: EnvironmentCwRuntimeIdentity
    bootstrap_identity: EnvironmentCwRuntimeIdentity
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ..., expected_incarnation: _Optional[_Union[EnvironmentCwRuntimeIncarnation, _Mapping]] = ..., expected_selection: _Optional[_Union[EnvironmentCwRuntimeExpectation, _Mapping]] = ..., identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., bootstrap_identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ...) -> None: ...

class UpdateEnvironmentCwRuntimeRequest(_message.Message):
    __slots__ = ("header", "chunk")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    header: UpdateEnvironmentCwRuntimeHeader
    chunk: bytes
    def __init__(self, header: _Optional[_Union[UpdateEnvironmentCwRuntimeHeader, _Mapping]] = ..., chunk: _Optional[bytes] = ...) -> None: ...

class UpdateEnvironmentCwRuntimeResponse(_message.Message):
    __slots__ = ("operation",)
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentCwRuntimeOperation
    def __init__(self, operation: _Optional[_Union[EnvironmentCwRuntimeOperation, _Mapping]] = ...) -> None: ...

class RollbackEnvironmentCwRuntimeRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "request_id", "expected_incarnation", "expected_selection", "identity")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_INCARNATION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SELECTION_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    request_id: str
    expected_incarnation: EnvironmentCwRuntimeIncarnation
    expected_selection: EnvironmentCwRuntimeExpectation
    identity: EnvironmentCwRuntimeIdentity
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ..., expected_incarnation: _Optional[_Union[EnvironmentCwRuntimeIncarnation, _Mapping]] = ..., expected_selection: _Optional[_Union[EnvironmentCwRuntimeExpectation, _Mapping]] = ..., identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ...) -> None: ...

class RollbackEnvironmentCwRuntimeResponse(_message.Message):
    __slots__ = ("operation",)
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentCwRuntimeOperation
    def __init__(self, operation: _Optional[_Union[EnvironmentCwRuntimeOperation, _Mapping]] = ...) -> None: ...

class ObserveEnvironmentCwRuntimeRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "request_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    request_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., request_id: _Optional[str] = ...) -> None: ...

class ObserveEnvironmentCwRuntimeResponse(_message.Message):
    __slots__ = ("operation",)
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    operation: EnvironmentCwRuntimeOperation
    def __init__(self, operation: _Optional[_Union[EnvironmentCwRuntimeOperation, _Mapping]] = ...) -> None: ...

class EnvironmentCwRuntimeStaged(_message.Message):
    __slots__ = ("sha256", "size")
    SHA256_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    sha256: str
    size: int
    def __init__(self, sha256: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...

class EnvironmentCwRuntimeSelected(_message.Message):
    __slots__ = ("sha256", "generation", "previous_sha256", "changed")
    SHA256_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_SHA256_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    sha256: str
    generation: int
    previous_sha256: str
    changed: bool
    def __init__(self, sha256: _Optional[str] = ..., generation: _Optional[int] = ..., previous_sha256: _Optional[str] = ..., changed: _Optional[bool] = ...) -> None: ...

class EnvironmentCwRuntimeCleaned(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnvironmentCwRuntimeAcknowledgement(_message.Message):
    __slots__ = ("checkpoint", "effect", "staged", "selected", "cleaned")
    CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    EFFECT_FIELD_NUMBER: _ClassVar[int]
    STAGED_FIELD_NUMBER: _ClassVar[int]
    SELECTED_FIELD_NUMBER: _ClassVar[int]
    CLEANED_FIELD_NUMBER: _ClassVar[int]
    checkpoint: int
    effect: str
    staged: EnvironmentCwRuntimeStaged
    selected: EnvironmentCwRuntimeSelected
    cleaned: EnvironmentCwRuntimeCleaned
    def __init__(self, checkpoint: _Optional[int] = ..., effect: _Optional[str] = ..., staged: _Optional[_Union[EnvironmentCwRuntimeStaged, _Mapping]] = ..., selected: _Optional[_Union[EnvironmentCwRuntimeSelected, _Mapping]] = ..., cleaned: _Optional[_Union[EnvironmentCwRuntimeCleaned, _Mapping]] = ...) -> None: ...

class EnvironmentCwRuntimeOperation(_message.Message):
    __slots__ = ("request_id", "incarnation", "action", "phase", "checkpoint", "issued_effect", "expected_selection", "identity", "bootstrap_identity", "acknowledgements", "error_code", "admitted_at", "issued_at", "terminal_at")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    INCARNATION_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    PHASE_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_FIELD_NUMBER: _ClassVar[int]
    ISSUED_EFFECT_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_SELECTION_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    BOOTSTRAP_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGEMENTS_FIELD_NUMBER: _ClassVar[int]
    ERROR_CODE_FIELD_NUMBER: _ClassVar[int]
    ADMITTED_AT_FIELD_NUMBER: _ClassVar[int]
    ISSUED_AT_FIELD_NUMBER: _ClassVar[int]
    TERMINAL_AT_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    incarnation: EnvironmentCwRuntimeIncarnation
    action: str
    phase: str
    checkpoint: int
    issued_effect: str
    expected_selection: EnvironmentCwRuntimeExpectation
    identity: EnvironmentCwRuntimeIdentity
    bootstrap_identity: EnvironmentCwRuntimeIdentity
    acknowledgements: _containers.RepeatedCompositeFieldContainer[EnvironmentCwRuntimeAcknowledgement]
    error_code: str
    admitted_at: _timestamp_pb2.Timestamp
    issued_at: _timestamp_pb2.Timestamp
    terminal_at: _timestamp_pb2.Timestamp
    def __init__(self, request_id: _Optional[str] = ..., incarnation: _Optional[_Union[EnvironmentCwRuntimeIncarnation, _Mapping]] = ..., action: _Optional[str] = ..., phase: _Optional[str] = ..., checkpoint: _Optional[int] = ..., issued_effect: _Optional[str] = ..., expected_selection: _Optional[_Union[EnvironmentCwRuntimeExpectation, _Mapping]] = ..., identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., bootstrap_identity: _Optional[_Union[EnvironmentCwRuntimeIdentity, _Mapping]] = ..., acknowledgements: _Optional[_Iterable[_Union[EnvironmentCwRuntimeAcknowledgement, _Mapping]]] = ..., error_code: _Optional[str] = ..., admitted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., issued_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., terminal_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...
