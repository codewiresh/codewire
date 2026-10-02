from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class BindWorkspaceRequest(_message.Message):
    __slots__ = ("wait_seconds",)
    WAIT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    wait_seconds: int
    def __init__(self, wait_seconds: _Optional[int] = ...) -> None: ...

class BindWorkspaceResponse(_message.Message):
    __slots__ = ("environment_id", "pod_uid", "operation_generation", "daemon_credential", "projection_selection_sha256", "managed_credential_clients")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    DAEMON_CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    PROJECTION_SELECTION_SHA256_FIELD_NUMBER: _ClassVar[int]
    MANAGED_CREDENTIAL_CLIENTS_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    pod_uid: str
    operation_generation: int
    daemon_credential: str
    projection_selection_sha256: str
    managed_credential_clients: str
    def __init__(self, environment_id: _Optional[str] = ..., pod_uid: _Optional[str] = ..., operation_generation: _Optional[int] = ..., daemon_credential: _Optional[str] = ..., projection_selection_sha256: _Optional[str] = ..., managed_credential_clients: _Optional[str] = ...) -> None: ...
