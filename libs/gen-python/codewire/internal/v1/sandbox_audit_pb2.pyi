from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ReportCredentialUsesRequest(_message.Message):
    __slots__ = ("pod_uid", "uses")
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    USES_FIELD_NUMBER: _ClassVar[int]
    pod_uid: str
    uses: _containers.RepeatedCompositeFieldContainer[CredentialUse]
    def __init__(self, pod_uid: _Optional[str] = ..., uses: _Optional[_Iterable[_Union[CredentialUse, _Mapping]]] = ...) -> None: ...

class CredentialUse(_message.Message):
    __slots__ = ("credential_id", "provider", "host", "host_withheld", "first_unix_ms", "last_unix_ms", "count")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    HOST_WITHHELD_FIELD_NUMBER: _ClassVar[int]
    FIRST_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    provider: str
    host: str
    host_withheld: bool
    first_unix_ms: int
    last_unix_ms: int
    count: int
    def __init__(self, credential_id: _Optional[str] = ..., provider: _Optional[str] = ..., host: _Optional[str] = ..., host_withheld: _Optional[bool] = ..., first_unix_ms: _Optional[int] = ..., last_unix_ms: _Optional[int] = ..., count: _Optional[int] = ...) -> None: ...

class ReportCredentialUsesResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
