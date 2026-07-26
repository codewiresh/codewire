import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshKeyValue(_message.Message):
    __slots__ = ("org_id", "network_id", "namespace", "key", "value", "expires_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    namespace: str
    key: str
    value: bytes
    expires_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., namespace: _Optional[str] = ..., key: _Optional[str] = ..., value: _Optional[bytes] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListMeshKeyValuesRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "namespace", "prefix", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    namespace: str
    prefix: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., namespace: _Optional[str] = ..., prefix: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListMeshKeyValuesResponse(_message.Message):
    __slots__ = ("entries", "next_page_token")
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[MeshKeyValue]
    next_page_token: str
    def __init__(self, entries: _Optional[_Iterable[_Union[MeshKeyValue, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class GetMeshKeyValueRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "namespace", "key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    namespace: str
    key: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., namespace: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class GetMeshKeyValueResponse(_message.Message):
    __slots__ = ("entry",)
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    entry: MeshKeyValue
    def __init__(self, entry: _Optional[_Union[MeshKeyValue, _Mapping]] = ...) -> None: ...

class SetMeshKeyValueRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "namespace", "key", "value", "ttl")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    namespace: str
    key: str
    value: bytes
    ttl: _duration_pb2.Duration
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., namespace: _Optional[str] = ..., key: _Optional[str] = ..., value: _Optional[bytes] = ..., ttl: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class SetMeshKeyValueResponse(_message.Message):
    __slots__ = ("entry",)
    ENTRY_FIELD_NUMBER: _ClassVar[int]
    entry: MeshKeyValue
    def __init__(self, entry: _Optional[_Union[MeshKeyValue, _Mapping]] = ...) -> None: ...

class DeleteMeshKeyValueRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "namespace", "key")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAMESPACE_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    namespace: str
    key: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., namespace: _Optional[str] = ..., key: _Optional[str] = ...) -> None: ...

class DeleteMeshKeyValueResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
