import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshNetwork(_message.Message):
    __slots__ = ("id", "org_id", "created_at", "node_count", "invite_count")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    NODE_COUNT_FIELD_NUMBER: _ClassVar[int]
    INVITE_COUNT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    created_at: _timestamp_pb2.Timestamp
    node_count: int
    invite_count: int
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., node_count: _Optional[int] = ..., invite_count: _Optional[int] = ...) -> None: ...

class ListMeshNetworksRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListMeshNetworksResponse(_message.Message):
    __slots__ = ("networks", "next_page_token")
    NETWORKS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    networks: _containers.RepeatedCompositeFieldContainer[MeshNetwork]
    next_page_token: str
    def __init__(self, networks: _Optional[_Iterable[_Union[MeshNetwork, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateMeshNetworkRequest(_message.Message):
    __slots__ = ("org_id", "network_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ...) -> None: ...

class CreateMeshNetworkResponse(_message.Message):
    __slots__ = ("network",)
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    network: MeshNetwork
    def __init__(self, network: _Optional[_Union[MeshNetwork, _Mapping]] = ...) -> None: ...

class DeleteMeshNetworkRequest(_message.Message):
    __slots__ = ("org_id", "network_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ...) -> None: ...

class DeleteMeshNetworkResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class JoinMeshNetworkRequest(_message.Message):
    __slots__ = ("invite_code",)
    INVITE_CODE_FIELD_NUMBER: _ClassVar[int]
    invite_code: str
    def __init__(self, invite_code: _Optional[str] = ...) -> None: ...

class JoinMeshNetworkResponse(_message.Message):
    __slots__ = ("network",)
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    network: MeshNetwork
    def __init__(self, network: _Optional[_Union[MeshNetwork, _Mapping]] = ...) -> None: ...
