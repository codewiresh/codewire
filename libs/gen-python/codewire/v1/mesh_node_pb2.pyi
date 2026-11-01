import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshNode(_message.Message):
    __slots__ = ("org_id", "network_id", "name", "peer_url", "connected", "last_seen_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PEER_URL_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_FIELD_NUMBER: _ClassVar[int]
    LAST_SEEN_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    name: str
    peer_url: str
    connected: bool
    last_seen_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., name: _Optional[str] = ..., peer_url: _Optional[str] = ..., connected: _Optional[bool] = ..., last_seen_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class MeshNodeEnrollment(_message.Message):
    __slots__ = ("id", "org_id", "network_id", "node_name", "owner_user_id", "issued_by_user_id", "expires_at", "created_at", "redeemed_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    OWNER_USER_ID_FIELD_NUMBER: _ClassVar[int]
    ISSUED_BY_USER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    REDEEMED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    network_id: str
    node_name: str
    owner_user_id: str
    issued_by_user_id: str
    expires_at: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    redeemed_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., node_name: _Optional[str] = ..., owner_user_id: _Optional[str] = ..., issued_by_user_id: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., redeemed_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListMeshNodesRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListMeshNodesResponse(_message.Message):
    __slots__ = ("nodes", "next_page_token")
    NODES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    nodes: _containers.RepeatedCompositeFieldContainer[MeshNode]
    next_page_token: str
    def __init__(self, nodes: _Optional[_Iterable[_Union[MeshNode, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class RevokeMeshNodeRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "node_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    node_name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., node_name: _Optional[str] = ...) -> None: ...

class RevokeMeshNodeResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CreateMeshNodeEnrollmentRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "node_name", "ttl")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    node_name: str
    ttl: _duration_pb2.Duration
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., node_name: _Optional[str] = ..., ttl: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class CreateMeshNodeEnrollmentResponse(_message.Message):
    __slots__ = ("enrollment", "enrollment_code")
    ENROLLMENT_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_CODE_FIELD_NUMBER: _ClassVar[int]
    enrollment: MeshNodeEnrollment
    enrollment_code: str
    def __init__(self, enrollment: _Optional[_Union[MeshNodeEnrollment, _Mapping]] = ..., enrollment_code: _Optional[str] = ...) -> None: ...

class RedeemMeshNodeEnrollmentRequest(_message.Message):
    __slots__ = ("enrollment_code", "node_name", "peer_url")
    ENROLLMENT_CODE_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    PEER_URL_FIELD_NUMBER: _ClassVar[int]
    enrollment_code: str
    node_name: str
    peer_url: str
    def __init__(self, enrollment_code: _Optional[str] = ..., node_name: _Optional[str] = ..., peer_url: _Optional[str] = ...) -> None: ...

class RedeemMeshNodeEnrollmentResponse(_message.Message):
    __slots__ = ("node", "enrollment")
    NODE_FIELD_NUMBER: _ClassVar[int]
    ENROLLMENT_FIELD_NUMBER: _ClassVar[int]
    node: MeshNode
    enrollment: MeshNodeEnrollment
    def __init__(self, node: _Optional[_Union[MeshNode, _Mapping]] = ..., enrollment: _Optional[_Union[MeshNodeEnrollment, _Mapping]] = ...) -> None: ...
