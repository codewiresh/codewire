import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshInvite(_message.Message):
    __slots__ = ("id", "org_id", "network_id", "created_by_user_id", "expires_at", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_USER_ID_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    network_id: str
    created_by_user_id: str
    expires_at: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., created_by_user_id: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListMeshInvitesRequest(_message.Message):
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

class ListMeshInvitesResponse(_message.Message):
    __slots__ = ("invites", "next_page_token")
    INVITES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    invites: _containers.RepeatedCompositeFieldContainer[MeshInvite]
    next_page_token: str
    def __init__(self, invites: _Optional[_Iterable[_Union[MeshInvite, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateMeshInviteRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "ttl")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    TTL_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    ttl: _duration_pb2.Duration
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., ttl: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ...) -> None: ...

class CreateMeshInviteResponse(_message.Message):
    __slots__ = ("invite", "invite_code")
    INVITE_FIELD_NUMBER: _ClassVar[int]
    INVITE_CODE_FIELD_NUMBER: _ClassVar[int]
    invite: MeshInvite
    invite_code: str
    def __init__(self, invite: _Optional[_Union[MeshInvite, _Mapping]] = ..., invite_code: _Optional[str] = ...) -> None: ...

class DeleteMeshInviteRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "invite_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    INVITE_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    invite_id: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., invite_id: _Optional[str] = ...) -> None: ...

class DeleteMeshInviteResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
