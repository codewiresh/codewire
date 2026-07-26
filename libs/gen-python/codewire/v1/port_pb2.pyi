import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PortAccess(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PORT_ACCESS_UNSPECIFIED: _ClassVar[PortAccess]
    PORT_ACCESS_PUBLIC: _ClassVar[PortAccess]
    PORT_ACCESS_ORG_MEMBERS: _ClassVar[PortAccess]
    PORT_ACCESS_CREATOR: _ClassVar[PortAccess]
PORT_ACCESS_UNSPECIFIED: PortAccess
PORT_ACCESS_PUBLIC: PortAccess
PORT_ACCESS_ORG_MEMBERS: PortAccess
PORT_ACCESS_CREATOR: PortAccess

class Port(_message.Message):
    __slots__ = ("id", "environment_id", "port", "label", "access", "preview_url", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    PREVIEW_URL_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    environment_id: str
    port: int
    label: str
    access: PortAccess
    preview_url: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., environment_id: _Optional[str] = ..., port: _Optional[int] = ..., label: _Optional[str] = ..., access: _Optional[_Union[PortAccess, str]] = ..., preview_url: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListPortsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListPortsResponse(_message.Message):
    __slots__ = ("ports", "next_page_token")
    PORTS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ports: _containers.RepeatedCompositeFieldContainer[Port]
    next_page_token: str
    def __init__(self, ports: _Optional[_Iterable[_Union[Port, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreatePortRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "port", "label", "access")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    LABEL_FIELD_NUMBER: _ClassVar[int]
    ACCESS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    port: int
    label: str
    access: PortAccess
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., port: _Optional[int] = ..., label: _Optional[str] = ..., access: _Optional[_Union[PortAccess, str]] = ...) -> None: ...

class CreatePortResponse(_message.Message):
    __slots__ = ("port",)
    PORT_FIELD_NUMBER: _ClassVar[int]
    port: Port
    def __init__(self, port: _Optional[_Union[Port, _Mapping]] = ...) -> None: ...

class DeletePortRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "port_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PORT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    port_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., port_id: _Optional[str] = ...) -> None: ...

class DeletePortResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
