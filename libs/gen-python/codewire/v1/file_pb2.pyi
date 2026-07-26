import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ListFilesRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "path", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    path: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., path: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListFilesResponse(_message.Message):
    __slots__ = ("entries", "next_page_token")
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    entries: _containers.RepeatedCompositeFieldContainer[FileEntry]
    next_page_token: str
    def __init__(self, entries: _Optional[_Iterable[_Union[FileEntry, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class FileEntry(_message.Message):
    __slots__ = ("name", "size", "is_dir", "mode", "mod_time")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    IS_DIR_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    MOD_TIME_FIELD_NUMBER: _ClassVar[int]
    name: str
    size: int
    is_dir: bool
    mode: int
    mod_time: _timestamp_pb2.Timestamp
    def __init__(self, name: _Optional[str] = ..., size: _Optional[int] = ..., is_dir: _Optional[bool] = ..., mode: _Optional[int] = ..., mod_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class DownloadFileRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "path")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    path: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class DownloadFileResponse(_message.Message):
    __slots__ = ("info", "chunk")
    INFO_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    info: FileEntry
    chunk: bytes
    def __init__(self, info: _Optional[_Union[FileEntry, _Mapping]] = ..., chunk: _Optional[bytes] = ...) -> None: ...

class UploadFileRequest(_message.Message):
    __slots__ = ("header", "chunk")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    header: UploadFileHeader
    chunk: bytes
    def __init__(self, header: _Optional[_Union[UploadFileHeader, _Mapping]] = ..., chunk: _Optional[bytes] = ...) -> None: ...

class UploadFileHeader(_message.Message):
    __slots__ = ("org_id", "environment_id", "path")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    path: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., path: _Optional[str] = ...) -> None: ...

class UploadFileResponse(_message.Message):
    __slots__ = ("path", "size")
    PATH_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    path: str
    size: int
    def __init__(self, path: _Optional[str] = ..., size: _Optional[int] = ...) -> None: ...
