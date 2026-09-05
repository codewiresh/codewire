import datetime

from codewire.v1 import common_pb2 as _common_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Preset(_message.Message):
    __slots__ = ("id", "org_id", "name", "slug", "language", "official", "description", "build_status", "build_error", "default_ttl_seconds", "created_at", "project_spec")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    OFFICIAL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    BUILD_STATUS_FIELD_NUMBER: _ClassVar[int]
    BUILD_ERROR_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    name: str
    slug: str
    language: str
    official: bool
    description: str
    build_status: str
    build_error: str
    default_ttl_seconds: int
    created_at: _timestamp_pb2.Timestamp
    project_spec: _common_pb2.ProjectSpec
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., language: _Optional[str] = ..., official: _Optional[bool] = ..., description: _Optional[str] = ..., build_status: _Optional[str] = ..., build_error: _Optional[str] = ..., default_ttl_seconds: _Optional[int] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., project_spec: _Optional[_Union[_common_pb2.ProjectSpec, _Mapping]] = ...) -> None: ...

class ListPresetsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListPresetsResponse(_message.Message):
    __slots__ = ("presets", "next_page_token")
    PRESETS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    presets: _containers.RepeatedCompositeFieldContainer[Preset]
    next_page_token: str
    def __init__(self, presets: _Optional[_Iterable[_Union[Preset, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreatePresetRequest(_message.Message):
    __slots__ = ("org_id", "name", "slug", "description", "default_ttl_seconds", "project_spec")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    slug: str
    description: str
    default_ttl_seconds: int
    project_spec: _common_pb2.ProjectSpec
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., description: _Optional[str] = ..., default_ttl_seconds: _Optional[int] = ..., project_spec: _Optional[_Union[_common_pb2.ProjectSpec, _Mapping]] = ...) -> None: ...

class CreatePresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class GetPresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ...) -> None: ...

class GetPresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class UpdatePresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id", "name", "description", "slug", "default_ttl_seconds", "project_spec")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TTL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PROJECT_SPEC_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    name: str
    description: str
    slug: str
    default_ttl_seconds: int
    project_spec: _common_pb2.ProjectSpec
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., slug: _Optional[str] = ..., default_ttl_seconds: _Optional[int] = ..., project_spec: _Optional[_Union[_common_pb2.ProjectSpec, _Mapping]] = ...) -> None: ...

class UpdatePresetResponse(_message.Message):
    __slots__ = ("preset",)
    PRESET_FIELD_NUMBER: _ClassVar[int]
    preset: Preset
    def __init__(self, preset: _Optional[_Union[Preset, _Mapping]] = ...) -> None: ...

class DeletePresetRequest(_message.Message):
    __slots__ = ("org_id", "preset_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PRESET_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    preset_id: str
    def __init__(self, org_id: _Optional[str] = ..., preset_id: _Optional[str] = ...) -> None: ...

class DeletePresetResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
