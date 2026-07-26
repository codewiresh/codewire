import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ApiKey(_message.Message):
    __slots__ = ("id", "user_id", "org_id", "name", "key_prefix", "scopes", "last_used_at", "expires_at", "disabled_at", "created_at", "created_by_name", "created_by_email")
    ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    KEY_PREFIX_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    LAST_USED_AT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    DISABLED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_NAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_EMAIL_FIELD_NUMBER: _ClassVar[int]
    id: str
    user_id: str
    org_id: str
    name: str
    key_prefix: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    last_used_at: _timestamp_pb2.Timestamp
    expires_at: _timestamp_pb2.Timestamp
    disabled_at: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    created_by_name: str
    created_by_email: str
    def __init__(self, id: _Optional[str] = ..., user_id: _Optional[str] = ..., org_id: _Optional[str] = ..., name: _Optional[str] = ..., key_prefix: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., last_used_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., disabled_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_by_name: _Optional[str] = ..., created_by_email: _Optional[str] = ...) -> None: ...

class ListApiKeysRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListApiKeysResponse(_message.Message):
    __slots__ = ("api_keys", "next_page_token")
    API_KEYS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    api_keys: _containers.RepeatedCompositeFieldContainer[ApiKey]
    next_page_token: str
    def __init__(self, api_keys: _Optional[_Iterable[_Union[ApiKey, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateApiKeyRequest(_message.Message):
    __slots__ = ("org_id", "name", "scopes", "expires_in_days")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SCOPES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_IN_DAYS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    scopes: _containers.RepeatedScalarFieldContainer[str]
    expires_in_days: int
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., scopes: _Optional[_Iterable[str]] = ..., expires_in_days: _Optional[int] = ...) -> None: ...

class CreateApiKeyResponse(_message.Message):
    __slots__ = ("api_key", "key")
    API_KEY_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    api_key: ApiKey
    key: str
    def __init__(self, api_key: _Optional[_Union[ApiKey, _Mapping]] = ..., key: _Optional[str] = ...) -> None: ...

class UpdateApiKeyRequest(_message.Message):
    __slots__ = ("org_id", "key_id", "disabled")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    key_id: str
    disabled: bool
    def __init__(self, org_id: _Optional[str] = ..., key_id: _Optional[str] = ..., disabled: _Optional[bool] = ...) -> None: ...

class UpdateApiKeyResponse(_message.Message):
    __slots__ = ("api_key",)
    API_KEY_FIELD_NUMBER: _ClassVar[int]
    api_key: ApiKey
    def __init__(self, api_key: _Optional[_Union[ApiKey, _Mapping]] = ...) -> None: ...

class DeleteApiKeyRequest(_message.Message):
    __slots__ = ("org_id", "key_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    key_id: str
    def __init__(self, org_id: _Optional[str] = ..., key_id: _Optional[str] = ...) -> None: ...

class DeleteApiKeyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
