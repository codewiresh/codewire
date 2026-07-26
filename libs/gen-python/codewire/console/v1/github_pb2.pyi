import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetGitHubConfigRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetGitHubConfigResponse(_message.Message):
    __slots__ = ("client_id", "app_slug")
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    APP_SLUG_FIELD_NUMBER: _ClassVar[int]
    client_id: str
    app_slug: str
    def __init__(self, client_id: _Optional[str] = ..., app_slug: _Optional[str] = ...) -> None: ...

class GetGitHubStatusRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetGitHubStatusResponse(_message.Message):
    __slots__ = ("connected", "username", "installation_id", "connected_at")
    CONNECTED_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    INSTALLATION_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTED_AT_FIELD_NUMBER: _ClassVar[int]
    connected: bool
    username: str
    installation_id: int
    connected_at: _timestamp_pb2.Timestamp
    def __init__(self, connected: _Optional[bool] = ..., username: _Optional[str] = ..., installation_id: _Optional[int] = ..., connected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListGitHubReposRequest(_message.Message):
    __slots__ = ("page", "per_page", "search")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    PER_PAGE_FIELD_NUMBER: _ClassVar[int]
    SEARCH_FIELD_NUMBER: _ClassVar[int]
    page: int
    per_page: int
    search: str
    def __init__(self, page: _Optional[int] = ..., per_page: _Optional[int] = ..., search: _Optional[str] = ...) -> None: ...

class ListGitHubReposResponse(_message.Message):
    __slots__ = ("repos",)
    REPOS_FIELD_NUMBER: _ClassVar[int]
    repos: _containers.RepeatedCompositeFieldContainer[GitHubRepo]
    def __init__(self, repos: _Optional[_Iterable[_Union[GitHubRepo, _Mapping]]] = ...) -> None: ...

class GitHubRepo(_message.Message):
    __slots__ = ("full_name", "html_url", "clone_url", "description", "language", "private", "default_branch", "updated_at")
    FULL_NAME_FIELD_NUMBER: _ClassVar[int]
    HTML_URL_FIELD_NUMBER: _ClassVar[int]
    CLONE_URL_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_BRANCH_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    full_name: str
    html_url: str
    clone_url: str
    description: str
    language: str
    private: bool
    default_branch: str
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, full_name: _Optional[str] = ..., html_url: _Optional[str] = ..., clone_url: _Optional[str] = ..., description: _Optional[str] = ..., language: _Optional[str] = ..., private: _Optional[bool] = ..., default_branch: _Optional[str] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class SaveGitHubTokenRequest(_message.Message):
    __slots__ = ("access_token", "refresh_token", "token_type", "expires_at", "refresh_token_expires_at", "installation_id", "github_username")
    ACCESS_TOKEN_FIELD_NUMBER: _ClassVar[int]
    REFRESH_TOKEN_FIELD_NUMBER: _ClassVar[int]
    TOKEN_TYPE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    REFRESH_TOKEN_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    INSTALLATION_ID_FIELD_NUMBER: _ClassVar[int]
    GITHUB_USERNAME_FIELD_NUMBER: _ClassVar[int]
    access_token: str
    refresh_token: str
    token_type: str
    expires_at: _timestamp_pb2.Timestamp
    refresh_token_expires_at: _timestamp_pb2.Timestamp
    installation_id: int
    github_username: str
    def __init__(self, access_token: _Optional[str] = ..., refresh_token: _Optional[str] = ..., token_type: _Optional[str] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., refresh_token_expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., installation_id: _Optional[int] = ..., github_username: _Optional[str] = ...) -> None: ...

class SaveGitHubTokenResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteGitHubTokenRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteGitHubTokenResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
