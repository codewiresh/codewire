import datetime

from codewire.v1 import environment_pb2 as _environment_pb2
from codewire.v1 import preset_pb2 as _preset_pb2
from codewire.v1 import secret_pb2 as _secret_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetEnvironmentCreateOptionsRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentCreateOptionsResponse(_message.Message):
    __slots__ = ("github_status", "presets", "secret_projects")
    GITHUB_STATUS_FIELD_NUMBER: _ClassVar[int]
    PRESETS_FIELD_NUMBER: _ClassVar[int]
    SECRET_PROJECTS_FIELD_NUMBER: _ClassVar[int]
    github_status: GitHubConnection
    presets: _containers.RepeatedCompositeFieldContainer[_preset_pb2.Preset]
    secret_projects: _containers.RepeatedCompositeFieldContainer[_secret_pb2.SecretProject]
    def __init__(self, github_status: _Optional[_Union[GitHubConnection, _Mapping]] = ..., presets: _Optional[_Iterable[_Union[_preset_pb2.Preset, _Mapping]]] = ..., secret_projects: _Optional[_Iterable[_Union[_secret_pb2.SecretProject, _Mapping]]] = ...) -> None: ...

class GitHubConnection(_message.Message):
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

class DetectRepoRequest(_message.Message):
    __slots__ = ("repo_url", "branch")
    REPO_URL_FIELD_NUMBER: _ClassVar[int]
    BRANCH_FIELD_NUMBER: _ClassVar[int]
    repo_url: str
    branch: str
    def __init__(self, repo_url: _Optional[str] = ..., branch: _Optional[str] = ...) -> None: ...

class DetectRepoResponse(_message.Message):
    __slots__ = ("result",)
    RESULT_FIELD_NUMBER: _ClassVar[int]
    result: _environment_pb2.DetectionResult
    def __init__(self, result: _Optional[_Union[_environment_pb2.DetectionResult, _Mapping]] = ...) -> None: ...

class IssueTerminalTicketRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueTerminalTicketResponse(_message.Message):
    __slots__ = ("ticket",)
    TICKET_FIELD_NUMBER: _ClassVar[int]
    ticket: str
    def __init__(self, ticket: _Optional[str] = ...) -> None: ...
