from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class IssueGitHubCredentialsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class IssueGitCredentialsRequest(_message.Message):
    __slots__ = ("host",)
    HOST_FIELD_NUMBER: _ClassVar[int]
    host: str
    def __init__(self, host: _Optional[str] = ...) -> None: ...

class IssueGitHubCredentialsResponse(_message.Message):
    __slots__ = ("token", "username", "host")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    token: str
    username: str
    host: str
    def __init__(self, token: _Optional[str] = ..., username: _Optional[str] = ..., host: _Optional[str] = ...) -> None: ...

class IssueGitCredentialsResponse(_message.Message):
    __slots__ = ("token", "username", "host")
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    token: str
    username: str
    host: str
    def __init__(self, token: _Optional[str] = ..., username: _Optional[str] = ..., host: _Optional[str] = ...) -> None: ...
