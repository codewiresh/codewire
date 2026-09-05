from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GitIdentity(_message.Message):
    __slots__ = ("git_name", "git_email")
    GIT_NAME_FIELD_NUMBER: _ClassVar[int]
    GIT_EMAIL_FIELD_NUMBER: _ClassVar[int]
    git_name: str
    git_email: str
    def __init__(self, git_name: _Optional[str] = ..., git_email: _Optional[str] = ...) -> None: ...

class GetGitIdentityRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetGitIdentityResponse(_message.Message):
    __slots__ = ("git_identity",)
    GIT_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    git_identity: GitIdentity
    def __init__(self, git_identity: _Optional[_Union[GitIdentity, _Mapping]] = ...) -> None: ...

class UpdateGitIdentityRequest(_message.Message):
    __slots__ = ("git_name", "git_email")
    GIT_NAME_FIELD_NUMBER: _ClassVar[int]
    GIT_EMAIL_FIELD_NUMBER: _ClassVar[int]
    git_name: str
    git_email: str
    def __init__(self, git_name: _Optional[str] = ..., git_email: _Optional[str] = ...) -> None: ...

class UpdateGitIdentityResponse(_message.Message):
    __slots__ = ("git_identity",)
    GIT_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    git_identity: GitIdentity
    def __init__(self, git_identity: _Optional[_Union[GitIdentity, _Mapping]] = ...) -> None: ...
