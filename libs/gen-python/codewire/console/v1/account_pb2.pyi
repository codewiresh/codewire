import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LoginKey(_message.Message):
    __slots__ = ("id", "name", "public_key", "fingerprint", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    public_key: str
    fingerprint: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., public_key: _Optional[str] = ..., fingerprint: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListLoginKeysRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListLoginKeysResponse(_message.Message):
    __slots__ = ("login_keys",)
    LOGIN_KEYS_FIELD_NUMBER: _ClassVar[int]
    login_keys: _containers.RepeatedCompositeFieldContainer[LoginKey]
    def __init__(self, login_keys: _Optional[_Iterable[_Union[LoginKey, _Mapping]]] = ...) -> None: ...

class CreateLoginKeyRequest(_message.Message):
    __slots__ = ("name", "public_key")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    name: str
    public_key: str
    def __init__(self, name: _Optional[str] = ..., public_key: _Optional[str] = ...) -> None: ...

class CreateLoginKeyResponse(_message.Message):
    __slots__ = ("login_key",)
    LOGIN_KEY_FIELD_NUMBER: _ClassVar[int]
    login_key: LoginKey
    def __init__(self, login_key: _Optional[_Union[LoginKey, _Mapping]] = ...) -> None: ...

class DeleteLoginKeyRequest(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class DeleteLoginKeyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SshKey(_message.Message):
    __slots__ = ("public_key", "fingerprint", "created_at", "regenerated_at")
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    REGENERATED_AT_FIELD_NUMBER: _ClassVar[int]
    public_key: str
    fingerprint: str
    created_at: _timestamp_pb2.Timestamp
    regenerated_at: _timestamp_pb2.Timestamp
    def __init__(self, public_key: _Optional[str] = ..., fingerprint: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., regenerated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class EnsureSshKeyRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnsureSshKeyResponse(_message.Message):
    __slots__ = ("ssh_key",)
    SSH_KEY_FIELD_NUMBER: _ClassVar[int]
    ssh_key: SshKey
    def __init__(self, ssh_key: _Optional[_Union[SshKey, _Mapping]] = ...) -> None: ...

class GetSshKeyRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetSshKeyResponse(_message.Message):
    __slots__ = ("ssh_key",)
    SSH_KEY_FIELD_NUMBER: _ClassVar[int]
    ssh_key: SshKey
    def __init__(self, ssh_key: _Optional[_Union[SshKey, _Mapping]] = ...) -> None: ...

class RegenerateSshKeyRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RegenerateSshKeyResponse(_message.Message):
    __slots__ = ("ssh_key",)
    SSH_KEY_FIELD_NUMBER: _ClassVar[int]
    ssh_key: SshKey
    def __init__(self, ssh_key: _Optional[_Union[SshKey, _Mapping]] = ...) -> None: ...

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

class GitCredential(_message.Message):
    __slots__ = ("id", "user_id", "name", "host", "auth_type", "username", "created_at", "updated_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    AUTH_TYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    user_id: str
    name: str
    host: str
    auth_type: str
    username: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., user_id: _Optional[str] = ..., name: _Optional[str] = ..., host: _Optional[str] = ..., auth_type: _Optional[str] = ..., username: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListGitCredentialsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListGitCredentialsResponse(_message.Message):
    __slots__ = ("git_credentials",)
    GIT_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    git_credentials: _containers.RepeatedCompositeFieldContainer[GitCredential]
    def __init__(self, git_credentials: _Optional[_Iterable[_Union[GitCredential, _Mapping]]] = ...) -> None: ...

class CreateGitCredentialRequest(_message.Message):
    __slots__ = ("name", "host", "auth_type", "username", "password")
    NAME_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    AUTH_TYPE_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    name: str
    host: str
    auth_type: str
    username: str
    password: str
    def __init__(self, name: _Optional[str] = ..., host: _Optional[str] = ..., auth_type: _Optional[str] = ..., username: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class CreateGitCredentialResponse(_message.Message):
    __slots__ = ("git_credential",)
    GIT_CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    git_credential: GitCredential
    def __init__(self, git_credential: _Optional[_Union[GitCredential, _Mapping]] = ...) -> None: ...

class UpdateGitCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "name", "username", "password")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PASSWORD_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    name: str
    username: str
    password: str
    def __init__(self, credential_id: _Optional[str] = ..., name: _Optional[str] = ..., username: _Optional[str] = ..., password: _Optional[str] = ...) -> None: ...

class UpdateGitCredentialResponse(_message.Message):
    __slots__ = ("git_credential",)
    GIT_CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    git_credential: GitCredential
    def __init__(self, git_credential: _Optional[_Union[GitCredential, _Mapping]] = ...) -> None: ...

class DeleteGitCredentialRequest(_message.Message):
    __slots__ = ("credential_id",)
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    def __init__(self, credential_id: _Optional[str] = ...) -> None: ...

class DeleteGitCredentialResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
