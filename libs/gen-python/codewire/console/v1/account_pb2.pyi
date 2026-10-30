from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
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

class AccountDeletionOrganization(_message.Message):
    __slots__ = ("id", "name", "slug", "role", "member_count", "environment_count")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    MEMBER_COUNT_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_COUNT_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    slug: str
    role: str
    member_count: int
    environment_count: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., role: _Optional[str] = ..., member_count: _Optional[int] = ..., environment_count: _Optional[int] = ...) -> None: ...

class GetAccountDeletionPlanRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetAccountDeletionPlanResponse(_message.Message):
    __slots__ = ("email", "personal_organizations", "shared_organizations", "blocking_organizations", "forfeited_credit_nano_eur")
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    PERSONAL_ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    SHARED_ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    BLOCKING_ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    FORFEITED_CREDIT_NANO_EUR_FIELD_NUMBER: _ClassVar[int]
    email: str
    personal_organizations: _containers.RepeatedCompositeFieldContainer[AccountDeletionOrganization]
    shared_organizations: _containers.RepeatedCompositeFieldContainer[AccountDeletionOrganization]
    blocking_organizations: _containers.RepeatedCompositeFieldContainer[AccountDeletionOrganization]
    forfeited_credit_nano_eur: int
    def __init__(self, email: _Optional[str] = ..., personal_organizations: _Optional[_Iterable[_Union[AccountDeletionOrganization, _Mapping]]] = ..., shared_organizations: _Optional[_Iterable[_Union[AccountDeletionOrganization, _Mapping]]] = ..., blocking_organizations: _Optional[_Iterable[_Union[AccountDeletionOrganization, _Mapping]]] = ..., forfeited_credit_nano_eur: _Optional[int] = ...) -> None: ...

class DeleteAccountRequest(_message.Message):
    __slots__ = ("confirm_email",)
    CONFIRM_EMAIL_FIELD_NUMBER: _ClassVar[int]
    confirm_email: str
    def __init__(self, confirm_email: _Optional[str] = ...) -> None: ...

class DeleteAccountResponse(_message.Message):
    __slots__ = ("operation_id",)
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    def __init__(self, operation_id: _Optional[str] = ...) -> None: ...
