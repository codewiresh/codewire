from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class CredentialAuthenticationKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CREDENTIAL_AUTHENTICATION_KIND_UNSPECIFIED: _ClassVar[CredentialAuthenticationKind]
    CREDENTIAL_AUTHENTICATION_KIND_OAUTH: _ClassVar[CredentialAuthenticationKind]
    CREDENTIAL_AUTHENTICATION_KIND_API_KEY: _ClassVar[CredentialAuthenticationKind]
    CREDENTIAL_AUTHENTICATION_KIND_ACCESS_TOKEN: _ClassVar[CredentialAuthenticationKind]
    CREDENTIAL_AUTHENTICATION_KIND_GITHUB_APP: _ClassVar[CredentialAuthenticationKind]
    CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY: _ClassVar[CredentialAuthenticationKind]

class CredentialStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CREDENTIAL_STATUS_UNSPECIFIED: _ClassVar[CredentialStatus]
    CREDENTIAL_STATUS_ACTIVE: _ClassVar[CredentialStatus]
    CREDENTIAL_STATUS_REVOKED: _ClassVar[CredentialStatus]
    CREDENTIAL_STATUS_EXPIRED: _ClassVar[CredentialStatus]
    CREDENTIAL_STATUS_REFRESH_FAILED: _ClassVar[CredentialStatus]
CREDENTIAL_AUTHENTICATION_KIND_UNSPECIFIED: CredentialAuthenticationKind
CREDENTIAL_AUTHENTICATION_KIND_OAUTH: CredentialAuthenticationKind
CREDENTIAL_AUTHENTICATION_KIND_API_KEY: CredentialAuthenticationKind
CREDENTIAL_AUTHENTICATION_KIND_ACCESS_TOKEN: CredentialAuthenticationKind
CREDENTIAL_AUTHENTICATION_KIND_GITHUB_APP: CredentialAuthenticationKind
CREDENTIAL_AUTHENTICATION_KIND_SSH_KEY: CredentialAuthenticationKind
CREDENTIAL_STATUS_UNSPECIFIED: CredentialStatus
CREDENTIAL_STATUS_ACTIVE: CredentialStatus
CREDENTIAL_STATUS_REVOKED: CredentialStatus
CREDENTIAL_STATUS_EXPIRED: CredentialStatus
CREDENTIAL_STATUS_REFRESH_FAILED: CredentialStatus

class ListGithubRepositoriesRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class GithubRepository(_message.Message):
    __slots__ = ("repository_id", "full_name", "default_branch", "clone_url", "is_private", "archived", "disabled")
    REPOSITORY_ID_FIELD_NUMBER: _ClassVar[int]
    FULL_NAME_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_BRANCH_FIELD_NUMBER: _ClassVar[int]
    CLONE_URL_FIELD_NUMBER: _ClassVar[int]
    IS_PRIVATE_FIELD_NUMBER: _ClassVar[int]
    ARCHIVED_FIELD_NUMBER: _ClassVar[int]
    DISABLED_FIELD_NUMBER: _ClassVar[int]
    repository_id: str
    full_name: str
    default_branch: str
    clone_url: str
    is_private: bool
    archived: bool
    disabled: bool
    def __init__(self, repository_id: _Optional[str] = ..., full_name: _Optional[str] = ..., default_branch: _Optional[str] = ..., clone_url: _Optional[str] = ..., is_private: _Optional[bool] = ..., archived: _Optional[bool] = ..., disabled: _Optional[bool] = ...) -> None: ...

class ListGithubRepositoriesResponse(_message.Message):
    __slots__ = ("repositories", "next_page_token")
    REPOSITORIES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    repositories: _containers.RepeatedCompositeFieldContainer[GithubRepository]
    next_page_token: str
    def __init__(self, repositories: _Optional[_Iterable[_Union[GithubRepository, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class Credential(_message.Message):
    __slots__ = ("id", "name", "provider", "authentication_kind", "account_hint", "status", "expires_at_unix", "revocation_generation", "ssh_public_key")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_KIND_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_HINT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    SSH_PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    provider: str
    authentication_kind: CredentialAuthenticationKind
    account_hint: str
    status: CredentialStatus
    expires_at_unix: int
    revocation_generation: int
    ssh_public_key: SshPublicKey
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., provider: _Optional[str] = ..., authentication_kind: _Optional[_Union[CredentialAuthenticationKind, str]] = ..., account_hint: _Optional[str] = ..., status: _Optional[_Union[CredentialStatus, str]] = ..., expires_at_unix: _Optional[int] = ..., revocation_generation: _Optional[int] = ..., ssh_public_key: _Optional[_Union[SshPublicKey, _Mapping]] = ...) -> None: ...

class SshPublicKey(_message.Message):
    __slots__ = ("openssh", "fingerprint")
    OPENSSH_FIELD_NUMBER: _ClassVar[int]
    FINGERPRINT_FIELD_NUMBER: _ClassVar[int]
    openssh: str
    fingerprint: str
    def __init__(self, openssh: _Optional[str] = ..., fingerprint: _Optional[str] = ...) -> None: ...

class GenerateSshCredentialRequest(_message.Message):
    __slots__ = ("name", "expires_at_unix")
    NAME_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    name: str
    expires_at_unix: int
    def __init__(self, name: _Optional[str] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class GenerateSshCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class AddSshCredentialRequest(_message.Message):
    __slots__ = ("name", "private_key", "passphrase", "expires_at_unix")
    NAME_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    PASSPHRASE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    name: str
    private_key: bytes
    passphrase: bytes
    expires_at_unix: int
    def __init__(self, name: _Optional[str] = ..., private_key: _Optional[bytes] = ..., passphrase: _Optional[bytes] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class AddSshCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class ListCredentialsRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListCredentialsResponse(_message.Message):
    __slots__ = ("credentials", "next_page_token")
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    credentials: _containers.RepeatedCompositeFieldContainer[Credential]
    next_page_token: str
    def __init__(self, credentials: _Optional[_Iterable[_Union[Credential, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class GetCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "name")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    name: str
    def __init__(self, credential_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class GetCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class EnrollCodexRequest(_message.Message):
    __slots__ = ("name", "credential_id", "expected_revocation_generation")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    name: str
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, name: _Optional[str] = ..., credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class EnrollGithubRequest(_message.Message):
    __slots__ = ("name", "credential_id", "expected_revocation_generation")
    NAME_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    name: str
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, name: _Optional[str] = ..., credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class AddApiKeyCredentialRequest(_message.Message):
    __slots__ = ("provider", "name", "value", "expires_at_unix")
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    provider: str
    name: str
    value: bytes
    expires_at_unix: int
    def __init__(self, provider: _Optional[str] = ..., name: _Optional[str] = ..., value: _Optional[bytes] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class AddApiKeyCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class AddClaudeSubscriptionTokenCredentialRequest(_message.Message):
    __slots__ = ("name", "token", "credential_id", "expected_revocation_generation")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    name: str
    token: bytes
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, name: _Optional[str] = ..., token: _Optional[bytes] = ..., credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class AddClaudeSubscriptionTokenCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class RenameCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "expected_revocation_generation", "expected_name", "name")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    expected_revocation_generation: int
    expected_name: str
    name: str
    def __init__(self, credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ..., expected_name: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class RenameCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class RotateApiKeyCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "expected_revocation_generation", "value", "expires_at_unix")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    expected_revocation_generation: int
    value: bytes
    expires_at_unix: int
    def __init__(self, credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ..., value: _Optional[bytes] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class RotateApiKeyCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class CodexDeviceChallenge(_message.Message):
    __slots__ = ("verification_url", "user_code", "expires_at_unix")
    VERIFICATION_URL_FIELD_NUMBER: _ClassVar[int]
    USER_CODE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    verification_url: str
    user_code: str
    expires_at_unix: int
    def __init__(self, verification_url: _Optional[str] = ..., user_code: _Optional[str] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class EnrollCodexResponse(_message.Message):
    __slots__ = ("challenge", "credential")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    challenge: CodexDeviceChallenge
    credential: Credential
    def __init__(self, challenge: _Optional[_Union[CodexDeviceChallenge, _Mapping]] = ..., credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class GithubDeviceChallenge(_message.Message):
    __slots__ = ("verification_url", "user_code", "expires_at_unix")
    VERIFICATION_URL_FIELD_NUMBER: _ClassVar[int]
    USER_CODE_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    verification_url: str
    user_code: str
    expires_at_unix: int
    def __init__(self, verification_url: _Optional[str] = ..., user_code: _Optional[str] = ..., expires_at_unix: _Optional[int] = ...) -> None: ...

class EnrollGithubResponse(_message.Message):
    __slots__ = ("challenge", "credential")
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    challenge: GithubDeviceChallenge
    credential: Credential
    def __init__(self, challenge: _Optional[_Union[GithubDeviceChallenge, _Mapping]] = ..., credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class CompleteGithubAppAuthorizationRequest(_message.Message):
    __slots__ = ("code", "credential_id", "expected_revocation_generation")
    CODE_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    code: bytes
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, code: _Optional[bytes] = ..., credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class CompleteGithubAppAuthorizationResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class RevokeCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "expected_revocation_generation")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class RevokeCredentialResponse(_message.Message):
    __slots__ = ("credential",)
    CREDENTIAL_FIELD_NUMBER: _ClassVar[int]
    credential: Credential
    def __init__(self, credential: _Optional[_Union[Credential, _Mapping]] = ...) -> None: ...

class DeleteCredentialRequest(_message.Message):
    __slots__ = ("credential_id", "expected_revocation_generation")
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    credential_id: str
    expected_revocation_generation: int
    def __init__(self, credential_id: _Optional[str] = ..., expected_revocation_generation: _Optional[int] = ...) -> None: ...

class DeleteCredentialResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
