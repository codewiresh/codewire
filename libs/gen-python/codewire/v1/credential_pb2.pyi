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
CREDENTIAL_STATUS_UNSPECIFIED: CredentialStatus
CREDENTIAL_STATUS_ACTIVE: CredentialStatus
CREDENTIAL_STATUS_REVOKED: CredentialStatus
CREDENTIAL_STATUS_EXPIRED: CredentialStatus
CREDENTIAL_STATUS_REFRESH_FAILED: CredentialStatus

class Credential(_message.Message):
    __slots__ = ("id", "name", "provider", "authentication_kind", "account_hint", "status", "expires_at_unix", "revocation_generation")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    AUTHENTICATION_KIND_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_HINT_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_UNIX_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    provider: str
    authentication_kind: CredentialAuthenticationKind
    account_hint: str
    status: CredentialStatus
    expires_at_unix: int
    revocation_generation: int
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., provider: _Optional[str] = ..., authentication_kind: _Optional[_Union[CredentialAuthenticationKind, str]] = ..., account_hint: _Optional[str] = ..., status: _Optional[_Union[CredentialStatus, str]] = ..., expires_at_unix: _Optional[int] = ..., revocation_generation: _Optional[int] = ...) -> None: ...

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
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

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
