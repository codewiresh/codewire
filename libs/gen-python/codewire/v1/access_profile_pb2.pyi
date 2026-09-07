from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AccessProfileEntry(_message.Message):
    __slots__ = ("capability_slot", "credential_id")
    CAPABILITY_SLOT_FIELD_NUMBER: _ClassVar[int]
    CREDENTIAL_ID_FIELD_NUMBER: _ClassVar[int]
    capability_slot: str
    credential_id: str
    def __init__(self, capability_slot: _Optional[str] = ..., credential_id: _Optional[str] = ...) -> None: ...

class AccessProfile(_message.Message):
    __slots__ = ("id", "name", "revision", "entries")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    revision: int
    entries: _containers.RepeatedCompositeFieldContainer[AccessProfileEntry]
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., revision: _Optional[int] = ..., entries: _Optional[_Iterable[_Union[AccessProfileEntry, _Mapping]]] = ...) -> None: ...

class ListAccessProfilesRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListAccessProfilesResponse(_message.Message):
    __slots__ = ("access_profiles", "next_page_token")
    ACCESS_PROFILES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    access_profiles: _containers.RepeatedCompositeFieldContainer[AccessProfile]
    next_page_token: str
    def __init__(self, access_profiles: _Optional[_Iterable[_Union[AccessProfile, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class GetAccessProfileRequest(_message.Message):
    __slots__ = ("access_profile_id", "name", "revision")
    ACCESS_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    access_profile_id: str
    name: str
    revision: int
    def __init__(self, access_profile_id: _Optional[str] = ..., name: _Optional[str] = ..., revision: _Optional[int] = ...) -> None: ...

class GetAccessProfileResponse(_message.Message):
    __slots__ = ("access_profile",)
    ACCESS_PROFILE_FIELD_NUMBER: _ClassVar[int]
    access_profile: AccessProfile
    def __init__(self, access_profile: _Optional[_Union[AccessProfile, _Mapping]] = ...) -> None: ...

class CreateAccessProfileRequest(_message.Message):
    __slots__ = ("name", "entries")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    name: str
    entries: _containers.RepeatedCompositeFieldContainer[AccessProfileEntry]
    def __init__(self, name: _Optional[str] = ..., entries: _Optional[_Iterable[_Union[AccessProfileEntry, _Mapping]]] = ...) -> None: ...

class CreateAccessProfileResponse(_message.Message):
    __slots__ = ("access_profile",)
    ACCESS_PROFILE_FIELD_NUMBER: _ClassVar[int]
    access_profile: AccessProfile
    def __init__(self, access_profile: _Optional[_Union[AccessProfile, _Mapping]] = ...) -> None: ...

class UpdateAccessProfileRequest(_message.Message):
    __slots__ = ("access_profile_id", "expected_revision", "entries")
    ACCESS_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    access_profile_id: str
    expected_revision: int
    entries: _containers.RepeatedCompositeFieldContainer[AccessProfileEntry]
    def __init__(self, access_profile_id: _Optional[str] = ..., expected_revision: _Optional[int] = ..., entries: _Optional[_Iterable[_Union[AccessProfileEntry, _Mapping]]] = ...) -> None: ...

class UpdateAccessProfileResponse(_message.Message):
    __slots__ = ("access_profile",)
    ACCESS_PROFILE_FIELD_NUMBER: _ClassVar[int]
    access_profile: AccessProfile
    def __init__(self, access_profile: _Optional[_Union[AccessProfile, _Mapping]] = ...) -> None: ...

class DeleteAccessProfileRequest(_message.Message):
    __slots__ = ("access_profile_id", "expected_revision")
    ACCESS_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    access_profile_id: str
    expected_revision: int
    def __init__(self, access_profile_id: _Optional[str] = ..., expected_revision: _Optional[int] = ...) -> None: ...

class DeleteAccessProfileResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnvironmentAccessProfileBinding(_message.Message):
    __slots__ = ("environment_id", "access_profile_id", "access_profile_revision")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_PROFILE_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_PROFILE_REVISION_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    access_profile_id: str
    access_profile_revision: int
    def __init__(self, environment_id: _Optional[str] = ..., access_profile_id: _Optional[str] = ..., access_profile_revision: _Optional[int] = ...) -> None: ...

class GetEnvironmentAccessProfileRequest(_message.Message):
    __slots__ = ("environment_id",)
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    def __init__(self, environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentAccessProfileResponse(_message.Message):
    __slots__ = ("binding", "personal_credentials_confirmed")
    BINDING_FIELD_NUMBER: _ClassVar[int]
    PERSONAL_CREDENTIALS_CONFIRMED_FIELD_NUMBER: _ClassVar[int]
    binding: EnvironmentAccessProfileBinding
    personal_credentials_confirmed: bool
    def __init__(self, binding: _Optional[_Union[EnvironmentAccessProfileBinding, _Mapping]] = ..., personal_credentials_confirmed: _Optional[bool] = ...) -> None: ...

class SetEnvironmentAccessProfileRequest(_message.Message):
    __slots__ = ("binding", "expected_binding", "confirm_personal_credentials")
    BINDING_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_BINDING_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_PERSONAL_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    binding: EnvironmentAccessProfileBinding
    expected_binding: EnvironmentAccessProfileBinding
    confirm_personal_credentials: bool
    def __init__(self, binding: _Optional[_Union[EnvironmentAccessProfileBinding, _Mapping]] = ..., expected_binding: _Optional[_Union[EnvironmentAccessProfileBinding, _Mapping]] = ..., confirm_personal_credentials: _Optional[bool] = ...) -> None: ...

class SetEnvironmentAccessProfileResponse(_message.Message):
    __slots__ = ("binding",)
    BINDING_FIELD_NUMBER: _ClassVar[int]
    binding: EnvironmentAccessProfileBinding
    def __init__(self, binding: _Optional[_Union[EnvironmentAccessProfileBinding, _Mapping]] = ...) -> None: ...

class ClearEnvironmentAccessProfileRequest(_message.Message):
    __slots__ = ("expected_binding",)
    EXPECTED_BINDING_FIELD_NUMBER: _ClassVar[int]
    expected_binding: EnvironmentAccessProfileBinding
    def __init__(self, expected_binding: _Optional[_Union[EnvironmentAccessProfileBinding, _Mapping]] = ...) -> None: ...

class ClearEnvironmentAccessProfileResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
