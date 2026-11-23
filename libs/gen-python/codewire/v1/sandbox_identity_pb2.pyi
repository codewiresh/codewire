import datetime

from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class IdentityGroupUserReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    IDENTITY_GROUP_USER_REASON_UNSPECIFIED: _ClassVar[IdentityGroupUserReason]
    IDENTITY_GROUP_USER_REASON_CREATOR: _ClassVar[IdentityGroupUserReason]
    IDENTITY_GROUP_USER_REASON_OWNER_GRANT: _ClassVar[IdentityGroupUserReason]
    IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT: _ClassVar[IdentityGroupUserReason]
    IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN: _ClassVar[IdentityGroupUserReason]
IDENTITY_GROUP_USER_REASON_UNSPECIFIED: IdentityGroupUserReason
IDENTITY_GROUP_USER_REASON_CREATOR: IdentityGroupUserReason
IDENTITY_GROUP_USER_REASON_OWNER_GRANT: IdentityGroupUserReason
IDENTITY_GROUP_USER_REASON_OPERATOR_GRANT: IdentityGroupUserReason
IDENTITY_GROUP_USER_REASON_ORGANIZATION_ADMIN: IdentityGroupUserReason

class EnvironmentIdentityGroups(_message.Message):
    __slots__ = ("environment_id", "groups", "version", "updated_at")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    groups: _containers.RepeatedScalarFieldContainer[str]
    version: int
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, environment_id: _Optional[str] = ..., groups: _Optional[_Iterable[str]] = ..., version: _Optional[int] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class GetEnvironmentIdentityGroupsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class GetEnvironmentIdentityGroupsResponse(_message.Message):
    __slots__ = ("groups",)
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    groups: EnvironmentIdentityGroups
    def __init__(self, groups: _Optional[_Union[EnvironmentIdentityGroups, _Mapping]] = ...) -> None: ...

class SetEnvironmentIdentityGroupsRequest(_message.Message):
    __slots__ = ("org_id", "environment_id", "groups")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    groups: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ..., groups: _Optional[_Iterable[str]] = ...) -> None: ...

class IdentityGroupUser(_message.Message):
    __slots__ = ("user_id", "email", "reason")
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    user_id: str
    email: str
    reason: IdentityGroupUserReason
    def __init__(self, user_id: _Optional[str] = ..., email: _Optional[str] = ..., reason: _Optional[_Union[IdentityGroupUserReason, str]] = ...) -> None: ...

class SetEnvironmentIdentityGroupsResponse(_message.Message):
    __slots__ = ("groups", "previous_groups", "changed", "can_run_code")
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_GROUPS_FIELD_NUMBER: _ClassVar[int]
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    CAN_RUN_CODE_FIELD_NUMBER: _ClassVar[int]
    groups: EnvironmentIdentityGroups
    previous_groups: _containers.RepeatedScalarFieldContainer[str]
    changed: bool
    can_run_code: _containers.RepeatedCompositeFieldContainer[IdentityGroupUser]
    def __init__(self, groups: _Optional[_Union[EnvironmentIdentityGroups, _Mapping]] = ..., previous_groups: _Optional[_Iterable[str]] = ..., changed: _Optional[bool] = ..., can_run_code: _Optional[_Iterable[_Union[IdentityGroupUser, _Mapping]]] = ...) -> None: ...

class IdentityAudienceGroups(_message.Message):
    __slots__ = ("names",)
    NAMES_FIELD_NUMBER: _ClassVar[int]
    names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, names: _Optional[_Iterable[str]] = ...) -> None: ...

class IdentityAudience(_message.Message):
    __slots__ = ("org_id", "audience", "visible_groups", "lifetime", "claim_created_by", "claim_environment_name", "file_name", "version", "created_by", "created_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    VISIBLE_GROUPS_FIELD_NUMBER: _ClassVar[int]
    LIFETIME_FIELD_NUMBER: _ClassVar[int]
    CLAIM_CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CLAIM_ENVIRONMENT_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    audience: str
    visible_groups: IdentityAudienceGroups
    lifetime: _duration_pb2.Duration
    claim_created_by: bool
    claim_environment_name: bool
    file_name: str
    version: int
    created_by: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., audience: _Optional[str] = ..., visible_groups: _Optional[_Union[IdentityAudienceGroups, _Mapping]] = ..., lifetime: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., claim_created_by: _Optional[bool] = ..., claim_environment_name: _Optional[bool] = ..., file_name: _Optional[str] = ..., version: _Optional[int] = ..., created_by: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class RegisterIdentityAudienceRequest(_message.Message):
    __slots__ = ("org_id", "audience", "visible_groups", "lifetime", "claim_created_by", "claim_environment_name", "file_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    VISIBLE_GROUPS_FIELD_NUMBER: _ClassVar[int]
    LIFETIME_FIELD_NUMBER: _ClassVar[int]
    CLAIM_CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CLAIM_ENVIRONMENT_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    audience: str
    visible_groups: IdentityAudienceGroups
    lifetime: _duration_pb2.Duration
    claim_created_by: bool
    claim_environment_name: bool
    file_name: str
    def __init__(self, org_id: _Optional[str] = ..., audience: _Optional[str] = ..., visible_groups: _Optional[_Union[IdentityAudienceGroups, _Mapping]] = ..., lifetime: _Optional[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]] = ..., claim_created_by: _Optional[bool] = ..., claim_environment_name: _Optional[bool] = ..., file_name: _Optional[str] = ...) -> None: ...

class RegisterIdentityAudienceResponse(_message.Message):
    __slots__ = ("audience",)
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    audience: IdentityAudience
    def __init__(self, audience: _Optional[_Union[IdentityAudience, _Mapping]] = ...) -> None: ...

class ListIdentityAudiencesRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListIdentityAudiencesResponse(_message.Message):
    __slots__ = ("audiences", "next_page_token")
    AUDIENCES_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    audiences: _containers.RepeatedCompositeFieldContainer[IdentityAudience]
    next_page_token: str
    def __init__(self, audiences: _Optional[_Iterable[_Union[IdentityAudience, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class RemoveIdentityAudienceRequest(_message.Message):
    __slots__ = ("org_id", "audience")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    audience: str
    def __init__(self, org_id: _Optional[str] = ..., audience: _Optional[str] = ...) -> None: ...

class RemoveIdentityAudienceResponse(_message.Message):
    __slots__ = ("audience",)
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    audience: str
    def __init__(self, audience: _Optional[str] = ...) -> None: ...

class StopIdentityMintingRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class StopIdentityMintingResponse(_message.Message):
    __slots__ = ("changed",)
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    changed: bool
    def __init__(self, changed: _Optional[bool] = ...) -> None: ...

class ResumeIdentityMintingRequest(_message.Message):
    __slots__ = ("org_id", "environment_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    environment_id: str
    def __init__(self, org_id: _Optional[str] = ..., environment_id: _Optional[str] = ...) -> None: ...

class ResumeIdentityMintingResponse(_message.Message):
    __slots__ = ("changed",)
    CHANGED_FIELD_NUMBER: _ClassVar[int]
    changed: bool
    def __init__(self, changed: _Optional[bool] = ...) -> None: ...
