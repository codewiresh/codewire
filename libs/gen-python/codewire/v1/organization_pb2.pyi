import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class OrgRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ORG_ROLE_UNSPECIFIED: _ClassVar[OrgRole]
    ORG_ROLE_OWNER: _ClassVar[OrgRole]
    ORG_ROLE_ADMIN: _ClassVar[OrgRole]
    ORG_ROLE_MEMBER: _ClassVar[OrgRole]

class InvitationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INVITATION_STATUS_UNSPECIFIED: _ClassVar[InvitationStatus]
    INVITATION_STATUS_PENDING: _ClassVar[InvitationStatus]
    INVITATION_STATUS_ACCEPTED: _ClassVar[InvitationStatus]
    INVITATION_STATUS_REVOKED: _ClassVar[InvitationStatus]
    INVITATION_STATUS_EXPIRED: _ClassVar[InvitationStatus]

class OrganizationDeletionState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ORGANIZATION_DELETION_STATE_UNSPECIFIED: _ClassVar[OrganizationDeletionState]
    ORGANIZATION_DELETION_STATE_ACTIVE: _ClassVar[OrganizationDeletionState]
    ORGANIZATION_DELETION_STATE_DELETING: _ClassVar[OrganizationDeletionState]
    ORGANIZATION_DELETION_STATE_DELETE_FAILED: _ClassVar[OrganizationDeletionState]
ORG_ROLE_UNSPECIFIED: OrgRole
ORG_ROLE_OWNER: OrgRole
ORG_ROLE_ADMIN: OrgRole
ORG_ROLE_MEMBER: OrgRole
INVITATION_STATUS_UNSPECIFIED: InvitationStatus
INVITATION_STATUS_PENDING: InvitationStatus
INVITATION_STATUS_ACCEPTED: InvitationStatus
INVITATION_STATUS_REVOKED: InvitationStatus
INVITATION_STATUS_EXPIRED: InvitationStatus
ORGANIZATION_DELETION_STATE_UNSPECIFIED: OrganizationDeletionState
ORGANIZATION_DELETION_STATE_ACTIVE: OrganizationDeletionState
ORGANIZATION_DELETION_STATE_DELETING: OrganizationDeletionState
ORGANIZATION_DELETION_STATE_DELETE_FAILED: OrganizationDeletionState

class Organization(_message.Message):
    __slots__ = ("id", "name", "slug", "created_by", "created_at", "updated_at", "deletion_state", "deletion_operation_id", "deletion_failure_code")
    ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    DELETION_STATE_FIELD_NUMBER: _ClassVar[int]
    DELETION_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    DELETION_FAILURE_CODE_FIELD_NUMBER: _ClassVar[int]
    id: str
    name: str
    slug: str
    created_by: str
    created_at: _timestamp_pb2.Timestamp
    updated_at: _timestamp_pb2.Timestamp
    deletion_state: OrganizationDeletionState
    deletion_operation_id: str
    deletion_failure_code: str
    def __init__(self, id: _Optional[str] = ..., name: _Optional[str] = ..., slug: _Optional[str] = ..., created_by: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., deletion_state: _Optional[_Union[OrganizationDeletionState, str]] = ..., deletion_operation_id: _Optional[str] = ..., deletion_failure_code: _Optional[str] = ...) -> None: ...

class OrganizationMembership(_message.Message):
    __slots__ = ("organization", "role", "assignments", "billing_plan", "billing_status", "trial_ends_at")
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    BILLING_PLAN_FIELD_NUMBER: _ClassVar[int]
    BILLING_STATUS_FIELD_NUMBER: _ClassVar[int]
    TRIAL_ENDS_AT_FIELD_NUMBER: _ClassVar[int]
    organization: Organization
    role: OrgRole
    assignments: _containers.RepeatedScalarFieldContainer[str]
    billing_plan: str
    billing_status: str
    trial_ends_at: _timestamp_pb2.Timestamp
    def __init__(self, organization: _Optional[_Union[Organization, _Mapping]] = ..., role: _Optional[_Union[OrgRole, str]] = ..., assignments: _Optional[_Iterable[str]] = ..., billing_plan: _Optional[str] = ..., billing_status: _Optional[str] = ..., trial_ends_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class OrgMember(_message.Message):
    __slots__ = ("id", "org_id", "user_id", "role", "email", "name", "image", "assignments", "created_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    IMAGE_FIELD_NUMBER: _ClassVar[int]
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    user_id: str
    role: OrgRole
    email: str
    name: str
    image: str
    assignments: _containers.RepeatedScalarFieldContainer[str]
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., user_id: _Optional[str] = ..., role: _Optional[_Union[OrgRole, str]] = ..., email: _Optional[str] = ..., name: _Optional[str] = ..., image: _Optional[str] = ..., assignments: _Optional[_Iterable[str]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class OrgInvitation(_message.Message):
    __slots__ = ("id", "org_id", "org_name", "email", "role", "invited_by", "inviter_name", "token", "status", "expires_at", "created_at", "accepted_at")
    ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_NAME_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    INVITED_BY_FIELD_NUMBER: _ClassVar[int]
    INVITER_NAME_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_AT_FIELD_NUMBER: _ClassVar[int]
    id: str
    org_id: str
    org_name: str
    email: str
    role: OrgRole
    invited_by: str
    inviter_name: str
    token: str
    status: InvitationStatus
    expires_at: _timestamp_pb2.Timestamp
    created_at: _timestamp_pb2.Timestamp
    accepted_at: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[str] = ..., org_id: _Optional[str] = ..., org_name: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[_Union[OrgRole, str]] = ..., invited_by: _Optional[str] = ..., inviter_name: _Optional[str] = ..., token: _Optional[str] = ..., status: _Optional[_Union[InvitationStatus, str]] = ..., expires_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., accepted_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListOrganizationsRequest(_message.Message):
    __slots__ = ("page_size", "page_token")
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    page_size: int
    page_token: str
    def __init__(self, page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListOrganizationsResponse(_message.Message):
    __slots__ = ("organizations", "next_page_token")
    ORGANIZATIONS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    organizations: _containers.RepeatedCompositeFieldContainer[OrganizationMembership]
    next_page_token: str
    def __init__(self, organizations: _Optional[_Iterable[_Union[OrganizationMembership, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateOrganizationRequest(_message.Message):
    __slots__ = ("name", "slug")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SLUG_FIELD_NUMBER: _ClassVar[int]
    name: str
    slug: str
    def __init__(self, name: _Optional[str] = ..., slug: _Optional[str] = ...) -> None: ...

class CreateOrganizationResponse(_message.Message):
    __slots__ = ("organization",)
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    organization: Organization
    def __init__(self, organization: _Optional[_Union[Organization, _Mapping]] = ...) -> None: ...

class GetOrganizationRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetOrganizationResponse(_message.Message):
    __slots__ = ("organization", "members")
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    organization: Organization
    members: _containers.RepeatedCompositeFieldContainer[OrgMember]
    def __init__(self, organization: _Optional[_Union[Organization, _Mapping]] = ..., members: _Optional[_Iterable[_Union[OrgMember, _Mapping]]] = ...) -> None: ...

class DeleteOrganizationRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class DeleteOrganizationResponse(_message.Message):
    __slots__ = ("operation_id", "state")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    operation_id: str
    state: OrganizationDeletionState
    def __init__(self, operation_id: _Optional[str] = ..., state: _Optional[_Union[OrganizationDeletionState, str]] = ...) -> None: ...

class ListMembersRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListMembersResponse(_message.Message):
    __slots__ = ("members", "next_page_token")
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    members: _containers.RepeatedCompositeFieldContainer[OrgMember]
    next_page_token: str
    def __init__(self, members: _Optional[_Iterable[_Union[OrgMember, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class UpdateMemberRoleRequest(_message.Message):
    __slots__ = ("org_id", "user_id", "role")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    user_id: str
    role: OrgRole
    def __init__(self, org_id: _Optional[str] = ..., user_id: _Optional[str] = ..., role: _Optional[_Union[OrgRole, str]] = ...) -> None: ...

class UpdateMemberRoleResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RemoveMemberRequest(_message.Message):
    __slots__ = ("org_id", "user_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    user_id: str
    def __init__(self, org_id: _Optional[str] = ..., user_id: _Optional[str] = ...) -> None: ...

class RemoveMemberResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetMemberAssignmentsRequest(_message.Message):
    __slots__ = ("org_id", "member_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    MEMBER_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    member_id: str
    def __init__(self, org_id: _Optional[str] = ..., member_id: _Optional[str] = ...) -> None: ...

class GetMemberAssignmentsResponse(_message.Message):
    __slots__ = ("assignments",)
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    assignments: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, assignments: _Optional[_Iterable[str]] = ...) -> None: ...

class UpdateMemberAssignmentsRequest(_message.Message):
    __slots__ = ("org_id", "member_id", "assignments")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    MEMBER_ID_FIELD_NUMBER: _ClassVar[int]
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    member_id: str
    assignments: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, org_id: _Optional[str] = ..., member_id: _Optional[str] = ..., assignments: _Optional[_Iterable[str]] = ...) -> None: ...

class UpdateMemberAssignmentsResponse(_message.Message):
    __slots__ = ("assignments",)
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    assignments: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, assignments: _Optional[_Iterable[str]] = ...) -> None: ...

class ListInvitationsRequest(_message.Message):
    __slots__ = ("org_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListInvitationsResponse(_message.Message):
    __slots__ = ("invitations", "next_page_token")
    INVITATIONS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    invitations: _containers.RepeatedCompositeFieldContainer[OrgInvitation]
    next_page_token: str
    def __init__(self, invitations: _Optional[_Iterable[_Union[OrgInvitation, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateInvitationRequest(_message.Message):
    __slots__ = ("org_id", "email", "role", "assignments")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    ASSIGNMENTS_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    email: str
    role: OrgRole
    assignments: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, org_id: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[_Union[OrgRole, str]] = ..., assignments: _Optional[_Iterable[str]] = ...) -> None: ...

class CreateInvitationResponse(_message.Message):
    __slots__ = ("invitation",)
    INVITATION_FIELD_NUMBER: _ClassVar[int]
    invitation: OrgInvitation
    def __init__(self, invitation: _Optional[_Union[OrgInvitation, _Mapping]] = ...) -> None: ...

class RevokeInvitationRequest(_message.Message):
    __slots__ = ("org_id", "invitation_id")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    INVITATION_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    invitation_id: str
    def __init__(self, org_id: _Optional[str] = ..., invitation_id: _Optional[str] = ...) -> None: ...

class RevokeInvitationResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class AcceptInvitationRequest(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...

class AcceptInvitationResponse(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class GetInvitationByTokenRequest(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...

class GetInvitationByTokenResponse(_message.Message):
    __slots__ = ("invitation",)
    INVITATION_FIELD_NUMBER: _ClassVar[int]
    invitation: OrgInvitation
    def __init__(self, invitation: _Optional[_Union[OrgInvitation, _Mapping]] = ...) -> None: ...
