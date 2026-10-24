from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class EnvironmentMeshMemberStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ENVIRONMENT_MESH_MEMBER_STATUS_UNSPECIFIED: _ClassVar[EnvironmentMeshMemberStatus]
    ENVIRONMENT_MESH_MEMBER_STATUS_LIVE: _ClassVar[EnvironmentMeshMemberStatus]
    ENVIRONMENT_MESH_MEMBER_STATUS_STALE: _ClassVar[EnvironmentMeshMemberStatus]
    ENVIRONMENT_MESH_MEMBER_STATUS_GONE: _ClassVar[EnvironmentMeshMemberStatus]
ENVIRONMENT_MESH_MEMBER_STATUS_UNSPECIFIED: EnvironmentMeshMemberStatus
ENVIRONMENT_MESH_MEMBER_STATUS_LIVE: EnvironmentMeshMemberStatus
ENVIRONMENT_MESH_MEMBER_STATUS_STALE: EnvironmentMeshMemberStatus
ENVIRONMENT_MESH_MEMBER_STATUS_GONE: EnvironmentMeshMemberStatus

class RedeemEnvironmentEnrollmentRequest(_message.Message):
    __slots__ = ("enrollment_code", "org_id", "network_id")
    ENROLLMENT_CODE_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    enrollment_code: str
    org_id: str
    network_id: str
    def __init__(self, enrollment_code: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ...) -> None: ...

class EnvironmentMeshMember(_message.Message):
    __slots__ = ("environment_id", "org_id", "network_id", "node_name", "pod_uid", "operation_generation", "attached_by_user_id")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    ATTACHED_BY_USER_ID_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    org_id: str
    network_id: str
    node_name: str
    pod_uid: str
    operation_generation: int
    attached_by_user_id: str
    def __init__(self, environment_id: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., node_name: _Optional[str] = ..., pod_uid: _Optional[str] = ..., operation_generation: _Optional[int] = ..., attached_by_user_id: _Optional[str] = ...) -> None: ...

class RedeemEnvironmentEnrollmentResponse(_message.Message):
    __slots__ = ("member",)
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    member: EnvironmentMeshMember
    def __init__(self, member: _Optional[_Union[EnvironmentMeshMember, _Mapping]] = ...) -> None: ...

class EnvironmentMeshMemberRef(_message.Message):
    __slots__ = ("environment_id", "org_id", "network_id", "pod_uid", "operation_generation")
    ENVIRONMENT_ID_FIELD_NUMBER: _ClassVar[int]
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    POD_UID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_GENERATION_FIELD_NUMBER: _ClassVar[int]
    environment_id: str
    org_id: str
    network_id: str
    pod_uid: str
    operation_generation: int
    def __init__(self, environment_id: _Optional[str] = ..., org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., pod_uid: _Optional[str] = ..., operation_generation: _Optional[int] = ...) -> None: ...

class CheckEnvironmentMembersRequest(_message.Message):
    __slots__ = ("members",)
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    members: _containers.RepeatedCompositeFieldContainer[EnvironmentMeshMemberRef]
    def __init__(self, members: _Optional[_Iterable[_Union[EnvironmentMeshMemberRef, _Mapping]]] = ...) -> None: ...

class CheckEnvironmentMembersResponse(_message.Message):
    __slots__ = ("statuses",)
    STATUSES_FIELD_NUMBER: _ClassVar[int]
    statuses: _containers.RepeatedScalarFieldContainer[EnvironmentMeshMemberStatus]
    def __init__(self, statuses: _Optional[_Iterable[_Union[EnvironmentMeshMemberStatus, str]]] = ...) -> None: ...
