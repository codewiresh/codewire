import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MeshGroupMessagesPolicy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED: _ClassVar[MeshGroupMessagesPolicy]
    MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY: _ClassVar[MeshGroupMessagesPolicy]
    MESH_GROUP_MESSAGES_POLICY_OPEN: _ClassVar[MeshGroupMessagesPolicy]

class MeshGroupDebugPolicy(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESH_GROUP_DEBUG_POLICY_UNSPECIFIED: _ClassVar[MeshGroupDebugPolicy]
    MESH_GROUP_DEBUG_POLICY_NONE: _ClassVar[MeshGroupDebugPolicy]
    MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY: _ClassVar[MeshGroupDebugPolicy]
    MESH_GROUP_DEBUG_POLICY_FULL: _ClassVar[MeshGroupDebugPolicy]
MESH_GROUP_MESSAGES_POLICY_UNSPECIFIED: MeshGroupMessagesPolicy
MESH_GROUP_MESSAGES_POLICY_INTERNAL_ONLY: MeshGroupMessagesPolicy
MESH_GROUP_MESSAGES_POLICY_OPEN: MeshGroupMessagesPolicy
MESH_GROUP_DEBUG_POLICY_UNSPECIFIED: MeshGroupDebugPolicy
MESH_GROUP_DEBUG_POLICY_NONE: MeshGroupDebugPolicy
MESH_GROUP_DEBUG_POLICY_OBSERVE_ONLY: MeshGroupDebugPolicy
MESH_GROUP_DEBUG_POLICY_FULL: MeshGroupDebugPolicy

class MeshGroup(_message.Message):
    __slots__ = ("org_id", "network_id", "name", "created_at", "created_by_user_id", "members", "policy")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_USER_ID_FIELD_NUMBER: _ClassVar[int]
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    name: str
    created_at: _timestamp_pb2.Timestamp
    created_by_user_id: str
    members: _containers.RepeatedCompositeFieldContainer[MeshGroupMember]
    policy: MeshGroupPolicy
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., name: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., created_by_user_id: _Optional[str] = ..., members: _Optional[_Iterable[_Union[MeshGroupMember, _Mapping]]] = ..., policy: _Optional[_Union[MeshGroupPolicy, _Mapping]] = ...) -> None: ...

class MeshGroupMember(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name", "node_name", "session_name", "created_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    node_name: str
    session_name: str
    created_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ..., node_name: _Optional[str] = ..., session_name: _Optional[str] = ..., created_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class MeshGroupPolicy(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name", "messages_policy", "debug_policy", "updated_at")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_POLICY_FIELD_NUMBER: _ClassVar[int]
    DEBUG_POLICY_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    messages_policy: MeshGroupMessagesPolicy
    debug_policy: MeshGroupDebugPolicy
    updated_at: _timestamp_pb2.Timestamp
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ..., messages_policy: _Optional[_Union[MeshGroupMessagesPolicy, str]] = ..., debug_policy: _Optional[_Union[MeshGroupDebugPolicy, str]] = ..., updated_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ListMeshGroupsRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "page_size", "page_token")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    page_size: int
    page_token: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ...) -> None: ...

class ListMeshGroupsResponse(_message.Message):
    __slots__ = ("groups", "next_page_token")
    GROUPS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    groups: _containers.RepeatedCompositeFieldContainer[MeshGroup]
    next_page_token: str
    def __init__(self, groups: _Optional[_Iterable[_Union[MeshGroup, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class CreateMeshGroupRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class CreateMeshGroupResponse(_message.Message):
    __slots__ = ("group",)
    GROUP_FIELD_NUMBER: _ClassVar[int]
    group: MeshGroup
    def __init__(self, group: _Optional[_Union[MeshGroup, _Mapping]] = ...) -> None: ...

class GetMeshGroupRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ...) -> None: ...

class GetMeshGroupResponse(_message.Message):
    __slots__ = ("group",)
    GROUP_FIELD_NUMBER: _ClassVar[int]
    group: MeshGroup
    def __init__(self, group: _Optional[_Union[MeshGroup, _Mapping]] = ...) -> None: ...

class DeleteMeshGroupRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ...) -> None: ...

class DeleteMeshGroupResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetMeshGroupPolicyRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name", "messages_policy", "debug_policy")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_POLICY_FIELD_NUMBER: _ClassVar[int]
    DEBUG_POLICY_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    messages_policy: MeshGroupMessagesPolicy
    debug_policy: MeshGroupDebugPolicy
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ..., messages_policy: _Optional[_Union[MeshGroupMessagesPolicy, str]] = ..., debug_policy: _Optional[_Union[MeshGroupDebugPolicy, str]] = ...) -> None: ...

class SetMeshGroupPolicyResponse(_message.Message):
    __slots__ = ("policy",)
    POLICY_FIELD_NUMBER: _ClassVar[int]
    policy: MeshGroupPolicy
    def __init__(self, policy: _Optional[_Union[MeshGroupPolicy, _Mapping]] = ...) -> None: ...

class AddMeshGroupMemberRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name", "node_name", "session_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    node_name: str
    session_name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ..., node_name: _Optional[str] = ..., session_name: _Optional[str] = ...) -> None: ...

class AddMeshGroupMemberResponse(_message.Message):
    __slots__ = ("member",)
    MEMBER_FIELD_NUMBER: _ClassVar[int]
    member: MeshGroupMember
    def __init__(self, member: _Optional[_Union[MeshGroupMember, _Mapping]] = ...) -> None: ...

class RemoveMeshGroupMemberRequest(_message.Message):
    __slots__ = ("org_id", "network_id", "group_name", "node_name", "session_name")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NETWORK_ID_FIELD_NUMBER: _ClassVar[int]
    GROUP_NAME_FIELD_NUMBER: _ClassVar[int]
    NODE_NAME_FIELD_NUMBER: _ClassVar[int]
    SESSION_NAME_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    network_id: str
    group_name: str
    node_name: str
    session_name: str
    def __init__(self, org_id: _Optional[str] = ..., network_id: _Optional[str] = ..., group_name: _Optional[str] = ..., node_name: _Optional[str] = ..., session_name: _Optional[str] = ...) -> None: ...

class RemoveMeshGroupMemberResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
